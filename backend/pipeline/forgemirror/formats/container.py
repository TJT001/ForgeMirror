"""FDX2 container reference implementation (build side).

Spec: docs/formats/container-v2.md. The runtime side must implement the same
layout independently in C++ and consume backend/tests/vectors/container/v2.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from typing import Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"FDX2"
VERSION = 2
HEADER_SIZE = 128
CHUNK_SIZE = 65536
ALG_AES_256_GCM = 1
KDF_HKDF_SHA256 = 1
TAG_SIZE = 16

MAX_FILE_COUNT = 64
MAX_FILE_SIZE = 1 << 30
MAX_TOTAL_SIZE = 2 << 30
MAX_TOTAL_CHUNKS = 1 << 15

LABEL_CHUNK = b"FM/fdx2/chunk/v1"
LABEL_TOC = b"FM/fdx2/toc/v1"

_HEADER = struct.Struct("<4sHHIBBH16sII8s12sIQIIQQ32s")
_ENTRY = struct.Struct("<IIQQIIQ32s")
_CHUNK_AAD = struct.Struct("<4sHBB16sIIII")

assert _HEADER.size == HEADER_SIZE
assert _ENTRY.size == 72
assert _CHUNK_AAD.size == 40


class ContainerError(Exception):
    """Raised when a container is malformed or fails authentication."""


@dataclass(frozen=True)
class FileSpec:
    name: str
    data: bytes


@dataclass(frozen=True)
class ContainerHeader:
    build_id: bytes
    file_count: int
    nonce_prefix: bytes
    toc_nonce: bytes
    total_plaintext_size: int
    total_chunk_count: int
    toc_offset: int
    toc_size: int


@dataclass(frozen=True)
class OpenedContainer:
    header: ContainerHeader
    files: list[bytes]


def _derive(key: bytes, build_id: bytes, label: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=build_id,
        info=label,
    ).derive(key)


def _chunk_aad(
    build_id: bytes,
    file_index: int,
    global_chunk_index: int,
    plaintext_len: int,
    flags: int,
) -> bytes:
    return _CHUNK_AAD.pack(
        MAGIC,
        VERSION,
        ALG_AES_256_GCM,
        KDF_HKDF_SHA256,
        build_id,
        file_index,
        global_chunk_index,
        plaintext_len,
        flags,
    )


def _chunk_count(size: int) -> int:
    return (size + CHUNK_SIZE - 1) // CHUNK_SIZE


def _validate_key_material(k_content: bytes, build_id: bytes) -> None:
    if len(k_content) != 32:
        raise ValueError("k_content must be 32 bytes")
    if len(build_id) != 16:
        raise ValueError("build_id must be 16 bytes")


def write_container(
    files: Sequence[FileSpec],
    *,
    k_content: bytes,
    build_id: bytes,
    nonce_prefix: bytes | None = None,
    toc_nonce: bytes | None = None,
) -> bytes:
    """Build an FDX2 container holding the given files in order."""
    _validate_key_material(k_content, build_id)
    if not 1 <= len(files) <= MAX_FILE_COUNT:
        raise ValueError(f"file count must be 1..{MAX_FILE_COUNT}")
    if len({spec.name for spec in files}) != len(files):
        raise ValueError("file names must be unique")

    nonce_prefix = nonce_prefix if nonce_prefix is not None else os.urandom(8)
    toc_nonce = toc_nonce if toc_nonce is not None else os.urandom(12)
    if len(nonce_prefix) != 8:
        raise ValueError("nonce_prefix must be 8 bytes")
    if len(toc_nonce) != 12:
        raise ValueError("toc_nonce must be 12 bytes")

    chunk_cipher = AESGCM(_derive(k_content, build_id, LABEL_CHUNK))
    toc_key = _derive(k_content, build_id, LABEL_TOC)

    toc_entries: list[bytes] = []
    chunk_blobs: list[bytes] = []
    offset = HEADER_SIZE
    global_chunk_index = 0
    total_plaintext = 0

    for file_index, spec in enumerate(files):
        data = bytes(spec.data)
        size = len(data)
        if size > MAX_FILE_SIZE:
            raise ValueError(f"file {spec.name} exceeds {MAX_FILE_SIZE} bytes")

        count = _chunk_count(size)
        data_offset = offset
        file_id = int.from_bytes(hashlib.sha256(data).digest()[:8], "little")

        for local_index in range(count):
            plaintext = data[local_index * CHUNK_SIZE:(local_index + 1) * CHUNK_SIZE]
            if global_chunk_index > 0xFFFFFFFF:
                raise ValueError("global chunk index overflow")
            nonce = nonce_prefix + struct.pack(">I", global_chunk_index)
            aad = _chunk_aad(build_id, file_index, global_chunk_index, len(plaintext), 0)
            chunk_blobs.append(chunk_cipher.encrypt(nonce, plaintext, aad))
            offset += len(plaintext) + TAG_SIZE
            global_chunk_index += 1

        total_plaintext += size
        if total_plaintext > MAX_TOTAL_SIZE:
            raise ValueError(f"container exceeds {MAX_TOTAL_SIZE} bytes")
        toc_entries.append(
            _ENTRY.pack(
                file_index,
                0,
                file_id,
                size,
                CHUNK_SIZE,
                count,
                data_offset,
                hashlib.sha256(data).digest(),
            )
        )

    if global_chunk_index > MAX_TOTAL_CHUNKS:
        raise ValueError(f"chunk count exceeds {MAX_TOTAL_CHUNKS}")

    toc_plaintext = b"".join(toc_entries)
    toc_offset = offset
    toc_size = len(toc_plaintext) + TAG_SIZE
    header = _HEADER.pack(
        MAGIC,
        VERSION,
        HEADER_SIZE,
        0,
        ALG_AES_256_GCM,
        KDF_HKDF_SHA256,
        0,
        build_id,
        len(files),
        CHUNK_SIZE,
        nonce_prefix,
        toc_nonce,
        0,
        total_plaintext,
        global_chunk_index,
        0,
        toc_offset,
        toc_size,
        b"\x00" * 32,
    )
    if len(header) != HEADER_SIZE:
        raise AssertionError("header size mismatch")

    return header + b"".join(chunk_blobs) + AESGCM(toc_key).encrypt(
        toc_nonce, toc_plaintext, header
    )


def open_container(blob: bytes, *, k_content: bytes) -> OpenedContainer:
    """Authenticate and decrypt an FDX2 container."""
    if len(k_content) != 32:
        raise ValueError("k_content must be 32 bytes")
    if len(blob) < HEADER_SIZE:
        raise ContainerError("container shorter than header")

    (
        magic,
        version,
        header_size,
        flags,
        alg,
        kdf,
        reserved,
        build_id,
        file_count,
        chunk_size,
        nonce_prefix,
        toc_nonce,
        reserved2,
        total_plaintext,
        total_chunks,
        reserved3,
        toc_offset,
        toc_size,
        reserved4,
    ) = _HEADER.unpack_from(blob, 0)

    if magic != MAGIC or version != VERSION or header_size != HEADER_SIZE:
        raise ContainerError("bad header identity")
    if flags != 0 or reserved != 0 or reserved2 != 0 or reserved3 != 0:
        raise ContainerError("unknown header flags")
    if any(reserved4):
        raise ContainerError("non-zero reserved header bytes")
    if alg != ALG_AES_256_GCM or kdf != KDF_HKDF_SHA256:
        raise ContainerError("unsupported algorithm")
    if not 1 <= file_count <= MAX_FILE_COUNT:
        raise ContainerError("invalid file count")
    if chunk_size != CHUNK_SIZE:
        raise ContainerError("invalid chunk size")
    if total_chunks > MAX_TOTAL_CHUNKS:
        raise ContainerError("chunk count over limit")
    if total_plaintext > MAX_TOTAL_SIZE:
        raise ContainerError("plaintext size over limit")
    if toc_offset < HEADER_SIZE or toc_offset > len(blob):
        raise ContainerError("invalid TOC offset")
    if toc_size != TAG_SIZE + _ENTRY.size * file_count:
        raise ContainerError("invalid TOC size")
    if toc_offset + toc_size != len(blob):
        raise ContainerError("trailing or truncated data")

    toc_key = _derive(k_content, build_id, LABEL_TOC)
    try:
        toc_plaintext = AESGCM(toc_key).decrypt(
            toc_nonce, blob[toc_offset:], blob[:HEADER_SIZE]
        )
    except InvalidTag as exc:
        raise ContainerError("TOC authentication failed") from exc

    if len(toc_plaintext) != _ENTRY.size * file_count:
        raise ContainerError("TOC length mismatch")

    entries: list[tuple[int, bytes]] = []
    expected_offset = HEADER_SIZE
    expected_chunks = 0
    expected_plaintext = 0
    for index in range(file_count):
        (
            file_index,
            file_flags,
            _file_id,
            plaintext_size,
            entry_chunk_size,
            entry_chunk_count,
            data_offset,
            plaintext_sha256,
        ) = _ENTRY.unpack_from(toc_plaintext, index * _ENTRY.size)

        if file_index != index:
            raise ContainerError("TOC entry index mismatch")
        if file_flags != 0:
            raise ContainerError("unknown file flags")
        if entry_chunk_size != CHUNK_SIZE:
            raise ContainerError("invalid entry chunk size")
        if plaintext_size > MAX_FILE_SIZE:
            raise ContainerError("file size over limit")
        if entry_chunk_count != _chunk_count(plaintext_size):
            raise ContainerError("chunk count mismatch")
        if data_offset != expected_offset:
            raise ContainerError("non-contiguous data region")
        if data_offset > toc_offset:
            raise ContainerError("data region overlaps TOC")

        remaining = plaintext_size
        for _ in range(entry_chunk_count):
            span = min(CHUNK_SIZE, remaining)
            expected_offset += span + TAG_SIZE
            remaining -= span
        if expected_offset > toc_offset:
            raise ContainerError("data region exceeds TOC offset")

        expected_chunks += entry_chunk_count
        expected_plaintext += plaintext_size
        entries.append((plaintext_size, plaintext_sha256))

    if expected_offset != toc_offset:
        raise ContainerError("data region does not end at TOC")
    if expected_chunks != total_chunks or expected_plaintext != total_plaintext:
        raise ContainerError("header totals mismatch")

    chunk_cipher = AESGCM(_derive(k_content, build_id, LABEL_CHUNK))
    files: list[bytes] = []
    cursor = HEADER_SIZE
    global_chunk_index = 0
    for file_index, (plaintext_size, plaintext_sha256) in enumerate(entries):
        parts: list[bytes] = []
        remaining = plaintext_size
        while remaining > 0:
            length = min(CHUNK_SIZE, remaining)
            ciphertext_len = length + TAG_SIZE
            ciphertext = blob[cursor:cursor + ciphertext_len]
            if len(ciphertext) != ciphertext_len:
                raise ContainerError("truncated chunk")
            nonce = nonce_prefix + struct.pack(">I", global_chunk_index)
            aad = _chunk_aad(build_id, file_index, global_chunk_index, length, 0)
            try:
                parts.append(chunk_cipher.decrypt(nonce, ciphertext, aad))
            except InvalidTag as exc:
                raise ContainerError("chunk authentication failed") from exc
            cursor += ciphertext_len
            remaining -= length
            global_chunk_index += 1

        data = b"".join(parts)
        if hashlib.sha256(data).digest() != plaintext_sha256:
            raise ContainerError("plaintext hash mismatch")
        files.append(data)

    if cursor != toc_offset:
        raise ContainerError("chunk region length mismatch")

    return OpenedContainer(
        header=ContainerHeader(
            build_id=build_id,
            file_count=file_count,
            nonce_prefix=nonce_prefix,
            toc_nonce=toc_nonce,
            total_plaintext_size=total_plaintext,
            total_chunk_count=total_chunks,
            toc_offset=toc_offset,
            toc_size=toc_size,
        ),
        files=files,
    )
