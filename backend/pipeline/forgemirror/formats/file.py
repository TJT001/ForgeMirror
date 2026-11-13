"""Encrypted file formats FMF1/FMF2 and the legacy migration tool.

FMF1 is the whole-file AES-GCM envelope written by the P1 shell. FMF2 is the
chunked format with per-chunk nonces and tags. ``migrate`` reads FMF1 (or
explicitly plaintext) and rewrites it as FMF2 atomically.
"""

from __future__ import annotations

import os
import secrets
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

FMF1_MAGIC = b"FMF1"
FMF1_HEADER = 20
FMF2_MAGIC = b"FMF2"
FMF2_VERSION = 2
FMF2_HEADER = 72
DEFAULT_CHUNK_SIZE = 65536
NONCE_SIZE = 12
TAG_SIZE = 16
FILE_INFO = b"FM/files/v1"


class FileFormatError(Exception):
    pass


def derive_file_key(k_content: bytes, build_id: str) -> bytes:
    salt = uuid.UUID(build_id).bytes
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=FILE_INFO
    ).derive(k_content)


def is_fmf1(blob: bytes) -> bool:
    return len(blob) >= FMF1_HEADER and blob[:4] == FMF1_MAGIC


def is_fmf2(blob: bytes) -> bool:
    return len(blob) >= FMF2_HEADER and blob[:4] == FMF2_MAGIC


def decrypt_fmf1(blob: bytes, key: bytes) -> bytes:
    if not is_fmf1(blob):
        raise FileFormatError("not an FMF1 file")
    version, algorithm, reserved = struct.unpack_from("<HBB", blob, 4)
    if version != 1 or algorithm != 1 or reserved != 0:
        raise FileFormatError("unsupported FMF1 header")
    header = blob[:FMF1_HEADER]
    nonce = blob[8:20]
    try:
        return AESGCM(key).decrypt(nonce, blob[FMF1_HEADER:], header)
    except InvalidTag as error:
        raise FileFormatError("FMF1 authentication failed") from error


def _chunk_aad(file_id: bytes, index: int, chunk_length: int) -> bytes:
    return (
        FMF2_MAGIC
        + struct.pack("<H", FMF2_VERSION)
        + file_id
        + struct.pack("<I", index)
        + struct.pack("<I", chunk_length)
    )


def _build_header(
    key: bytes,
    file_id: bytes,
    chunk_size: int,
    plaintext_length: int,
    chunk_count: int,
) -> bytes:
    nonce = secrets.token_bytes(NONCE_SIZE)
    prefix = (
        FMF2_MAGIC
        + struct.pack("<H", FMF2_VERSION)
        + bytes([1, 0])
        + file_id
        + struct.pack("<I", chunk_size)
        + struct.pack("<Q", plaintext_length)
        + struct.pack("<I", chunk_count)
        + nonce
    )
    if len(prefix) != 52:
        raise AssertionError("FMF2 header prefix size")
    tag = AESGCM(key).encrypt(nonce, b"", prefix)
    if len(tag) != TAG_SIZE:
        raise AssertionError("FMF2 header tag size")
    return prefix + tag + b"\x00" * 4


def encode_fmf2(
    plaintext: bytes, key: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> bytes:
    if chunk_size < 1024 or chunk_size > (1 << 20) or chunk_size & (chunk_size - 1):
        raise FileFormatError("unsupported chunk size")
    file_id = secrets.token_bytes(16)
    chunk_count = (len(plaintext) + chunk_size - 1) // chunk_size
    header = _build_header(key, file_id, chunk_size, len(plaintext), chunk_count)
    parts = [header]
    aes = AESGCM(key)
    for index in range(chunk_count):
        offset = index * chunk_size
        chunk = plaintext[offset : offset + chunk_size]
        chunk_length = len(chunk)
        padded = chunk + b"\x00" * (chunk_size - chunk_length)
        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext = aes.encrypt(
            nonce, padded, _chunk_aad(file_id, index, chunk_length)
        )
        parts.append(nonce + ciphertext)
    return b"".join(parts)


@dataclass
class Fmf2Info:
    file_id: bytes
    chunk_size: int
    plaintext_length: int
    chunk_count: int


def decode_fmf2(blob: bytes, key: bytes) -> tuple[Fmf2Info, bytes]:
    if not is_fmf2(blob):
        raise FileFormatError("not an FMF2 file")
    version, algorithm = struct.unpack_from("<HB", blob, 4)
    if version != FMF2_VERSION or algorithm != 1 or blob[7] != 0:
        raise FileFormatError("unsupported FMF2 header")
    file_id = blob[8:24]
    chunk_size, plaintext_length, chunk_count = struct.unpack_from("<IQI", blob, 24)
    if (
        chunk_size < 1024
        or chunk_size > (1 << 20)
        or chunk_size & (chunk_size - 1)
        or chunk_count != (plaintext_length + chunk_size - 1) // chunk_size
    ):
        raise FileFormatError("invalid FMF2 header")
    nonce = blob[40:52]
    tag = blob[52:68]
    try:
        AESGCM(key).decrypt(nonce, tag, blob[:52])
    except InvalidTag as error:
        raise FileFormatError("FMF2 header authentication failed") from error
    record_size = NONCE_SIZE + chunk_size + TAG_SIZE
    if len(blob) != FMF2_HEADER + chunk_count * record_size:
        raise FileFormatError("FMF2 length mismatch")
    aes = AESGCM(key)
    output = bytearray()
    for index in range(chunk_count):
        offset = FMF2_HEADER + index * record_size
        chunk_nonce = blob[offset : offset + NONCE_SIZE]
        ciphertext = blob[offset + NONCE_SIZE : offset + record_size]
        chunk_length = min(chunk_size, plaintext_length - index * chunk_size)
        try:
            plaintext = aes.decrypt(
                chunk_nonce, ciphertext, _chunk_aad(file_id, index, chunk_length)
            )
        except InvalidTag as error:
            raise FileFormatError(f"FMF2 chunk {index} authentication failed") from error
        if len(plaintext) != chunk_size:
            raise FileFormatError(f"FMF2 chunk {index} length mismatch")
        output.extend(plaintext[:chunk_length])
    return Fmf2Info(file_id, chunk_size, plaintext_length, chunk_count), bytes(output)


def migrate(
    source: Path,
    out: Path,
    key: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    assume_plaintext: bool = False,
) -> dict:
    blob = source.read_bytes()
    if is_fmf2(blob):
        raise FileFormatError(f"already FMF2: {source}")
    if is_fmf1(blob):
        plaintext = decrypt_fmf1(blob, key)
        source_format = "fmf1"
    elif assume_plaintext:
        plaintext = blob
        source_format = "plaintext"
    else:
        raise FileFormatError(
            f"not FMF1 ({source}); pass --assume-plaintext to migrate plaintext"
        )
    encoded = encode_fmf2(plaintext, key, chunk_size)
    out.parent.mkdir(parents=True, exist_ok=True)
    temp = out.with_name(out.name + ".tmp")
    with open(temp, "wb") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, out)
    return {
        "ok": True,
        "source": str(source),
        "out": str(out),
        "source_format": source_format,
        "plaintext_bytes": len(plaintext),
        "chunk_size": chunk_size,
        "chunk_count": (len(plaintext) + chunk_size - 1) // chunk_size,
        "fmf2_bytes": len(encoded),
    }


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    if not key:
        raise FileFormatError("empty RC4 key")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    output = bytearray(len(data))
    i = j = 0
    for index, value in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output[index] = value ^ state[(state[i] + state[j]) & 0xFF]
    return bytes(output)


def decrypt_dve(blob: bytes, key: bytes, enc_type: int = 0,
                chunk: int = 0x20000, xor_byte: int = 0xAC) -> bytes:
    """Decode a SecNeo DVE-style RC4 file.

    enc_type == 0: whole-file RC4.
    enc_type != 0: first ``chunk`` bytes RC4, the remainder XOR ``xor_byte``.
    """
    if enc_type == 0:
        return rc4_crypt(blob, key)
    head = min(len(blob), chunk)
    output = bytearray(blob)
    if head:
        output[:head] = rc4_crypt(blob[:head], key)
    for index in range(head, len(blob)):
        output[index] ^= xor_byte
    return bytes(output)


def migrate_rc4(
    source: Path,
    out: Path,
    key: bytes,
    enc_type: int = 0,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    out_key: bytes | None = None,
) -> dict:
    blob = source.read_bytes()
    plaintext = decrypt_dve(blob, key, enc_type)
    encoded = encode_fmf2(plaintext, out_key if out_key is not None else key, chunk_size)
    out.parent.mkdir(parents=True, exist_ok=True)
    temp = out.with_name(out.name + ".tmp")
    with open(temp, "wb") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, out)
    return {
        "ok": True,
        "source": str(source),
        "out": str(out),
        "source_format": f"dve-rc4-{enc_type}",
        "plaintext_bytes": len(plaintext),
        "chunk_size": chunk_size,
        "chunk_count": (len(plaintext) + chunk_size - 1) // chunk_size,
        "fmf2_bytes": len(encoded),
    }
