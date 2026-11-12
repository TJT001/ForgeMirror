from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND / "pipeline"))

from forgemirror.formats.container import (  # noqa: E402
    CHUNK_SIZE,
    HEADER_SIZE,
    ContainerError,
    FileSpec,
    open_container,
    write_container,
)

K_CONTENT = hashlib.sha256(b"forgemirror-test-key").digest()
BUILD_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
NONCE_PREFIX = bytes.fromhex("0102030405060708")
TOC_NONCE = bytes.fromhex("1112131415161718191a1b1c")
VECTORS = BACKEND / "tests" / "vectors" / "container" / "v2"


def build(files: list[FileSpec]) -> bytes:
    return write_container(
        files,
        k_content=K_CONTENT,
        build_id=BUILD_ID,
        nonce_prefix=NONCE_PREFIX,
        toc_nonce=TOC_NONCE,
    )


class ContainerRoundTripTests(unittest.TestCase):
    def test_single_file(self) -> None:
        data = bytes(range(256)) * 4
        blob = build([FileSpec("classes.dex", data)])
        opened = open_container(blob, k_content=K_CONTENT)
        self.assertEqual(opened.files, [data])
        self.assertEqual(opened.header.file_count, 1)
        self.assertEqual(opened.header.total_plaintext_size, len(data))

    def test_multi_file_with_empty_and_chunk_boundary(self) -> None:
        files = [
            FileSpec("classes.dex", b"a" * (2 * CHUNK_SIZE)),
            FileSpec("classes2.dex", b""),
            FileSpec("classes3.dex", b"b" * (CHUNK_SIZE + 1)),
        ]
        opened = open_container(build(files), k_content=K_CONTENT)
        self.assertEqual(opened.files, [spec.data for spec in files])
        self.assertEqual(opened.header.total_chunk_count, 4)

    def test_committed_vectors(self) -> None:
        if not VECTORS.is_dir():
            self.skipTest("vectors not generated")
        cases = sorted(path for path in VECTORS.iterdir() if path.is_dir())
        self.assertTrue(cases, "no vector cases found")
        for case in cases:
            with self.subTest(case=case.name):
                meta = json.loads((case / "meta.json").read_text())
                blob = (case / "container.fdx").read_bytes()
                self.assertEqual(hashlib.sha256(blob).hexdigest(), meta["container_sha256"])
                opened = open_container(blob, k_content=bytes.fromhex(meta["k_content"]))
                self.assertEqual(len(opened.files), len(meta["files"]))
                for data, expected in zip(opened.files, meta["files"]):
                    self.assertEqual(hashlib.sha256(data).hexdigest(), expected["sha256"])
                    self.assertEqual(len(data), expected["size"])


class ContainerNegativeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = b"c" * 1024
        self.blob = build([FileSpec("classes.dex", self.data)])

    def test_wrong_key(self) -> None:
        with self.assertRaises(ContainerError):
            open_container(self.blob, k_content=b"\x00" * 32)

    def test_tampered_chunk(self) -> None:
        tampered = bytearray(self.blob)
        tampered[HEADER_SIZE] ^= 0x01
        with self.assertRaises(ContainerError):
            open_container(bytes(tampered), k_content=K_CONTENT)

    def test_tampered_header_flags(self) -> None:
        tampered = bytearray(self.blob)
        tampered[8] = 1
        with self.assertRaises(ContainerError):
            open_container(bytes(tampered), k_content=K_CONTENT)

    def test_truncated(self) -> None:
        with self.assertRaises(ContainerError):
            open_container(self.blob[:-1], k_content=K_CONTENT)

    def test_trailing_data(self) -> None:
        with self.assertRaises(ContainerError):
            open_container(self.blob + b"\x00", k_content=K_CONTENT)

    def test_duplicate_nonce_attempt(self) -> None:
        data = b"d" * (2 * CHUNK_SIZE)
        blob = bytearray(build([FileSpec("classes.dex", data)]))
        first = bytes(blob[HEADER_SIZE:HEADER_SIZE + CHUNK_SIZE + 16])
        second = HEADER_SIZE + CHUNK_SIZE + 16
        blob[second:second + CHUNK_SIZE + 16] = first
        with self.assertRaises(ContainerError):
            open_container(bytes(blob), k_content=K_CONTENT)

    def test_writer_rejects_empty_and_duplicate(self) -> None:
        with self.assertRaises(ValueError):
            build([])
        with self.assertRaises(ValueError):
            build([FileSpec("a", b""), FileSpec("a", b"")])
        with self.assertRaises(ValueError):
            write_container(
                [FileSpec("a", b"")],
                k_content=b"\x00" * 31,
                build_id=BUILD_ID,
            )


if __name__ == "__main__":
    unittest.main()
