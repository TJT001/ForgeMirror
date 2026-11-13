from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pipeline"))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

from forgemirror.formats import file as fmfile  # noqa: E402

KEY = bytes(range(1, 33))


def encrypt_fmf1(plaintext: bytes, key: bytes = KEY) -> bytes:
    nonce = os.urandom(12)
    header = b"FMF1" + struct.pack("<HBB", 1, 1, 0) + nonce
    return header + AESGCM(key).encrypt(nonce, plaintext, header)


def pattern(length: int, seed: int = 7) -> bytes:
    return bytes((index * 31 + seed) & 0xFF for index in range(length))


class FileFormatTests(unittest.TestCase):
    def test_fmf2_roundtrip_sizes(self) -> None:
        for length in (0, 1, 1023, 1024, 65535, 65536, 65537, 200000):
            with self.subTest(length=length):
                plaintext = pattern(length)
                blob = fmfile.encode_fmf2(plaintext, KEY)
                info, decoded = fmfile.decode_fmf2(blob, KEY)
                self.assertEqual(decoded, plaintext)
                self.assertEqual(info.plaintext_length, length)
                self.assertEqual(
                    info.chunk_count, (length + 65535) // 65536
                )

    def test_migrate_fmf1(self) -> None:
        plaintext = pattern(150000)
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "legacy.bin"
            out = Path(temporary) / "migrated.bin"
            source.write_bytes(encrypt_fmf1(plaintext))
            result = fmfile.migrate(source, out, KEY)
            self.assertEqual(result["source_format"], "fmf1")
            self.assertEqual(result["plaintext_bytes"], len(plaintext))
            _, decoded = fmfile.decode_fmf2(out.read_bytes(), KEY)
            self.assertEqual(decoded, plaintext)

    def test_migrate_plaintext_requires_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "plain.bin"
            out = Path(temporary) / "migrated.bin"
            source.write_bytes(b"plain")
            with self.assertRaises(fmfile.FileFormatError):
                fmfile.migrate(source, out, KEY)
            result = fmfile.migrate(source, out, KEY, assume_plaintext=True)
            self.assertEqual(result["source_format"], "plaintext")
            _, decoded = fmfile.decode_fmf2(out.read_bytes(), KEY)
            self.assertEqual(decoded, b"plain")

    def test_migrate_rejects_fmf2_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "already.bin"
            source.write_bytes(fmfile.encode_fmf2(b"data", KEY))
            with self.assertRaises(fmfile.FileFormatError):
                fmfile.migrate(source, Path(temporary) / "out.bin", KEY)

    def test_tampered_chunk_rejected(self) -> None:
        blob = bytearray(fmfile.encode_fmf2(pattern(5000), KEY))
        blob[fmfile.FMF2_HEADER + fmfile.NONCE_SIZE + 100] ^= 0xFF
        with self.assertRaises(fmfile.FileFormatError):
            fmfile.decode_fmf2(bytes(blob), KEY)

    def test_tampered_header_rejected(self) -> None:
        blob = bytearray(fmfile.encode_fmf2(pattern(5000), KEY))
        blob[28] ^= 0x01
        with self.assertRaises(fmfile.FileFormatError):
            fmfile.decode_fmf2(bytes(blob), KEY)

    def test_wrong_key_rejected(self) -> None:
        blob = fmfile.encode_fmf2(b"secret", KEY)
        with self.assertRaises(fmfile.FileFormatError):
            fmfile.decode_fmf2(blob, bytes(32))

    def test_derive_file_key(self) -> None:
        key = fmfile.derive_file_key(b"k" * 32, "b2f321f3-d8ea-444d-8c02-4e7671c84cda")
        self.assertEqual(len(key), 32)
        self.assertEqual(
            key,
            fmfile.derive_file_key(b"k" * 32, "b2f321f3-d8ea-444d-8c02-4e7671c84cda"),
        )


if __name__ == "__main__":
    unittest.main()
