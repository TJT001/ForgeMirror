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


    def test_rc4_known_vector(self) -> None:
        self.assertEqual(
            fmfile.rc4_crypt(b"Plaintext", b"Key").hex(),
            "bbf316e8d940af0ad3",
        )

    def test_migrate_dve_rc4_type0(self) -> None:
        plaintext = pattern(70000)
        key = bytes(range(1, 33))
        encrypted = fmfile.rc4_crypt(plaintext, key)
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "legacy.dve"
            out = Path(temporary) / "migrated.bin"
            source.write_bytes(encrypted)
            result = fmfile.migrate_rc4(source, out, key, enc_type=0)
            self.assertEqual(result["source_format"], "dve-rc4-0")
            _, decoded = fmfile.decode_fmf2(out.read_bytes(), key)
            self.assertEqual(decoded, plaintext)

    def test_migrate_dve_rc4_type1(self) -> None:
        plaintext = pattern(70000)
        key = bytes(range(1, 33))
        head = 0x20000
        encrypted = bytearray(plaintext)
        encrypted[:head] = fmfile.rc4_crypt(plaintext[:head], key)
        for index in range(head, len(encrypted)):
            encrypted[index] ^= 0xAC
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "legacy.dve"
            out = Path(temporary) / "migrated.bin"
            source.write_bytes(bytes(encrypted))
            result = fmfile.migrate_rc4(source, out, key, enc_type=1)
            self.assertEqual(result["source_format"], "dve-rc4-1")
            _, decoded = fmfile.decode_fmf2(out.read_bytes(), key)
            self.assertEqual(decoded, plaintext)


if __name__ == "__main__":
    unittest.main()


class LegacyMetadataTests(unittest.TestCase):
    def test_parse_edata(self) -> None:
        from forgemirror.formats.legacy import parse_edata

        parsed = parse_edata("enc_type/0\nshared_prefs/*.xml\n!databases/a.db\n")
        self.assertEqual(parsed.enc_type, 0)
        self.assertEqual(parsed.rules, ["shared_prefs/*.xml"])
        self.assertEqual(parsed.excludes, ["databases/a.db"])

    def test_parse_classes_dve(self) -> None:
        from forgemirror.formats.legacy import parse_classes_dve

        blob = bytes(range(16)) + (123456).to_bytes(8, "little", signed=True)
        stamp = parse_classes_dve(blob)
        self.assertEqual(stamp.md5, bytes(range(16)).hex())
        self.assertEqual(stamp.ctime, 123456)

    def test_edata_to_policy(self) -> None:
        from forgemirror.formats.legacy import edata_to_policy, parse_edata

        policy = edata_to_policy(parse_edata(
            "enc_type/0\nshared_prefs/*.xml\n!databases/a.db\n"))
        self.assertEqual(policy["schema"], "forgemirror.policy/1")
        self.assertEqual(policy["rules"][0]["pattern"], "shared_prefs/*.xml")
        self.assertEqual(policy["excludes"][0]["pattern"], "databases/a.db")

    def test_decode_res_rule(self) -> None:
        from forgemirror.formats.legacy import decode_res_rule

        rules = b"shared_prefs/*.xml\ndatabases/*.db"
        struct = bytearray(0x20 + len(rules))
        struct[0x0C:0x10] = len(rules).to_bytes(4, "little")
        struct[0x10:0x14] = (0x20).to_bytes(4, "little")
        struct[0x18:0x1C] = (1).to_bytes(4, "little")
        struct[0x1C:0x20] = (2).to_bytes(4, "little")
        struct[0x20:] = rules
        key = b"KEY_RES_ENC"
        encrypted = bytes(value ^ key[index % len(key)]
                          for index, value in enumerate(struct))
        decoded = decode_res_rule(encrypted)
        self.assertEqual(decoded["count"], 2)
        self.assertEqual(decoded["rules"], rules.decode())
