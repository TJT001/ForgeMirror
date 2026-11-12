from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pipeline"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from forgemirror.formats.policy import (  # noqa: E402
    PolicyError,
    open_policy,
    pack_policy,
)

K_CONTENT = hashlib.sha256(b"policy-test-key").digest()
BUILD_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
POLICY = {
    "schema": "forgemirror.policy/1",
    "version": 1,
    "min_shell_version": "1.0.0",
    "rules": [{"pattern": "shared_prefs/*.xml", "action": "encrypt"}],
    "excludes": [{"pattern": "databases/*.db"}],
}


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def pack(self) -> bytes:
        return pack_policy(
            POLICY,
            k_content=K_CONTENT,
            build_id=BUILD_ID,
            private_key=self.private_key,
        )

    def test_roundtrip(self) -> None:
        blob = self.pack()
        opened = open_policy(
            blob,
            k_content=K_CONTENT,
            build_id=BUILD_ID,
            public_key=self.public_key,
        )
        self.assertEqual(opened, POLICY)

    def test_tampered_ciphertext(self) -> None:
        blob = bytearray(self.pack())
        blob[24] ^= 0x01
        with self.assertRaises(PolicyError):
            open_policy(
                bytes(blob),
                k_content=K_CONTENT,
                build_id=BUILD_ID,
                public_key=self.public_key,
            )

    def test_wrong_public_key(self) -> None:
        blob = self.pack()
        with self.assertRaises(PolicyError):
            open_policy(
                blob,
                k_content=K_CONTENT,
                build_id=BUILD_ID,
                public_key=Ed25519PrivateKey.generate().public_key(),
            )

    def test_wrong_content_key(self) -> None:
        blob = self.pack()
        with self.assertRaises(PolicyError):
            open_policy(
                blob,
                k_content=b"\x00" * 32,
                build_id=BUILD_ID,
                public_key=self.public_key,
            )

    def test_invalid_policy_rejected(self) -> None:
        with self.assertRaises(ValueError):
            pack_policy(
                {**POLICY, "schema": "other"},
                k_content=K_CONTENT,
                build_id=BUILD_ID,
                private_key=self.private_key,
            )


if __name__ == "__main__":
    unittest.main()
