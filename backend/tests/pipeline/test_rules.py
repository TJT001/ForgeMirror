from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pipeline"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from forgemirror.formats.rules import (  # noqa: E402
    RulesError,
    open_rules,
    pack_rules,
)

K_CONTENT = hashlib.sha256(b"rules-test-key").digest()
BUILD_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
RULES = {
    "schema": "forgemirror.rules/1",
    "version": 1,
    "min_shell_version": "1.0.0",
    "rules": [
        {"id": "demo_all", "logic": "all", "strings": ["alpha", "beta"]},
        {"id": "demo_any", "logic": "any", "strings": ["gamma", "delta"]},
    ],
}


class RulesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = Ed25519PrivateKey.generate()

    def test_roundtrip(self) -> None:
        blob = pack_rules(RULES, k_content=K_CONTENT, build_id=BUILD_ID,
                          private_key=self.key)
        opened = open_rules(blob, k_content=K_CONTENT, build_id=BUILD_ID,
                            public_key=self.key.public_key())
        self.assertEqual(opened, RULES)

    def test_wrong_key(self) -> None:
        blob = pack_rules(RULES, k_content=K_CONTENT, build_id=BUILD_ID,
                          private_key=self.key)
        with self.assertRaises(RulesError):
            open_rules(blob, k_content=b"\x00" * 32, build_id=BUILD_ID,
                       public_key=self.key.public_key())

    def test_wrong_public_key(self) -> None:
        blob = pack_rules(RULES, k_content=K_CONTENT, build_id=BUILD_ID,
                          private_key=self.key)
        with self.assertRaises(RulesError):
            open_rules(blob, k_content=K_CONTENT, build_id=BUILD_ID,
                       public_key=Ed25519PrivateKey.generate().public_key())

    def test_invalid_rule(self) -> None:
        with self.assertRaises(ValueError):
            pack_rules({"schema": "other"}, k_content=K_CONTENT,
                       build_id=BUILD_ID, private_key=self.key)


if __name__ == "__main__":
    unittest.main()
