from __future__ import annotations

import hashlib
import json
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

YIDUN = {
    "schema": "forgemirror.yidun-signatures/1",
    "source": {
        "vendor": "NetEase Yidun",
        "library": "libnesec.so",
        "sample_sha256": (
            "8ff576e1cc403f0d6173bee361dabc362be6319f4b71ceb375834600a50005ff"
        ),
        "evidence": "docs/research/libnesec_易盾加固还原.md",
    },
    "root": {"su_paths": ["/system/bin/su"]},
    "dex": {
        "standard_magic": ["dex\n035\u0000"],
        "dex2oat_markers": ["dex2oat"],
    },
}

YIDUN_ASSET = (
    Path(__file__).resolve().parents[3]
    / "android" / "shield" / "src" / "main" / "assets" / "yidun-signatures.json"
)


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

    def test_yidun_roundtrip(self) -> None:
        payload = {**RULES, "yidun": YIDUN}
        blob = pack_rules(payload, k_content=K_CONTENT, build_id=BUILD_ID,
                          private_key=self.key)
        opened = open_rules(blob, k_content=K_CONTENT, build_id=BUILD_ID,
                            public_key=self.key.public_key())
        self.assertEqual(opened["yidun"], YIDUN)

    def test_yidun_bad_schema(self) -> None:
        payload = {**RULES, "yidun": {**YIDUN, "schema": "other"}}
        with self.assertRaises(ValueError):
            pack_rules(payload, k_content=K_CONTENT, build_id=BUILD_ID,
                       private_key=self.key)

    def test_yidun_missing_source(self) -> None:
        payload = {**RULES, "yidun": {
            key: value for key, value in YIDUN.items() if key != "source"
        }}
        with self.assertRaises(ValueError):
            pack_rules(payload, k_content=K_CONTENT, build_id=BUILD_ID,
                       private_key=self.key)

    def test_yidun_bad_leaf(self) -> None:
        payload = {**RULES, "yidun": {
            **YIDUN, "root": {"su_paths": [1]},
        }}
        with self.assertRaises(ValueError):
            pack_rules(payload, k_content=K_CONTENT, build_id=BUILD_ID,
                       private_key=self.key)

    def test_yidun_asset_roundtrip(self) -> None:
        asset = json.loads(YIDUN_ASSET.read_text(encoding="utf-8"))
        payload = {**RULES, "yidun": asset}
        blob = pack_rules(payload, k_content=K_CONTENT, build_id=BUILD_ID,
                          private_key=self.key)
        opened = open_rules(blob, k_content=K_CONTENT, build_id=BUILD_ID,
                            public_key=self.key.public_key())
        self.assertEqual(
            opened["yidun"]["source"]["sample_sha256"],
            asset["source"]["sample_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
