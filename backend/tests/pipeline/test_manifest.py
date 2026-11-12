from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pipeline"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from forgemirror.formats.manifest import (  # noqa: E402
    ManifestError,
    canonical_json,
    sign_manifest,
    verify_manifest,
)

MANIFEST = {
    "schema": "forgemirror.manifest/1",
    "build_id": "00112233-4455-6677-8899-aabbccddeeff",
    "shell_version": "1.0.0",
    "policy_version": 1,
    "rule_version": 1,
    "app": {
        "package": "dev.forgemirror.demo",
        "version_code": 1,
        "cert_sha256": "00" * 32,
    },
    "artifacts": [
        {"path": "assets/container.fdx", "size": 1, "sha256": "11" * 32},
        {"path": "lib/arm64-v8a/libshield_core.so", "size": 2, "sha256": "22" * 32},
    ],
}


class ManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def test_sign_and_verify(self) -> None:
        signed = sign_manifest(MANIFEST, private_key=self.private_key, key_id="test-key")
        unsigned = verify_manifest(signed, public_key=self.public_key)
        self.assertEqual(unsigned, MANIFEST)
        self.assertEqual(signed["signature"]["key_id"], "test-key")

    def test_tampered_field(self) -> None:
        signed = sign_manifest(MANIFEST, private_key=self.private_key, key_id="test-key")
        signed["artifacts"][0]["size"] = 9
        with self.assertRaises(ManifestError):
            verify_manifest(signed, public_key=self.public_key)

    def test_wrong_key(self) -> None:
        signed = sign_manifest(MANIFEST, private_key=self.private_key, key_id="test-key")
        with self.assertRaises(ManifestError):
            verify_manifest(
                signed, public_key=Ed25519PrivateKey.generate().public_key()
            )

    def test_unsorted_artifacts_rejected(self) -> None:
        document = {**MANIFEST, "artifacts": list(reversed(MANIFEST["artifacts"]))}
        with self.assertRaises(ValueError):
            sign_manifest(document, private_key=self.private_key, key_id="test-key")

    def test_canonical_json_is_stable(self) -> None:
        self.assertEqual(canonical_json({"b": 1, "a": [2, 3]}), b'{"a":[2,3],"b":1}')


if __name__ == "__main__":
    unittest.main()
