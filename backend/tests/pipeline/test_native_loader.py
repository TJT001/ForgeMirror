from __future__ import annotations

import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pipeline"))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

from forgemirror.protect import _encrypt_native, _native_key  # noqa: E402


class NativeEnvelopeTests(unittest.TestCase):
    def test_native_envelope_matches_runtime_format(self) -> None:
        key = _native_key(b"k" * 32, str(uuid.uuid4()))
        plaintext = b"\x7fELF" + bytes(range(64))
        envelope = _encrypt_native(plaintext, key)
        self.assertEqual(envelope[:4], b"FMN1")
        nonce = envelope[4:16]
        self.assertEqual(
            AESGCM(key).decrypt(nonce, envelope[16:], envelope[:16]),
            plaintext,
        )


if __name__ == "__main__":
    unittest.main()
