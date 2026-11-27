from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pipeline"))

from forgemirror.intake import SIGNING_MODES  # noqa: E402
from forgemirror.protect import ProtectOptions, protect  # noqa: E402


def _options(**overrides) -> ProtectOptions:
    values = {
        "apk": Path("app.apk"),
        "container": Path("container.fdx"),
        "key_file": Path("k_content.bin"),
        "out": Path("out.apk"),
        "build_id": "11111111-2222-4333-8444-555555555555",
        "aar": Path("shield.aar"),
    }
    values.update(overrides)
    return ProtectOptions(**values)


class SigningModeTests(unittest.TestCase):
    def test_uber_is_a_signing_mode(self) -> None:
        self.assertIn("uber", SIGNING_MODES)

    def test_uber_requires_signer_jar(self) -> None:
        with self.assertRaises(SystemExit):
            protect(_options(signing_mode="uber"), None)

    def test_custom_keystore_requires_password(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jar") as jar:
            options = _options(
                signing_mode="uber",
                uber_apk_signer=Path(jar.name),
                keystore=Path("release.jks"),
                ks_pass=None,
            )
            with self.assertRaises(SystemExit):
                protect(options, None)


if __name__ == "__main__":
    unittest.main()
