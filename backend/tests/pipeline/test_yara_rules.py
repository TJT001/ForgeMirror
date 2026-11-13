from __future__ import annotations

import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pipeline"))

from forgemirror.formats import yara_rules  # noqa: E402

AVAILABLE = yara_rules.yara is not None

POSITIVE = {
    "fm_dynamic_instrumentation": b"frida-server",
    "fm_xposed_framework": b"XposedBridge",
    "fm_root_shell": b"/system/xbin/su",
    "fm_debugger_attach": b"ptrace TracerPid",
    "fm_emulator_artifact": b"goldfish ranchu",
    "fm_hook_framework": b"Dobby",
    "fm_dex_memory_loading": b"InMemoryDexClassLoader makeInMemoryDexElements",
    "fm_signature_tamper": b"GET_SIGNATURES signatures",
    "fm_network_interception": b"tcpdump",
}

MISSING_FEATURE = {
    "fm_debugger_attach": b"ptrace",
    "fm_emulator_artifact": b"goldfish",
    "fm_dex_memory_loading": b"InMemoryDexClassLoader",
}


@unittest.skipUnless(AVAILABLE, "yara-python not installed")
class YaraRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = yara_rules.compile_rules()

    def test_nine_rules_compile(self) -> None:
        self.assertEqual(yara_rules.NINE_RULES.count("rule fm_"), 9)

    def test_each_rule_matches_positive_sample(self) -> None:
        for rule, payload in POSITIVE.items():
            with self.subTest(rule=rule):
                matches = yara_rules.scan_bytes(payload, self.rules)
                self.assertIn(rule, matches)

    def test_missing_feature_does_not_match(self) -> None:
        for rule, payload in MISSING_FEATURE.items():
            with self.subTest(rule=rule):
                self.assertNotIn(rule, yara_rules.scan_bytes(payload, self.rules))

    def test_negative_sample(self) -> None:
        self.assertEqual(yara_rules.scan_bytes(b"hello world", self.rules), [])

    def test_scan_apk_native_libs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            apk = Path(temporary) / "demo.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("lib/arm64-v8a/libdemo.so", b"frida-server")
                archive.writestr("classes.dex", b"not scanned")
            matches = yara_rules.scan_apk(apk, rules=self.rules)
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].rule, "fm_dynamic_instrumentation")
            self.assertEqual(matches[0].entry, "lib/arm64-v8a/libdemo.so")


if __name__ == "__main__":
    unittest.main()
