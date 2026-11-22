from __future__ import annotations

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pipeline"))

import worker  # noqa: E402

TASK = {
    "id": "task-1",
    "source_path": "/tmp/app.aab",
    "profile": "enhanced",
    "signing_mode": "hsm",
}


class WorkerCommandTests(unittest.TestCase):
    def test_defaults_keep_advanced_flags_off(self) -> None:
        command = worker.build_protect_command(dict(TASK, options={}))
        self.assertIn("--profile", command)
        self.assertIn("enhanced", command)
        self.assertNotIn("--no-self-decrypt-core", command)
        self.assertNotIn("--no-detection", command)

    def test_all_options_are_forwarded(self) -> None:
        options = {
            "auth_url": "https://auth.example",
            "event_url": "https://events.example",
            "event_token": "token",
            "no_key_asset": True,
            "self_decrypt_core": False,
            "decoy_dynamic": False,
            "corrupt_section_names": False,
            "self_decrypt_text": False,
            "detection": False,
            "whitebox": True,
            "whitebox_random_table": False,
            "ai_decoy": True,
            "response": "block",
            "max_native_file_mb": 64,
            "in_memory_libs": "liba.so,libb.so",
            "alg": "ed25519",
            "shell_version": "1.2.3",
            "aab_mode": "split",
            "splits": ["/tmp/split.apk"],
            "device_specs": ["/tmp/device.json"],
        }
        command = worker.build_protect_command(dict(TASK, options=options))
        joined = " ".join(command)
        for expected in (
            "--auth-url https://auth.example",
            "--event-url https://events.example",
            "--event-token token",
            "--no-key-asset",
            "--no-self-decrypt-core",
            "--no-decoy-dynamic",
            "--keep-section-names",
            "--no-self-decrypt-text",
            "--no-detection",
            "--whitebox-key",
            "--no-whitebox-random-table",
            "--ai-decoy",
            "--response block",
            "--max-native-file-mb 64",
            "--in-memory-libs liba.so,libb.so",
            "--alg ed25519",
            "--shell-version 1.2.3",
            "--aab-mode split",
            "--split /tmp/split.apk",
            "--device-spec /tmp/device.json",
        ):
            self.assertIn(expected, joined)


class WorkerResultTests(unittest.TestCase):
    def test_single_apk_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / "protected.apk").write_bytes(b"apk")
            (work / "gate.json").write_text('{"passed": true}')
            (work / "protected.protect.json").write_text(
                '{"package": "demo", "version_code": 1}')
            result, package, version, passed = worker.package_result(work)
            self.assertEqual(result, work / "protected.apk")
            self.assertEqual(package, "demo")
            self.assertEqual(version, 1)
            self.assertTrue(passed)

    def test_split_result_is_archived(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / "protected.apk").write_bytes(b"apk")
            (work / "protected.apk.splits.json").write_text("{}")
            split_dir = work / "protected_splits"
            split_dir.mkdir()
            (split_dir / "split.apk").write_bytes(b"split")
            (work / "gate.json").write_text('{"passed": true}')
            result, _, _, passed = worker.package_result(work)
            self.assertEqual(result, work / "protected-set.zip")
            self.assertTrue(passed)
            with zipfile.ZipFile(result) as archive:
                self.assertIn("protected.apk", archive.namelist())
                self.assertIn("protected_splits/split.apk", archive.namelist())

    def test_batch_result_includes_sets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            set_dir = work / "00_spec"
            set_dir.mkdir()
            (set_dir / "protected.apk").write_bytes(b"apk")
            (set_dir / "protected.protect.json").write_text(
                '{"package": "demo", "version_code": 2}')
            (set_dir / "gate.json").write_text('{"passed": true}')
            (work / "batch.json").write_text(json.dumps({
                "ok": True,
                "sets": [{"out": str(set_dir)}],
            }))
            result, package, version, passed = worker.package_result(work)
            self.assertEqual(result, work / "protected-set.zip")
            self.assertEqual(package, "demo")
            self.assertEqual(version, 2)
            self.assertTrue(passed)
            with zipfile.ZipFile(result) as archive:
                self.assertIn("batch.json", archive.namelist())
                self.assertIn("sets/00/protected.apk", archive.namelist())


if __name__ == "__main__":
    unittest.main()
