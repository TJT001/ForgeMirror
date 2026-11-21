from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pipeline"))

from typer.testing import CliRunner  # noqa: E402

from forgemirror import cli  # noqa: E402


class BatchCliTests(unittest.TestCase):
    def test_multiple_device_specs_create_independent_sets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            aab = root / "app.aab"
            aab.write_bytes(b"aab")
            spec1 = root / "spec-30.json"
            spec2 = root / "spec-26.json"
            spec1.write_text("{}")
            spec2.write_text("{}")
            out = root / "batch"

            def fake_build(options, tools):
                work = Path(options.out)
                work.mkdir(parents=True, exist_ok=True)
                (work / "container.fdx").write_bytes(b"FDX2")
                key_dir = work / "keys"
                key_dir.mkdir()
                (key_dir / "k_content.bin").write_bytes(b"k" * 32)
                return {
                    "ok": True, "out": str(work), "build_id": options.build_id,
                    "apk": str(work / "base.apk"), "splits": [],
                }

            def fake_protect(options, tools):
                return {"ok": True, "apk": str(options.out), "splits": []}

            with mock.patch.object(cli, "_discover", return_value=object()), \
                    mock.patch.object(cli, "run_build", side_effect=fake_build), \
                    mock.patch.object(cli, "protect", side_effect=fake_protect), \
                    mock.patch.object(cli, "run_gate",
                                      return_value={"passed": True, "failed": [],
                                                    "checks": []}):
                result = CliRunner().invoke(cli.app, [
                    "protect", "--apk", str(aab),
                    "--aab-mode", "split",
                    "--device-spec", str(spec1),
                    "--device-spec", str(spec2),
                    "--out", str(out),
                    "--signing-mode", "hsm",
                ])
            self.assertEqual(result.exit_code, 0, result.output)
            batch = json.loads((out / "batch.json").read_text())
            self.assertTrue(batch["ok"])
            self.assertEqual(len(batch["sets"]), 2)
            self.assertTrue((out / "00_spec-30").is_dir())
            self.assertTrue((out / "01_spec-26").is_dir())
            self.assertEqual(
                batch["device_specs"], [str(spec1), str(spec2)])

    def test_page_alignment_failure_fails_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            apk = root / "base.apk"
            apk.write_bytes(b"apk")
            out = root / "out"

            class PageTools:
                def verify_page_alignment(self, path):
                    return False, "unaligned"

            def fake_build(options, tools):
                work = Path(options.out)
                work.mkdir(parents=True, exist_ok=True)
                (work / "container.fdx").write_bytes(b"FDX2")
                key_dir = work / "keys"
                key_dir.mkdir()
                (key_dir / "k_content.bin").write_bytes(b"k" * 32)
                return {"ok": True, "out": str(work), "build_id": options.build_id,
                        "apk": str(work / "base.apk"), "splits": []}

            with mock.patch.object(cli, "_discover", return_value=PageTools()), \
                    mock.patch.object(cli, "run_build", side_effect=fake_build), \
                    mock.patch.object(cli, "protect",
                                      return_value={"ok": True,
                                                    "apk": str(out / "protected.apk"),
                                                    "splits": []}), \
                    mock.patch.object(cli, "run_gate",
                                      return_value={"passed": True, "failed": [],
                                                    "checks": []}):
                result = CliRunner().invoke(cli.app, [
                    "protect", "--apk", str(apk), "--out", str(out),
                    "--signing-mode", "hsm",
                ])
            self.assertEqual(result.exit_code, 1)
            gate = json.loads((out / "gate.json").read_text())
            self.assertFalse(gate["passed"])
            self.assertTrue(any("page_alignment_16k" in item
                                for item in gate["failed"]))

    def test_build_creates_one_set_per_device_spec(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            aab = root / "app.aab"
            aab.write_bytes(b"aab")
            spec1 = root / "spec-30.json"
            spec2 = root / "spec-26.json"
            spec1.write_text("{}")
            spec2.write_text("{}")
            out = root / "builds"

            def fake_build(options, tools):
                work = Path(options.out)
                work.mkdir(parents=True, exist_ok=True)
                (work / "container.fdx").write_bytes(b"FDX2")
                return {"ok": True, "out": str(work),
                        "build_id": options.build_id, "splits": []}

            with mock.patch.object(cli, "_discover", return_value=object()), \
                    mock.patch.object(cli, "run_build", side_effect=fake_build):
                result = CliRunner().invoke(cli.app, [
                    "build", "--apk", str(aab),
                    "--aab-mode", "split",
                    "--device-spec", str(spec1),
                    "--device-spec", str(spec2),
                    "--out", str(out),
                ])
            self.assertEqual(result.exit_code, 0, result.output)
            batch = json.loads((out / "batch.json").read_text())
            self.assertEqual(batch["schema"], "forgemirror.build-batch/1")
            self.assertTrue(batch["ok"])
            self.assertEqual(len(batch["sets"]), 2)
            self.assertTrue((out / "00_spec-30" / "container.fdx").is_file())
            self.assertTrue((out / "01_spec-26" / "container.fdx").is_file())

    def test_device_spec_rejected_for_universal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            aab = root / "app.aab"
            aab.write_bytes(b"aab")
            spec = root / "spec.json"
            spec.write_text("{}")
            with mock.patch.object(cli, "_discover", return_value=object()), \
                    mock.patch.object(cli, "run_build") as build:
                result = CliRunner().invoke(cli.app, [
                    "protect", "--apk", str(aab),
                    "--device-spec", str(spec),
                    "--out", str(root / "out"),
                ])
            self.assertEqual(result.exit_code, 2)
            build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
