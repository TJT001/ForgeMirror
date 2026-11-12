from __future__ import annotations

import json
import stat
import struct
import sys
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

TESTS = Path(__file__).resolve()
sys.path.insert(0, str(TESTS.parents[2] / "pipeline"))

from forgemirror import errors  # noqa: E402
from forgemirror.dex_stage import StageError, run_dex_stage  # noqa: E402
from forgemirror.formats.container import open_container  # noqa: E402
from forgemirror.intake import run_intake  # noqa: E402
from forgemirror.inventory import run_inventory  # noqa: E402
from forgemirror.pipeline import BuildOptions, run_build  # noqa: E402

BUILD_ID = "00112233-4455-6677-8899-aabbccddeeff"
CERT = "3050b4521ad2c7fcb14b386cddd22acb122b2d60a1d8f325e29afc80ae525170"

BADGING = """package: name='dev.forgemirror.demo' versionCode='1' versionName='1.0'
minSdkVersion:'26'
targetSdkVersion:'37'
native-code: 'arm64-v8a' 'armeabi-v7a'
"""

XMLTREE = """N: android=http://schemas.android.com/apk/res/android (line=2)
  E: manifest (line=2)
    A: package="dev.forgemirror.demo" (Raw: "dev.forgemirror.demo")
    A: http://schemas.android.com/apk/res/android:versionCode(0x0101021b)=1
      E: uses-sdk (line=7)
        A: http://schemas.android.com/apk/res/android:minSdkVersion(0x0101020c)=26
        A: http://schemas.android.com/apk/res/android:targetSdkVersion(0x01010270)=37
      E: application (line=17)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="dev.forgemirror.demo.HarnessApplication" (Raw: "dev.forgemirror.demo.HarnessApplication")
        A: http://schemas.android.com/apk/res/android:appComponentFactory(0x0101057a)="androidx.core.app.CoreComponentFactory" (Raw: "androidx.core.app.CoreComponentFactory")
          E: activity (line=30)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)="dev.forgemirror.demo.MainActivity" (Raw: "dev.forgemirror.demo.MainActivity")
          E: provider (line=40)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)="dev.forgemirror.demo.HarnessProvider" (Raw: "dev.forgemirror.demo.HarnessProvider")
            A: http://schemas.android.com/apk/res/android:authorities(0x01010018)="dev.forgemirror.demo.harness" (Raw: "dev.forgemirror.demo.harness")
          E: service (line=45)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)="dev.forgemirror.demo.HarnessService" (Raw: "dev.forgemirror.demo.HarnessService")
          E: service (line=48)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)="dev.forgemirror.demo.HarnessRemoteService" (Raw: "dev.forgemirror.demo.HarnessRemoteService")
            A: http://schemas.android.com/apk/res/android:process(0x01010011)=":remote" (Raw: ":remote")
          E: receiver (line=53)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)="dev.forgemirror.demo.HarnessReceiver" (Raw: "dev.forgemirror.demo.HarnessReceiver")
"""


class FakeTools:
    def __init__(self, badging: str = BADGING, xmltree: str = XMLTREE, cert: str | None = CERT):
        self._badging = badging
        self._xmltree = xmltree
        self._cert = cert

    def badging(self, apk: Path) -> str:
        return self._badging

    def xmltree(self, apk: Path) -> str:
        return self._xmltree

    def cert_sha256(self, apk: Path) -> str | None:
        return self._cert

    def tool_versions(self) -> dict[str, str]:
        return {"aapt2": "fake", "apksigner": "fake", "build-tools": "fake"}


def elf_header(machine: int) -> bytes:
    return (
        b"\x7fELF"
        + bytes([2, 1, 1, 0])
        + b"\x00" * 8
        + b"\x00\x00"
        + struct.pack("<H", machine)
        + b"\x00" * 64
    )


def make_apk(
    tmp_path: Path,
    *,
    include_bad_lib: bool = False,
    hardened: bool = False,
    dex_bytes: bytes | None = None,
    extra: dict[str, bytes] | None = None,
) -> Path:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr(
            "classes.dex",
            dex_bytes if dex_bytes is not None else b"dex\n035\x00" + b"\x00" * 64,
        )
        archive.writestr("classes2.dex", b"dex\n035\x00" + b"\x01" * 64)
        archive.writestr("lib/arm64-v8a/libx.so", elf_header(183))
        archive.writestr("lib/armeabi-v7a/libx.so", elf_header(40))
        archive.writestr("assets/config.json", b"{}")
        if include_bad_lib:
            archive.writestr("lib/arm64-v8a/libbad.so", elf_header(3))
        if hardened:
            archive.writestr("assets/coreclasses.bangcle", b"x")
        for name, data in (extra or {}).items():
            archive.writestr(name, data)
    return apk


class IntakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(self.id().replace(".", "_"))
        self.tmp.mkdir(exist_ok=True)

    def tearDown(self) -> None:
        for path in sorted(self.tmp.rglob("*"), reverse=True):
            path.unlink() if path.is_file() else path.rmdir()
        self.tmp.rmdir()

    def test_accepts_normal_apk(self) -> None:
        apk = make_apk(self.tmp)
        result = run_intake(
            apk,
            build_id=BUILD_ID,
            profile="basic",
            signing_mode="hsm",
            tools=FakeTools(),
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.package, "dev.forgemirror.demo")
        self.assertEqual(result.cert_sha256, CERT)
        self.assertEqual(result.abis, ["arm64-v8a", "armeabi-v7a"])

    def test_rejects_old_min_sdk(self) -> None:
        apk = make_apk(self.tmp)
        result = run_intake(
            apk,
            build_id=BUILD_ID,
            profile="basic",
            signing_mode="hsm",
            tools=FakeTools(badging=BADGING.replace("minSdkVersion:'26'", "minSdkVersion:'25'")),
        )
        self.assertFalse(result.ok)
        self.assertIn(errors.E_MIN_SDK, result.reason_codes)

    def test_rejects_hardened_apk(self) -> None:
        apk = make_apk(self.tmp, hardened=True)
        result = run_intake(
            apk,
            build_id=BUILD_ID,
            profile="basic",
            signing_mode="hsm",
            tools=FakeTools(),
        )
        self.assertFalse(result.ok)
        self.assertIn(errors.E_ALREADY_HARDENED, result.reason_codes)

    def test_rejects_unlisted_cert(self) -> None:
        apk = make_apk(self.tmp)
        result = run_intake(
            apk,
            build_id=BUILD_ID,
            profile="basic",
            signing_mode="hsm",
            tools=FakeTools(),
            cert_allowlist={"00" * 32},
        )
        self.assertFalse(result.ok)
        self.assertIn(errors.E_CERT_NOT_ALLOWED, result.reason_codes)

    def test_unsigned_customer_local_is_warning(self) -> None:
        apk = make_apk(self.tmp)
        result = run_intake(
            apk,
            build_id=BUILD_ID,
            profile="basic",
            signing_mode="customer_local",
            tools=FakeTools(cert=None),
        )
        self.assertTrue(result.ok)
        self.assertIn(errors.W_UNSIGNED, result.warnings)

    def test_rejects_non_zip(self) -> None:
        path = self.tmp / "not-apk.bin"
        path.write_bytes(b"not a zip")
        result = run_intake(
            path,
            build_id=BUILD_ID,
            profile="basic",
            signing_mode="customer_local",
            tools=FakeTools(),
        )
        self.assertFalse(result.ok)
        self.assertIn(errors.E_APK_NOT_ZIP, result.reason_codes)

    def test_hsm_requires_cert(self) -> None:
        apk = make_apk(self.tmp)
        result = run_intake(
            apk,
            build_id=BUILD_ID,
            profile="basic",
            signing_mode="hsm",
            tools=FakeTools(cert=None),
        )
        self.assertFalse(result.ok)
        self.assertIn(errors.E_CERT_MISSING, result.reason_codes)


class InventoryTests(unittest.TestCase):
    def test_inventory_and_anomaly(self) -> None:
        tmp = Path("inventory_test_tmp")
        tmp.mkdir(exist_ok=True)
        try:
            apk = make_apk(tmp, include_bad_lib=True)
            inventory = run_inventory(apk, tools=FakeTools())
            self.assertEqual([entry.name for entry in inventory.dex], ["classes.dex", "classes2.dex"])
            self.assertEqual(inventory.application, "dev.forgemirror.demo.HarnessApplication")
            self.assertEqual(inventory.components.activities, 1)
            self.assertEqual(inventory.components.services, 2)
            self.assertEqual(inventory.components.providers, 1)
            self.assertEqual(inventory.components.receivers, 1)
            self.assertTrue(any(item.kind == "abi_mismatch" for item in inventory.anomalies))
            self.assertEqual(inventory.fingerprint["package"], "dev.forgemirror.demo")
        finally:
            for path in sorted(tmp.rglob("*"), reverse=True):
                path.unlink() if path.is_file() else path.rmdir()
            tmp.rmdir()

    def test_invalid_dex_and_elf_anomalies(self) -> None:
        tmp = Path("inventory_invalid_test_tmp")
        tmp.mkdir(exist_ok=True)
        try:
            apk = make_apk(
                tmp,
                dex_bytes=b"not a dex",
                extra={"lib/arm64-v8a/libbad.so": b"not an elf"},
            )
            inventory = run_inventory(apk, tools=FakeTools())
            kinds = {item.kind for item in inventory.anomalies}
            self.assertIn("invalid_dex", kinds)
            self.assertIn("invalid_elf", kinds)
        finally:
            for path in sorted(tmp.rglob("*"), reverse=True):
                path.unlink() if path.is_file() else path.rmdir()
            tmp.rmdir()


class DexStageTests(unittest.TestCase):
    def test_container_roundtrip_and_key_mode(self) -> None:
        tmp = Path("dex_stage_test_tmp")
        tmp.mkdir(exist_ok=True)
        try:
            apk = make_apk(tmp)
            inventory = run_inventory(apk, tools=FakeTools())
            key = b"k" * 32
            result = run_dex_stage(
                apk,
                inventory,
                tmp / "out",
                build_id=BUILD_ID,
                profile="basic",
                k_content=key,
            )
            opened = open_container(result.container.read_bytes(), k_content=key)
            with zipfile.ZipFile(apk) as archive:
                self.assertEqual(opened.files[0], archive.read("classes.dex"))
                self.assertEqual(opened.files[1], archive.read("classes2.dex"))
            self.assertEqual(stat.S_IMODE(result.key_file.stat().st_mode), 0o600)
            manifest = json.loads(result.dex_manifest.read_text())
            self.assertEqual([item["name"] for item in manifest["files"]], ["classes.dex", "classes2.dex"])
        finally:
            for path in sorted(tmp.rglob("*"), reverse=True):
                path.unlink() if path.is_file() else path.rmdir()
            tmp.rmdir()

    def test_self_test_failure_aborts(self) -> None:
        tmp = Path("dex_stage_failure_test_tmp")
        tmp.mkdir(exist_ok=True)
        try:
            apk = make_apk(tmp)
            inventory = run_inventory(apk, tools=FakeTools())
            with mock.patch(
                "forgemirror.dex_stage.open_container",
                return_value=SimpleNamespace(files=[b"wrong"]),
            ):
                with self.assertRaises(StageError):
                    run_dex_stage(
                        apk,
                        inventory,
                        tmp / "out",
                        build_id=BUILD_ID,
                        profile="basic",
                        k_content=b"k" * 32,
                    )
        finally:
            for path in sorted(tmp.rglob("*"), reverse=True):
                path.unlink() if path.is_file() else path.rmdir()
            tmp.rmdir()


class PipelineTests(unittest.TestCase):
    def test_build_writes_s0_s1_s2(self) -> None:
        tmp = Path("pipeline_test_tmp")
        tmp.mkdir(exist_ok=True)
        try:
            apk = make_apk(tmp)
            out = tmp / "out"
            result = run_build(
                BuildOptions(apk=apk, out=out, build_id=BUILD_ID, profile="basic"),
                FakeTools(),
            )
            self.assertTrue(result["ok"])
            for name in ("intake.json", "inventory.json", "container.fdx", "dex_manifest.json", "build.meta.json"):
                self.assertTrue((out / name).is_file(), name)
            key = (out / "keys" / "k_content.bin").read_bytes()
            opened = open_container((out / "container.fdx").read_bytes(), k_content=key)
            self.assertEqual(len(opened.files), 2)
            meta = json.loads((out / "build.meta.json").read_text())
            self.assertEqual(meta["app"]["package"], "dev.forgemirror.demo")
            self.assertEqual(meta["status"], "s2-partial")
        finally:
            for path in sorted(tmp.rglob("*"), reverse=True):
                path.unlink() if path.is_file() else path.rmdir()
            tmp.rmdir()

    def test_build_stops_at_s0(self) -> None:
        tmp = Path("pipeline_reject_tmp")
        tmp.mkdir(exist_ok=True)
        try:
            apk = make_apk(tmp, hardened=True)
            out = tmp / "out"
            result = run_build(
                BuildOptions(apk=apk, out=out, build_id=BUILD_ID, profile="basic"),
                FakeTools(),
            )
            self.assertFalse(result["ok"])
            self.assertEqual(result["stage"], "s0")
            self.assertTrue((out / "intake.json").is_file())
            self.assertFalse((out / "container.fdx").exists())
        finally:
            for path in sorted(tmp.rglob("*"), reverse=True):
                path.unlink() if path.is_file() else path.rmdir()
            tmp.rmdir()


class CliTests(unittest.TestCase):
    def test_help_loads(self) -> None:
        from typer.testing import CliRunner

        from forgemirror.cli import app

        result = CliRunner().invoke(app, ["--help"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("build", result.output)


if __name__ == "__main__":
    unittest.main()
