from __future__ import annotations

import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pipeline"))

from forgemirror import errors  # noqa: E402
from forgemirror.dex_stage import run_dex_stage  # noqa: E402
from forgemirror.formats.container import open_container  # noqa: E402
from forgemirror.intake import run_intake  # noqa: E402
from forgemirror.inventory import run_inventory  # noqa: E402

BUILD_ID = "00112233-4455-6677-8899-aabbccddeeff"
CERT = "3050b4521ad2c7fcb14b386cddd22acb122b2d60a1d8f325e29afc80ae525170"
SPLIT = "config.arm64_v8a"

BASE_BADGING = """package: name='dev.forgemirror.demo' versionCode='7' versionName='1.0'
minSdkVersion:'26'
targetSdkVersion:'37'
native-code: 'arm64-v8a'
"""
SPLIT_BADGING = """package: name='dev.forgemirror.demo' versionCode='7' versionName='1.0' split='config.arm64_v8a'
minSdkVersion:'26'
targetSdkVersion:'37'
native-code: 'arm64-v8a'
"""
BASE_XML = """N: android=http://schemas.android.com/apk/res/android (line=2)
  E: manifest (line=2)
    A: package="dev.forgemirror.demo" (Raw: "dev.forgemirror.demo")
    A: http://schemas.android.com/apk/res/android:versionCode(0x0101021b)=7
      E: application (line=3)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="dev.forgemirror.demo.App" (Raw: "dev.forgemirror.demo.App")
"""
SPLIT_XML = """N: android=http://schemas.android.com/apk/res/android (line=2)
  E: manifest (line=2)
    A: package="dev.forgemirror.demo" (Raw: "dev.forgemirror.demo")
    A: split="config.arm64_v8a" (Raw: "config.arm64_v8a")
    A: http://schemas.android.com/apk/res/android:versionCode(0x0101021b)=7
"""
DEX = b"dex\n035\x00" + b"\x00" * 64
def elf_arm64(align: int = 0x1000) -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    struct.pack_into("<H", header, 18, 183)
    struct.pack_into("<Q", header, 0x20, 64)
    struct.pack_into("<H", header, 0x36, 56)
    struct.pack_into("<H", header, 0x38, 1)
    phdr = bytearray(56)
    struct.pack_into("<I", phdr, 0, 1)
    struct.pack_into("<Q", phdr, 48, align)
    return bytes(header + phdr)


ELF_ARM64 = elf_arm64(0x1000)


class SplitTools:
    def __init__(self, certs: dict[str, str | None] | None = None,
                 split_version: int = 7):
        self.certs = certs or {}
        self.split_version = split_version

    def badging(self, apk: Path) -> str:
        if apk.name.startswith("split"):
            text = SPLIT_BADGING.replace("versionCode='7'",
                                         f"versionCode='{self.split_version}'")
            return text
        return BASE_BADGING

    def xmltree(self, apk: Path) -> str:
        if apk.name.startswith("split"):
            return SPLIT_XML.replace("=7", f"={self.split_version}")
        return BASE_XML

    def cert_sha256(self, apk: Path) -> str | None:
        if apk.name in self.certs:
            return self.certs[apk.name]
        return CERT

    def tool_versions(self) -> dict[str, str]:
        return {"aapt2": "fake", "apksigner": "fake", "build-tools": "fake"}


def make_base(tmp: Path) -> Path:
    apk = tmp / "base.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", DEX)
        archive.writestr("classes2.dex", b"dex\n035\x00" + b"\x02" * 64)
        archive.writestr("lib/arm64-v8a/libdemo.so", ELF_ARM64)
        archive.writestr("assets/base.txt", b"base")
    return apk


def make_split(tmp: Path, name: str = "split_config.arm64_v8a.apk",
               dex: bytes | None = DEX) -> Path:
    apk = tmp / name
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"split-manifest")
        if dex is not None:
            archive.writestr("classes.dex", dex)
        archive.writestr("lib/arm64-v8a/libdemo2.so", ELF_ARM64)
    return apk


class SplitIntakeTests(unittest.TestCase):
    def test_valid_split_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            base, split = make_base(tmp), make_split(tmp)
            result = run_intake(base, build_id=BUILD_ID, profile="basic",
                                signing_mode="hsm", tools=SplitTools(),
                                splits=[split])
            self.assertTrue(result.ok, result.reason_codes)
            self.assertEqual(result.split_names, [SPLIT])

    def test_version_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            base, split = make_base(tmp), make_split(tmp)
            result = run_intake(base, build_id=BUILD_ID, profile="basic",
                                signing_mode="hsm", tools=SplitTools(split_version=8),
                                splits=[split])
            self.assertIn(errors.E_SPLIT_MISMATCH, result.reason_codes)

    def test_certificate_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            base, split = make_base(tmp), make_split(tmp)
            result = run_intake(base, build_id=BUILD_ID, profile="basic",
                                signing_mode="hsm",
                                tools=SplitTools(certs={split.name: "00" * 32}),
                                splits=[split])
            self.assertIn(errors.E_SPLIT_CERT_MISMATCH, result.reason_codes)

    def test_duplicate_split_name_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            base = make_base(tmp)
            split = make_split(tmp)
            other = make_split(tmp, "split_copy.apk")
            result = run_intake(base, build_id=BUILD_ID, profile="basic",
                                signing_mode="hsm", tools=SplitTools(),
                                splits=[split, other])
            self.assertIn(errors.E_SPLIT_DUPLICATE, result.reason_codes)


class SplitInventoryTests(unittest.TestCase):
    def test_dex_and_libs_are_merged_with_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            base, split = make_base(tmp), make_split(tmp)
            inventory = run_inventory(base, tools=SplitTools(), splits=[split])
            self.assertEqual(
                [(entry.source, entry.name) for entry in inventory.dex],
                [("base", "classes.dex"), ("base", "classes2.dex"),
                 (SPLIT, "classes.dex")],
            )
            self.assertIn(("base", "lib/arm64-v8a/libdemo.so"),
                          [(entry.source, entry.path) for entry in inventory.libs])
            self.assertIn((SPLIT, "lib/arm64-v8a/libdemo2.so"),
                          [(entry.source, entry.path) for entry in inventory.libs])
            self.assertEqual(inventory.split_names, [SPLIT])

    def test_container_uses_split_names_and_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            base, split = make_base(tmp), make_split(tmp)
            inventory = run_inventory(base, tools=SplitTools(), splits=[split])
            result = run_dex_stage(
                base, inventory, tmp / "out", build_id=BUILD_ID,
                profile="basic", k_content=b"\x11" * 32,
                split_apks={SPLIT: split},
            )
            opened = open_container(result.container.read_bytes(),
                                    k_content=b"\x11" * 32)
            self.assertEqual(
                [item["name"] for item in result.files],
                ["classes.dex", "classes2.dex", "config.arm64_v8a/classes.dex"],
            )
            self.assertEqual(opened.files[-1], DEX)


if __name__ == "__main__":
    unittest.main()


# --- protect split set -------------------------------------------------------

import base64  # noqa: E402
import json  # noqa: E402
import shutil  # noqa: E402
import uuid  # noqa: E402
from unittest import mock  # noqa: E402

from forgemirror.formats import axml  # noqa: E402
from forgemirror.formats.axml import (  # noqa: E402
    ANDROID_NS,
    TYPE_INT_DEC,
    TYPE_STRING,
    Attr,
    Document,
    EndElement,
    EndNamespace,
    StartElement,
    StartNamespace,
)
from forgemirror.formats.container import FileSpec, write_container  # noqa: E402
from forgemirror.gate import run_gate  # noqa: E402
from forgemirror.protect import ProtectOptions, protect  # noqa: E402


def base_manifest() -> bytes:
    document = Document()
    document.flags = 0
    document.strings = [
        "android", ANDROID_NS, "manifest", "package",
        "dev.forgemirror.demo", "uses-sdk", "minSdkVersion",
        "application", "name", "dev.forgemirror.demo.App", "versionCode",
    ]
    document.chunks = [
        StartNamespace(0, 1),
        StartElement(0xFFFFFFFF, 2, [
            Attr(0xFFFFFFFF, 3, 4, TYPE_STRING, 4),
            Attr(1, 10, 0xFFFFFFFF, TYPE_INT_DEC, 7),
        ]),
        StartElement(0xFFFFFFFF, 5, [
            Attr(1, 6, 0xFFFFFFFF, TYPE_INT_DEC, 26),
        ]),
        StartElement(1, 7, [
            Attr(1, 8, 9, TYPE_STRING, 9),
        ]),
        EndElement(1, 7),
        EndElement(0xFFFFFFFF, 5),
        EndElement(0xFFFFFFFF, 2),
        EndNamespace(0, 1),
    ]
    return axml.serialize(document)


class ProtectTools:
    def badging(self, apk: Path) -> str:
        return SPLIT_BADGING if apk.name.startswith("split") else BASE_BADGING

    def strip_so(self, data: bytes, name: str = "lib.so") -> bytes:
        return data

    def align_apk(self, apk_in: Path, apk_out: Path, alignment: int = 4) -> None:
        shutil.copyfile(apk_in, apk_out)

    def sign_debug(self, apk_in: Path, apk_out: Path) -> None:
        shutil.copyfile(apk_in, apk_out)

    def verify(self, apk: Path) -> str:
        return f"certificate SHA-256 digest: {CERT}"

    def debug_signer_sha256(self) -> str:
        return CERT

    def cert_sha256(self, apk: Path) -> str:
        return CERT


class ProtectSplitTests(unittest.TestCase):
    def test_split_assets_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            base = tmp / "base.apk"
            split = tmp / "split_config.arm64_v8a.apk"
            with zipfile.ZipFile(base, "w") as archive:
                archive.writestr("AndroidManifest.xml", base_manifest())
                archive.writestr("classes.dex", DEX)
                archive.writestr("lib/arm64-v8a/libdemo.so", ELF_ARM64)
            with zipfile.ZipFile(split, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"split")
                archive.writestr("classes.dex", b"dex\n035\x00" + b"\x03" * 64)
                archive.writestr("lib/arm64-v8a/libdemo2.so", ELF_ARM64)
                archive.writestr("lib/arm64-v8a/libshield_core.so", ELF_ARM64)

            key = b"\x22" * 32
            key_file = tmp / "k.bin"
            key_file.write_bytes(key)
            container = tmp / "container.fdx"
            container.write_bytes(write_container(
                [FileSpec(name="classes.dex", data=DEX)],
                k_content=key, build_id=uuid.UUID(BUILD_ID).bytes,
            ))
            aar = tmp / "shield.aar"
            aar.write_bytes(b"aar")

            with mock.patch("forgemirror.protect._stub_from_aar",
                            return_value=(DEX, {
                                "lib/arm64-v8a/libshield_boot.so": b"boot",
                                "lib/arm64-v8a/libshield_dummy.so": b"dummy",
                            }, 0)):
                result = protect(ProtectOptions(
                    apk=base, container=container, key_file=key_file,
                    out=tmp / "protected.apk", build_id=BUILD_ID, aar=aar,
                    signing_mode="hsm", self_decrypt_text=False,
                    decoy_dynamic=False, self_decrypt_core=False,
                    in_memory_libs="libdemo.so,libdemo2.so", splits=[split],
                ), ProtectTools())

            self.assertEqual(result["split_count"], 1)
            self.assertTrue(any("W_16KB_ALIGN" in item
                                for item in result["warnings"]))
            with zipfile.ZipFile(tmp / "protected.apk") as archive:
                names = set(archive.namelist())
                self.assertIn("assets/shield/native/arm64-v8a/libdemo.so.enc", names)
                self.assertIn("assets/shield/native/arm64-v8a/libdemo2.so.enc", names)
                self.assertNotIn("lib/arm64-v8a/libdemo.so", names)
                envelope = json.loads(archive.read("assets/shield/manifest.sig"))

            split_out = tmp / "protected_splits" / split.name
            self.assertTrue(split_out.is_file())
            with zipfile.ZipFile(split_out) as archive:
                split_names = set(archive.namelist())
            self.assertNotIn("classes.dex", split_names)
            self.assertNotIn("lib/arm64-v8a/libdemo2.so", split_names)
            self.assertNotIn("lib/arm64-v8a/libshield_core.so", split_names)

            payload = json.loads(base64.b64decode(envelope["payload"]))
            self.assertEqual(payload["splits"][0]["file"], split.name)
            self.assertEqual(payload["splits"][0]["sha256"],
                             __import__("hashlib").sha256(
                                 split_out.read_bytes()).hexdigest())

            gate = run_gate(tmp / "protected.apk", container, key,
                            splits=[split_out])
            self.assertTrue(gate["passed"], gate)
            self.assertIn("split_manifest_entries",
                          [item["name"] for item in gate["checks"]])

            data = bytearray(split_out.read_bytes())
            data[-1] ^= 0x01
            split_out.write_bytes(bytes(data))
            tampered = run_gate(tmp / "protected.apk", container, key,
                                splits=[split_out])
            self.assertFalse(tampered["passed"])
            self.assertIn("split_manifest_entries", tampered["failed"])
