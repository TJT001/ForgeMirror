"""Android SDK tool wrappers used by the build pipeline."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class ToolError(Exception):
    """Raised when an Android SDK tool is missing or fails."""


def _default_sdk_root() -> Path:
    for variable in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        value = os.environ.get(variable)
        if value:
            return Path(value)
    for candidate in (Path.home() / "Library" / "Android" / "sdk", Path.home() / "Android" / "Sdk"):
        if candidate.is_dir():
            return candidate
    return Path.home() / "Library" / "Android" / "sdk"


@dataclass(frozen=True)
class AndroidTools:
    sdk_root: Path
    build_tools_version: str
    aapt2: Path
    apksigner: Path
    zipalign: Path
    d8: Path

    @classmethod
    def discover(
        cls, sdk_root: Path | None = None, build_tools_version: str | None = None
    ) -> "AndroidTools":
        root = Path(sdk_root) if sdk_root else _default_sdk_root()
        build_tools = root / "build-tools"
        if not build_tools.is_dir():
            raise ToolError(f"Android build-tools not found under {root}")

        if build_tools_version:
            tool_dir = build_tools / build_tools_version
        else:
            candidates = sorted(
                (path for path in build_tools.iterdir() if path.is_dir()),
                key=lambda path: [int(part) if part.isdigit() else part for part in re.split(r"[.-]", path.name)],
            )
            if not candidates:
                raise ToolError(f"no build-tools versions under {build_tools}")
            tool_dir = candidates[-1]

        aapt2 = tool_dir / "aapt2"
        apksigner = tool_dir / "apksigner"
        zipalign = tool_dir / "zipalign"
        d8 = tool_dir / "d8"
        if not aapt2.is_file():
            raise ToolError(f"aapt2 not found at {aapt2}")
        if not apksigner.is_file():
            raise ToolError(f"apksigner not found at {apksigner}")
        if not zipalign.is_file():
            raise ToolError(f"zipalign not found at {zipalign}")
        if not d8.is_file():
            raise ToolError(f"d8 not found at {d8}")
        return cls(
            sdk_root=root,
            build_tools_version=tool_dir.name,
            aapt2=aapt2,
            apksigner=apksigner,
            zipalign=zipalign,
            d8=d8,
        )

    def _run(self, arguments: list[str], timeout: int = 180, stderr_fallback: bool = False) -> str:
        try:
            process = subprocess.run(
                arguments,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except OSError as exc:
            raise ToolError(f"failed to run {arguments[0]}: {exc}") from exc
        if process.returncode != 0:
            detail = (process.stderr or process.stdout).strip().splitlines()
            message = detail[-1] if detail else f"exit {process.returncode}"
            raise ToolError(f"{Path(arguments[0]).name} failed: {message}")
        return process.stdout if process.stdout or not stderr_fallback else process.stderr

    def badging(self, apk: Path) -> str:
        return self._run([str(self.aapt2), "dump", "badging", str(apk)])

    def xmltree(self, apk: Path) -> str:
        return self._run(
            [
                str(self.aapt2),
                "dump",
                "xmltree",
                "--file",
                "AndroidManifest.xml",
                str(apk),
            ]
        )

    def debug_signer_sha256(self) -> str | None:
        keystore = Path.home() / ".android" / "debug.keystore"
        if not keystore.is_file():
            return None
        keytool = shutil.which("keytool")
        if keytool is None:
            java_home = os.environ.get("JAVA_HOME")
            if java_home:
                candidate = Path(java_home) / "bin" / "keytool"
                if candidate.is_file():
                    keytool = str(candidate)
        if keytool is None:
            return None
        try:
            output = self._run([
                keytool, "-list", "-v", "-keystore", str(keystore),
                "-storepass", "android", "-alias", "androiddebugkey",
            ])
        except ToolError:
            return None
        match = re.search(r"SHA256:\s*([0-9a-fA-F:]+)", output)
        return match.group(1).replace(":", "").lower() if match else None

    def cert_sha256(self, apk: Path) -> str | None:
        try:
            output = self._run([str(self.apksigner), "verify", "--print-certs", str(apk)])
        except ToolError:
            return None
        match = re.search(r"certificate SHA-256 digest:\s*([0-9a-fA-F:]+)", output)
        if not match:
            return None
        return match.group(1).replace(":", "").lower()

    def align_apk(self, apk_in: Path, apk_out: Path, alignment: int = 4) -> None:
        self._run(
            [
                str(self.zipalign),
                "-P",
                "16",
                "-f",
                str(alignment),
                str(apk_in),
                str(apk_out),
            ]
        )

    def sign_debug(self, apk_in: Path, apk_out: Path) -> None:
        keystore = Path.home() / ".android" / "debug.keystore"
        if not keystore.is_file():
            raise ToolError(f"debug keystore not found at {keystore}")
        self._run(
            [
                str(self.apksigner),
                "sign",
                "--ks",
                str(keystore),
                "--ks-pass",
                "pass:android",
                "--key-pass",
                "pass:android",
                "--ks-key-alias",
                "androiddebugkey",
                "--out",
                str(apk_out),
                str(apk_in),
            ]
        )

    def verify(self, apk: Path) -> str:
        return self._run([str(self.apksigner), "verify", "--print-certs", str(apk)])

    def verify_page_alignment(self, apk: Path) -> tuple[bool, str]:
        try:
            self._run([
                str(self.zipalign), "-c", "-P", "16", "-v", "4", str(apk)
            ], timeout=120)
            return True, "16 KB aligned"
        except ToolError as error:
            return False, str(error)

    def _java(self) -> str:
        java_home = os.environ.get("JAVA_HOME")
        if java_home:
            candidate = Path(java_home) / "bin" / "java"
            if candidate.is_file():
                return str(candidate)
        java = shutil.which("java")
        if java is None:
            raise ToolError("java not found; required for bundletool")
        return java

    def _bundletool(self, explicit: Path | None = None) -> list[str]:
        candidates: list[Path] = []
        if explicit is not None:
            candidates.append(Path(explicit))
        env = os.environ.get("BUNDLETOOL")
        if env:
            candidates.append(Path(env))
        found = shutil.which("bundletool")
        if found:
            candidates.append(Path(found))
        sdk_jar = self.sdk_root / "bundletool.jar"
        candidates.append(sdk_jar)
        for candidate in candidates:
            if not candidate.is_file():
                continue
            if candidate.suffix == ".jar":
                return [self._java(), "-jar", str(candidate)]
            return [str(candidate)]
        raise ToolError(
            "bundletool not found; pass --bundletool or set BUNDLETOOL"
        )

    def aab_to_universal(self, aab: Path, out: Path,
                         bundletool: Path | None = None) -> Path:
        import tempfile
        import zipfile

        command = self._bundletool(bundletool)
        out.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="fm-bundletool-") as tmp:
            apks = Path(tmp) / "bundle.apks"
            self._run(
                [
                    *command,
                    "build-apks",
                    f"--bundle={aab}",
                    f"--output={apks}",
                    "--mode=universal",
                    f"--aapt2={self.aapt2}",
                    "--overwrite",
                ],
                timeout=600,
            )
            with zipfile.ZipFile(apks) as archive:
                names = archive.namelist()
                if "universal.apk" not in names:
                    raise ToolError("bundletool produced no universal.apk")
                out.write_bytes(archive.read("universal.apk"))
        return out

    def aab_to_splits(self, aab: Path, out_dir: Path,
                      bundletool: Path | None = None,
                      device_spec: Path | None = None) -> list[Path]:
        import tempfile
        import zipfile

        command = self._bundletool(bundletool)
        out_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="fm-bundletool-") as tmp:
            apks = Path(tmp) / "bundle.apks"
            arguments = [
                *command,
                "build-apks",
                f"--bundle={aab}",
                f"--output={apks}",
                "--mode=default",
                f"--aapt2={self.aapt2}",
                "--overwrite",
            ]
            if device_spec is not None:
                arguments.append(f"--device-spec={device_spec}")
            self._run(arguments, timeout=600)
            outputs: list[Path] = []
            with zipfile.ZipFile(apks) as archive:
                for name in sorted(archive.namelist()):
                    if not name.startswith("splits/") or not name.endswith(".apk"):
                        continue
                    target = out_dir / Path(name).name
                    target.write_bytes(archive.read(name))
                    outputs.append(target)
            if not outputs:
                raise ToolError("bundletool produced no split APKs")
            return outputs

    def _android_jar(self) -> Path:
        platforms = self.sdk_root / "platforms"
        if not platforms.is_dir():
            raise ToolError(f"Android platforms not found under {self.sdk_root}")
        candidates = sorted(
            (path for path in platforms.iterdir() if path.is_dir()),
            key=lambda path: [int(part) if part.isdigit() else part for part in re.split(r"[.-]", path.name)],
        )
        if not candidates:
            raise ToolError(f"no Android platforms under {platforms}")
        jar = candidates[-1] / "android.jar"
        if not jar.is_file():
            raise ToolError(f"android.jar not found at {jar}")
        return jar

    def dex_jar(self, jar: Path, out_dir: Path, min_api: int = 26) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
        self._run(
            [
                str(self.d8),
                "--min-api",
                str(min_api),
                "--lib",
                str(self._android_jar()),
                "--output",
                str(out_dir),
                str(jar),
            ]
        )
        dex = out_dir / "classes.dex"
        if not dex.is_file():
            raise ToolError(f"d8 did not produce {dex}")
        return dex

    def _llvm_strip(self) -> Path:
        ndk = self.sdk_root / "ndk"
        if not ndk.is_dir():
            raise ToolError(f"Android NDK not found under {self.sdk_root}")
        versions = sorted(
            (path for path in ndk.iterdir() if path.is_dir()),
            key=lambda path: [int(part) if part.isdigit() else part
                              for part in re.split(r"[.-]", path.name)],
        )
        for version in reversed(versions):
            for host in ("darwin-arm64", "darwin-x86_64", "linux-x86_64", "windows-x86_64"):
                binary = version / "toolchains" / "llvm" / "prebuilt" / host / "bin" / "llvm-strip"
                if binary.is_file():
                    return binary
        raise ToolError("llvm-strip not found in Android NDK")

    def strip_so(self, data: bytes, name: str = "lib.so") -> bytes:
        import tempfile

        with tempfile.TemporaryDirectory(prefix="fm-strip-") as tmp:
            source = Path(tmp) / name
            source.write_bytes(data)
            self._run([str(self._llvm_strip()), "--strip-unneeded", str(source)])
            return source.read_bytes()

    def tool_versions(self) -> dict[str, str]:
        versions: dict[str, str] = {"build-tools": self.build_tools_version}
        for name, command in (("aapt2", [str(self.aapt2), "version"]), ("apksigner", [str(self.apksigner), "version"])):
            try:
                output = self._run(command, timeout=30, stderr_fallback=True).strip()
            except ToolError:
                versions[name] = "unknown"
                continue
            versions[name] = output.splitlines()[0] if output else "unknown"
        return versions
