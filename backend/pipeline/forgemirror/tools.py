"""Android SDK tool wrappers used by the build pipeline."""

from __future__ import annotations

import os
import re
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
        if not aapt2.is_file():
            raise ToolError(f"aapt2 not found at {aapt2}")
        if not apksigner.is_file():
            raise ToolError(f"apksigner not found at {apksigner}")
        if not zipalign.is_file():
            raise ToolError(f"zipalign not found at {zipalign}")
        return cls(
            sdk_root=root,
            build_tools_version=tool_dir.name,
            aapt2=aapt2,
            apksigner=apksigner,
            zipalign=zipalign,
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
