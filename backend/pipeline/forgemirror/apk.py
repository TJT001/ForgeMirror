"""APK and ELF inspection helpers for the S0/S1 stages."""

from __future__ import annotations

import hashlib
import re
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .models import AssetEntry, ComponentInfo, DexEntry, LibEntry, ManifestInfo

ELF_MACHINES = {
    3: "x86",
    40: "armeabi-v7a",
    62: "x86_64",
    183: "arm64-v8a",
    243: "riscv64",
}

ABI_TO_MACHINE = {
    "x86": 3,
    "armeabi": 40,
    "armeabi-v7a": 40,
    "x86_64": 62,
    "arm64-v8a": 183,
    "riscv64": 243,
}

_DEX_RE = re.compile(r"^classes(\d*)\.dex$")
_LIB_RE = re.compile(r"^lib/([^/]+)/([^/]+\.so)$")
_HARDENED_MARKERS = ("com.secneo", "dexdata0", "bangcle", "libdexhelper", "libmobisec")


@dataclass(frozen=True)
class BadgingInfo:
    package: str | None
    version_code: int | None
    version_name: str | None
    min_sdk: int | None
    target_sdk: int | None
    native_code: list[str]
    split: str | None = None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_zip(path: Path) -> bool:
    return zipfile.is_zipfile(path)


def parse_badging(text: str) -> BadgingInfo:
    package = None
    version_code = None
    version_name = None
    match = re.search(
        r"package: name='([^']+)'(?: versionCode='([^']+)')?(?: versionName='([^']*)')?"
        r"(?: split='([^']*)')?",
        text,
    )
    if match:
        package = match.group(1) or None
        version_code = int(match.group(2)) if match.group(2) else None
        version_name = match.group(3) if match.group(3) else None

    min_match = re.search(r"(?:minSdkVersion|sdkVersion):'(\d+)'", text)
    target_match = re.search(r"targetSdkVersion:'(\d+)'", text)
    native_match = re.search(r"native-code: (.*)", text)
    native_code = re.findall(r"'([^']+)'", native_match.group(1)) if native_match else []

    return BadgingInfo(
        package=package,
        version_code=version_code,
        version_name=version_name,
        min_sdk=int(min_match.group(1)) if min_match else None,
        target_sdk=int(target_match.group(1)) if target_match else None,
        native_code=native_code,
        split=match.group(4) if match and match.group(4) else None,
    )


def _parse_attribute(text: str) -> tuple[str | None, str | None]:
    head, separator, tail = text.strip().partition("=")
    if not separator:
        return None, None
    name = head.split("(", 1)[0].rsplit(":", 1)[-1].strip()
    if not name:
        return None, None
    rest = tail.strip()
    raw = re.search(r'\(Raw: "(.*)"\)\s*$', rest)
    if raw:
        return name, raw.group(1)
    if rest.startswith('"') and rest.endswith('"'):
        return name, rest[1:-1]
    return name, re.sub(r"\s*\(Raw:.*$", "", rest)


@dataclass
class _Frame:
    tag: str
    indent: int
    component: ComponentInfo | None = None


def parse_xmltree(text: str) -> ManifestInfo:
    info = ManifestInfo()
    stack: list[_Frame] = []

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        if stripped.startswith("E: "):
            tag = stripped[3:].split()[0] if len(stripped) > 3 else ""
            while stack and stack[-1].indent >= indent:
                stack.pop()
            component = None
            if tag == "activity":
                component = ComponentInfo()
                info.activities.append(component)
            elif tag == "service":
                component = ComponentInfo()
                info.services.append(component)
            elif tag == "receiver":
                component = ComponentInfo()
                info.receivers.append(component)
            elif tag == "provider":
                component = ComponentInfo()
                info.providers.append(component)
            stack.append(_Frame(tag=tag, indent=indent, component=component))
            continue

        if not stripped.startswith("A: ") or not stack:
            continue

        name, value = _parse_attribute(stripped[3:])
        if name is None or value is None:
            continue
        frame = stack[-1]
        if frame.tag == "manifest" and name == "package":
            info.package = value
        elif frame.tag == "application":
            if name == "name":
                info.application = value
            elif name == "appComponentFactory":
                info.app_component_factory = value
        elif frame.component is not None:
            if name == "name":
                frame.component.name = value
            elif name == "exported":
                frame.component.exported = value.lower() == "true"
            elif name == "process":
                frame.component.process = value
            elif name == "authorities":
                frame.component.authorities = value

    return info


def _natural_dex_key(name: str) -> int:
    match = _DEX_RE.match(name)
    if not match:
        return 1 << 30
    suffix = match.group(1)
    return int(suffix) if suffix else 1


def list_dex(apk: Path, source: str = "base") -> list[DexEntry]:
    entries: list[DexEntry] = []
    with zipfile.ZipFile(apk) as archive:
        for info in archive.infolist():
            if not _DEX_RE.match(info.filename) or info.is_dir():
                continue
            digest = hashlib.sha256()
            with archive.open(info) as stream:
                prefix = stream.read(8)
                digest.update(prefix)
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(chunk)
            valid = len(prefix) >= 8 and prefix[:4] == b"dex\n"
            version = prefix[4:7].decode("ascii", "replace") if valid else None
            entries.append(
                DexEntry(
                    name=info.filename,
                    size=info.file_size,
                    sha256=digest.hexdigest(),
                    version=version,
                    valid=valid,
                    source=source,
                )
            )
    entries.sort(key=lambda entry: _natural_dex_key(entry.name))
    return entries


def elf_arch(prefix: bytes) -> str | None:
    if len(prefix) < 20 or prefix[:4] != b"\x7fELF":
        return None
    data_encoding = prefix[5]
    if data_encoding not in (1, 2):
        return None
    endian = "<" if data_encoding == 1 else ">"
    machine = struct.unpack(endian + "H", prefix[18:20])[0]
    return ELF_MACHINES.get(machine)


def list_libs(apk: Path, source: str = "base") -> list[LibEntry]:
    entries: list[LibEntry] = []
    with zipfile.ZipFile(apk) as archive:
        for info in archive.infolist():
            match = _LIB_RE.match(info.filename)
            if not match or info.is_dir():
                continue
            abi_dir = match.group(1)
            digest = hashlib.sha256()
            with archive.open(info) as stream:
                prefix = stream.read(20)
                digest.update(prefix)
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(chunk)
            entries.append(
                LibEntry(
                    path=info.filename,
                    abi_dir=abi_dir,
                    arch=elf_arch(prefix),
                    size=info.file_size,
                    sha256=digest.hexdigest(),
                    source=source,
                )
            )
    entries.sort(key=lambda entry: entry.path)
    return entries


def list_assets(apk: Path) -> list[AssetEntry]:
    entries: list[AssetEntry] = []
    with zipfile.ZipFile(apk) as archive:
        for info in archive.infolist():
            if info.is_dir() or not info.filename.startswith("assets/"):
                continue
            digest = hashlib.sha256()
            with archive.open(info) as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(chunk)
            entries.append(
                AssetEntry(path=info.filename, size=info.file_size, sha256=digest.hexdigest())
            )
    entries.sort(key=lambda entry: entry.path)
    return entries


def hardened_markers(apk: Path, manifest_text: str) -> list[str]:
    with zipfile.ZipFile(apk) as archive:
        haystack = [name.lower() for name in archive.namelist()]
    haystack.append(manifest_text.lower())
    return sorted({marker for marker in _HARDENED_MARKERS if any(marker in item for item in haystack)})


def read_apk_entry(apk: Path, name: str) -> bytes:
    with zipfile.ZipFile(apk) as archive:
        return archive.read(name)
