"""Build-time semantic decoy symbols for the stub DEX.

The generated classes are compiled into the stub class jar before d8 and are
never referenced by the runtime. They exist to add semantic noise for
automated and AI-assisted triage; they do not alter app behavior.
"""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path

from .jdk import java_tool

DEFAULT_LEXICON = Path(__file__).resolve().parents[1] / "data" / "ai_decoy.json"
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PACKAGE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")


def _normalize_group(group: dict) -> dict:
    package = group.get("package", "")
    if not _PACKAGE.fullmatch(package):
        raise ValueError("AI decoy package is not a Java package name")
    classes = group.get("classes") or []
    fields = group.get("fields") or []
    strings = group.get("strings") or []
    if not classes or not fields:
        raise ValueError("AI decoy group needs classes and fields")
    if len(set(classes)) != len(classes) or len(set(fields)) != len(fields):
        raise ValueError("AI decoy names must be unique")
    for name in [*classes, *fields]:
        if not _IDENTIFIER.fullmatch(name):
            raise ValueError(f"AI decoy name is not a Java identifier: {name}")
    if not all(isinstance(value, str) for value in strings):
        raise ValueError("AI decoy strings must be text")
    return {"package": package, "classes": classes,
            "fields": fields, "strings": strings}


def load_lexicon(path: Path | None = None) -> dict:
    data = json.loads(Path(path or DEFAULT_LEXICON).read_text(encoding="utf-8"))
    if data.get("schema") != "forgemirror.ai-decoy/1":
        raise ValueError("unsupported AI decoy lexicon")
    raw_groups = data.get("groups")
    if raw_groups is None:
        raw_groups = [data]
    groups = [_normalize_group(group) for group in raw_groups]
    if not groups:
        raise ValueError("AI decoy lexicon is empty")
    seen: set[str] = set()
    for group in groups:
        for name in group["classes"]:
            qualified = f'{group["package"]}.{name}'
            if qualified in seen:
                raise ValueError(f"duplicate AI decoy class: {qualified}")
            seen.add(qualified)
    return {"groups": groups}


def _source(package: str, class_name: str, fields: list[str],
            strings: list[str]) -> str:
    lines = [f"package {package};", "",
             f"public final class {class_name} {{"]
    for index, field in enumerate(fields):
        value = strings[index % len(strings)] if strings else field
        lines.append(f'    public static final String {field} = "{value}";')
    lines.append("")
    lines.append(f"    private {class_name}() {{")
    lines.append("    }")
    for field in fields:
        method = field[0].upper() + field[1:]
        lines.append("")
        lines.append(f"    public static String get{method}() {{")
        lines.append(f"        return {field};")
        lines.append("    }")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _jar_directory(directory: Path, target: Path) -> None:
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as jar:
        for path in sorted(directory.rglob("*.class")):
            name = path.relative_to(directory).as_posix()
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            jar.writestr(info, path.read_bytes())


def build_decoy_jar(lexicon_path: Path | None, target: Path) -> int:
    lexicon = load_lexicon(lexicon_path)
    with tempfile.TemporaryDirectory(prefix="fm-decoy-") as temporary:
        root = Path(temporary)
        source_dir = root / "src"
        classes_dir = root / "classes"
        sources = []
        total = 0
        for group in lexicon["groups"]:
            package = group["package"]
            package_dir = source_dir / package.replace(".", "/")
            package_dir.mkdir(parents=True, exist_ok=True)
            for class_name in group["classes"]:
                path = package_dir / f"{class_name}.java"
                path.write_text(
                    _source(package, class_name, group["fields"],
                            group["strings"]),
                    encoding="utf-8")
                sources.append(str(path))
                total += 1
        classes_dir.mkdir(parents=True)
        process = subprocess.run(
            [java_tool("javac"), "--release", "11", "-encoding", "UTF-8",
             "-d", str(classes_dir), *sources],
            capture_output=True, text=True,
        )
        if process.returncode != 0:
            raise RuntimeError(process.stderr[-1000:] or "javac failed")
        _jar_directory(classes_dir, target)
    return total


def merge_jar(base: Path, extra: Path, target: Path) -> None:
    with zipfile.ZipFile(base) as first, zipfile.ZipFile(extra) as second, \
            zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as out:
        seen: set[str] = set()
        for archive in (first, second):
            for info in archive.infolist():
                if info.filename in seen:
                    continue
                seen.add(info.filename)
                entry = zipfile.ZipInfo(info.filename,
                                        date_time=(1980, 1, 1, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.external_attr = 0o644 << 16
                out.writestr(entry, archive.read(info.filename))
