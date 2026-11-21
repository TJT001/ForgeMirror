"""Locates the JDK used by build-time Java tools."""
from __future__ import annotations

import os
import shutil
from pathlib import Path


def jdk_home() -> Path:
    candidates: list[Path] = []
    if os.environ.get("JAVA_HOME"):
        candidates.append(Path(os.environ["JAVA_HOME"]))
    candidates.extend([
        Path("/opt/homebrew/opt/openjdk"),
        Path("/usr/lib/jvm/default-java"),
    ])
    javac = shutil.which("javac")
    if javac:
        candidates.append(Path(javac).resolve().parent.parent)
    for candidate in candidates:
        if (candidate / "bin" / "javac").is_file() and (
                candidate / "bin" / "java").is_file():
            return candidate
    raise RuntimeError("a JDK is required for build-time Java tools; set JAVA_HOME")


def java_tool(name: str) -> str:
    return str(jdk_home() / "bin" / name)
