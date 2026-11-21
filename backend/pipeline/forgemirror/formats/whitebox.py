"""Build-time CTR wrapping with the vendored Chow white-box AES table."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

MAGIC = b"WBK1"
NONCE_SIZE = 12
_TABLE_RELATIVE = Path("android/shield/src/main/java/com/risid/wbaes")
_TOOL = Path("backend/tools/whitebox/WhiteboxKeyTool.java")
_CACHE = Path(tempfile.gettempdir()) / "forgemirror-wbaes"


def _root() -> Path:
    return Path(__file__).resolve().parents[4]


def _jdk_home() -> Path:
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
    raise RuntimeError("a JDK is required for white-box key wrapping; set JAVA_HOME")


def _java_tool(name: str) -> str:
    return str(_jdk_home() / "bin" / name)


def _classes() -> Path:
    root = _root()
    sources = sorted((root / _TABLE_RELATIVE).glob("*.java"))
    tool = root / _TOOL
    if not sources or not tool.is_file():
        raise RuntimeError("white-box AES sources are missing")
    digest = hashlib.sha256()
    for path in [*sources, tool]:
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    target = _CACHE / digest.hexdigest()[:16]
    marker = target / "com/risid/wbaes/AES.class"
    if marker.is_file():
        return target
    target.mkdir(parents=True, exist_ok=True)
    command = [_java_tool("javac"), "-d", str(target),
               *(str(path) for path in sources), str(tool)]
    process = subprocess.run(command, capture_output=True, text=True)
    if process.returncode != 0:
        raise RuntimeError(process.stderr[-1000:] or "javac failed")
    return target


def wrap(table: bytes, key: bytes, nonce: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("content key must be 32 bytes")
    if len(nonce) != NONCE_SIZE:
        raise ValueError("nonce must be 12 bytes")
    classes = _classes()
    with tempfile.TemporaryDirectory(prefix="fm-wbaes-") as temporary:
        tmp = Path(temporary)
        table_path = tmp / "wbaes.table"
        output = tmp / "wrapped.bin"
        table_path.write_bytes(table)
        command = [
            _java_tool("java"), "-cp", str(classes),
            "com.risid.wbaes.WhiteboxKeyTool", "wrap",
            str(table_path), "-", nonce.hex(), str(output),
        ]
        process = subprocess.run(command, input=key.hex() + "\n",
                                 capture_output=True, text=True)
        if process.returncode != 0:
            raise RuntimeError(process.stderr[-1000:] or "white-box wrap failed")
        return output.read_bytes()
