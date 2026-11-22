"""Build-time white-box AES wrapping, table export and per-build generation."""
from __future__ import annotations

import glob
import hashlib
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from .jdk import java_tool as _java_tool
from .jdk import jdk_home as _jdk_home

MAGIC = b"WBK1"
NONCE_SIZE = 12
_TABLE_RELATIVE = Path("backend/tools/whitebox/java/com/risid/wbaes")
_TOOL = Path("backend/tools/whitebox/WhiteboxKeyTool.java")
_CACHE = Path(tempfile.gettempdir()) / "forgemirror-wbaes"
_BCPROV_VERSION = "1.61"
_BCPROV_SHA256 = ("dba6e408f205215ad1a89b70b37353d3cdae4ec61037e1feee885704e2413458")
_BCPROV_URL = ("https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/"
               f"{_BCPROV_VERSION}/bcprov-jdk15on-{_BCPROV_VERSION}.jar")


def _root() -> Path:
    return Path(__file__).resolve().parents[4]


def _bouncy_jar() -> Path:
    cached = _CACHE / f"bcprov-jdk15on-{_BCPROV_VERSION}.jar"
    if cached.is_file() and hashlib.sha256(cached.read_bytes()).hexdigest() == _BCPROV_SHA256:
        return cached
    for candidate in sorted(glob.glob(str(
            Path.home() / ".gradle/caches/modules-2/files-2.1/"
            "org.bouncycastle/bcprov-jdk15on" / _BCPROV_VERSION / "*" /
            f"bcprov-jdk15on-{_BCPROV_VERSION}.jar"))):
        jar = Path(candidate)
        if hashlib.sha256(jar.read_bytes()).hexdigest() == _BCPROV_SHA256:
            return jar
    _CACHE.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(_BCPROV_URL, cached)
    if hashlib.sha256(cached.read_bytes()).hexdigest() != _BCPROV_SHA256:
        cached.unlink(missing_ok=True)
        raise RuntimeError("bcprov download failed checksum verification")
    return cached


def _classes() -> Path:
    root = _root()
    sources = sorted((root / _TABLE_RELATIVE).glob("*.java"))
    sources += sorted((root / _TABLE_RELATIVE / "generator").glob("*.java"))
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
    command = [_java_tool("javac"), "-cp", str(_bouncy_jar()),
               "-d", str(target),
               *(str(path) for path in sources), str(tool)]
    process = subprocess.run(command, capture_output=True, text=True)
    if process.returncode != 0:
        raise RuntimeError(process.stderr[-1000:] or "javac failed")
    return target


def generate_table(out: Path) -> None:
    """Generates a fresh serialized white-box table from a random key."""
    classes = _classes()
    key = __import__("secrets").token_bytes(16)
    with tempfile.TemporaryDirectory(prefix="fm-wbaes-") as temporary:
        output = Path(temporary) / "wbaes.generated"
        command = [
            _java_tool("java"), "-cp", f"{classes}:{_bouncy_jar()}",
            "com.risid.wbaes.WhiteboxKeyTool", "generate", "-",
            str(output),
        ]
        process = subprocess.run(command, input=key.hex() + "\n",
                                 capture_output=True, text=True)
        if process.returncode != 0:
            raise RuntimeError(process.stderr[-1000:] or "table generation failed")
        out.write_bytes(output.read_bytes())


def export_table(table: bytes) -> bytes:
    classes = _classes()
    with tempfile.TemporaryDirectory(prefix="fm-wbaes-") as temporary:
        tmp = Path(temporary)
        table_path = tmp / "wbaes.table"
        output = tmp / "wbaes.flat"
        table_path.write_bytes(table)
        command = [
            _java_tool("java"), "-cp", str(classes),
            "com.risid.wbaes.WhiteboxKeyTool", "export",
            str(table_path), str(output),
        ]
        process = subprocess.run(command, capture_output=True, text=True)
        if process.returncode != 0:
            raise RuntimeError(process.stderr[-1000:] or "white-box export failed")
        return output.read_bytes()


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
