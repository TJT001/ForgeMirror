"""Generates native vault vectors: FDX2 container, WBK1 blob, flat table."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend" / "pipeline"))

from forgemirror.formats.container import FileSpec, write_container  # noqa: E402
from forgemirror.formats import whitebox  # noqa: E402

OUT = ROOT / "backend" / "tests" / "vectors" / "vault"
TABLE = ROOT / "backend" / "pipeline" / "forgemirror" / "data" / "wbaes.table"

KEY = bytes(range(32))
BUILD_ID = bytes(range(16))
NONCE = bytes(range(12))
FILES = [
    ("classes.dex", bytes((i * 7 + 3) & 0xFF for i in range(100))),
    ("classes2.dex", bytes((i * 11 + 5) & 0xFF for i in range(70000))),
    ("empty.bin", b""),
]
LABELS = {
    1: b"FM/policy/v1",
    2: b"FM/files/v1",
    3: b"FM/native/v1",
    4: b"FM/rules/v1",
    5: b"FM/core/v1",
}


def main() -> int:
    try:
        whitebox._jdk_home()
    except RuntimeError:
        print("no JDK; skipping vault vectors", file=sys.stderr)
        return 0
    OUT.mkdir(parents=True, exist_ok=True)
    table = TABLE.read_bytes()
    (OUT / "container.fdx").write_bytes(write_container(
        [FileSpec(name, data) for name, data in FILES],
        k_content=KEY,
        build_id=BUILD_ID,
        nonce_prefix=bytes(range(8)),
        toc_nonce=bytes(range(12, 24)),
    ))
    (OUT / "key.wb").write_bytes(whitebox.wrap(table, KEY, NONCE))
    (OUT / "wbaes.flat").write_bytes(whitebox.export_table(table))
    (OUT / "build_id.bin").write_bytes(BUILD_ID)
    for index, (_, data) in enumerate(FILES):
        (OUT / f"expected-{index}.bin").write_bytes(data)
    for ident, label in LABELS.items():
        derived = HKDF(algorithm=hashes.SHA256(), length=32,
                       salt=BUILD_ID, info=label).derive(KEY)
        (OUT / f"derive-{ident}.bin").write_bytes(derived)
    (OUT / "manifest.json").write_text(json.dumps({
        "files": [name for name, _ in FILES],
        "derive_ids": sorted(LABELS),
    }, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
