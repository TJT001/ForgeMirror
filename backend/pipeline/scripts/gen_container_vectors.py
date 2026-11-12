#!/usr/bin/env python3
"""Generate deterministic FDX2 test vectors."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend" / "pipeline"))

from forgemirror.formats.container import FileSpec, write_container  # noqa: E402

VECTORS = ROOT / "backend" / "tests" / "vectors" / "container" / "v2"
K_CONTENT = hashlib.sha256(b"forgemirror-fdx2-test-key-v1").digest()
BUILD_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
NONCE_PREFIX = bytes.fromhex("0102030405060708")
TOC_NONCE = bytes.fromhex("1112131415161718191a1b1c")


def deterministic(size: int, seed: bytes) -> bytes:
    chunks: list[bytes] = []
    produced = 0
    counter = 0
    while produced < size:
        block = hashlib.sha256(seed + counter.to_bytes(4, "little")).digest()
        chunks.append(block)
        produced += len(block)
        counter += 1
    return b"".join(chunks)[:size]


CASES = {
    "single": [
        FileSpec("classes.dex", deterministic(1024, b"single")),
    ],
    "multi": [
        FileSpec("classes.dex", deterministic(65792, b"multi-a")),
        FileSpec("classes2.dex", b""),
        FileSpec("classes3.dex", deterministic(65537, b"multi-b")),
    ],
}


def main() -> None:
    for name, files in CASES.items():
        blob = write_container(
            files,
            k_content=K_CONTENT,
            build_id=BUILD_ID,
            nonce_prefix=NONCE_PREFIX,
            toc_nonce=TOC_NONCE,
        )
        case = VECTORS / name
        case.mkdir(parents=True, exist_ok=True)
        (case / "container.fdx").write_bytes(blob)
        (case / "key.bin").write_bytes(K_CONTENT)
        (case / "expected.txt").write_text(
            "".join(
                f"{hashlib.sha256(spec.data).hexdigest()} {len(spec.data)} {spec.name}\n"
                for spec in files
            )
        )
        meta = {
            "format": "FDX2",
            "version": 2,
            "note": "public test vector; never use these keys in production",
            "k_content": K_CONTENT.hex(),
            "build_id": BUILD_ID.hex(),
            "nonce_prefix": NONCE_PREFIX.hex(),
            "toc_nonce": TOC_NONCE.hex(),
            "files": [
                {
                    "name": spec.name,
                    "size": len(spec.data),
                    "sha256": hashlib.sha256(spec.data).hexdigest(),
                }
                for spec in files
            ],
            "container_sha256": hashlib.sha256(blob).hexdigest(),
        }
        (case / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
        print(f"{name}: {len(blob)} bytes")


if __name__ == "__main__":
    main()
