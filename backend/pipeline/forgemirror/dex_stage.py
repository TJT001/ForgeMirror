"""S2 DEX stage: build and self-test the FDX2 container."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import errors
from .apk import read_apk_entry
from .formats.container import CHUNK_SIZE, FileSpec, open_container, write_container
from .models import Inventory


class StageError(Exception):
    """Raised when a stage cannot produce a valid artifact."""


@dataclass(frozen=True)
class DexStageResult:
    container: Path
    dex_manifest: Path
    key_file: Path
    container_sha256: str
    files: list[dict[str, object]]


def _write_key(path: Path, key: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)
    os.chmod(path, 0o600)


def run_dex_stage(
    apk: Path,
    inventory: Inventory,
    out_dir: Path,
    *,
    build_id: str,
    profile: str,
    k_content: bytes | None = None,
    key_file: Path | None = None,
    split_apks: dict[str, Path] | None = None,
) -> DexStageResult:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    entries = [entry for entry in inventory.dex if entry.valid]
    if not entries:
        raise StageError(errors.E_NO_DEX)

    sources = {"base": Path(apk)}
    sources.update(split_apks or {})
    files: list[FileSpec] = []
    file_sources: list[str] = []
    for entry in entries:
        source = entry.source if entry.source in sources else "base"
        data = read_apk_entry(sources[source], entry.name)
        if source == "base":
            name = entry.name
        else:
            safe = "".join(char if char.isalnum() or char in "._-" else "_"
                           for char in source)
            name = f"{safe}/{entry.name}"
        files.append(FileSpec(name=name, data=data))
        file_sources.append(source)

    if k_content is None and key_file is not None and Path(key_file).is_file():
        k_content = Path(key_file).read_bytes()
    if k_content is None:
        k_content = os.urandom(32)
    if len(k_content) != 32:
        raise StageError("k_content must be 32 bytes")

    key_path = out_dir / "keys" / "k_content.bin"
    _write_key(key_path, k_content)

    build_id_bytes = uuid.UUID(build_id).bytes
    blob = write_container(files, k_content=k_content, build_id=build_id_bytes)

    opened = open_container(blob, k_content=k_content)
    if opened.files != [spec.data for spec in files]:
        raise StageError(errors.E_CONTAINER_SELFTEST)

    container_path = out_dir / "container.fdx"
    container_path.write_bytes(blob)

    dex_manifest = {
        "schema": "forgemirror.dex.manifest/1",
        "format": "FDX2",
        "version": 2,
        "build_id": build_id,
        "profile": profile,
        "files": [
            {
                "index": index,
                "name": spec.name,
                "size": len(spec.data),
                "sha256": hashlib.sha256(spec.data).hexdigest(),
                "chunk_count": (len(spec.data) + CHUNK_SIZE - 1) // CHUNK_SIZE,
                "source": file_sources[index],
            }
            for index, spec in enumerate(files)
        ],
    }
    manifest_path = out_dir / "dex_manifest.json"
    manifest_path.write_text(
        json.dumps(dex_manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )

    return DexStageResult(
        container=container_path,
        dex_manifest=manifest_path,
        key_file=key_path,
        container_sha256=hashlib.sha256(blob).hexdigest(),
        files=dex_manifest["files"],
    )
