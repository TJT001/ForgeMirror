"""End-to-end P1-A build orchestration (S0 -> S1 -> S2)."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path

from .apk import parse_badging
from .dex_stage import run_dex_stage
from .progress import emit as emit_progress
from .intake import run_intake
from .inventory import run_inventory
from .tools import AndroidTools, ToolError


@dataclass
class BuildOptions:
    apk: Path
    out: Path | None = None
    profile: str = "basic"
    signing_mode: str = "customer_local"
    build_id: str | None = None
    cert_allowlist: set[str] | None = None
    allow_unsigned: bool = False
    shell_version: str = "0.1.0"
    key_file: Path | None = None
    splits: list[Path] | None = None
    bundletool: Path | None = None
    aab_mode: str = "universal"
    device_spec: Path | None = None
    progress_file: Path | None = None


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def run_build(options: BuildOptions, tools: AndroidTools) -> dict:
    build_id = options.build_id or str(uuid.uuid4())
    out_dir = Path(options.out) if options.out is not None else Path("artifacts") / build_id
    out_dir.mkdir(parents=True, exist_ok=True)
    emit_progress(options.progress_file, "s0", "running", 5, "准入检查")

    apk = Path(options.apk)
    splits = [Path(item) for item in (options.splits or [])]
    bundled = apk.suffix.lower() == ".aab"
    if bundled:
        if options.splits:
            emit_progress(options.progress_file, "s0", "failed", 5,
                          "AAB 不能与 split 同时使用")
            return {
                "ok": False,
                "stage": "s0",
                "build_id": build_id,
                "out": str(out_dir),
                "reason_codes": ["E_AAB_INVALID"],
                "warnings": ["--split cannot be combined with .aab input"],
            }
        if options.aab_mode not in ("universal", "split"):
            emit_progress(options.progress_file, "s0", "failed", 5,
                          f"不支持的 AAB 模式：{options.aab_mode}")
            return {
                "ok": False,
                "stage": "s0",
                "build_id": build_id,
                "out": str(out_dir),
                "reason_codes": ["E_AAB_INVALID"],
                "warnings": [f"unsupported AAB mode: {options.aab_mode}"],
            }
        try:
            if options.aab_mode == "split":
                candidates = tools.aab_to_splits(
                    apk, out_dir / "bundle_splits",
                    options.bundletool, options.device_spec,
                )
                bases = [
                    path for path in candidates
                    if not parse_badging(tools.badging(path)).split
                ]
                if len(bases) != 1:
                    raise ToolError(
                        f"expected one base APK, found {len(bases)}"
                    )
                apk = bases[0]
                splits = [path for path in candidates if path != apk]
            else:
                apk = tools.aab_to_universal(
                    apk, out_dir / "universal.apk", options.bundletool
                )
        except ToolError as error:
            code = "E_BUNDLETOOL_MISSING" if "bundletool not found" in str(error) else "E_AAB_INVALID"
            emit_progress(options.progress_file, "s0", "failed", 5, str(error))
            return {
                "ok": False,
                "stage": "s0",
                "build_id": build_id,
                "out": str(out_dir),
                "reason_codes": [code],
                "warnings": [str(error)],
            }

    intake = run_intake(
        apk,
        build_id=build_id,
        profile=options.profile,
        signing_mode=options.signing_mode,
        tools=tools,
        cert_allowlist=options.cert_allowlist,
        allow_unsigned=options.allow_unsigned or bundled,
        splits=splits,
    )
    _write_json(out_dir / "intake.json", intake.model_dump(mode="json", by_alias=True))
    if not intake.ok:
        emit_progress(options.progress_file, "s0", "failed", 5,
                      "准入失败：" + ",".join(intake.reason_codes))
        return {
            "ok": False,
            "stage": "s0",
            "build_id": build_id,
            "out": str(out_dir),
            "reason_codes": intake.reason_codes,
            "warnings": intake.warnings,
        }

    emit_progress(options.progress_file, "s0", "done", 12, "准入通过")
    emit_progress(options.progress_file, "s1", "running", 14, "资产清点")
    inventory = run_inventory(
        apk, tools=tools, shell_version=options.shell_version,
        splits=splits,
    )
    _write_json(out_dir / "inventory.json", inventory.model_dump(mode="json", by_alias=True))

    emit_progress(options.progress_file, "s1", "done", 24, "清单完成")
    emit_progress(options.progress_file, "s2", "running", 26, "写入 FDX2 容器")
    split_apks = {
        name: path
        for name, path in zip(intake.split_names, splits)
    }
    dex_result = run_dex_stage(
        apk,
        inventory,
        out_dir,
        build_id=build_id,
        profile=options.profile,
        key_file=options.key_file,
        split_apks=split_apks,
    )

    artifacts = []
    for path in (dex_result.container, dex_result.dex_manifest):
        data = path.read_bytes()
        artifacts.append(
            {"path": path.name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        )
    artifacts.sort(key=lambda item: item["path"])

    emit_progress(options.progress_file, "s2", "done", 35, "容器写入完成")
    build_meta = {
        "schema": "forgemirror.build.meta/1",
        "build_id": build_id,
        "profile": options.profile,
        "signing_mode": options.signing_mode,
        "app": {
            "package": inventory.package,
            "version_code": inventory.version_code,
            "cert_sha256": intake.cert_sha256,
            "splits": [
                {"name": name,
                 "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                for name, path in zip(intake.split_names, splits)
            ],
        },
        "shell": {"version": options.shell_version, "container": "FDX2"},
        "artifacts": artifacts,
        "hashes": {
            "container": dex_result.container_sha256,
            "intake": hashlib.sha256((out_dir / "intake.json").read_bytes()).hexdigest(),
            "inventory": hashlib.sha256((out_dir / "inventory.json").read_bytes()).hexdigest(),
        },
        "status": "s2-partial",
    }
    _write_json(out_dir / "build.meta.json", build_meta)

    return {
        "ok": True,
        "stage": "s2",
        "build_id": build_id,
        "out": str(out_dir),
        "package": inventory.package,
        "dex_count": len(dex_result.files),
        "container": str(dex_result.container),
        "container_sha256": dex_result.container_sha256,
        "key_file": str(dex_result.key_file),
        "warnings": intake.warnings,
        "anomalies": [anomaly.model_dump() for anomaly in inventory.anomalies],
        "split_names": intake.split_names,
        "splits": [str(path) for path in splits],
        "apk": str(apk),
    }
