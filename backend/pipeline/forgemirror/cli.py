"""Command line entry points for the build pipeline."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import typer

from .intake import PROFILES, SIGNING_MODES, run_intake
from .inventory import run_inventory
from .gate import run_gate
from .formats.legacy import decode_res_rule, edata_to_policy, parse_classes_dve, parse_edata
from .formats.file import (
    DEFAULT_CHUNK_SIZE,
    FileFormatError,
    derive_file_key,
    migrate as migrate_encrypted_file,
    migrate_rc4 as migrate_rc4_file,
)
from .pipeline import BuildOptions, run_build
from .protect import ProtectOptions, protect
from .tools import AndroidTools, ToolError

ROOT = Path(__file__).resolve().parents[3]

app = typer.Typer(help="ForgeMirror build pipeline", no_args_is_help=True)


def _echo(payload: dict) -> None:
    typer.echo(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


def _load_allowlist(path: Path | None) -> set[str] | None:
    if path is None:
        return None
    values = set()
    for line in Path(path).read_text().splitlines():
        value = line.strip().lower()
        if value and not value.startswith("#"):
            values.add(value)
    return values


def _attach_page_checks(gate: dict, tools, paths: list[Path]) -> dict:
    verify = getattr(tools, "verify_page_alignment", None)
    if verify is None:
        return gate
    failures: list[str] = []
    for path in paths:
        passed, detail = verify(path)
        name = f"page_alignment_16k:{path.name}"
        gate.setdefault("checks", []).append({
            "name": name,
            "status": "pass" if passed else "fail",
            "detail": detail,
        })
        if not passed:
            failures.append(name)
    if failures:
        gate["passed"] = False
        gate.setdefault("failed", []).extend(failures)
    return gate


def _discover(sdk_root: Path | None, build_tools: str | None) -> AndroidTools:
    try:
        return AndroidTools.discover(sdk_root, build_tools)
    except ToolError as exc:
        typer.echo(f"tool error: {exc}", err=True)
        raise typer.Exit(2) from exc


@app.command()
def build(
    apk: Path = typer.Option(..., "--apk", exists=True, dir_okay=False, readable=True),
    out: Path | None = typer.Option(None, "--out", "-o", help="output directory"),
    profile: str = typer.Option("basic", "--profile"),
    signing_mode: str = typer.Option("customer_local", "--signing-mode"),
    build_id: str | None = typer.Option(None, "--build-id"),
    cert_allowlist: Path | None = typer.Option(None, "--cert-allowlist"),
    allow_unsigned: bool = typer.Option(False, "--allow-unsigned"),
    shell_version: str = typer.Option("0.1.0", "--shell-version"),
    key_file: Path | None = typer.Option(None, "--key-file"),
    sdk_root: Path | None = typer.Option(None, "--sdk-root"),
    build_tools: str | None = typer.Option(None, "--build-tools"),
    split: list[Path] = typer.Option([], "--split", exists=True, dir_okay=False,
                                     help="Repeatable split APK belonging to the base APK."),
    bundletool: Path | None = typer.Option(None, "--bundletool",
                                           help="bundletool executable or standalone jar."),
    aab_mode: str = typer.Option("universal", "--aab-mode",
                                 help="AAB conversion mode: universal or split."),
    device_spec: list[Path] = typer.Option([], "--device-spec", exists=True,
                                           dir_okay=False,
                                           help="Repeatable bundletool device spec for --aab-mode=split."),
) -> None:
    """Run S0 -> S1 -> S2 and write the build artifacts."""
    if profile not in PROFILES:
        typer.echo(f"invalid profile: {profile}", err=True)
        raise typer.Exit(2)
    if signing_mode not in SIGNING_MODES:
        typer.echo(f"invalid signing mode: {signing_mode}", err=True)
        raise typer.Exit(2)

    tools = _discover(sdk_root, build_tools)
    if device_spec and (apk.suffix.lower() != ".aab" or aab_mode != "split"):
        typer.echo("--device-spec requires .aab with --aab-mode split", err=True)
        raise typer.Exit(2)
    if len(device_spec) > 1:
        if apk.suffix.lower() != ".aab" or aab_mode != "split":
            typer.echo("multiple --device-spec requires .aab with --aab-mode split",
                       err=True)
            raise typer.Exit(2)
        if split:
            typer.echo("--split cannot be combined with AAB device specs", err=True)
            raise typer.Exit(2)

    batch_id = build_id or str(uuid.uuid4())
    specs: list[Path | None] = list(device_spec) or [None]
    batch_root = out
    if len(specs) > 1 and batch_root is None:
        batch_root = Path("artifacts") / batch_id
    used_names: set[str] = set()
    allowlist = _load_allowlist(cert_allowlist)

    def build_one(spec: Path | None, index: int) -> dict:
        if len(specs) == 1:
            work_out = out
        else:
            assert batch_root is not None
            stem = spec.stem if spec is not None else "default"
            safe = "".join(char if char.isalnum() or char in "._-" else "_"
                           for char in stem)
            name = f"{index:02d}_{safe}"
            while name in used_names:
                name = f"{index:02d}_{safe}_{len(used_names)}"
            used_names.add(name)
            work_out = Path(batch_root) / name
        return run_build(
            BuildOptions(
                apk=apk,
                out=work_out,
                profile=profile,
                signing_mode=signing_mode,
                build_id=batch_id,
                cert_allowlist=allowlist,
                allow_unsigned=allow_unsigned,
                shell_version=shell_version,
                key_file=key_file,
                splits=split,
                bundletool=bundletool,
                aab_mode=aab_mode,
                device_spec=spec,
            ),
            tools,
        )

    if len(specs) == 1:
        result = build_one(specs[0], 0)
        _echo(result)
        if not result["ok"]:
            raise typer.Exit(1)
        return

    assert batch_root is not None
    batch_root = Path(batch_root)
    batch_root.mkdir(parents=True, exist_ok=True)
    outcomes = [build_one(spec, index) for index, spec in enumerate(specs)]
    batch = {
        "schema": "forgemirror.build-batch/1",
        "batch_id": batch_id,
        "aab": str(apk),
        "device_specs": [str(spec) for spec in specs if spec is not None],
        "ok": all(item["ok"] for item in outcomes),
        "sets": outcomes,
    }
    (batch_root / "batch.json").write_text(
        json.dumps(batch, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )
    _echo(batch)
    if not batch["ok"]:
        raise typer.Exit(1)


@app.command("protect")
def protect_apk(
    apk: Path = typer.Option(..., "--apk", exists=True, dir_okay=False, readable=True),
    out: Path | None = typer.Option(None, "--out", "-o", help="output directory"),
    profile: str = typer.Option("basic", "--profile"),
    signing_mode: str = typer.Option("customer_local", "--signing-mode"),
    build_id: str | None = typer.Option(None, "--build-id"),
    shield_aar: Path = typer.Option(
        ROOT / "android" / "shield" / "build" / "outputs" / "aar" / "shield-debug.aar",
        "--shield-aar",
    ),
    auth_url: str = typer.Option("", "--auth-url"),
    event_url: str = typer.Option("", "--event-url"),
    event_token: str = typer.Option("dev-client-token", "--event-token"),
    no_key_asset: bool = typer.Option(False, "--no-key-asset"),
    self_decrypt_core: bool = typer.Option(
        True, "--self-decrypt-core/--no-self-decrypt-core"
    ),
    decoy_dynamic: bool = typer.Option(
        True, "--decoy-dynamic/--no-decoy-dynamic"
    ),
    corrupt_section_names: bool = typer.Option(
        True, "--corrupt-section-names/--keep-section-names"
    ),
    self_decrypt_text: bool = typer.Option(
        True, "--self-decrypt-text/--no-self-decrypt-text"
    ),
    in_memory_libs: str = typer.Option(
        "", "--in-memory-libs",
        help="Comma-separated customer .so basenames to load from encrypted assets.",
    ),
    key_dir: Path = typer.Option(Path("artifacts/keys"), "--key-dir"),
    content_key: Path | None = typer.Option(
        None, "--key-file", exists=True, dir_okay=False, readable=True,
        help="Reuse an existing 32-byte content key for reproducible builds.",
    ),
    alg: str = typer.Option("ecdsa-p256-sha256", "--alg"),
    shell_version: str = typer.Option("0.1.0", "--shell-version"),
    sdk_root: Path | None = typer.Option(None, "--sdk-root"),
    build_tools: str | None = typer.Option(None, "--build-tools"),
    split: list[Path] = typer.Option([], "--split", exists=True, dir_okay=False,
                                     help="Repeatable split APK belonging to the base APK."),
    bundletool: Path | None = typer.Option(None, "--bundletool",
                                           help="bundletool executable or standalone jar."),
    aab_mode: str = typer.Option("universal", "--aab-mode",
                                 help="AAB conversion mode: universal or split."),
    device_spec: list[Path] = typer.Option([], "--device-spec", exists=True,
                                           dir_okay=False,
                                           help="Repeatable bundletool device spec for --aab-mode=split."),
) -> None:
    """Run S0-S2, rewrite the manifest (S6), align/sign (S7), and gate (S8)."""
    if profile not in PROFILES:
        typer.echo(f"invalid profile: {profile}", err=True)
        raise typer.Exit(2)
    if signing_mode not in SIGNING_MODES:
        typer.echo(f"invalid signing mode: {signing_mode}", err=True)
        raise typer.Exit(2)

    tools = _discover(sdk_root, build_tools)
    if device_spec and (apk.suffix.lower() != ".aab" or aab_mode != "split"):
        typer.echo("--device-spec requires .aab with --aab-mode split", err=True)
        raise typer.Exit(2)
    if len(device_spec) > 1:
        if apk.suffix.lower() != ".aab" or aab_mode != "split":
            typer.echo("multiple --device-spec requires .aab with --aab-mode split",
                       err=True)
            raise typer.Exit(2)
        if split:
            typer.echo("--split cannot be combined with AAB device specs", err=True)
            raise typer.Exit(2)

    batch_id = build_id or str(uuid.uuid4())
    specs: list[Path | None] = list(device_spec) or [None]
    batch_root = out
    if len(specs) > 1 and batch_root is None:
        batch_root = Path("artifacts") / batch_id
    used_names: set[str] = set()

    def protect_one(spec: Path | None, index: int) -> dict:
        if len(specs) == 1:
            work_out = out
        else:
            assert batch_root is not None
            stem = (spec.stem if spec is not None else "default")
            safe = "".join(char if char.isalnum() or char in "._-" else "_"
                           for char in stem)
            name = f"{index:02d}_{safe}"
            while name in used_names:
                name = f"{index:02d}_{safe}_{len(used_names)}"
            used_names.add(name)
            work_out = Path(batch_root) / name
        build_result = run_build(
            BuildOptions(
                apk=apk,
                out=work_out,
                profile=profile,
                signing_mode=signing_mode,
                build_id=batch_id,
                shell_version=shell_version,
                key_file=content_key,
                splits=split,
                bundletool=bundletool,
                aab_mode=aab_mode,
                device_spec=spec,
            ),
            tools,
        )
        if not build_result["ok"]:
            return {"ok": False, "spec": str(spec) if spec else None,
                    "build": build_result}

        work_dir = Path(build_result["out"])
        container = work_dir / "container.fdx"
        key_file = work_dir / "keys" / "k_content.bin"
        effective_apk = Path(build_result.get("apk", apk))
        effective_splits = [Path(item) for item in build_result.get("splits", [])]
        result = protect(
            ProtectOptions(
                apk=effective_apk,
                container=container,
                key_file=key_file,
                out=work_dir / "protected.apk",
                build_id=build_result["build_id"],
                aar=shield_aar,
                profile=profile,
                signing_mode=signing_mode,
                auth_url=auth_url,
                event_url=event_url,
                event_token=event_token,
                no_key_asset=no_key_asset,
                key_dir=key_dir,
                self_decrypt_core=self_decrypt_core,
                decoy_dynamic=decoy_dynamic,
                corrupt_section_names=corrupt_section_names,
                self_decrypt_text=self_decrypt_text,
                in_memory_libs=in_memory_libs,
                alg=alg,
                splits=effective_splits,
            ),
            tools,
        )
        base_out = Path(result["apk"])
        split_dir = base_out.with_name(base_out.stem + "_splits")
        split_paths = [split_dir / item["file"]
                       for item in result.get("splits", [])]
        gate = run_gate(base_out, container, key_file.read_bytes(),
                        splits=split_paths)
        gate = _attach_page_checks(gate, tools, [base_out, *split_paths])
        (work_dir / "gate.json").write_text(
            json.dumps(gate, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        )
        return {"ok": gate["passed"], "spec": str(spec) if spec else None,
                "out": str(work_dir), "build": build_result,
                "result": result, "gate": gate}

    if len(specs) == 1:
        outcome = protect_one(specs[0], 0)
        if "build" in outcome and "result" not in outcome:
            _echo(outcome["build"])
            raise typer.Exit(1)
        _echo({**outcome["result"], "gate": outcome["gate"]})
        if not outcome["ok"]:
            raise typer.Exit(1)
        return

    assert batch_root is not None
    batch_root = Path(batch_root)
    batch_root.mkdir(parents=True, exist_ok=True)
    outcomes = [protect_one(spec, index)
                for index, spec in enumerate(specs)]
    batch = {
        "schema": "forgemirror.aab-batch/1",
        "batch_id": batch_id,
        "aab": str(apk),
        "device_specs": [str(spec) for spec in specs if spec is not None],
        "ok": all(item["ok"] for item in outcomes),
        "sets": outcomes,
    }
    (batch_root / "batch.json").write_text(
        json.dumps(batch, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )
    _echo(batch)
    if not batch["ok"]:
        raise typer.Exit(1)


@app.command("migrate-file")
def migrate_file(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    out: Path = typer.Option(..., "--out", dir_okay=False, writable=True),
    key_file: Path | None = typer.Option(
        None, "--key-file", help="raw 32-byte file key"
    ),
    k_content: Path | None = typer.Option(
        None, "--k-content", help="container content key to derive the file key"
    ),
    build_id: str | None = typer.Option(
        None, "--build-id", help="build id used with --k-content"
    ),
    chunk_size: int = typer.Option(DEFAULT_CHUNK_SIZE, "--chunk-size"),
    assume_plaintext: bool = typer.Option(False, "--assume-plaintext"),
    rc4_key: str | None = typer.Option(
        None, "--rc4-key", help="hex RC4 key for DVE legacy files"
    ),
    rc4_type: int = typer.Option(0, "--rc4-type", min=0),
) -> None:
    """Migrate an FMF1/plaintext or DVE RC4 file to FMF2."""
    if key_file is not None:
        key = key_file.read_bytes()
    elif k_content is not None and build_id:
        key = derive_file_key(k_content.read_bytes(), build_id)
    elif rc4_key is not None:
        key = b""
    else:
        typer.echo("need --key-file or --k-content with --build-id", err=True)
        raise typer.Exit(2)
    if rc4_key is None and len(key) != 32:
        typer.echo("file key must be 32 bytes", err=True)
        raise typer.Exit(2)
    try:
        if rc4_key is not None:
            rc4_bytes = bytes.fromhex(rc4_key)
            out_key = key if len(key) == 32 else None
            if out_key is None and len(rc4_bytes) != 32:
                typer.echo("RC4 migration needs a 32-byte output key", err=True)
                raise typer.Exit(2)
            result = migrate_rc4_file(
                input, out, rc4_bytes, enc_type=rc4_type,
                chunk_size=chunk_size, out_key=out_key,
            )
        else:
            result = migrate_encrypted_file(
                input, out, key, chunk_size=chunk_size,
                assume_plaintext=assume_plaintext,
            )
    except FileFormatError as error:
        typer.echo(f"migrate failed: {error}", err=True)
        raise typer.Exit(1) from error
    _echo(result)


@app.command("legacy-inspect")
def legacy_inspect(
    edata: Path | None = typer.Option(None, "--edata", exists=True, dir_okay=False),
    dve: Path | None = typer.Option(None, "--dve", exists=True, dir_okay=False),
    res_rule: Path | None = typer.Option(None, "--res-rule", exists=True, dir_okay=False),
    info_y: Path | None = typer.Option(None, "--info-y", exists=True, dir_okay=False),
) -> None:
    """Inspect SecNeo .edata, classes.dve, RES_RULE, or INFO- material."""
    result: dict = {"ok": True}
    if edata is not None:
        parsed = parse_edata(edata.read_text())
        result["edata"] = {
            "enc_type": parsed.enc_type,
            "rules": parsed.rules,
            "excludes": parsed.excludes,
        }
    if dve is not None:
        stamp = parse_classes_dve(dve.read_bytes())
        result["classes_dve"] = {"md5": stamp.md5, "ctime": stamp.ctime}
    if res_rule is not None:
        result["res_rule"] = decode_res_rule(res_rule.read_bytes())
    if info_y is not None:
        from .formats.infoy import InfoYError, parse as parse_info_y

        try:
            parsed_info = parse_info_y(info_y.read_bytes())
        except InfoYError as error:
            typer.echo(f"info.y error: {error}", err=True)
            raise typer.Exit(1) from error
        result["info_y"] = {
            "digest": parsed_info.digest.hex(),
            "sections": [
                {"index": section.index, "offset": section.offset,
                 "flags": section.flags, "size": section.size}
                for section in parsed_info.sections
            ],
            "strings": parsed_info.strings,
        }
    if edata is None and dve is None and res_rule is None and info_y is None:
        typer.echo("need --edata, --dve, --res-rule or --info-y", err=True)
        raise typer.Exit(2)
    _echo(result)


@app.command("edata-to-policy")
def edata_to_policy_command(
    edata: Path = typer.Option(..., "--edata", exists=True, dir_okay=False),
    out: Path = typer.Option(..., "--out", dir_okay=False),
) -> None:
    """Convert a SecNeo .edata policy into a ForgeMirror policy JSON."""
    parsed = parse_edata(edata.read_text())
    policy = edata_to_policy(parsed)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(policy, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    _echo({"ok": True, "out": str(out), "rules": len(parsed.rules),
           "excludes": len(parsed.excludes), "enc_type": parsed.enc_type})


@app.command("yara-check")
def yara_check(
    rules_file: Path | None = typer.Option(None, "--rules", exists=True, dir_okay=False),
) -> None:
    """Compile YARA rules (default: the nine demo rules)."""
    from .formats import yara_rules

    source = rules_file.read_text() if rules_file else yara_rules.PRODUCT_RULES
    try:
        yara_rules.compile_rules(source)
    except (yara_rules.YaraUnavailable, yara_rules.YaraRuleError) as error:
        typer.echo(f"yara error: {error}", err=True)
        raise typer.Exit(1) from error
    _echo({"ok": True, "rules_file": str(rules_file) if rules_file else "builtin"})


@app.command("yara-scan")
def yara_scan(
    apk: Path = typer.Option(..., "--apk", exists=True, dir_okay=False),
    rules_file: Path | None = typer.Option(None, "--rules", exists=True, dir_okay=False),
) -> None:
    """Scan an APK's native libraries with YARA rules."""
    from .formats import yara_rules

    source = rules_file.read_text() if rules_file else yara_rules.PRODUCT_RULES
    try:
        matches = yara_rules.scan_apk(apk, source=source)
    except (yara_rules.YaraUnavailable, yara_rules.YaraRuleError) as error:
        typer.echo(f"yara error: {error}", err=True)
        raise typer.Exit(1) from error
    _echo(
        {
            "ok": True,
            "matches": [
                {"rule": match.rule, "entry": match.entry, "sha256": match.sha256}
                for match in matches
            ],
        }
    )


@app.command()
def inspect(
    apk: Path = typer.Option(..., "--apk", exists=True, dir_okay=False, readable=True),
    sdk_root: Path | None = typer.Option(None, "--sdk-root"),
    build_tools: str | None = typer.Option(None, "--build-tools"),
) -> None:
    """Print S0 and S1 output without writing artifacts."""
    tools = _discover(sdk_root, build_tools)
    intake = run_intake(
        apk,
        build_id="inspect",
        profile="basic",
        signing_mode="customer_local",
        tools=tools,
        allow_unsigned=True,
    )
    inventory = run_inventory(apk, tools=tools)
    _echo(
        {
            "intake": intake.model_dump(mode="json", by_alias=True),
            "inventory": inventory.model_dump(mode="json", by_alias=True),
        }
    )


if __name__ == "__main__":
    app()
