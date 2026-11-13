"""Command line entry points for the build pipeline."""

from __future__ import annotations

import json
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
) -> None:
    """Run S0 -> S1 -> S2 and write the build artifacts."""
    if profile not in PROFILES:
        typer.echo(f"invalid profile: {profile}", err=True)
        raise typer.Exit(2)
    if signing_mode not in SIGNING_MODES:
        typer.echo(f"invalid signing mode: {signing_mode}", err=True)
        raise typer.Exit(2)

    tools = _discover(sdk_root, build_tools)
    result = run_build(
        BuildOptions(
            apk=apk,
            out=out,
            profile=profile,
            signing_mode=signing_mode,
            build_id=build_id,
            cert_allowlist=_load_allowlist(cert_allowlist),
            allow_unsigned=allow_unsigned,
            shell_version=shell_version,
            key_file=key_file,
        ),
        tools,
    )
    _echo(result)
    if not result["ok"]:
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
    key_dir: Path = typer.Option(Path("artifacts/keys"), "--key-dir"),
    alg: str = typer.Option("ecdsa-p256-sha256", "--alg"),
    shell_version: str = typer.Option("0.1.0", "--shell-version"),
    sdk_root: Path | None = typer.Option(None, "--sdk-root"),
    build_tools: str | None = typer.Option(None, "--build-tools"),
) -> None:
    """Run S0-S2, rewrite the manifest (S6), align/sign (S7), and gate (S8)."""
    if profile not in PROFILES:
        typer.echo(f"invalid profile: {profile}", err=True)
        raise typer.Exit(2)
    if signing_mode not in SIGNING_MODES:
        typer.echo(f"invalid signing mode: {signing_mode}", err=True)
        raise typer.Exit(2)

    tools = _discover(sdk_root, build_tools)
    build_result = run_build(
        BuildOptions(
            apk=apk,
            out=out,
            profile=profile,
            signing_mode=signing_mode,
            build_id=build_id,
            shell_version=shell_version,
        ),
        tools,
    )
    if not build_result["ok"]:
        _echo(build_result)
        raise typer.Exit(1)

    work_dir = Path(build_result["out"])
    container = work_dir / "container.fdx"
    key_file = work_dir / "keys" / "k_content.bin"
    result = protect(
        ProtectOptions(
            apk=apk,
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
            alg=alg,
        ),
        tools,
    )
    gate = run_gate(work_dir / "protected.apk", container, key_file.read_bytes())
    (work_dir / "gate.json").write_text(
        json.dumps(gate, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )
    _echo({**result, "gate": gate})
    if not gate["passed"]:
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
) -> None:
    """Inspect SecNeo .edata, classes.dve, or RES_RULE material."""
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
    if edata is None and dve is None and res_rule is None:
        typer.echo("need --edata or --dve", err=True)
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

    source = rules_file.read_text() if rules_file else yara_rules.NINE_RULES
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

    source = rules_file.read_text() if rules_file else yara_rules.NINE_RULES
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
