"""Command line entry points for the build pipeline."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from .intake import PROFILES, SIGNING_MODES, run_intake
from .inventory import run_inventory
from .gate import run_gate
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
