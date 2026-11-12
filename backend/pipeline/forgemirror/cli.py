"""Command line entry points for the build pipeline."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from .intake import PROFILES, SIGNING_MODES, run_intake
from .inventory import run_inventory
from .pipeline import BuildOptions, run_build
from .tools import AndroidTools, ToolError

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
