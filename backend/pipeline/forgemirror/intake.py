"""S0 intake: validate the APK before any transformation."""

from __future__ import annotations

from pathlib import Path

from . import errors
from .apk import (
    hardened_markers,
    is_zip,
    list_dex,
    list_libs,
    parse_badging,
    parse_xmltree,
    sha256_file,
)
from .models import IntakeResult
from .tools import AndroidTools, ToolError

MIN_SDK = 26
PROFILES = ("basic", "enhanced", "financial")
SIGNING_MODES = ("hsm", "customer_local")


def run_intake(
    apk: Path,
    *,
    build_id: str,
    profile: str,
    signing_mode: str,
    tools: AndroidTools,
    cert_allowlist: set[str] | None = None,
    allow_unsigned: bool = False,
) -> IntakeResult:
    apk = Path(apk)
    result = IntakeResult(
        ok=False,
        build_id=build_id,
        profile=profile,
        signing_mode=signing_mode,
        apk=str(apk),
    )

    if profile not in PROFILES:
        result.reason_codes.append(errors.E_BAD_PROFILE)
    if signing_mode not in SIGNING_MODES:
        result.reason_codes.append(errors.E_BAD_SIGNING_MODE)
    if not apk.is_file():
        result.reason_codes.append(errors.E_APK_UNREADABLE)
        return result
    if not is_zip(apk):
        result.reason_codes.append(errors.E_APK_NOT_ZIP)
        return result

    try:
        result.apk_sha256 = sha256_file(apk)
        badging = parse_badging(tools.badging(apk))
        xmltree = tools.xmltree(apk)
        manifest = parse_xmltree(xmltree)
        cert_sha256 = tools.cert_sha256(apk)
        result.tool_versions = tools.tool_versions()
    except ToolError:
        result.reason_codes.append(errors.E_APK_UNREADABLE)
        return result

    result.package = badging.package or manifest.package
    result.version_code = badging.version_code
    result.version_name = badging.version_name
    result.min_sdk = badging.min_sdk
    result.target_sdk = badging.target_sdk
    result.cert_sha256 = cert_sha256
    result.application = manifest.application
    result.app_component_factory = manifest.app_component_factory

    libs = list_libs(apk)
    result.abis = badging.native_code or sorted({entry.abi_dir for entry in libs})

    if result.min_sdk is None:
        result.reason_codes.append(errors.E_MANIFEST_UNREADABLE)
    elif result.min_sdk < MIN_SDK:
        # The shell loads DEX in memory (API 26+) and raises the manifest
        # minSdkVersion during S6; keep the intake as a warning.
        result.warnings.append(errors.W_MIN_SDK_RAISED)

    markers = hardened_markers(apk, xmltree)
    if markers:
        result.reason_codes.append(errors.E_ALREADY_HARDENED)

    dex = list_dex(apk)
    if not dex:
        result.reason_codes.append(errors.E_NO_DEX)
    elif not any(entry.valid for entry in dex):
        result.reason_codes.append(errors.E_NO_DEX)

    if cert_sha256 is None:
        if signing_mode == "customer_local" or allow_unsigned:
            result.warnings.append(errors.W_UNSIGNED)
        else:
            result.reason_codes.append(errors.E_CERT_MISSING)
    elif cert_allowlist is not None and cert_sha256 not in cert_allowlist:
        result.reason_codes.append(errors.E_CERT_NOT_ALLOWED)

    result.ok = not result.reason_codes
    return result
