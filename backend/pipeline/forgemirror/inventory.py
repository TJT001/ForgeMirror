"""S1 inventory: describe the APK without modifying it."""

from __future__ import annotations

from pathlib import Path

from .apk import (
    list_assets,
    list_dex,
    list_libs,
    parse_badging,
    parse_xmltree,
    sha256_file,
)
from .models import Anomaly, Inventory
from .tools import AndroidTools


def run_inventory(
    apk: Path,
    *,
    tools: AndroidTools,
    shell_version: str = "0.1.0",
    policy_version: int = 0,
    rule_version: int = 0,
    splits: list[Path] | None = None,
) -> Inventory:
    apk = Path(apk)
    badging = parse_badging(tools.badging(apk))
    manifest = parse_xmltree(tools.xmltree(apk))
    dex = list_dex(apk)
    libs = list_libs(apk)
    assets = list_assets(apk)
    split_names: list[str] = []
    for split in (Path(item) for item in (splits or [])):
        split_badging = parse_badging(tools.badging(split))
        split_name = split_badging.split or split.stem
        split_names.append(split_name)
        dex.extend(list_dex(split, source=split_name))
        libs.extend(list_libs(split, source=split_name))

    anomalies: list[Anomaly] = []
    for entry in dex:
        if not entry.valid:
            anomalies.append(Anomaly(kind="invalid_dex", detail=entry.name))

    lib_abis = sorted({entry.abi_dir for entry in libs})
    native_abis = sorted(set(badging.native_code))
    if native_abis and lib_abis and set(native_abis) != set(lib_abis):
        anomalies.append(
            Anomaly(
                kind="abi_dir_mismatch",
                detail=f"native-code={native_abis} lib-dirs={lib_abis}",
            )
        )

    for entry in libs:
        expected = "armeabi-v7a" if entry.abi_dir == "armeabi" else entry.abi_dir
        if entry.arch is None:
            anomalies.append(Anomaly(kind="invalid_elf", detail=entry.path))
        elif entry.arch != expected:
            anomalies.append(
                Anomaly(kind="abi_mismatch", detail=f"{entry.path}: {entry.arch}")
            )

    if manifest.application is None:
        anomalies.append(
            Anomaly(kind="missing_application", detail="no android:name on <application>")
        )

    package = badging.package or manifest.package
    if not package:
        raise ValueError("APK manifest has no package name")
    if badging.version_code is None:
        raise ValueError("APK manifest has no versionCode")
    if badging.min_sdk is None:
        raise ValueError("APK manifest has no minSdkVersion")

    return Inventory(
        package=package,
        version_code=badging.version_code,
        version_name=badging.version_name,
        min_sdk=badging.min_sdk,
        target_sdk=badging.target_sdk,
        abis=native_abis or lib_abis,
        dex=dex,
        libs=libs,
        assets=assets,
        application=manifest.application,
        app_component_factory=manifest.app_component_factory,
        components=manifest.counts(),
        providers=manifest.providers,
        anomalies=anomalies,
        fingerprint={
            "package": package,
            "version_code": badging.version_code,
            "shell_version": shell_version,
            "policy_version": policy_version,
            "rule_version": rule_version,
        },
        apk_sha256=sha256_file(apk),
        split_names=split_names,
    )
