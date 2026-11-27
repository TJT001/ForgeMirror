"""Generic S6: turn an arbitrary APK into a protected APK without a custom
build variant. Rewrites the binary manifest, swaps business DEX for the stub,
injects encrypted assets, signs the manifest, aligns, and signs the package.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import tempfile
import uuid
import zipfile
from dataclasses import dataclass, field
from uuid import UUID
from pathlib import Path

from .apk import elf_arch, elf_max_page_size, parse_badging, sha256_file
from .formats import axml
from .formats.elf import ElfError, add_dynamic_decoy
from .formats.selfdecrypt import add_dt_init_lzss
from .formats.container import open_container
from .formats.policy import pack_policy
from .formats.rules import pack_rules
from .formats.ai_decoy import build_decoy_jar, merge_jar
from .formats.whitebox import export_table, generate_table, wrap as wrap_whitebox
from .progress import emit as emit_progress
from .formats.yara_rules import RUNTIME_RULES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .s6 import (
    build_envelope,
    collect_artifacts,
    inject,
    load_or_create_key,
    parse_signer,
    public_der,
    sha256_bytes,
)
from .tools import AndroidTools

DEX_RE = re.compile(r"^classes\d*\.dex$")

YIDUN_SIGNATURE_ASSET = (
    Path(__file__).resolve().parents[3]
    / "android" / "shield" / "src" / "main" / "assets" / "yidun-signatures.json"
)


def _load_yidun_signatures() -> dict:
    try:
        with YIDUN_SIGNATURE_ASSET.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise RuntimeError(
            f"Yidun signature asset missing: {YIDUN_SIGNATURE_ASSET}"
        ) from exc
    if not isinstance(data, dict):
        raise RuntimeError("Yidun signature asset must be a JSON object")
    return data

DEFAULT_POLICY = {
    "schema": "forgemirror.policy/1",
    "version": 1,
    "min_shell_version": "0.1.0",
    "rules": [
        {"pattern": "shared_prefs/*.xml", "action": "encrypt"},
        {"pattern": "files/**/*.txt", "action": "encrypt"},
    ],
    "excludes": [
        {"pattern": "databases/*"},
        {"pattern": "cache/**"},
    ],
}

DEFAULT_RULES = {
    "schema": "forgemirror.rules/1",
    "version": 2,
    "min_shell_version": "0.1.0",
    "yara": RUNTIME_RULES,
    "rules": [
        {
            "id": "demo_jni",
            "logic": "all",
            "strings": ["Java_dev_forgemirror_demo_MainActivity_stringFromJNI"],
        },
        {
            "id": "frida_like",
            "logic": "any",
            "strings": ["frida", "FRIDA"],
        },
    ],
    "yidun": _load_yidun_signatures(),
}


@dataclass
class ProtectOptions:
    apk: Path
    container: Path
    key_file: Path
    out: Path
    build_id: str
    aar: Path
    profile: str = "basic"
    signing_mode: str = "customer_local"
    uber_apk_signer: Path | None = None
    keystore: Path | None = None
    ks_alias: str = "androiddebugkey"
    ks_pass: str | None = None
    key_pass: str | None = None
    auth_url: str = ""
    event_url: str = ""
    event_token: str = "dev-client-token"
    no_key_asset: bool = False
    key_dir: Path = Path("artifacts/keys")
    alg: str = "ecdsa-p256-sha256"
    strip_customer_libs: bool = True
    self_decrypt_core: bool = True
    decoy_dynamic: bool = True
    corrupt_section_names: bool = True
    self_decrypt_text: bool = True
    in_memory_libs: str = ""
    splits: list[Path] = field(default_factory=list)
    detection: bool = True
    response: str = "toast"
    max_native_file_mb: int = 128
    whitebox: bool = False
    whitebox_random_table: bool = True
    ai_decoy: bool = False
    ai_decoy_lexicon: Path | None = None
    progress_file: Path | None = None


def _stub_from_aar(aar: Path, tools: AndroidTools, tmp: Path,
                   ai_decoy: bool = False,
                   lexicon: Path | None = None
                   ) -> tuple[bytes, dict[str, bytes], int]:
    with zipfile.ZipFile(aar) as archive:
        classes_jar = tmp / "classes.jar"
        classes_jar.write_bytes(archive.read("classes.jar"))
        libs: dict[str, bytes] = {}
        for name in archive.namelist():
            if not name.startswith("jni/") or not name.endswith(".so"):
                continue
            parts = name.split("/")
            if len(parts) < 3:
                continue
            libs[f"lib/{parts[1]}/{parts[2]}"] = archive.read(name)
    if not libs:
        raise SystemExit(f"shield AAR has no native libs: {aar}")
    decoy_classes = 0
    if ai_decoy:
        decoy_jar = tmp / "ai-decoy.jar"
        decoy_classes = build_decoy_jar(lexicon, decoy_jar)
        merged = tmp / "classes-decoy.jar"
        merge_jar(classes_jar, decoy_jar, merged)
        classes_jar = merged
    stub = tools.dex_jar(classes_jar, tmp / "stub").read_bytes()
    return stub, libs, decoy_classes


def _rewrite_zip(source: Path, target: Path, entries: dict[str, bytes],
                 drop: set[str] | None = None) -> None:
    dropped = drop or set()
    with zipfile.ZipFile(source) as src, zipfile.ZipFile(
        target, "w", compression=zipfile.ZIP_DEFLATED
    ) as dst:
        for info in src.infolist():
            if DEX_RE.match(info.filename):
                continue
            if info.filename in entries or info.filename in dropped:
                continue
            dst.writestr(info, src.read(info.filename))
        for name, data in entries.items():
            stored = name.startswith("lib/") and name.endswith(".so")
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            dst.writestr(info, data)


def _core_key(k_content: bytes, build_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=UUID(build_id).bytes,
        info=b"FM/core/v1",
    ).derive(k_content)


def _native_key(k_content: bytes, build_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=UUID(build_id).bytes,
        info=b"FM/native/v1",
    ).derive(k_content)


def _encrypt_native(data: bytes, key: bytes) -> bytes:
    magic = b"FMN1"
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, data, magic + nonce)
    return magic + nonce + ciphertext


def _encrypt_core(data: bytes, key: bytes) -> bytes:
    magic = b"FMC1"
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, data, magic + nonce)
    return magic + nonce + ciphertext


def protect(options: ProtectOptions, tools: AndroidTools) -> dict:
    if options.signing_mode not in ("hsm", "customer_local", "uber"):
        raise SystemExit(f"unsupported signing mode: {options.signing_mode}")
    if options.signing_mode == "uber":
        if options.uber_apk_signer is None:
            raise SystemExit("--signing-mode uber requires --uber-apk-signer")
        if not options.uber_apk_signer.is_file():
            raise SystemExit(
                f"uber-apk-signer jar not found: {options.uber_apk_signer}"
            )
        if options.keystore is not None and options.ks_pass is None:
            raise SystemExit("--keystore requires --ks-pass")
    if not options.aar.is_file():
        raise SystemExit(f"shield AAR not found: {options.aar}")
    k_content = options.key_file.read_bytes()
    container = options.container.read_bytes()
    opened = open_container(container, k_content=k_content)
    if not container.startswith(b"FDX2"):
        raise SystemExit("container does not start with FDX2")

    split_names: list[str] = []
    for split in options.splits:
        name = parse_badging(tools.badging(split)).split
        if not name:
            raise SystemExit(f"split APK has no split name: {split}")
        split_names.append(name)
    if len(set(split_names)) != len(split_names):
        raise SystemExit("duplicate split names")

    sources = [options.apk, *options.splits]
    input_abis: set[str] = set()
    alignment_warnings: list[str] = []
    for source in sources:
        with zipfile.ZipFile(source) as archive:
            for info in archive.infolist():
                if not info.filename.startswith("lib/") or not info.filename.endswith(".so"):
                    continue
                parts = info.filename.split("/")
                if len(parts) < 3:
                    continue
                expected = "armeabi-v7a" if parts[1] == "armeabi" else parts[1]
                input_abis.add(expected)
                payload = archive.read(info.filename)
                arch = elf_arch(payload[:20])
                if arch != expected:
                    raise SystemExit(
                        f"ABI mismatch in {info.filename}: ELF {arch} != dir {expected}"
                    )
                if payload[4:5] == b"\x02":
                    align = elf_max_page_size(payload)
                    if align is not None and align < 0x4000:
                        alignment_warnings.append(
                            f"W_16KB_ALIGN: {info.filename} max-page-size=0x{align:x}"
                        )
    with zipfile.ZipFile(options.apk) as archive:
        original_manifest = archive.read("AndroidManifest.xml")
    document = axml.parse(original_manifest)
    package = document.package_name()
    if not package:
        raise SystemExit("APK manifest has no package name")
    original_application, original_factory = document.application_names()
    version_code = document.manifest_version_code() or 0
    raised_min_sdk = document.raise_min_sdk(26)

    cleartext = (options.auth_url.startswith("http://")
                 or options.event_url.startswith("http://"))
    document.rewrite_application(
        "dev.forgemirror.shield.ShieldApplication",
        "dev.forgemirror.shield.ShieldAppComponentFactory",
        cleartext=cleartext,
    )
    document.inject_child("application", "provider", [
        ("name", "dev.forgemirror.shield.ShieldProvider"),
        ("authorities", f"{package}.shield.bootstrap"),
        ("exported", False),
    ])
    document.inject_child("application", "activity", [
        ("name", "dev.forgemirror.shield.ShieldRecoveryActivity"),
        ("exported", False),
    ])
    rewritten_manifest = axml.serialize(document)

    input_cert = tools.cert_sha256(options.apk) or ""
    signer_cert = None
    if options.signing_mode == "hsm":
        signer_cert = tools.debug_signer_sha256()
        cert = signer_cert or input_cert
    elif options.signing_mode == "uber":
        if options.keystore is None:
            cert = tools.debug_signer_sha256() or ""
        else:
            cert = tools.keystore_sha256(
                options.keystore, options.ks_alias, options.ks_pass or ""
            ) or ""
    else:
        cert = ""
    signing_key = load_or_create_key(options.key_dir, options.alg)
    der = public_der(signing_key)
    policy_alg = "ecdsa-p256-sha256-raw" if options.alg == "ecdsa-p256-sha256" else options.alg

    emit_progress(options.progress_file, "s3", "running", 36, "打包策略与规则")
    policy_pkg = pack_policy(
        DEFAULT_POLICY,
        k_content=k_content,
        build_id=uuid.UUID(options.build_id).bytes,
        private_key=signing_key,
        alg=policy_alg,
    )
    rules_pkg = pack_rules(
        DEFAULT_RULES,
        k_content=k_content,
        build_id=uuid.UUID(options.build_id).bytes,
        private_key=signing_key,
        alg=policy_alg,
    )
    emit_progress(options.progress_file, "s3", "done", 45, "策略与规则完成")
    emit_progress(options.progress_file, "s4", "skipped", 45,
                  "S4 授权链不在当前离线保护范围")

    options.out.parent.mkdir(parents=True, exist_ok=True)
    warnings: list[str] = list(alignment_warnings)
    if raised_min_sdk is not None and raised_min_sdk < 26:
        warnings.append(
            f"minSdkVersion raised {raised_min_sdk} -> 26 (in-memory DEX loading)"
        )
    if not cert:
        warnings.append(
            "W_CERT_UNPINNED: signing certificate pin disabled for "
            f"{options.signing_mode}"
        )
    elif options.signing_mode == "hsm" and signer_cert is None:
        warnings.append(
            "W_CERT_FALLBACK: could not read debug keystore; pinning the "
            "input APK certificate"
        )
    emit_progress(options.progress_file, "s5", "running", 46, "native 库处理")
    with tempfile.TemporaryDirectory(prefix="fm-protect-") as tmp:
        tmp = Path(tmp)
        stub_dex, shield_libs, decoy_classes = _stub_from_aar(
            options.aar, tools, tmp, options.ai_decoy, options.ai_decoy_lexicon)
        if decoy_classes:
            warnings.append(
                f"W_AI_DECOY: injected {decoy_classes} unused decoy classes")
        shield_libs = {
            name: data for name, data in shield_libs.items()
            if (("armeabi-v7a" if name.split("/")[1] == "armeabi"
                 else name.split("/")[1]) in input_abis)
        }
        core_libs = {name for name in shield_libs
                     if name.endswith("/libshield_core.so")}
        drop_libs: set[str] = set()
        core_assets: dict[str, bytes] = {}
        if options.self_decrypt_text:
            for name in list(shield_libs):
                base = name.rsplit("/", 1)[-1]
                if base not in ("libshield_boot.so", "libshield_hook.so",
                                "libshield_yara.so"):
                    continue
                try:
                    shield_libs[name], result = add_dt_init_lzss(shield_libs[name])
                    if result.applied:
                        warnings.append(
                            f"self-decrypt text {name}: {result.target_size}B -> "
                            f"{result.payload_size}B"
                        )
                except ElfError as error:
                    warnings.append(f"self-decrypt text skipped for {name}: {error}")
        if options.decoy_dynamic:
            for name in list(shield_libs):
                if "libshield" not in name and "libshadowhook" not in name:
                    continue
                if name.endswith("/libshield_core.so"):
                    continue
                try:
                    shield_libs[name], _ = add_dynamic_decoy(
                        shield_libs[name],
                        corrupt_section_names=options.corrupt_section_names,
                    )
                except ElfError as error:
                    warnings.append(f"dynamic decoy skipped for {name}: {error}")
        if options.self_decrypt_core:
            core_key = _core_key(k_content, options.build_id)
            for name in list(shield_libs):
                if not name.endswith("/libshield_core.so"):
                    continue
                abi = name.split("/")[1]
                core_assets[f"assets/shield/core/{abi}.enc"] = _encrypt_core(
                    shield_libs[name], core_key
                )
                del shield_libs[name]
            drop_libs.update(core_libs)

        stripped_libs: dict[str, bytes] = {}
        split_entries: dict[Path, dict[str, bytes]] = {
            split: {} for split in options.splits
        }
        split_drops: dict[Path, set[str]] = {
            split: set() for split in options.splits
        }
        shield_names = {
            "libshield_boot.so", "libshield_core.so", "libshield_hook.so",
            "libshield_yara.so", "libshield_dummy.so", "libshadowhook.so",
            "libshadowhook_nothing.so",
        }
        for split in options.splits:
            with zipfile.ZipFile(split) as archive:
                for info in archive.infolist():
                    base_name = Path(info.filename).name
                    if base_name in shield_names or base_name.startswith(
                            "libshield_holder_"):
                        split_drops[split].add(info.filename)
        stripped_count = 0
        if options.strip_customer_libs:
            for source in sources:
                target = stripped_libs if source == options.apk else split_entries[source]
                with zipfile.ZipFile(source) as archive:
                    for info in archive.infolist():
                        if not info.filename.startswith("lib/") or not info.filename.endswith(".so"):
                            continue
                        if Path(info.filename).name in shield_names:
                            continue
                        try:
                            target[info.filename] = tools.strip_so(
                                archive.read(info.filename), Path(info.filename).name
                            )
                            stripped_count += 1
                        except Exception as error:
                            warnings.append(f"strip failed for {info.filename}: {error}")

        native_assets: dict[str, bytes] = {}
        selected = {name.strip() for name in options.in_memory_libs.split(",")
                    if name.strip()}
        if selected:
            native_key = _native_key(k_content, options.build_id)
            for source in sources:
                with zipfile.ZipFile(source) as archive:
                    for info in archive.infolist():
                        if not info.filename.startswith("lib/") or not info.filename.endswith(".so"):
                            continue
                        parts = info.filename.split("/")
                        if len(parts) < 3:
                            continue
                        base = parts[-1]
                        if base not in selected:
                            continue
                        data = None
                        if source == options.apk:
                            data = stripped_libs.get(info.filename)
                        else:
                            data = split_entries[source].get(info.filename)
                        if data is None:
                            data = archive.read(info.filename)
                        native_assets[
                            f"assets/shield/native/{parts[1]}/{base}.enc"
                        ] = _encrypt_native(data, native_key)
                        holder = "libshield_holder_" + hashlib.sha256(
                            base.encode("utf-8")).hexdigest()[:16] + ".so"
                        template = f"lib/{parts[1]}/libshield_dummy.so"
                        if template in shield_libs:
                            shield_libs[f"lib/{parts[1]}/{holder}"] = shield_libs[template]
                        if source == options.apk:
                            drop_libs.add(info.filename)
                            stripped_libs.pop(info.filename, None)
                        else:
                            split_drops[source].add(info.filename)
                            split_entries[source].pop(info.filename, None)

        key_asset = "" if options.no_key_asset else "shield/k_content.bin"
        whitebox_entries: dict[str, bytes] = {}
        if options.whitebox and not options.no_key_asset:
            if options.whitebox_random_table:
                with tempfile.TemporaryDirectory(prefix="fm-wbtable-") as temporary:
                    generated = Path(temporary) / "wbaes.generated"
                    generate_table(generated)
                    table = generated.read_bytes()
            else:
                table_path = Path(__file__).with_name("data") / "wbaes.table"
                if not table_path.is_file():
                    raise SystemExit("white-box table missing from pipeline data")
                table = table_path.read_bytes()
            nonce = os.urandom(12)
            whitebox_entries["assets/shield/wbaes.table"] = export_table(table)
            whitebox_entries["assets/shield/k_content.wb"] = wrap_whitebox(
                table, k_content, nonce
            )
            key_asset = "shield/k_content.wb"
            drop_libs.add("assets/wbaes.table")
            warnings.append("W_WHITEBOX: content key wrapped by Chow white-box AES")
        elif options.whitebox:
            warnings.append("W_WHITEBOX_IGNORED: --no-key-asset disables the vault")

        emit_progress(options.progress_file, "s5", "done", 58, "native 库处理完成")
        config = {
            "schema": "forgemirror.shield.config/1",
            "original_application": original_application or "",
            "original_factory": original_factory or "",
            "shell_version": "0.1.0",
            "container": "container.fdx",
            "manifest": "shield/manifest.sig",
            "trusted_key": "shield/trusted_key.der",
            "key": key_asset,
            "policy": "shield/policy.pkg",
            "rules": "shield/rules.pkr",
            "build_id": options.build_id,
            "auth_url": options.auth_url,
            "event_url": options.event_url,
            "event_token": options.event_token,
            "detection": options.detection,
            "response": options.response,
            "rules_version": DEFAULT_RULES["version"],
            "cert_sha256": cert,
            "max_native_file_mb": options.max_native_file_mb,
            "core": "shield/core" if core_assets else "",
            "app_id": package,
            "build_salt": secrets.token_hex(16),
        }
        entries = {
            "AndroidManifest.xml": rewritten_manifest,
            "classes.dex": stub_dex,
            "assets/container.fdx": container,
            "assets/shield/config.json": json.dumps(
                config, indent=2, sort_keys=True
            ).encode("utf-8"),
            "assets/shield/policy.pkg": policy_pkg,
            "assets/shield/rules.pkr": rules_pkg,
            "assets/shield/trusted_key.der": der,
        }
        if not options.no_key_asset and not options.whitebox:
            entries["assets/shield/k_content.bin"] = k_content
        entries.update(whitebox_entries)
        entries.update(stripped_libs)
        entries.update(shield_libs)
        entries.update(core_assets)
        entries.update(native_assets)

        emit_progress(options.progress_file, "s6", "running", 60, "注入与重打包")
        injected = tmp / "injected.apk"
        _rewrite_zip(options.apk, injected, entries, drop_libs)

        split_outputs: list[dict] = []
        split_dir = options.out.with_name(options.out.stem + "_splits")
        if options.splits:
            split_dir.mkdir(parents=True, exist_ok=True)
        used_names: set[str] = set()
        for index, (split, split_name) in enumerate(
                zip(options.splits, split_names)):
            staged = tmp / f"split-{index}.apk"
            _rewrite_zip(split, staged, split_entries[split],
                         split_drops[split])
            target_name = Path(split.name).name
            if target_name in used_names:
                target_name = f"{index}_{target_name}"
            used_names.add(target_name)
            target = split_dir / target_name
            if options.signing_mode == "customer_local":
                tools.align_apk(staged, target)
            else:
                aligned_split = tmp / f"split-{index}-aligned.apk"
                tools.align_apk(staged, aligned_split)
                if options.signing_mode == "uber":
                    tools.sign_uber(
                        aligned_split, target, options.uber_apk_signer,
                        options.keystore, options.ks_alias,
                        options.ks_pass, options.key_pass,
                    )
                else:
                    tools.sign_debug(aligned_split, target)
            split_outputs.append({
                "name": split_name,
                "file": target.name,
                "size": target.stat().st_size,
                "sha256": sha256_file(target),
            })

        emit_progress(options.progress_file, "s6", "done", 74, "重打包完成")
        fixed = {
            "classes.dex",
            "assets/container.fdx",
            "assets/shield/config.json",
            "assets/shield/policy.pkg",
            "assets/shield/rules.pkr",
            "assets/shield/trusted_key.der",
        }
        fixed.update(core_assets)
        fixed.update(native_assets)
        if not options.no_key_asset and not options.whitebox:
            fixed.add("assets/shield/k_content.bin")
        fixed.update(whitebox_entries)
        artifacts = collect_artifacts(injected, fixed, all_libs=True)

        payload = {
            "schema": "forgemirror.manifest/1",
            "build_id": options.build_id,
            "shell_version": "0.1.0",
            "policy_version": 0,
            "rule_version": 0,
            "app": {
                "package": package,
                "version_code": version_code,
                "cert_sha256": cert,
            },
            "artifacts": artifacts,
        }
        if split_outputs:
            payload["splits"] = split_outputs
        envelope = build_envelope(payload, signing_key, options.alg)

        emit_progress(options.progress_file, "s7", "running", 76, "对齐与签名")
        with_manifest = tmp / "manifest.apk"
        inject(injected, with_manifest, {"assets/shield/manifest.sig": envelope})
        if options.signing_mode == "customer_local":
            tools.align_apk(with_manifest, options.out)
            signed = False
        else:
            aligned = tmp / "aligned.apk"
            tools.align_apk(with_manifest, aligned)
            if options.signing_mode == "uber":
                tools.sign_uber(
                    aligned, options.out, options.uber_apk_signer,
                    options.keystore, options.ks_alias,
                    options.ks_pass, options.key_pass,
                )
            else:
                tools.sign_debug(aligned, options.out)
            signed = True
        emit_progress(options.progress_file, "s7", "done", 88,
                      "签名完成" if signed else "对齐完成")

        if split_outputs:
            set_manifest = {
                "schema": "forgemirror.apk-set/1",
                "package": package,
                "version_code": version_code,
                "signing_mode": options.signing_mode,
                "base": {
                    "file": options.out.name,
                    "sha256": sha256_file(options.out),
                },
                "splits": split_outputs,
            }
            options.out.with_name(options.out.name + ".splits.json").write_text(
                json.dumps(set_manifest, indent=2, sort_keys=True,
                           ensure_ascii=False) + "\n"
            )

    signer = parse_signer(tools.verify(options.out)) if signed else None
    meta = {
        "ok": True,
        "apk": str(options.out),
        "package": package,
        "version_code": version_code,
        "original_application": original_application,
        "original_factory": original_factory,
        "dex_count": len(opened.files),
        "container_sha256": sha256_bytes(container),
        "stub_dex_bytes": len(stub_dex),
        "artifact_count": len(artifacts),
        "auth_url": options.auth_url or None,
        "key_embedded": not options.no_key_asset,
        "algorithm": options.alg,
        "signing_mode": options.signing_mode,
        "signed": signed,
        "stripped_libs": stripped_count,
        "whitebox": options.whitebox and not options.no_key_asset,
        "ai_decoy_classes": decoy_classes,
        "key_asset": key_asset,
        "split_count": len(split_outputs),
        "splits": split_outputs,
        "in_memory_libs": sorted(selected) if selected else [],
        "rule_count": len(DEFAULT_RULES["rules"]),
        "warnings": warnings,
        "signer_sha256": signer,
    }
    if signed and signer and cert and signer != cert:
        warnings.append(
            f"W_SIGNER_MISMATCH: config pins {cert}, APK signed by {signer}"
        )
    options.out.with_suffix(".protect.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )
    return meta
