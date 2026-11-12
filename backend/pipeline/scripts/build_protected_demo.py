#!/usr/bin/env python3
"""P1-C protected demo: stub-only APK + encrypted container DEX.

Removes business DEX from the APK, adds a stub-only classes.dex, injects the
container/key/manifest, then aligns and signs. The stub decrypts the container
into memory and loads business classes with InMemoryDexClassLoader.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import uuid
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend" / "pipeline"))

from forgemirror.apk import parse_badging  # noqa: E402
from forgemirror.formats.container import FileSpec, open_container, write_container  # noqa: E402
from forgemirror.s6 import (  # noqa: E402
    build_envelope,
    collect_artifacts,
    inject,
    load_or_create_key,
    parse_signer,
    public_der,
    sha256_bytes,
)
from forgemirror.tools import AndroidTools  # noqa: E402

DEX_RE = re.compile(r"^classes\d*\.dex$")


def build_without_dex(
    source: Path, target: Path, entries: dict[str, bytes], keep_dex: bool = False
) -> None:
    replace = set(entries)
    with zipfile.ZipFile(source) as src, zipfile.ZipFile(
        target, "w", compression=zipfile.ZIP_DEFLATED
    ) as dst:
        for info in src.infolist():
            if info.filename in replace:
                continue
            if not keep_dex and DEX_RE.match(info.filename):
                continue
            dst.writestr(info, src.read(info.filename))
        for name, data in entries.items():
            dst.writestr(name, data)


def extract_classes_jar(aar: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(aar) as archive:
        data = archive.read("classes.jar")
    path = out_dir / "classes.jar"
    path.write_bytes(data)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True, help="Gradle shielded APK")
    parser.add_argument("--container", type=Path, required=True, help="P1-A container.fdx")
    parser.add_argument("--key-file", type=Path, required=True, help="P1-A k_content.bin")
    parser.add_argument(
        "--aar",
        type=Path,
        default=ROOT / "android/shield/build/outputs/aar/shield-debug.aar",
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--build-id", default=str(uuid.uuid4()))
    parser.add_argument("--shell-version", default="0.1.0")
    parser.add_argument(
        "--alg",
        default="ecdsa-p256-sha256",
        choices=("ecdsa-p256-sha256", "ed25519"),
    )
    parser.add_argument("--key-dir", type=Path, default=Path("artifacts/keys"))
    parser.add_argument(
        "--extra-dex",
        type=Path,
        action="append",
        default=[],
        help="additional DEX file to append to the container (repeatable)",
    )
    parser.add_argument("--sdk-root", type=Path, default=None)
    parser.add_argument("--build-tools", default=None)
    args = parser.parse_args()

    tools = AndroidTools.discover(args.sdk_root, args.build_tools)
    if not args.aar.is_file():
        raise SystemExit(f"shield AAR not found: {args.aar} (run :shield:assembleDebug)")
    badging = parse_badging(tools.badging(args.apk))
    if not badging.package or badging.version_code is None:
        raise SystemExit("cannot read package/versionCode from shielded APK")
    cert = tools.cert_sha256(args.apk)
    if cert is None:
        raise SystemExit("shielded APK is not signed; certificate required")

    k_content = args.key_file.read_bytes()
    container = args.container.read_bytes()
    opened = open_container(container, k_content=k_content)
    if not container.startswith(b"FDX2"):
        raise SystemExit("container does not start with FDX2")

    import hashlib
    import struct

    with zipfile.ZipFile(args.apk) as archive:
        base_specs = [
            FileSpec(
                name=info.filename,
                data=archive.read(info.filename),
            )
            for info in archive.infolist()
            if DEX_RE.match(info.filename) and not info.is_dir()
        ]
    extra_specs = [
        FileSpec(name=f"stress{index}.dex", data=path.read_bytes())
        for index, path in enumerate(args.extra_dex, start=1)
    ]
    if extra_specs:
        build_id_bytes = struct.pack(
            ">QQ",
            int(args.build_id.replace("-", "")[:16], 16),
            int(args.build_id.replace("-", "")[16:], 16),
        )
        reused_prefix = opened.header.nonce_prefix
        container = write_container(
            base_specs + extra_specs,
            k_content=k_content,
            build_id=build_id_bytes,
            nonce_prefix=reused_prefix,
        )
        opened = open_container(container, k_content=k_content)

    signing_key = load_or_create_key(args.key_dir, args.alg)
    der = public_der(signing_key)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fm-p1c-") as tmp:
        tmp = Path(tmp)
        classes_jar = extract_classes_jar(args.aar, tmp / "aar")
        stub_dex = tools.dex_jar(classes_jar, tmp / "stub").read_bytes()

        with zipfile.ZipFile(args.apk) as archive:
            config = json.loads(archive.read("assets/shield/config.json"))
        config["container"] = "container.fdx"
        config["key"] = "shield/k_content.bin"

        injected = tmp / "injected.apk"
        build_without_dex(
            args.apk,
            injected,
            {
                "classes.dex": stub_dex,
                "assets/container.fdx": container,
                "assets/shield/config.json": json.dumps(
                    config, indent=2, sort_keys=True
                ).encode("utf-8"),
                "assets/shield/k_content.bin": k_content,
                "assets/shield/trusted_key.der": der,
            },
        )

        fixed = {
            "classes.dex",
            "assets/container.fdx",
            "assets/shield/config.json",
            "assets/shield/k_content.bin",
            "assets/shield/trusted_key.der",
        }
        payload = {
            "schema": "forgemirror.manifest/1",
            "build_id": args.build_id,
            "shell_version": args.shell_version,
            "policy_version": 0,
            "rule_version": 0,
            "app": {
                "package": badging.package,
                "version_code": badging.version_code,
                "cert_sha256": cert,
            },
            "artifacts": collect_artifacts(injected, fixed),
        }
        manifest_json = build_envelope(payload, signing_key, args.alg)

        with_manifest = tmp / "manifest.apk"
        inject(injected, with_manifest, {"assets/shield/manifest.sig": manifest_json})
        aligned = tmp / "aligned.apk"
        tools.align_apk(with_manifest, aligned)
        tools.sign_debug(aligned, args.out)

    verify_output = tools.verify(args.out)
    payload_path = args.out.with_suffix(".manifest.json")
    payload_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )
    print(
        json.dumps(
            {
                "ok": True,
                "apk": str(args.out),
                "package": badging.package,
                "version_code": badging.version_code,
                "dex_count": len(opened.files),
                "container_sha256": sha256_bytes(container),
                "stub_dex_bytes": len(stub_dex),
                "artifact_count": len(payload["artifacts"]),
                "algorithm": args.alg,
                "signer_sha256": parse_signer(verify_output),
                "manifest": str(payload_path),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
