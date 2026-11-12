#!/usr/bin/env python3
"""P1-B minimal S6 demo: inject protected assets, sign a manifest, align, and sign.

This operates on the Gradle `shielded` variant. General binary AXML rewriting of
arbitrary APKs remains a separate S6 task.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend" / "pipeline"))

from forgemirror.apk import parse_badging  # noqa: E402
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

FIXED_ARTIFACTS = {
    "assets/container.fdx",
    "assets/shield/config.json",
    "assets/shield/trusted_key.der",
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True, help="Gradle shielded APK")
    parser.add_argument("--container", type=Path, required=True, help="P1-A container.fdx")
    parser.add_argument("--out", type=Path, required=True, help="final signed APK")
    parser.add_argument("--build-id", default=str(uuid.uuid4()))
    parser.add_argument("--shell-version", default="0.1.0")
    parser.add_argument(
        "--alg",
        default="ecdsa-p256-sha256",
        choices=("ecdsa-p256-sha256", "ed25519"),
        help="P1-B default ECDSA P-256; Ed25519 is the P2 native target",
    )
    parser.add_argument("--key-dir", type=Path, default=Path("artifacts/keys"))
    parser.add_argument("--sdk-root", type=Path, default=None)
    parser.add_argument("--build-tools", default=None)
    args = parser.parse_args()

    tools = AndroidTools.discover(args.sdk_root, args.build_tools)
    badging = parse_badging(tools.badging(args.apk))
    if not badging.package or badging.version_code is None:
        raise SystemExit("cannot read package/versionCode from shielded APK")
    cert = tools.cert_sha256(args.apk)
    if cert is None:
        raise SystemExit("shielded APK is not signed; certificate required")
    container = args.container.read_bytes()
    if not container.startswith(b"FDX2"):
        raise SystemExit("container does not start with FDX2")

    key = load_or_create_key(args.key_dir, args.alg)
    der = public_der(key)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fm-s6-") as tmp:
        tmp = Path(tmp)
        injected = tmp / "injected.apk"
        inject(
            args.apk,
            injected,
            {
                "assets/container.fdx": container,
                "assets/shield/trusted_key.der": der,
            },
        )

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
            "artifacts": collect_artifacts(injected, FIXED_ARTIFACTS),
        }
        manifest_json = build_envelope(payload, key, args.alg)

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
                "container": str(args.container),
                "container_sha256": sha256_bytes(container),
                "artifact_count": len(payload["artifacts"]),
                "build_id": args.build_id,
                "package": badging.package,
                "version_code": badging.version_code,
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
