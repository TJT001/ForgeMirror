#!/usr/bin/env python3
"""P1-B minimal S6 demo: inject protected assets, sign a manifest, align, and sign.

This operates on the Gradle `shielded` variant. General binary AXML rewriting of
arbitrary APKs remains a separate S6 task.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import uuid
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend" / "pipeline"))

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from forgemirror.apk import parse_badging  # noqa: E402
from forgemirror.formats.manifest import canonical_json  # noqa: E402
from forgemirror.tools import AndroidTools  # noqa: E402


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inject(source: Path, target: Path, entries: dict[str, bytes]) -> None:
    replace = set(entries)
    with zipfile.ZipFile(source) as src, zipfile.ZipFile(
        target, "w", compression=zipfile.ZIP_DEFLATED
    ) as dst:
        for info in src.infolist():
            if info.filename in replace:
                continue
            dst.writestr(info, src.read(info.filename))
        for name, data in entries.items():
            dst.writestr(name, data)


def collect_artifacts(apk: Path) -> list[dict]:
    fixed = {
        "assets/container.fdx",
        "assets/shield/config.json",
        "assets/shield/trusted_key.der",
    }
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        missing = fixed - set(names)
        if missing:
            raise SystemExit(f"missing injected assets: {sorted(missing)}")
        libs = {
            name
            for name in names
            if name.startswith("lib/")
            and (name.endswith("/libshield_boot.so") or name.endswith("/libshield_core.so"))
        }
        artifacts = []
        for path in sorted(fixed | libs):
            info = archive.getinfo(path)
            artifacts.append(
                {
                    "path": path,
                    "size": info.file_size,
                    "sha256": sha256_bytes(archive.read(path)),
                }
            )
    return artifacts


def load_or_create_key(key_dir: Path, algorithm: str):
    key_dir.mkdir(parents=True, exist_ok=True)
    if algorithm == "ed25519":
        path = key_dir / "ed25519_private.pem"
        if path.is_file():
            return serialization.load_pem_private_key(path.read_bytes(), password=None)
        key = Ed25519PrivateKey.generate()
    else:
        path = key_dir / "ecdsa_private.pem"
        if path.is_file():
            return serialization.load_pem_private_key(path.read_bytes(), password=None)
        key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    os.chmod(path, 0o600)
    return key


def sign_payload(key, algorithm: str, payload: bytes) -> bytes:
    if algorithm == "ed25519":
        return key.sign(payload)
    return key.sign(payload, ec.ECDSA(hashes.SHA256()))


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
    public_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fm-s6-") as tmp:
        tmp = Path(tmp)
        injected = tmp / "injected.apk"
        inject(
            args.apk,
            injected,
            {
                "assets/container.fdx": container,
                "assets/shield/trusted_key.der": public_der,
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
            "artifacts": collect_artifacts(injected),
        }
        payload_bytes = canonical_json(payload)
        envelope = {
            "alg": args.alg,
            "key_id": "p1b-dev",
            "payload": base64.b64encode(payload_bytes).decode("ascii"),
            "signature": base64.b64encode(
                sign_payload(key, args.alg, payload_bytes)
            ).decode("ascii"),
        }
        manifest_json = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")

        with_manifest = tmp / "manifest.apk"
        inject(injected, with_manifest, {"assets/shield/manifest.sig": manifest_json})
        aligned = tmp / "aligned.apk"
        tools.align_apk(with_manifest, aligned)
        tools.sign_debug(aligned, args.out)

    verify_output = tools.verify(args.out)
    signer = re.search(r"certificate SHA-256 digest:\s*([0-9a-fA-F:]+)", verify_output)
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
                "signer_sha256": (signer.group(1).replace(":", "").lower() if signer else None),
                "manifest": str(payload_path),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
