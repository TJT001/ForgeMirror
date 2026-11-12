"""Shared S6 helpers for the P1-B/P1-C demo scripts."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .formats.manifest import canonical_json


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


def collect_artifacts(apk: Path, fixed: set[str]) -> list[dict]:
    with zipfile.ZipFile(apk) as archive:
        names = set(archive.namelist())
        missing = fixed - names
        if missing:
            raise SystemExit(f"missing injected artifacts: {sorted(missing)}")
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


def public_der(key) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def build_envelope(payload: dict, key, algorithm: str, key_id: str = "p1c-dev") -> bytes:
    payload_bytes = canonical_json(payload)
    envelope = {
        "alg": algorithm,
        "key_id": key_id,
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signature": base64.b64encode(sign_payload(key, algorithm, payload_bytes)).decode("ascii"),
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_signer(output: str) -> str | None:
    match = re.search(r"certificate SHA-256 digest:\s*([0-9a-fA-F:]+)", output)
    return match.group(1).replace(":", "").lower() if match else None
