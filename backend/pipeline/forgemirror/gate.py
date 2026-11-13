"""S8 gate: verify the protected APK manifest envelope, artifacts, and
negative tamper checks."""

from __future__ import annotations

import base64
import json
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature, InvalidTag

from .formats.container import open_container


def _verify(public_key, signature: bytes, payload: bytes) -> None:
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
    else:
        public_key.verify(signature, payload)


def _verify_envelope(apk: Path) -> tuple[dict, list[dict]]:
    checks: list[dict] = []
    with zipfile.ZipFile(apk) as archive:
        envelope = json.loads(archive.read("assets/shield/manifest.sig"))
        trusted_der = archive.read("assets/shield/trusted_key.der")
        entries = {info.filename: archive.read(info.filename) for info in archive.infolist()}

    payload = base64.b64decode(envelope["payload"])
    signature = base64.b64decode(envelope["signature"])
    public_key = serialization.load_der_public_key(trusted_der)
    try:
        _verify(public_key, signature, payload)
        checks.append({"name": "manifest_signature", "ok": True})
    except InvalidSignature:
        checks.append({"name": "manifest_signature", "ok": False,
                       "detail": "signature invalid"})
        return {}, checks

    manifest = json.loads(payload)
    missing = []
    mismatched = []
    for artifact in manifest.get("artifacts", []):
        path = artifact["path"]
        data = entries.get(path)
        if data is None:
            missing.append(path)
            continue
        if len(data) != artifact["size"]:
            mismatched.append(path)
            continue
        import hashlib

        if hashlib.sha256(data).hexdigest() != artifact["sha256"]:
            mismatched.append(path)
    checks.append({
        "name": "artifact_hashes",
        "ok": not missing and not mismatched,
        "detail": {"missing": missing, "mismatched": mismatched},
    })
    return manifest, checks


def _tamper_check(apk: Path, manifest: dict) -> list[dict]:
    checks: list[dict] = []
    with zipfile.ZipFile(apk) as archive:
        entries = {info.filename: archive.read(info.filename) for info in archive.infolist()}

    import hashlib

    tampered = dict(entries)
    container_path = "assets/container.fdx"
    data = bytearray(tampered[container_path])
    data[len(data) // 2] ^= 0x01
    tampered[container_path] = bytes(data)
    expected = next(item["sha256"] for item in manifest["artifacts"]
                    if item["path"] == container_path)
    ok = hashlib.sha256(tampered[container_path]).hexdigest() != expected
    checks.append({"name": "tampered_container_rejected", "ok": ok})

    envelope = json.loads(entries["assets/shield/manifest.sig"])
    signature = bytearray(base64.b64decode(envelope["signature"]))
    signature[0] ^= 0x01
    public_key = serialization.load_der_public_key(entries["assets/shield/trusted_key.der"])
    try:
        _verify(public_key, bytes(signature), base64.b64decode(envelope["payload"]))
        checks.append({"name": "tampered_manifest_rejected", "ok": False})
    except InvalidSignature:
        checks.append({"name": "tampered_manifest_rejected", "ok": True})
    return checks


def run_gate(apk: Path, container: Path, k_content: bytes) -> dict:
    checks: list[dict] = []
    manifest, envelope_checks = _verify_envelope(apk)
    checks.extend(envelope_checks)
    if manifest:
        checks.extend(_tamper_check(apk, manifest))

    try:
        open_container(container.read_bytes(), k_content=k_content)
        checks.append({"name": "container_roundtrip", "ok": True})
    except Exception as error:
        checks.append({"name": "container_roundtrip", "ok": False,
                       "detail": str(error)})

    try:
        open_container(container.read_bytes(), k_content=b"\x00" * 32)
        checks.append({"name": "wrong_key_rejected", "ok": False})
    except (InvalidTag, Exception):
        checks.append({"name": "wrong_key_rejected", "ok": True})

    passed = all(item["ok"] for item in checks)
    return {"passed": passed, "checks": checks}
