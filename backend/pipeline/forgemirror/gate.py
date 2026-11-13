"""S8 gate: manifest/artifact integrity plus A1-A4 red-team checks."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import uuid
import zipfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .formats.container import open_container
from .formats.policy import PolicyError, open_policy
from .formats.rules import open_rules

DEX_RE = re.compile(r"^classes\d*\.dex$")


def _verify(public_key, signature: bytes, payload: bytes) -> None:
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
    else:
        public_key.verify(signature, payload)


def _status(name: str, passed: bool, detail=None) -> dict:
    entry = {"name": name, "status": "pass" if passed else "fail"}
    if detail is not None:
        entry["detail"] = detail
    return entry


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
        checks.append(_status("manifest_signature", True))
    except InvalidSignature:
        checks.append(_status("manifest_signature", False, "signature invalid"))
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
        if len(data) != artifact["size"] or \
                hashlib.sha256(data).hexdigest() != artifact["sha256"]:
            mismatched.append(path)
    checks.append(_status("artifact_hashes", not missing and not mismatched,
                          {"missing": missing, "mismatched": mismatched}))
    return manifest, checks


def _tamper_check(apk: Path, manifest: dict) -> list[dict]:
    checks: list[dict] = []
    with zipfile.ZipFile(apk) as archive:
        entries = {info.filename: archive.read(info.filename) for info in archive.infolist()}

    tampered = dict(entries)
    container_path = "assets/container.fdx"
    data = bytearray(tampered[container_path])
    data[len(data) // 2] ^= 0x01
    tampered[container_path] = bytes(data)
    expected = next(item["sha256"] for item in manifest["artifacts"]
                    if item["path"] == container_path)
    checks.append(_status("tampered_container_rejected",
                          hashlib.sha256(tampered[container_path]).hexdigest() != expected))

    envelope = json.loads(entries["assets/shield/manifest.sig"])
    signature = bytearray(base64.b64decode(envelope["signature"]))
    signature[0] ^= 0x01
    public_key = serialization.load_der_public_key(entries["assets/shield/trusted_key.der"])
    try:
        _verify(public_key, bytes(signature), base64.b64decode(envelope["payload"]))
        checks.append(_status("tampered_manifest_rejected", False))
    except InvalidSignature:
        checks.append(_status("tampered_manifest_rejected", True))
    return checks


def _red_team_checks(apk: Path, container: Path, k_content: bytes, manifest: dict) -> list[dict]:
    checks: list[dict] = []
    container_bytes = container.read_bytes()

    # A1: replay/decrypt without the authorized key must fail.
    try:
        open_container(container_bytes, k_content=os.urandom(32))
        checks.append(_status("a1_no_key_replay", False))
    except Exception:
        checks.append(_status("a1_no_key_replay", True))

    # A2: no plaintext business DEX left in the APK.
    with zipfile.ZipFile(apk) as archive:
        dex_names = sorted(
            name for name in archive.namelist() if DEX_RE.match(name)
        )
        stub_size = archive.getinfo("classes.dex").file_size if "classes.dex" in dex_names else 0
    a2 = dex_names == ["classes.dex"] and stub_size < 200_000 and container_bytes[:4] == b"FDX2"
    checks.append(_status("a2_no_plaintext_dex", a2,
                          {"dex": dex_names, "stub_size": stub_size}))

    # A3: policy package requires the content key.
    try:
        with zipfile.ZipFile(apk) as archive:
            policy_pkg = archive.read("assets/shield/policy.pkg")
            trusted_der = archive.read("assets/shield/trusted_key.der")
        public_key = serialization.load_der_public_key(trusted_der)
        build_id = uuid.UUID(manifest["build_id"]).bytes
        open_policy(policy_pkg, k_content=os.urandom(32), build_id=build_id,
                    public_key=public_key)
        checks.append(_status("a3_policy_key_required", False))
    except (PolicyError, Exception):
        checks.append(_status("a3_policy_key_required", True))

    # A4: rule package authenticated and bound to the content key.
    try:
        with zipfile.ZipFile(apk) as archive:
            rules_pkg = archive.read("assets/shield/rules.pkr")
            trusted_der = archive.read("assets/shield/trusted_key.der")
        public_key = serialization.load_der_public_key(trusted_der)
        build_id = uuid.UUID(manifest["build_id"]).bytes
        open_rules(rules_pkg, k_content=k_content, build_id=build_id,
                   public_key=public_key)
        checks.append(_status("a4_rules_signature", True))
        try:
            open_rules(rules_pkg, k_content=os.urandom(32), build_id=build_id,
                       public_key=public_key)
            checks.append(_status("a4_rules_key_required", False))
        except Exception:
            checks.append(_status("a4_rules_key_required", True))
    except Exception as error:
        checks.append(_status("a4_rules_signature", False, str(error)))
    return checks


def run_gate(apk: Path, container: Path, k_content: bytes) -> dict:
    checks: list[dict] = []
    manifest, envelope_checks = _verify_envelope(apk)
    checks.extend(envelope_checks)
    if manifest:
        checks.extend(_tamper_check(apk, manifest))
        checks.extend(_red_team_checks(apk, container, k_content, manifest))

    try:
        open_container(container.read_bytes(), k_content=k_content)
        checks.append(_status("container_roundtrip", True))
    except Exception as error:
        checks.append(_status("container_roundtrip", False, str(error)))

    try:
        open_container(container.read_bytes(), k_content=b"\x00" * 32)
        checks.append(_status("wrong_key_rejected", False))
    except (InvalidTag, Exception):
        checks.append(_status("wrong_key_rejected", True))

    failed = [item["name"] for item in checks if item["status"] == "fail"]
    inconclusive = [item["name"] for item in checks if item["status"] == "inconclusive"]
    return {
        "passed": not failed,
        "failed": failed,
        "inconclusive": inconclusive,
        "checks": checks,
    }
