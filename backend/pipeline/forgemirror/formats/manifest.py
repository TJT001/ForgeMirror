"""Manifest signing and verification (P0 subset of manifest v1)."""

from __future__ import annotations

import base64
import json
import re
import uuid
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SCHEMA = "forgemirror.manifest/1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_ARTIFACTS = 4096


class ManifestError(Exception):
    """Raised when a manifest is malformed or fails verification."""


def canonical_json(value: Any) -> bytes:
    """Deterministic JSON subset used for P0; replace with RFC 8785 JCS later."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _validate_path(path: str) -> None:
    if not path or path.startswith("/") or "\\" in path:
        raise ValueError(f"invalid artifact path: {path!r}")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"invalid artifact path: {path!r}")


def validate_manifest(document: dict[str, Any]) -> None:
    if document.get("schema") != SCHEMA:
        raise ValueError("unsupported manifest schema")
    try:
        uuid.UUID(str(document.get("build_id")))
    except ValueError as exc:
        raise ValueError("build_id must be a UUID") from exc

    for field in ("shell_version", "policy_version", "rule_version"):
        if field not in document:
            raise ValueError(f"missing {field}")
    if not isinstance(document["policy_version"], int) or document["policy_version"] < 1:
        raise ValueError("policy_version must be a positive integer")
    if not isinstance(document["rule_version"], int) or document["rule_version"] < 0:
        raise ValueError("rule_version must be a non-negative integer")
    if not isinstance(document["shell_version"], str) or not document["shell_version"]:
        raise ValueError("shell_version must be a non-empty string")

    app = document.get("app")
    if not isinstance(app, dict):
        raise ValueError("app must be an object")
    if not isinstance(app.get("package"), str) or not app["package"]:
        raise ValueError("app.package must be a non-empty string")
    if not isinstance(app.get("version_code"), int) or app["version_code"] < 1:
        raise ValueError("app.version_code must be a positive integer")
    if not isinstance(app.get("cert_sha256"), str) or not _HEX64.match(app["cert_sha256"]):
        raise ValueError("app.cert_sha256 must be 64 lowercase hex characters")

    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= _MAX_ARTIFACTS:
        raise ValueError(f"artifacts must contain 1..{_MAX_ARTIFACTS} items")
    paths: list[str] = []
    for item in artifacts:
        if not isinstance(item, dict):
            raise ValueError("artifact must be an object")
        path = item.get("path")
        if not isinstance(path, str):
            raise ValueError("artifact.path must be a string")
        _validate_path(path)
        if not isinstance(item.get("size"), int) or item["size"] < 0:
            raise ValueError("artifact.size must be a non-negative integer")
        digest = item.get("sha256")
        if not isinstance(digest, str) or not _HEX64.match(digest):
            raise ValueError("artifact.sha256 must be 64 lowercase hex characters")
        paths.append(path)
    if paths != sorted(paths):
        raise ValueError("artifacts must be sorted by path")


def sign_manifest(
    document: dict[str, Any],
    *,
    private_key: Ed25519PrivateKey,
    key_id: str,
) -> dict[str, Any]:
    validate_manifest(document)
    unsigned = {key: value for key, value in document.items() if key != "signature"}
    signature = private_key.sign(canonical_json(unsigned))
    signed = dict(unsigned)
    signed["signature"] = {
        "alg": "ed25519",
        "key_id": key_id,
        "value": base64.b64encode(signature).decode("ascii"),
    }
    return signed


def verify_manifest(
    document: dict[str, Any], *, public_key: Ed25519PublicKey
) -> dict[str, Any]:
    validate_manifest(document)
    signature = document.get("signature")
    if not isinstance(signature, dict) or signature.get("alg") != "ed25519":
        raise ManifestError("missing or unsupported signature")
    value = signature.get("value")
    if not isinstance(value, str):
        raise ManifestError("signature.value must be base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ManifestError("signature.value is not valid base64") from exc

    unsigned = {key: value for key, value in document.items() if key != "signature"}
    try:
        public_key.verify(raw, canonical_json(unsigned))
    except InvalidSignature as exc:
        raise ManifestError("manifest signature invalid") from exc
    return unsigned
