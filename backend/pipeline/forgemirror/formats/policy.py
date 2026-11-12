"""SPK1 policy package codec (build side)."""

from __future__ import annotations

import json
import os
import struct
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"SPK1"
VERSION = 1
CIPHER_AES_256_GCM = 1
TAG_SIZE = 16
SIGNATURE_SIZE = 64
MAX_PLAINTEXT = 1 << 20
MAX_RULES = 1024
LABEL = b"FM/policy/v1"

_HEADER = struct.Struct("<4sHBB12sI")
assert _HEADER.size == 24


class PolicyError(Exception):
    """Raised when a policy package is malformed or fails authentication."""


def _derive(k_content: bytes, build_id: bytes) -> bytes:
    if len(k_content) != 32 or len(build_id) != 16:
        raise ValueError("k_content must be 32 bytes and build_id 16 bytes")
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=build_id, info=LABEL
    ).derive(k_content)


def _validate(policy: dict[str, Any]) -> None:
    if policy.get("schema") != "forgemirror.policy/1":
        raise ValueError("unsupported policy schema")
    version = policy.get("version")
    if not isinstance(version, int) or version < 1:
        raise ValueError("version must be a positive integer")
    if not isinstance(policy.get("min_shell_version"), str):
        raise ValueError("min_shell_version must be a string")
    for field in ("rules", "excludes"):
        items = policy.get(field)
        if not isinstance(items, list) or len(items) > MAX_RULES:
            raise ValueError(f"{field} must be a list of at most {MAX_RULES} items")
        for item in items:
            if not isinstance(item, dict):
                raise ValueError(f"{field} item must be an object")
            pattern = item.get("pattern")
            if not isinstance(pattern, str) or not 1 <= len(pattern) <= 512:
                raise ValueError("pattern must be 1..512 characters")
            if field == "rules" and item.get("action") != "encrypt":
                raise ValueError("v1 only supports action=encrypt")


def pack_policy(
    policy: dict[str, Any],
    *,
    k_content: bytes,
    build_id: bytes,
    private_key: Ed25519PrivateKey,
) -> bytes:
    _validate(policy)
    plaintext = json.dumps(
        policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    if len(plaintext) > MAX_PLAINTEXT:
        raise ValueError("policy plaintext too large")

    nonce = os.urandom(12)
    header = _HEADER.pack(MAGIC, VERSION, CIPHER_AES_256_GCM, 0, nonce, len(plaintext))
    key = _derive(k_content, build_id)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header)
    signature = private_key.sign(header + ciphertext)
    return header + ciphertext + signature


def open_policy(
    blob: bytes,
    *,
    k_content: bytes,
    build_id: bytes,
    public_key: Ed25519PublicKey,
) -> dict[str, Any]:
    minimum = _HEADER.size + TAG_SIZE + SIGNATURE_SIZE
    if len(blob) < minimum:
        raise PolicyError("policy package too short")

    magic, version, cipher, reserved, nonce, plaintext_len = _HEADER.unpack_from(blob, 0)
    if magic != MAGIC or version != VERSION or cipher != CIPHER_AES_256_GCM or reserved != 0:
        raise PolicyError("bad policy header")
    if plaintext_len > MAX_PLAINTEXT:
        raise PolicyError("policy plaintext too large")
    if len(blob) != _HEADER.size + plaintext_len + TAG_SIZE + SIGNATURE_SIZE:
        raise PolicyError("policy length mismatch")

    body = blob[:-SIGNATURE_SIZE]
    signature = blob[-SIGNATURE_SIZE:]
    try:
        public_key.verify(signature, body)
    except InvalidSignature as exc:
        raise PolicyError("policy signature invalid") from exc

    try:
        plaintext = AESGCM(_derive(k_content, build_id)).decrypt(
            nonce, blob[_HEADER.size:-SIGNATURE_SIZE], blob[:_HEADER.size]
        )
    except InvalidTag as exc:
        raise PolicyError("policy authentication failed") from exc

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PolicyError(f"duplicate policy key: {key}")
            result[key] = value
        return result

    try:
        policy = json.loads(plaintext.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError("policy JSON invalid") from exc
    if not isinstance(policy, dict):
        raise PolicyError("policy JSON must be an object")
    try:
        _validate(policy)
    except ValueError as exc:
        raise PolicyError(str(exc)) from exc
    return policy
