"""PKR1 rule package codec (build side)."""

from __future__ import annotations

import json
import os
import struct
from typing import Any

from cryptography.exceptions import InvalidTag

from .policy import SIG_ECDSA_P256_RAW, SIG_ED25519, _sign, _verify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MAGIC = b"PKR1"
VERSION = 1
CIPHER_AES_256_GCM = 1
TAG_SIZE = 16
SIGNATURE_SIZE = 64
MAX_PLAINTEXT = 1 << 20
MAX_RULES = 256
MAX_STRINGS = 32
LABEL = b"FM/rules/v1"
YIDUN_SCHEMA = "forgemirror.yidun-signatures/1"
MAX_YIDUN_VALUES = 1024
MAX_YIDUN_STRING = 256
MAX_YIDUN_DEPTH = 3

_HEADER = struct.Struct("<4sHHBB12sI")
assert _HEADER.size == 26


class RulesError(Exception):
    """Raised when a rule package is malformed or fails authentication."""


def _derive(k_content: bytes, build_id: bytes) -> bytes:
    if len(k_content) != 32 or len(build_id) != 16:
        raise ValueError("k_content must be 32 bytes and build_id 16 bytes")
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=build_id, info=LABEL
    ).derive(k_content)


def _validate(rules: dict[str, Any]) -> None:
    if rules.get("schema") != "forgemirror.rules/1":
        raise ValueError("unsupported rules schema")
    version = rules.get("version")
    if not isinstance(version, int) or version < 1:
        raise ValueError("version must be a positive integer")
    if not isinstance(rules.get("min_shell_version"), str):
        raise ValueError("min_shell_version must be a string")
    items = rules.get("rules")
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_RULES:
        raise ValueError(f"rules must contain 1..{MAX_RULES} items")
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("rule must be an object")
        if not isinstance(item.get("id"), str) or not item["id"]:
            raise ValueError("rule id required")
        if item.get("logic") not in ("all", "any"):
            raise ValueError("rule logic must be all or any")
        strings = item.get("strings")
        if not isinstance(strings, list) or not 1 <= len(strings) <= MAX_STRINGS:
            raise ValueError(f"rule strings must contain 1..{MAX_STRINGS} items")
        if not all(isinstance(value, str) and value for value in strings):
            raise ValueError("rule strings must be non-empty strings")
    yidun = rules.get("yidun")
    if yidun is not None:
        _validate_yidun(yidun)


def _validate_yidun(yidun: Any) -> None:
    if not isinstance(yidun, dict):
        raise ValueError("yidun must be an object")
    if yidun.get("schema") != YIDUN_SCHEMA:
        raise ValueError("unsupported yidun signature schema")
    source = yidun.get("source")
    if not isinstance(source, dict):
        raise ValueError("yidun source required")
    for key in ("vendor", "library", "sample_sha256", "evidence"):
        value = source.get(key)
        if not isinstance(value, str) or not value or len(value) > MAX_YIDUN_STRING:
            raise ValueError(f"yidun source.{key} required")
    digest = source["sample_sha256"].lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError("yidun source.sample_sha256 must be 64 hex chars")
    _validate_yidun_node(yidun, 0)


def _validate_yidun_node(node: Any, depth: int) -> None:
    if depth > MAX_YIDUN_DEPTH:
        raise ValueError("yidun nesting too deep")
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "source":
                continue
            _validate_yidun_node(value, depth + 1)
    elif isinstance(node, list):
        if len(node) > MAX_YIDUN_VALUES:
            raise ValueError("yidun list too large")
        for value in node:
            _validate_yidun_node(value, depth + 1)
    elif isinstance(node, str):
        if not node or len(node) > MAX_YIDUN_STRING:
            raise ValueError("yidun strings must be 1..256 chars")
    elif isinstance(node, bool):
        pass
    else:
        raise ValueError("yidun leaves must be strings or booleans")


def pack_rules(
    rules: dict[str, Any],
    *,
    k_content: bytes,
    build_id: bytes,
    private_key: Any,
    alg: str = "ed25519",
) -> bytes:
    _validate(rules)
    plaintext = json.dumps(
        rules, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    if len(plaintext) > MAX_PLAINTEXT:
        raise ValueError("rules plaintext too large")

    sig_alg = SIG_ED25519 if alg == "ed25519" else SIG_ECDSA_P256_RAW
    nonce = os.urandom(12)
    min_version = 10000  # 1.0.0
    header = _HEADER.pack(
        MAGIC, VERSION, min_version, CIPHER_AES_256_GCM, sig_alg, nonce, len(plaintext)
    )
    ciphertext = AESGCM(_derive(k_content, build_id)).encrypt(
        nonce, plaintext, header
    )
    return header + ciphertext + _sign(private_key, alg, header + ciphertext)


def open_rules(
    blob: bytes,
    *,
    k_content: bytes,
    build_id: bytes,
    public_key: Any,
) -> dict[str, Any]:
    minimum = _HEADER.size + TAG_SIZE + SIGNATURE_SIZE
    if len(blob) < minimum:
        raise RulesError("rule package too short")
    magic, version, min_version, cipher, sig_alg, nonce, plaintext_len = _HEADER.unpack_from(
        blob, 0
    )
    if magic != MAGIC or version != VERSION or cipher != CIPHER_AES_256_GCM:
        raise RulesError("bad rule package header")
    if plaintext_len > MAX_PLAINTEXT:
        raise RulesError("rule plaintext too large")
    if len(blob) != _HEADER.size + plaintext_len + TAG_SIZE + SIGNATURE_SIZE:
        raise RulesError("rule package length mismatch")

    body = blob[:-SIGNATURE_SIZE]
    signature = blob[-SIGNATURE_SIZE:]
    try:
        _verify(public_key, sig_alg, signature, body)
    except Exception as exc:
        raise RulesError("rule signature invalid") from exc

    try:
        plaintext = AESGCM(_derive(k_content, build_id)).decrypt(
            nonce, blob[_HEADER.size:-SIGNATURE_SIZE], blob[:_HEADER.size]
        )
    except InvalidTag as exc:
        raise RulesError("rule authentication failed") from exc

    rules = json.loads(plaintext.decode("utf-8"))
    _validate(rules)
    return rules
