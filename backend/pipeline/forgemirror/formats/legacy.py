"""Inspection helpers for SecNeo DVE legacy metadata."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class EData:
    enc_type: int
    rules: list[str]
    excludes: list[str]


@dataclass
class DveStamp:
    md5: str
    ctime: int


def parse_edata(text: str) -> EData:
    enc_type = 0
    rules: list[str] = []
    excludes: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("enc_type/"):
            enc_type = int(line.split("/", 1)[1])
        elif line.startswith("!"):
            excludes.append(line[1:])
        else:
            rules.append(line)
    return EData(enc_type=enc_type, rules=rules, excludes=excludes)


def parse_classes_dve(blob: bytes) -> DveStamp:
    if len(blob) < 24:
        raise ValueError("classes.dve must be at least 24 bytes")
    digest = blob[:16].hex()
    ctime = int.from_bytes(blob[16:24], "little", signed=True)
    return DveStamp(md5=digest, ctime=ctime)


def edata_to_policy(edata: EData) -> dict:
    return {
        "schema": "forgemirror.policy/1",
        "version": 1,
        "min_shell_version": "0.1.0",
        "rules": [{"pattern": pattern, "action": "encrypt"}
                  for pattern in edata.rules],
        "excludes": [{"pattern": pattern} for pattern in edata.excludes],
    }


def decode_res_rule(blob: bytes, key: bytes = b"KEY_RES_ENC") -> dict:
    """Best-effort decode of SecNeo RES_RULE (repeating-key XOR).

    The asset embeds an in-memory struct; offsets that look like pointers are
    reported as-is, while length/count/rules are extracted when they fit.
    """
    if not blob or not key:
        raise ValueError("RES_RULE data and key required")
    plain = bytes(value ^ key[index % len(key)]
                  for index, value in enumerate(blob))
    result: dict = {"decrypted_bytes": len(plain), "prefix": plain[:16].hex()}
    if len(plain) >= 0x20:
        length = int.from_bytes(plain[0x0C:0x10], "little")
        buffer_offset = int.from_bytes(plain[0x10:0x14], "little")
        flags = int.from_bytes(plain[0x18:0x1C], "little")
        count = int.from_bytes(plain[0x1C:0x20], "little")
        result.update({
            "length": length,
            "buffer_offset": buffer_offset,
            "flags": flags,
            "count": count,
        })
        end = 0x20 + length
        if 0 < length <= len(plain) - 0x20:
            rules = plain[0x20:end]
            result["rules"] = rules.rstrip(b"\x00").decode("utf-8", "replace")
    return result
