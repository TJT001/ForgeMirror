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
