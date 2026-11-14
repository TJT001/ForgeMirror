"""Parser for the reference shell's INFO- rule container."""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

MAGIC = b"INFO-"
HEADER_SIZE = 0x16
MAX_SECTIONS = 16
RECORD_SIZE = 12


class InfoYError(Exception):
    pass


@dataclass
class InfoSection:
    index: int
    offset: int
    flags: int
    size: int


@dataclass
class InfoY:
    digest: bytes
    count: int
    sections: list[InfoSection]
    strings: list[str]
    body: bytes


def parse(data: bytes) -> InfoY:
    if len(data) < HEADER_SIZE:
        raise InfoYError("INFO file too short")
    if data[:5] != MAGIC:
        raise InfoYError("bad INFO magic")
    digest = data[5:21]
    count = data[0x15]
    if count > MAX_SECTIONS:
        raise InfoYError("too many INFO sections")
    table_end = HEADER_SIZE + count * RECORD_SIZE
    if table_end > len(data):
        raise InfoYError("truncated INFO section table")
    sections: list[InfoSection] = []
    for index in range(count):
        offset, flags, size = struct.unpack_from(
            "<III", data, HEADER_SIZE + index * RECORD_SIZE)
        if offset > len(data) or size > len(data) - offset:
            raise InfoYError("INFO section out of range")
        sections.append(InfoSection(index, offset, flags, size))
    body = data[HEADER_SIZE:]
    if hashlib.md5(body).digest() != digest:
        raise InfoYError("INFO digest mismatch")
    strings: list[str] = []
    seen = set()
    for section in sections:
        blob = data[section.offset:section.offset + section.size]
        for value in blob.split(b"\x00"):
            if len(value) < 2 or len(value) > 256:
                continue
            if all(0x20 <= byte < 0x7f for byte in value):
                text = value.decode("ascii")
                if text not in seen:
                    seen.add(text)
                    strings.append(text)
    return InfoY(digest, count, sections, strings, body)
