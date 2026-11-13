"""ELF dynamic-table decoy post-processing.

The linker locates PT_DYNAMIC by p_vaddr (load bias + virtual address), while
many static tools read it by p_offset. We append a decoy table containing only
NEEDED/SONAME/STRTAB/STRSZ, point p_offset at it, and leave p_vaddr on the real
table.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

ELF_MAGIC = b"\x7fELF"
PT_DYNAMIC = 2
DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_STRSZ = 10
DT_SONAME = 14


class ElfError(Exception):
    pass


@dataclass
class DecoyResult:
    applied: bool
    real_offset: int
    decoy_offset: int
    vaddr: int
    needed: int
    decoy_size: int = 0
    real_size: int = 0
    names_corrupted: bool = False


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def add_dynamic_decoy(data: bytes, patch_section: bool = True,
                      corrupt_section_names: bool = True) -> tuple[bytes, DecoyResult]:
    if len(data) < 0x40 or data[:4] != ELF_MAGIC:
        raise ElfError("not an ELF file")
    if data[4] not in (1, 2):
        raise ElfError("unsupported ELF class")
    if data[5] != 1:
        raise ElfError("only little-endian ELF is supported")

    buffer = bytearray(data)
    if data[4] == 2:
        result, info = _decoy64(buffer)
    else:
        result, info = _decoy32(buffer)
    if info.applied:
        mutable = bytearray(result)
        if patch_section:
            _patch_dynamic_section(mutable, data[4], info.decoy_offset, info.real_size)
        if corrupt_section_names:
            info.names_corrupted = _corrupt_section_names(mutable, data[4])
        result = bytes(mutable)
    return result, info


def _decoy64(buffer: bytearray) -> tuple[bytes, DecoyResult]:
    phoff = _u64(buffer, 0x20)
    phentsize = _u16(buffer, 0x36)
    phnum = _u16(buffer, 0x38)
    for index in range(phnum):
        header = phoff + index * phentsize
        if _u32(buffer, header) != PT_DYNAMIC:
            continue
        real_offset = _u64(buffer, header + 8)
        vaddr = _u64(buffer, header + 16)
        filesz = _u64(buffer, header + 32)
        entries = _read_dynamic(buffer, real_offset, 16, 8)
        decoy = _build_decoy(entries, 16, 8)
        decoy_offset = (len(buffer) + 7) & ~7
        buffer.extend(b"\x00" * (decoy_offset - len(buffer)))
        buffer.extend(decoy)
        if filesz > len(decoy):
            buffer.extend(b"\x00" * (filesz - len(decoy)))
        struct.pack_into("<Q", buffer, header + 8, decoy_offset)
        return bytes(buffer), DecoyResult(True, real_offset, decoy_offset,
                                          vaddr, _count_needed(entries),
                                          len(decoy), filesz)
    return bytes(buffer), DecoyResult(False, 0, 0, 0, 0)


def _decoy32(buffer: bytearray) -> tuple[bytes, DecoyResult]:
    phoff = _u32(buffer, 0x1C)
    phentsize = _u16(buffer, 0x2A)
    phnum = _u16(buffer, 0x2C)
    for index in range(phnum):
        header = phoff + index * phentsize
        if _u32(buffer, header) != PT_DYNAMIC:
            continue
        real_offset = _u32(buffer, header + 4)
        vaddr = _u32(buffer, header + 8)
        filesz = _u32(buffer, header + 16)
        entries = _read_dynamic(buffer, real_offset, 8, 4)
        decoy = _build_decoy(entries, 8, 4)
        decoy_offset = (len(buffer) + 3) & ~3
        buffer.extend(b"\x00" * (decoy_offset - len(buffer)))
        buffer.extend(decoy)
        if filesz > len(decoy):
            buffer.extend(b"\x00" * (filesz - len(decoy)))
        struct.pack_into("<I", buffer, header + 4, decoy_offset)
        return bytes(buffer), DecoyResult(True, real_offset, decoy_offset,
                                          vaddr, _count_needed(entries),
                                          len(decoy), filesz)
    return bytes(buffer), DecoyResult(False, 0, 0, 0, 0)


def _read_dynamic(buffer: bytearray, offset: int, entry_size: int,
                  value_size: int) -> list[tuple[int, int]]:
    entries: list[tuple[int, int]] = []
    position = offset
    while position + entry_size <= len(buffer):
        tag = _u32(buffer, position)
        value = _u64(buffer, position + value_size) if value_size == 8 \
            else _u32(buffer, position + 4)
        entries.append((tag, value))
        if tag == DT_NULL:
            break
        position += entry_size
    return entries


def _build_decoy(entries: list[tuple[int, int]], entry_size: int,
                 value_size: int) -> bytes:
    keep: list[tuple[int, int]] = []
    soname_seen = False
    strtab_seen = False
    strsz_seen = False
    for tag, value in entries:
        if tag == DT_NEEDED:
            keep.append((tag, value))
        elif tag == DT_SONAME and not soname_seen:
            keep.append((tag, value))
            soname_seen = True
        elif tag == DT_STRTAB and not strtab_seen:
            keep.append((tag, value))
            strtab_seen = True
        elif tag == DT_STRSZ and not strsz_seen:
            keep.append((tag, value))
            strsz_seen = True
    keep.append((DT_NULL, 0))
    output = bytearray()
    for tag, value in keep:
        if entry_size == 16:
            output.extend(struct.pack("<QQ", tag, value))
        else:
            output.extend(struct.pack("<II", tag, value))
    return bytes(output)


def _count_needed(entries: list[tuple[int, int]]) -> int:
    return sum(1 for tag, _ in entries if tag == DT_NEEDED)


def _corrupt_section_names(buffer: bytearray, elf_class: int) -> bool:
    if elf_class == 2:
        shoff = _u64(buffer, 0x28)
        shentsize = _u16(buffer, 0x3A)
        shnum = _u16(buffer, 0x3C)
        shstrndx = _u16(buffer, 0x3E)
        if shoff == 0 or shstrndx >= shnum:
            return False
        header = shoff + shstrndx * shentsize
        offset = _u64(buffer, header + 0x18)
        size = _u64(buffer, header + 0x20)
    else:
        shoff = _u32(buffer, 0x20)
        shentsize = _u16(buffer, 0x2E)
        shnum = _u16(buffer, 0x30)
        shstrndx = _u16(buffer, 0x32)
        if shoff == 0 or shstrndx >= shnum:
            return False
        header = shoff + shstrndx * shentsize
        offset = _u32(buffer, header + 0x10)
        size = _u32(buffer, header + 0x14)
    if size == 0 or offset + size > len(buffer):
        return False
    buffer[offset:offset + size] = b"\xA5" * size
    return True


def _patch_dynamic_section(buffer: bytearray, elf_class: int,
                           decoy_offset: int, real_size: int) -> None:
    if elf_class == 2:
        shoff = _u64(buffer, 0x28)
        shentsize = _u16(buffer, 0x3A)
        shnum = _u16(buffer, 0x3C)
        for index in range(shnum):
            header = shoff + index * shentsize
            if _u32(buffer, header + 4) == 6:  # SHT_DYNAMIC
                struct.pack_into("<Q", buffer, header + 0x18, decoy_offset)
                struct.pack_into("<Q", buffer, header + 0x20, real_size)
                return
    else:
        shoff = _u32(buffer, 0x20)
        shentsize = _u16(buffer, 0x2E)
        shnum = _u16(buffer, 0x30)
        for index in range(shnum):
            header = shoff + index * shentsize
            if _u32(buffer, header + 4) == 6:
                struct.pack_into("<I", buffer, header + 0x10, decoy_offset)
                struct.pack_into("<I", buffer, header + 0x14, real_size)
                return
