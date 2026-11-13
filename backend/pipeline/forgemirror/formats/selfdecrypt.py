"""DT_INIT LZSS self-decrypt post-processing.

`.text` is LZSS-compressed, XOR-masked, appended to the file and mapped by
extending the last PT_LOAD. `fm_meta` is patched with the target/payload
virtual addresses and key; the plaintext `.text` bytes are overwritten.
"""

from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass

from .elf import ElfError

ELF_MAGIC = b"\x7fELF"
MAGIC = 0x464D53444C5A3031
PT_LOAD = 1
PT_DYNAMIC = 2
SHT_PROGBITS = 1
PAGE = 0x1000


@dataclass
class SelfDecryptResult:
    applied: bool
    target_vaddr: int = 0
    target_size: int = 0
    payload_vaddr: int = 0
    payload_size: int = 0
    ratio: float = 0.0


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _align(value: int, alignment: int = PAGE) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _sections(data: bytes) -> list[dict]:
    elf_class = data[4]
    if elf_class == 2:
        shoff = _u64(data, 0x28)
        shentsize = _u16(data, 0x3A)
        shnum = _u16(data, 0x3C)
        shstrndx = _u16(data, 0x3E)
        fields = "<IIQQQQIIQQ"
    else:
        shoff = _u32(data, 0x20)
        shentsize = _u16(data, 0x2E)
        shnum = _u16(data, 0x30)
        shstrndx = _u16(data, 0x32)
        fields = "<IIIIIIIIII"
    if shoff == 0 or shnum == 0 or shstrndx >= shnum:
        return []
    headers = []
    for index in range(shnum):
        header = shoff + index * shentsize
        values = struct.unpack_from(fields, data, header)
        headers.append({
            "index": index,
            "name": values[0],
            "type": values[1],
            "flags": values[2],
            "addr": values[3],
            "offset": values[4],
            "size": values[5],
            "header": header,
        })
    string_header = headers[shstrndx]
    strings = data[string_header["offset"]:string_header["offset"] + string_header["size"]]
    for item in headers:
        start = item["name"]
        end = strings.find(b"\x00", start)
        item["name"] = strings[start:end if end >= 0 else len(strings)].decode(
            "utf-8", "replace")
    return headers


def _section_header_fields(data: bytes) -> tuple[int, int, int, int]:
    if data[4] == 2:
        return (_u64(data, 0x28), _u16(data, 0x3A), _u16(data, 0x3C),
                _u16(data, 0x3E))
    return (_u32(data, 0x20), _u16(data, 0x2E), _u16(data, 0x30),
            _u16(data, 0x32))


def _segments(data: bytes) -> list[dict]:
    elf_class = data[4]
    if elf_class == 2:
        phoff = _u64(data, 0x20)
        phentsize = _u16(data, 0x36)
        phnum = _u16(data, 0x38)
        fields = "<IIQQQQQQ"
    else:
        phoff = _u32(data, 0x1C)
        phentsize = _u16(data, 0x2A)
        phnum = _u16(data, 0x2C)
        fields = "<IIIIIIII"
    result = []
    for index in range(phnum):
        header = phoff + index * phentsize
        values = struct.unpack_from(fields, data, header)
        if elf_class == 2:
            ptype, flags, offset, vaddr, paddr, filesz, memsz, align = values
        else:
            ptype, offset, vaddr, paddr, filesz, memsz, flags, align = values
        result.append({
            "index": index,
            "type": ptype,
            "header": header,
            "offset": offset,
            "vaddr": vaddr,
            "filesz": filesz,
            "memsz": memsz,
        })
    return result


def lzss_compress(data: bytes) -> bytes:
    output = bytearray()
    flags_position = -1
    flags = 0
    bit = 8
    index: dict[bytes, list[int]] = {}
    position = 0
    length = len(data)
    while position < length:
        if bit == 8:
            flags_position = len(output)
            output.append(0)
            flags = 0
            bit = 0
        best_length = 0
        best_offset = 0
        if position + 3 <= length:
            key = data[position:position + 3]
            candidates = index.get(key, [])
            for candidate in reversed(candidates[-64:]):
                if position - candidate > 4096:
                    break
                limit = min(18, length - position)
                matched = 3
                while matched < limit and data[candidate + matched] == data[position + matched]:
                    matched += 1
                if matched > best_length:
                    best_length = matched
                    best_offset = position - candidate - 1
                if matched == limit:
                    break
        if best_length >= 3:
            low = best_offset & 0xFF
            high = ((best_offset >> 4) & 0xF0) | (best_length - 3)
            output.append(low)
            output.append(high)
            consumed = best_length
        else:
            output.append(data[position])
            flags |= 1 << bit
            consumed = 1
        for item in range(position, position + consumed):
            if item + 3 <= length:
                index.setdefault(data[item:item + 3], []).append(item)
        position += consumed
        bit += 1
        if bit == 8 and flags_position >= 0:
            output[flags_position] = flags
    if flags_position >= 0 and bit < 8:
        output[flags_position] = flags
    return bytes(output)


def lzss_decompress(data: bytes, expected: int, key: bytes = b"") -> bytes:
    output = bytearray()
    position = 0
    flags = 0
    bit = 8

    def read() -> int:
        nonlocal position
        value = data[position]
        if key:
            value ^= key[position & 31]
        position += 1
        return value

    while len(output) < expected:
        if bit == 8:
            flags = read()
            bit = 0
        if flags & (1 << bit):
            output.append(read())
        else:
            low = read()
            high = read()
            offset = low | ((high & 0xF0) << 4)
            length = (high & 0x0F) + 3
            if offset + 1 > len(output):
                raise ValueError("bad LZSS offset")
            for _ in range(length):
                if len(output) >= expected:
                    break
                output.append(output[len(output) - offset - 1])
        bit += 1
    return bytes(output)


def add_dt_init_lzss(data: bytes, key: bytes | None = None) -> tuple[bytes, SelfDecryptResult]:
    if len(data) < 0x40 or data[:4] != ELF_MAGIC or data[5] != 1:
        raise ElfError("unsupported ELF")
    sections = _sections(data)
    text = next((item for item in sections if item["name"] == ".text"), None)
    meta = next((item for item in sections if item["name"] == ".fm_meta"), None)
    if text is None or meta is None:
        return data, SelfDecryptResult(False)
    if text["type"] != SHT_PROGBITS or text["size"] == 0 or meta["size"] < 80:
        return data, SelfDecryptResult(False)

    plaintext = bytes(data[text["offset"]:text["offset"] + text["size"]])
    compressed = lzss_compress(plaintext)
    if key is None:
        key = secrets.token_bytes(32)
    payload = bytes(value ^ key[index & 31] for index, value in enumerate(compressed))

    segments = _segments(data)
    dynamic = next(item for item in segments if item["type"] == PT_DYNAMIC)
    loads = [item for item in segments if item["type"] == PT_LOAD]
    if not loads:
        return data, SelfDecryptResult(False)
    last = max(loads, key=lambda item: item["vaddr"] + item["memsz"])
    required = last["offset"] + max(last["filesz"], last["memsz"])
    payload_offset = _align(max(len(data), required))
    payload_vaddr = last["vaddr"] + (payload_offset - last["offset"])

    shoff, shentsize, shnum, shstrndx = _section_header_fields(data)
    if shoff == 0 or shnum == 0 or shstrndx >= shnum:
        return data, SelfDecryptResult(False)
    shstr = sections[shstrndx]
    shstr_new = _align(payload_offset + len(payload))
    shoff_new = _align(shstr_new + shstr["size"])

    buffer = bytearray(data)
    new_end = shoff_new + shnum * shentsize
    if len(buffer) < new_end:
        buffer.extend(b"\x00" * (new_end - len(buffer)))
    buffer[shstr_new:shstr_new + shstr["size"]] = \
        data[shstr["offset"]:shstr["offset"] + shstr["size"]]
    table = bytearray(data[shoff:shoff + shnum * shentsize])
    offset_field = 0x18 if data[4] == 2 else 0x10
    struct.pack_into("<Q" if data[4] == 2 else "<I", table,
                     shstrndx * shentsize + offset_field, shstr_new)
    buffer[shoff_new:shoff_new + len(table)] = table
    struct.pack_into("<Q" if data[4] == 2 else "<I", buffer,
                     0x28 if data[4] == 2 else 0x20, shoff_new)

    # The last PT_LOAD's memory size covers .bss beyond p_filesz. Extending
    # p_filesz makes the kernel file-back those pages, so every byte mapped
    # into .bss must be zero or static objects (mutexes, vtables) start with
    # garbage.
    bss_file_start = last["offset"] + last["filesz"]
    if bss_file_start < payload_offset:
        buffer[bss_file_start:payload_offset] = \
            b"\x00" * (payload_offset - bss_file_start)
    buffer[payload_offset:payload_offset + len(payload)] = payload
    new_size = payload_offset + len(payload) - last["offset"]
    if data[4] == 2:
        struct.pack_into("<Q", buffer, last["header"] + 32, new_size)
        struct.pack_into("<Q", buffer, last["header"] + 40, max(last["memsz"], new_size))
    else:
        struct.pack_into("<I", buffer, last["header"] + 16, new_size)
        struct.pack_into("<I", buffer, last["header"] + 20, max(last["memsz"], new_size))

    struct.pack_into(
        "<QQQQQQ32s", buffer, meta["offset"],
        MAGIC, text["addr"], text["size"], payload_vaddr, len(payload),
        dynamic["vaddr"], key,
    )
    buffer[text["offset"]:text["offset"] + text["size"]] = b"\xA5" * text["size"]
    result = SelfDecryptResult(
        True, text["addr"], text["size"], payload_vaddr, len(payload),
        len(payload) / max(1, len(plaintext)),
    )
    return bytes(buffer), result
