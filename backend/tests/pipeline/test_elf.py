from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pipeline"))

from forgemirror.formats.elf import add_dynamic_decoy  # noqa: E402


def _elf64() -> bytes:
    data = bytearray(1024)
    data[:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[6] = 1
    struct.pack_into("<HHI", data, 16, 2, 183, 1)
    struct.pack_into("<Q", data, 24, 0)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<Q", data, 40, 0)
    struct.pack_into("<H", data, 52, 64)
    struct.pack_into("<H", data, 54, 56)
    struct.pack_into("<H", data, 56, 2)
    struct.pack_into("<H", data, 58, 64)
    struct.pack_into("<H", data, 60, 0)
    struct.pack_into("<H", data, 62, 0)
    # section header table: 3 entries at 400, shstrtab at 480
    struct.pack_into("<Q", data, 40, 400)
    struct.pack_into("<H", data, 58, 64)
    struct.pack_into("<H", data, 60, 3)
    struct.pack_into("<H", data, 62, 2)
    # section 1: SHT_DYNAMIC at file offset 200
    struct.pack_into("<IIQQQQIIQQ", data, 400 + 64, 0, 6, 0, 0x2000, 200, 128, 0, 0, 0, 8)
    # section 2: SHT_STRTAB at file offset 480
    struct.pack_into("<IIQQQQIIQQ", data, 400 + 128, 5, 3, 0, 0x3000, 600, 16, 0, 0, 1, 1)
    data[600:616] = b"\x00.text\x00.dyn\x00"
    # PT_LOAD
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0, 0, 1024, 1024, 0x1000)
    # PT_DYNAMIC at file offset 200
    struct.pack_into("<IIQQQQQQ", data, 120, 2, 6, 200, 0x2000, 0x2000, 128, 128, 8)
    entries = [
        (1, 1), (1, 2), (14, 3), (5, 0x3000), (10, 64), (7, 0x1234), (0, 0)
    ]
    for index, (tag, value) in enumerate(entries):
        struct.pack_into("<QQ", data, 200 + index * 16, tag, value)
    return bytes(data)


class ElfDecoyTests(unittest.TestCase):
    def test_dynamic_decoy(self) -> None:
        original = _elf64()
        output, info = add_dynamic_decoy(original)
        self.assertTrue(info.applied)
        self.assertNotEqual(info.real_offset, info.decoy_offset)
        self.assertEqual(info.needed, 2)

        phdr = struct.unpack_from("<IIQQQQQQ", output, 120)
        self.assertEqual(phdr[0], 2)
        self.assertEqual(phdr[2], info.decoy_offset)

        def tags(blob: bytes, offset: int) -> list[int]:
            values = []
            position = offset
            while True:
                tag, _ = struct.unpack_from("<QQ", blob, position)
                values.append(tag)
                if tag == 0:
                    return values
                position += 16

        self.assertEqual(tags(output, info.decoy_offset),
                         [1, 1, 14, 5, 10, 0])
        self.assertEqual(tags(output, 200), [1, 1, 14, 5, 10, 7, 0])
        self.assertTrue(info.names_corrupted)
        self.assertEqual(output[600:616], b"\xA5" * 16)
        # .dynamic section offset follows the decoy, size stays real
        section = struct.unpack_from("<IIQQQQIIQQ", output, 400 + 64)
        self.assertEqual(section[4], info.decoy_offset)
        self.assertEqual(section[5], info.real_size)
