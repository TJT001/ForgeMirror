from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pipeline"))

from forgemirror.formats.elf import add_dynamic_decoy  # noqa: E402


def _elf64() -> bytes:
    data = bytearray(512)
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
    # PT_LOAD
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0, 0, 512, 512, 0x1000)
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
        output, info = add_dynamic_decoy(original, patch_section=False)
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
