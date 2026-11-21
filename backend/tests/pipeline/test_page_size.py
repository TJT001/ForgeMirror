from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pipeline"))

from forgemirror.apk import elf_max_page_size  # noqa: E402


def elf(elf_class: int, align: int) -> bytes:
    if elf_class == 2:
        header = bytearray(64)
        header[:4] = b"\x7fELF"
        header[4] = 2
        header[5] = 1
        struct.pack_into("<Q", header, 0x20, 64)
        struct.pack_into("<H", header, 0x36, 56)
        struct.pack_into("<H", header, 0x38, 1)
        phdr = bytearray(56)
        struct.pack_into("<I", phdr, 0, 1)
        struct.pack_into("<Q", phdr, 48, align)
    else:
        header = bytearray(52)
        header[:4] = b"\x7fELF"
        header[4] = 1
        header[5] = 1
        struct.pack_into("<I", header, 0x1C, 52)
        struct.pack_into("<H", header, 0x2A, 32)
        struct.pack_into("<H", header, 0x2C, 1)
        phdr = bytearray(32)
        struct.pack_into("<I", phdr, 0, 1)
        struct.pack_into("<I", phdr, 28, align)
    return bytes(header + phdr)


class PageSizeTests(unittest.TestCase):
    def test_elf64_alignment(self) -> None:
        self.assertEqual(elf_max_page_size(elf(2, 0x4000)), 0x4000)
        self.assertEqual(elf_max_page_size(elf(2, 0x1000)), 0x1000)

    def test_elf32_alignment(self) -> None:
        self.assertEqual(elf_max_page_size(elf(1, 0x4000)), 0x4000)

    def test_invalid_input(self) -> None:
        self.assertIsNone(elf_max_page_size(b"not an elf"))
        self.assertIsNone(elf_max_page_size(b"\x7fELF"))


if __name__ == "__main__":
    unittest.main()
