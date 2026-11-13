from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pipeline"))

from forgemirror.formats.selfdecrypt import (  # noqa: E402
    MAGIC,
    _sections,
    add_dt_init_lzss,
    lzss_decompress,
)


def _elf64() -> bytes:
    data = bytearray(0x600)
    data[:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[6] = 1
    struct.pack_into("<HHI", data, 16, 2, 183, 1)
    struct.pack_into("<Q", data, 24, 0)
    struct.pack_into("<Q", data, 32, 0x40)
    struct.pack_into("<Q", data, 40, 0x400)
    struct.pack_into("<H", data, 52, 64)
    struct.pack_into("<H", data, 54, 56)
    struct.pack_into("<H", data, 56, 2)
    struct.pack_into("<H", data, 58, 64)
    struct.pack_into("<H", data, 60, 5)
    struct.pack_into("<H", data, 62, 4)
    struct.pack_into("<IIQQQQQQ", data, 0x40, 1, 5, 0, 0, 0, 0x1B0, 0x300, 0x1000)
    struct.pack_into("<IIQQQQQQ", data, 0x78, 2, 6, 0xC0, 0xC0, 0xC0, 0x10, 0x10, 8)
    struct.pack_into("<QQ", data, 0xC0, 0, 0)

    text = b"\x1f\x20\x03\xd5" * 8
    data[0x140:0x160] = text
    struct.pack_into("<QQQQQQ32s", data, 0x160, 0, 0, 0, 0, 0, 0,
                     b"\x00" * 32)
    strings = b"\x00.text\x00.fm_meta\x00.dynamic\x00.shstrtab\x00"
    data[0x1B0:0x1B0 + len(strings)] = strings

    def section(index: int, name: int, kind: int, flags: int, addr: int,
                offset: int, size: int) -> None:
        struct.pack_into("<IIQQQQIIQQ", data, 0x400 + index * 64,
                         name, kind, flags, addr, offset, size, 0, 0, 1, 1)

    section(0, 0, 0, 0, 0, 0, 0)
    section(1, 1, 1, 6, 0x140, 0x140, len(text))
    section(2, 7, 1, 3, 0x160, 0x160, 0x50)
    section(3, 16, 6, 3, 0xC0, 0xC0, 0x10)
    section(4, 25, 3, 0, 0, 0x1B0, len(strings))
    return bytes(data)


class SelfDecryptTests(unittest.TestCase):
    def test_dt_init_lzss(self) -> None:
        original = _elf64()
        output, result = add_dt_init_lzss(original, key=b"\x11" * 32)
        self.assertTrue(result.applied)
        self.assertEqual(result.target_size, 0x20)
        self.assertEqual(result.payload_vaddr, 0x1000)

        sections = _sections(output)
        names = [item["name"] for item in sections]
        self.assertIn(".text", names)
        self.assertIn(".fm_meta", names)
        self.assertIn(".shstrtab", names)

        meta = next(item for item in sections if item["name"] == ".fm_meta")
        magic, target_vaddr, target_size, payload_vaddr, payload_size, \
            dynamic_vaddr, key = struct.unpack_from("<QQQQQQ32s", output,
                                                    meta["offset"])
        self.assertEqual(magic, MAGIC)
        self.assertEqual(target_vaddr, 0x140)
        self.assertEqual(target_size, 0x20)
        self.assertEqual(payload_vaddr, 0x1000)
        self.assertEqual(dynamic_vaddr, 0xC0)
        self.assertEqual(key, b"\x11" * 32)

        payload = output[0x1000:0x1000 + payload_size]
        self.assertEqual(lzss_decompress(payload, target_size, key),
                         original[0x140:0x160])
        self.assertEqual(output[0x140:0x160], b"\xA5" * 0x20)

        # The last PT_LOAD's .bss now starts at 0x1B0 in the file; every byte
        # mapped into it must be zero after the extension.
        self.assertFalse(any(output[0x1B0:0x1000]))
        filesz, memsz = struct.unpack_from("<QQ", output, 0x40 + 32)
        self.assertEqual(filesz, 0x1000 + payload_size)
        self.assertGreaterEqual(memsz, filesz)

        shoff = struct.unpack_from("<Q", output, 0x28)[0]
        self.assertGreater(shoff, 0x1000 + payload_size)
        self.assertEqual(struct.unpack_from("<I", output, shoff + 4)[0], 0)


if __name__ == "__main__":
    unittest.main()
