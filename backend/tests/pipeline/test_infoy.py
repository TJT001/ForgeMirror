from __future__ import annotations

import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pipeline"))

from forgemirror.formats.infoy import InfoYError, parse  # noqa: E402


def _info_y() -> bytes:
    count = 1
    offset = 0x16 + count * 12
    blob = b"frida\x00xposed\x00"
    record = struct.pack("<III", offset, 1, len(blob))
    body = record + b"\x00" * (offset - 0x16 - len(record)) + blob
    digest = hashlib.md5(body).digest()
    header = bytearray(b"INFO-" + digest + bytes([count]))
    return bytes(header) + body


class InfoYTests(unittest.TestCase):
    def test_parse_sections_and_strings(self) -> None:
        parsed = parse(_info_y())
        self.assertEqual(parsed.count, 1)
        self.assertEqual(parsed.sections[0].offset, 0x22)
        self.assertIn("frida", parsed.strings)
        self.assertIn("xposed", parsed.strings)

    def test_digest_mismatch_rejected(self) -> None:
        data = bytearray(_info_y())
        data[-1] ^= 0x01
        with self.assertRaises(InfoYError):
            parse(bytes(data))


if __name__ == "__main__":
    unittest.main()
