import subprocess
import tempfile
import unittest
from pathlib import Path

from backend.pipeline.forgemirror.formats import whitebox

TABLE = (Path(__file__).resolve().parents[2]
         / "pipeline/forgemirror/data/wbaes.table")


def _jdk_available():
    try:
        whitebox._jdk_home()
    except RuntimeError:
        return False
    return True


@unittest.skipUnless(_jdk_available(), "JDK required")
class WhiteboxWrapTests(unittest.TestCase):
    def test_wrap_layout_and_roundtrip(self):
        table = TABLE.read_bytes()
        key = bytes(range(32))
        nonce = bytes(range(12))
        blob = whitebox.wrap(table, key, nonce)

        self.assertEqual(len(blob), 4 + 12 + 32)
        self.assertEqual(blob[:4], b"WBK1")
        self.assertEqual(blob[4:16], nonce)
        self.assertNotEqual(blob[16:], key)

        with tempfile.TemporaryDirectory() as temporary:
            wrapped = Path(temporary) / "wrapped.bin"
            wrapped.write_bytes(blob)
            command = [
                whitebox._java_tool("java"), "-cp", str(whitebox._classes()),
                "com.risid.wbaes.WhiteboxKeyTool", "unwrap",
                str(TABLE), "-", nonce.hex(), str(wrapped),
            ]
            process = subprocess.run(command, input="00" * 32 + "\n",
                                     capture_output=True, text=True)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(Path(str(wrapped) + ".out").read_bytes(), key)


if __name__ == "__main__":
    unittest.main()
