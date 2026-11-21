import tempfile
import unittest
import zipfile
from pathlib import Path

from backend.pipeline.forgemirror.formats import ai_decoy


def _jdk_available():
    try:
        ai_decoy.java_tool("javac")
    except RuntimeError:
        return False
    return True


@unittest.skipUnless(_jdk_available(), "JDK required")
class AiDecoyTests(unittest.TestCase):
    def test_jar_contains_each_lexicon_class(self):
        lexicon = ai_decoy.load_lexicon()
        expected = sum(len(group["classes"]) for group in lexicon["groups"])
        with tempfile.TemporaryDirectory() as temporary:
            jar = Path(temporary) / "decoy.jar"
            count = ai_decoy.build_decoy_jar(None, jar)
            self.assertEqual(count, expected)
            with zipfile.ZipFile(jar) as archive:
                names = set(archive.namelist())
        for group in lexicon["groups"]:
            package = group["package"].replace(".", "/")
            for name in group["classes"]:
                self.assertIn(f"{package}/{name}.class", names)

    def test_merge_keeps_base_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base.jar"
            extra = root / "extra.jar"
            merged = root / "merged.jar"
            with zipfile.ZipFile(base, "w") as archive:
                archive.writestr("base/Entry.class", b"base")
            with zipfile.ZipFile(extra, "w") as archive:
                archive.writestr("extra/Entry.class", b"extra")
            ai_decoy.merge_jar(base, extra, merged)
            with zipfile.ZipFile(merged) as archive:
                self.assertEqual(archive.read("base/Entry.class"), b"base")
                self.assertEqual(archive.read("extra/Entry.class"), b"extra")


if __name__ == "__main__":
    unittest.main()
