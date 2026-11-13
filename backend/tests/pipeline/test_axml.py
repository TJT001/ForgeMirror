from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pipeline"))

from forgemirror.formats import axml  # noqa: E402
from forgemirror.formats.axml import (  # noqa: E402
    ANDROID_NS,
    TYPE_INT_BOOLEAN,
    TYPE_STRING,
    Attr,
    Document,
    EndElement,
    EndNamespace,
    StartElement,
    StartNamespace,
)


def _sample() -> Document:
    document = Document()
    document.flags = 0
    document.strings = [
        "android",
        ANDROID_NS,
        "manifest",
        "package",
        "application",
        "name",
        "com.example",
        "OriginalApp",
        "provider",
        "authorities",
        "exported",
        "com.example.shield.bootstrap",
        "appComponentFactory",
    ]
    document.chunks = [
        StartNamespace(0, 1),
        StartElement(0xFFFFFFFF, 2, [
            Attr(0xFFFFFFFF, 3, 6, TYPE_STRING, 6),
        ]),
        StartElement(1, 4, [
            Attr(1, 5, 7, TYPE_STRING, 7),
        ]),
        EndElement(1, 4),
        EndElement(0xFFFFFFFF, 2),
        EndNamespace(0, 1),
    ]
    return document


class AxmlTests(unittest.TestCase):
    def test_roundtrip_and_rewrite(self) -> None:
        blob = axml.serialize(_sample())
        document = axml.parse(blob)
        self.assertEqual(document.package_name(), "com.example")
        self.assertEqual(document.application_names()[0], "OriginalApp")

        document.rewrite_application("ShieldApp", "ShieldFactory", cleartext=True)
        document.inject_child("application", "provider", [
            ("name", "dev.forgemirror.shield.ShieldProvider"),
            ("authorities", "com.example.shield.bootstrap"),
            ("exported", False),
        ])
        document.inject_child("application", "activity", [
            ("name", "dev.forgemirror.shield.ShieldRecoveryActivity"),
            ("exported", False),
        ])
        blob = axml.serialize(document)
        roundtrip = axml.parse(blob)

        application, factory = roundtrip.application_names()
        self.assertEqual(application, "ShieldApp")
        self.assertEqual(factory, "ShieldFactory")
        provider_index = roundtrip.find_start("provider")
        provider = roundtrip.chunks[provider_index]
        self.assertEqual(
            roundtrip.attr_value(provider, "authorities"),
            "com.example.shield.bootstrap",
        )
        self.assertEqual(
            roundtrip.attr_value(provider, "name"),
            "dev.forgemirror.shield.ShieldProvider",
        )
        self.assertIsNotNone(roundtrip.find_start("activity"))

    def test_attributes_sorted_by_resource_id(self) -> None:
        document = Document()
        document.flags = 0
        document.strings = [
            "android",
            ANDROID_NS,
            "manifest",
            "application",
            "usesCleartextTraffic",
            "name",
        ]
        document.chunks = [
            StartNamespace(0, 1),
            StartElement(0xFFFFFFFF, 2),
            StartElement(1, 3, [
                Attr(1, 4, 0xFFFFFFFF, TYPE_INT_BOOLEAN, 0xFFFFFFFF),
                Attr(1, 5, 0xFFFFFFFF, TYPE_STRING, 2),
            ]),
            EndElement(1, 3),
            EndElement(0xFFFFFFFF, 2),
            EndNamespace(0, 1),
        ]
        roundtrip = axml.parse(axml.serialize(document))
        application = roundtrip.chunks[roundtrip.find_start("application")]
        ids = [roundtrip.resource_ids[attr.name] for attr in application.attrs]
        self.assertEqual(ids, sorted(ids))


if __name__ == "__main__":
    unittest.main()
