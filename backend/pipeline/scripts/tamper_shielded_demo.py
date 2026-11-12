#!/usr/bin/env python3
"""Create a tampered copy of a shielded APK for P1-B recovery tests."""

from __future__ import annotations

import argparse
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend" / "pipeline"))

from forgemirror.tools import AndroidTools  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--remove", action="append", required=True)
    parser.add_argument("--sdk-root", type=Path, default=None)
    parser.add_argument("--build-tools", default=None)
    args = parser.parse_args()

    tools = AndroidTools.discover(args.sdk_root, args.build_tools)
    removed = set(args.remove)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="fm-tamper-") as tmp:
        tmp = Path(tmp)
        stripped = tmp / "stripped.apk"
        found = set()
        with zipfile.ZipFile(args.apk) as src, zipfile.ZipFile(
            stripped, "w", compression=zipfile.ZIP_DEFLATED
        ) as dst:
            for info in src.infolist():
                if info.filename in removed:
                    found.add(info.filename)
                    continue
                dst.writestr(info, src.read(info.filename))
        missing = removed - found
        if missing:
            raise SystemExit(f"entries not found: {sorted(missing)}")
        aligned = tmp / "aligned.apk"
        tools.align_apk(stripped, aligned)
        tools.sign_debug(aligned, args.out)

    print(f"tampered apk: {args.out} (removed {sorted(removed)})")


if __name__ == "__main__":
    main()
