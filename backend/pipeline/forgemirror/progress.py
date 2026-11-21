"""Append-only stage progress for the worker's task event stream."""
from __future__ import annotations

import json
from pathlib import Path


def emit(path: Path | None, stage: str, status: str, progress: int,
         message: str) -> None:
    if path is None:
        return
    line = json.dumps({
        "stage": stage,
        "status": status,
        "progress": progress,
        "message": message,
    }, ensure_ascii=False)
    try:
        with Path(path).open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        return
