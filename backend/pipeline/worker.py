#!/usr/bin/env python3
"""ForgeMirror pipeline worker: claims tasks from PostgreSQL, runs S0-S2."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import zipfile
import time
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "backend" / "pipeline"
DATA_DIR = Path(os.environ.get("DATA_DIR", ROOT / "backend" / "data"))
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgres://forgemirror:forgemirror_dev@localhost:5432/forgemirror?sslmode=disable",
)
WORKER_ID = os.environ.get("WORKER_ID", f"worker-{os.getpid()}")
LEASE_SECONDS = int(os.environ.get("LEASE_SECONDS", "60"))
IDLE_SLEEP = float(os.environ.get("IDLE_SLEEP", "1"))

CLAIM_SQL = """
WITH candidate AS (
    SELECT id FROM tasks
    WHERE status = 'queued'
       OR (status = 'running' AND lease_expires_at < now())
    ORDER BY created_at
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
UPDATE tasks t
SET status = 'running',
    attempt = t.attempt + 1,
    lease_owner = %s,
    lease_expires_at = now() + make_interval(secs => %s),
    heartbeat_at = now(),
    updated_at = now()
FROM candidate c
WHERE t.id = c.id
RETURNING t.id, t.source_path, t.profile, t.signing_mode, t.options,
          t.attempt, t.max_attempts
"""


def connect() -> psycopg.Connection:
    return psycopg.connect(DATABASE_URL, autocommit=True, row_factory=dict_row)


def claim(conn: psycopg.Connection) -> dict | None:
    with conn.transaction():
        return conn.execute(CLAIM_SQL, (WORKER_ID, LEASE_SECONDS)).fetchone()


def add_event(conn: psycopg.Connection, task: dict, sequence: int, *,
              stage: str | None = None, status: str | None = None,
              progress: int | None = None, reason: str | None = None,
              message: str | None = None) -> None:
    conn.execute(
        """
        INSERT INTO task_events
            (task_id, attempt, sequence, stage, status, progress, reason_code, message)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (task_id, attempt, sequence) DO NOTHING
        """,
        (task["id"], task["attempt"], sequence, stage, status, progress, reason, message),
    )


def heartbeat(conn: psycopg.Connection, task: dict) -> bool:
    row = conn.execute(
        """
        UPDATE tasks
        SET lease_expires_at = now() + make_interval(secs => %s),
            heartbeat_at = now(),
            updated_at = now()
        WHERE id = %s AND lease_owner = %s AND status = 'running'
        RETURNING (status = 'canceled') AS canceled
        """,
        (LEASE_SECONDS, task["id"], WORKER_ID),
    ).fetchone()
    return bool(row and row["canceled"])


def _option(task: dict, key: str, fallback=None):
    options = task.get("options") or {}
    if isinstance(options, str):
        try:
            options = json.loads(options)
        except json.JSONDecodeError:
            options = {}
    return options.get(key, fallback)


def _env_or_option(task: dict, key: str, env_name: str) -> str:
    options = task.get("options") or {}
    if isinstance(options, str):
        try:
            options = json.loads(options)
        except json.JSONDecodeError:
            options = {}
    if key in options and options.get(key):
        return str(options.get(key))
    return os.environ.get(env_name, "")


def build_protect_command(task: dict) -> list[str]:
    work_dir = DATA_DIR / "works" / str(task["id"])
    shield_aar = os.environ.get(
        "SHIELD_AAR",
        str(ROOT / "android" / "shield" / "build" / "outputs" / "aar" / "shield-debug.aar"),
    )
    source = task["source_path"]
    command = [
        sys.executable, "-m", "forgemirror.cli", "protect",
        "--apk", source,
        "--out", str(work_dir),
        "--profile", task["profile"],
        "--signing-mode", task["signing_mode"],
        "--build-id", str(task["id"]),
        "--shield-aar", shield_aar,
    ]
    auth_url = _env_or_option(task, "auth_url", "AUTH_URL")
    if auth_url:
        command.extend(["--auth-url", auth_url])
    event_url = _env_or_option(task, "event_url", "EVENT_URL")
    if event_url:
        command.extend(["--event-url", event_url])
    event_token = _env_or_option(task, "event_token", "EVENT_TOKEN")
    if event_token:
        command.extend(["--event-token", event_token])
    if _option(task, "no_key_asset", False):
        command.append("--no-key-asset")
    if _option(task, "self_decrypt_core", True) is False:
        command.append("--no-self-decrypt-core")
    if _option(task, "decoy_dynamic", True) is False:
        command.append("--no-decoy-dynamic")
    if _option(task, "corrupt_section_names", True) is False:
        command.append("--keep-section-names")
    if _option(task, "self_decrypt_text", True) is False:
        command.append("--no-self-decrypt-text")
    if _option(task, "detection", True) is False:
        command.append("--no-detection")
    if _option(task, "whitebox", False):
        command.append("--whitebox-key")
    response = _option(task, "response")
    if response:
        command.extend(["--response", str(response)])
    max_native = _option(task, "max_native_file_mb")
    if max_native is not None:
        command.extend(["--max-native-file-mb", str(max_native)])
    in_memory = _option(task, "in_memory_libs")
    if in_memory:
        command.extend(["--in-memory-libs", str(in_memory)])
    alg = _option(task, "alg")
    if alg:
        command.extend(["--alg", str(alg)])
    shell_version = _option(task, "shell_version")
    if shell_version:
        command.extend(["--shell-version", str(shell_version)])
    aab_mode = _option(task, "aab_mode")
    if aab_mode:
        command.extend(["--aab-mode", str(aab_mode)])
    for split in _option(task, "splits", []) or []:
        command.extend(["--split", str(split)])
    for spec in _option(task, "device_specs", []) or []:
        command.extend(["--device-spec", str(spec)])
    return command


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def package_result(work_dir: Path) -> tuple[Path | None, str | None, int | None, bool]:
    batch = _read_json(work_dir / "batch.json")
    sets = batch.get("sets") if isinstance(batch.get("sets"), list) else []
    if sets:
        archive = work_dir / "protected-set.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            bundle.write(work_dir / "batch.json", "batch.json")
            for index, item in enumerate(sets):
                set_dir = Path(str(item.get("out", "")))
                if not set_dir.is_dir():
                    continue
                for name in ("protected.apk", "protected.apk.splits.json",
                             "protected.protect.json", "gate.json"):
                    path = set_dir / name
                    if path.is_file():
                        bundle.write(path, f"sets/{index:02d}/{name}")
                split_dir = set_dir / "protected_splits"
                if split_dir.is_dir():
                    for split in sorted(split_dir.glob("*.apk")):
                        bundle.write(split, f"sets/{index:02d}/splits/{split.name}")
        first = {}
        for item in sets:
            first = _read_json(Path(str(item.get("out", ""))) / "protected.protect.json")
            if first:
                break
        return (archive, first.get("package"), first.get("version_code"),
                bool(batch.get("ok")))

    protected = work_dir / "protected.apk"
    if not protected.is_file():
        return None, None, None, False
    meta = _read_json(work_dir / "protected.protect.json")
    gate = _read_json(work_dir / "gate.json")
    if (work_dir / "protected.apk.splits.json").is_file() or             (work_dir / "protected_splits").is_dir():
        archive = work_dir / "protected-set.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            for name in ("protected.apk", "protected.apk.splits.json",
                         "protected.protect.json", "gate.json"):
                path = work_dir / name
                if path.is_file():
                    bundle.write(path, name)
            split_dir = work_dir / "protected_splits"
            if split_dir.is_dir():
                for split in sorted(split_dir.glob("*.apk")):
                    bundle.write(split, f"protected_splits/{split.name}")
        return (archive, meta.get("package"), meta.get("version_code"),
                bool(gate.get("passed")))
    return (protected, meta.get("package"), meta.get("version_code"),
            bool(gate.get("passed")))


def run_pipeline(task: dict) -> tuple[bool, str | None, str | None, dict]:
    work_dir = DATA_DIR / "works" / str(task["id"])
    work_dir.mkdir(parents=True, exist_ok=True)
    command = build_protect_command(task)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(PIPELINE)
    process = subprocess.Popen(
        command, cwd=str(ROOT), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    last_heartbeat = time.time()
    while process.poll() is None:
        time.sleep(0.5)
        if time.time() - last_heartbeat >= 10:
            conn = connect()
            try:
                if heartbeat(conn, task):
                    process.terminate()
                    break
            finally:
                conn.close()
            last_heartbeat = time.time()
    stdout, stderr = process.communicate()

    result, package, version_code, gate_passed = package_result(work_dir)
    summary = {
        "package": package,
        "version_code": version_code,
        "result": str(result) if result is not None else None,
        "sha256": _sha256(result) if result is not None else None,
        "result_kind": "zip" if result is not None and result.suffix == ".zip" else "apk"
        if result is not None else None,
    }

    if process.returncode != 0 or result is None or not gate_passed:
        reason = "E_GATE" if result is not None and not gate_passed else "E_PIPELINE"
        intake_path = work_dir / "intake.json"
        if reason == "E_PIPELINE" and intake_path.is_file():
            try:
                codes = _read_json(intake_path).get("reason_codes") or []
                if codes:
                    reason = codes[0]
            except Exception:
                pass
        detail = (stderr or stdout or "").strip()
        return False, reason, detail[-2000:] or None, summary
    return True, None, None, summary


def main() -> None:
    conn = connect()
    print(f"worker {WORKER_ID} connected, data dir {DATA_DIR}", flush=True)
    try:
        while True:
            task = claim(conn)
            if task is None:
                time.sleep(IDLE_SLEEP)
                continue
            print(f"claimed {task['id']} attempt={task['attempt']}", flush=True)
            add_event(conn, task, 1, stage="queue", status="running", progress=5,
                      message="claimed by worker")
            add_event(conn, task, 2, stage="s0-s8", status="running", progress=40,
                      message="running protect pipeline")

            ok, reason, detail, summary = run_pipeline(task)
            if ok:
                add_event(conn, task, 3, stage="done", status="succeeded", progress=100,
                          message=f"protected apk {summary.get('sha256')}")
                conn.execute(
                    """
                    UPDATE tasks
                    SET status = 'succeeded', result_path = %s, package_name = %s,
                        version_code = %s, reason_code = NULL, error_message = NULL,
                        lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
                    WHERE id = %s AND lease_owner = %s
                    """,
                    (summary.get("result"), summary.get("package"),
                     summary.get("version_code"), task["id"], WORKER_ID),
                )
                print(f"succeeded {task['id']}", flush=True)
            else:
                add_event(conn, task, 3, stage="failed", status="failed", progress=100,
                          reason=reason, message=detail)
                if task["attempt"] < task["max_attempts"]:
                    conn.execute(
                        """
                        UPDATE tasks
                        SET status = 'queued', reason_code = %s, error_message = %s,
                            lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
                        WHERE id = %s AND lease_owner = %s
                        """,
                        (reason, detail, task["id"], WORKER_ID),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE tasks
                        SET status = 'failed', reason_code = %s, error_message = %s,
                            lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
                        WHERE id = %s AND lease_owner = %s
                        """,
                        (reason, detail, task["id"], WORKER_ID),
                    )
                print(f"failed {task['id']} reason={reason}", flush=True)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
