#!/usr/bin/env python3
"""ForgeMirror pipeline worker: claims tasks from PostgreSQL, runs S0-S2."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
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
RETURNING t.id, t.source_path, t.profile, t.signing_mode, t.attempt, t.max_attempts
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


def run_pipeline(task: dict) -> tuple[bool, str | None, str | None, dict]:
    work_dir = DATA_DIR / "works" / str(task["id"])
    work_dir.mkdir(parents=True, exist_ok=True)
    shield_aar = os.environ.get(
        "SHIELD_AAR",
        str(ROOT / "android" / "shield" / "build" / "outputs" / "aar" / "shield-debug.aar"),
    )
    command = [
        sys.executable, "-m", "forgemirror.cli", "protect",
        "--apk", task["source_path"],
        "--out", str(work_dir),
        "--profile", task["profile"],
        "--signing-mode", task["signing_mode"],
        "--build-id", str(task["id"]),
        "--shield-aar", shield_aar,
    ]
    auth_url = os.environ.get("AUTH_URL", "")
    if auth_url:
        command.extend(["--auth-url", auth_url])
    if os.environ.get("NO_KEY_ASSET", "").lower() in ("1", "true", "yes"):
        command.append("--no-key-asset")
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

    summary: dict = {}
    protected = work_dir / "protected.apk"
    protect_meta_path = work_dir / "protected.protect.json"
    if protect_meta_path.is_file():
        try:
            meta = json.loads(protect_meta_path.read_text())
            summary = {
                "package": meta.get("package"),
                "version_code": meta.get("version_code"),
                "result": str(protected),
                "sha256": hashlib.sha256(protected.read_bytes()).hexdigest()
                if protected.is_file() else None,
            }
        except Exception:
            summary = {}

    gate_path = work_dir / "gate.json"
    gate_passed = False
    if gate_path.is_file():
        try:
            gate_passed = bool(json.loads(gate_path.read_text()).get("passed"))
        except Exception:
            gate_passed = False

    if process.returncode != 0 or not protected.is_file() or not gate_passed:
        reason = "E_GATE" if gate_path.is_file() and not gate_passed else "E_PIPELINE"
        intake_path = work_dir / "intake.json"
        if reason == "E_PIPELINE" and intake_path.is_file():
            try:
                codes = json.loads(intake_path.read_text()).get("reason_codes") or []
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
