CREATE TABLE IF NOT EXISTS tasks (
    id UUID PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'canceled')),
    profile TEXT NOT NULL DEFAULT 'basic',
    signing_mode TEXT NOT NULL DEFAULT 'customer_local',
    source_path TEXT NOT NULL,
    source_sha256 TEXT,
    package_name TEXT,
    version_code BIGINT,
    attempt INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,
    heartbeat_at TIMESTAMPTZ,
    work_dir TEXT,
    result_path TEXT,
    reason_code TEXT,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tasks_status_created_idx ON tasks (status, created_at);

CREATE TABLE IF NOT EXISTS task_events (
    id BIGSERIAL PRIMARY KEY,
    task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    attempt INT NOT NULL,
    sequence INT NOT NULL,
    stage TEXT,
    status TEXT,
    progress INT,
    reason_code TEXT,
    message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (task_id, attempt, sequence)
);

CREATE INDEX IF NOT EXISTS task_events_task_idx ON task_events (task_id, id);
