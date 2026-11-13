CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    app_package TEXT NOT NULL,
    device_id TEXT,
    kind TEXT NOT NULL,
    rule_id TEXT,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    evidence_hash TEXT,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS security_events_package_time_idx
    ON security_events (app_package, created_at DESC);
