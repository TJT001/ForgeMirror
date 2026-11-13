CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    public_key_der BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS auth_challenges (
    id UUID PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    nonce BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS auth_challenges_device_idx
    ON auth_challenges (device_id, created_at);

CREATE TABLE IF NOT EXISTS grants (
    id UUID PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    task_id UUID NOT NULL,
    wrapped_key BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS grants_device_task_idx
    ON grants (device_id, task_id, created_at);
