CREATE TABLE IF NOT EXISTS rule_packages (
    id BIGSERIAL PRIMARY KEY,
    app_package TEXT NOT NULL,
    version INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (app_package, version)
);

CREATE TABLE IF NOT EXISTS client_config (
    app_package TEXT PRIMARY KEY,
    detection BOOLEAN NOT NULL DEFAULT TRUE,
    response TEXT NOT NULL DEFAULT 'toast',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
