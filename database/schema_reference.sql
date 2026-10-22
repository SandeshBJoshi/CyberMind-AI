-- Reference schema for PostgreSQL. Not required for the default SQLite setup
-- (SQLAlchemy creates these tables automatically on startup) - useful if you
-- want to inspect/migrate the schema manually when running against Postgres.

CREATE TABLE IF NOT EXISTS admin_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR UNIQUE NOT NULL,
    hashed_password VARCHAR NOT NULL,
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id VARCHAR PRIMARY KEY,
    user_label VARCHAR DEFAULT 'demo_user',
    status VARCHAR DEFAULT 'active',
    last_ip VARCHAR,
    last_device VARCHAR,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now(),
    locked_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_events (
    id SERIAL PRIMARY KEY,
    "timestamp" TIMESTAMP DEFAULT now(),
    session_id VARCHAR,
    event_type VARCHAR,
    ip_address VARCHAR,
    device_info VARCHAR,
    details JSONB,
    rule_flags JSONB,
    ml_anomaly BOOLEAN DEFAULT false,
    internal_score FLOAT DEFAULT 0,
    status VARCHAR DEFAULT 'SAFE',
    action_taken VARCHAR DEFAULT 'none'
);
CREATE INDEX IF NOT EXISTS idx_events_session ON security_events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events("timestamp");

CREATE TABLE IF NOT EXISTS lockdown_records (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR,
    triggered_at TIMESTAMP DEFAULT now(),
    reason JSONB,
    unlocked_at TIMESTAMP,
    unlocked_by VARCHAR
);
