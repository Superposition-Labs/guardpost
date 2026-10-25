-- The 0.2 schema. IF NOT EXISTS throughout: a database created by 0.2 (which
-- had no schema_migrations table) already has these tables, and this
-- migration must apply to it as a no-op.

CREATE TABLE IF NOT EXISTS ip_reputation (
    ip_address TEXT PRIMARY KEY,
    data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS banned_emails (
    normalized_email_hash TEXT PRIMARY KEY,
    data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    username TEXT NOT NULL,
    domain TEXT NOT NULL,
    ip_address TEXT,
    timestamp REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_registrations_timestamp
    ON registrations (timestamp);
