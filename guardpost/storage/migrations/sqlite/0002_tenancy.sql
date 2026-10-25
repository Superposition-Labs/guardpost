-- 0.3 tenancy.
--
-- * tenants / api_keys.
-- * Bans become per tenant. The 0.2 bans (banned_emails, one global list)
--   move to the legacy tenant: gp_meta.legacy_tenant, recorded from
--   GUARDPOST_LEGACY_TENANT before migrations run ('default' if absent).
-- * The plaintext `registrations` table is dropped. Per-tenant activity is
--   kept as registration_events, which hold no email and only a keyed hash
--   of the IP, plus all-time per-tenant counters. The legacy tenant's
--   counters start from what 0.2's /stats reported (the per-IP counters;
--   /24 rows excluded, which 0.2 double-counted).
-- * ip_reputation is unchanged: it is shared by every tenant.
--
-- The runner VACUUMs after this migration, so the dropped plaintext does not
-- linger in free pages:
-- guardpost:vacuum-after

INSERT OR IGNORE INTO gp_meta (key, value) VALUES ('legacy_tenant', 'default');

CREATE TABLE tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    config_json TEXT NOT NULL DEFAULT '{}',
    key_version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE api_keys (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    key_sha256 TEXT NOT NULL,
    scopes TEXT NOT NULL,
    label TEXT,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    expires_at TEXT,
    revoked_at TEXT
);

CREATE INDEX idx_api_keys_tenant ON api_keys (tenant_id);

INSERT INTO tenants (id, name, status, config_json, key_version, created_at, updated_at)
SELECT value, value, 'active', '{}', 1,
       strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now'), strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now')
FROM gp_meta WHERE key = 'legacy_tenant';

CREATE TABLE bans (
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    email_hash TEXT NOT NULL,
    banned_at TEXT NOT NULL,
    banned_by TEXT,
    reason TEXT,
    PRIMARY KEY (tenant_id, email_hash)
);

INSERT INTO bans (tenant_id, email_hash, banned_at, banned_by, reason)
SELECT (SELECT value FROM gp_meta WHERE key = 'legacy_tenant'),
       normalized_email_hash,
       COALESCE(json_extract(data, '$.banned_at'), strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now')),
       json_extract(data, '$.banned_by'),
       json_extract(data, '$.reason')
FROM banned_emails;

DROP TABLE banned_emails;

CREATE TABLE registration_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    ts REAL NOT NULL,
    suspicious INTEGER NOT NULL DEFAULT 0,
    -- HMAC(tenant key, ip): counts distinct addresses, never reveals one.
    ip_key TEXT,
    -- clean | graylisted | blacklisted | whitelisted, as recorded.
    ip_status TEXT
);

CREATE INDEX idx_registration_events_tenant_ts ON registration_events (tenant_id, ts);

CREATE TABLE tenant_counters (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants (id),
    total_registrations INTEGER NOT NULL DEFAULT 0,
    suspicious_registrations INTEGER NOT NULL DEFAULT 0
);

INSERT INTO tenant_counters (tenant_id, total_registrations, suspicious_registrations)
SELECT (SELECT value FROM gp_meta WHERE key = 'legacy_tenant'),
       COALESCE(SUM(json_extract(data, '$.total_registrations')), 0),
       COALESCE(SUM(json_extract(data, '$.suspicious_registrations')), 0)
FROM ip_reputation
WHERE ip_address NOT LIKE '%/%';

DROP INDEX IF EXISTS idx_registrations_timestamp;
DROP TABLE registrations;
