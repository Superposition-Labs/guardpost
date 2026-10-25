-- 0.3 v2 ledger: the pseudonymous per-tenant account ledger behind /api/v2.
--
-- Every *_key column is an HMAC under the tenant key
-- tk = HKDF(GUARDPOST_SECRET, tenant): the same email, IP or device hashes
-- differently in every tenant, and nothing here holds a plaintext email, IP,
-- user agent or name. Times are UNIX seconds (REAL). Window queries read
-- created_at in [occurred_at - window, occurred_at).
--
-- Bans (0002) are re-keyed from sha256 to HMAC by the keyed data migration
-- (guardpost/ledger/rekey.py) the first time the instance runs with a real
-- GUARDPOST_SECRET: SQL cannot compute an HMAC without the secret.

CREATE TABLE accounts (
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    account_id TEXT NOT NULL,
    -- HMAC(tk, sha256(normalized email)); NULL once the account is deleted.
    email_key TEXT,
    -- HMAC(tk, sha256(User-Agent|Accept-Language)).
    fp_key TEXT,
    ip_key TEXT,
    -- HMAC(tk, network key): the /24 of a global IPv4, the address for IPv6;
    -- NULL for a non-global address.
    net_key TEXT,
    name_key_h TEXT,
    created_at REAL NOT NULL,
    decision TEXT,
    reasons_json TEXT NOT NULL DEFAULT '[]',
    method TEXT,
    returning_user INTEGER NOT NULL DEFAULT 0,
    -- 'check' (committed check), 'import' (backfill) or 'event' (a bare created event).
    source TEXT NOT NULL DEFAULT 'check',
    check_id TEXT,
    signals_purged_at REAL,
    deleted_at REAL,
    banned_at REAL,
    paid_at REAL,
    flagged_at REAL,
    referral_code_retracted_at REAL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (tenant_id, account_id)
);

CREATE INDEX idx_accounts_email ON accounts (tenant_id, email_key) WHERE email_key IS NOT NULL;
CREATE INDEX idx_accounts_fp ON accounts (tenant_id, fp_key, created_at) WHERE fp_key IS NOT NULL;
CREATE INDEX idx_accounts_ip ON accounts (tenant_id, ip_key, created_at) WHERE ip_key IS NOT NULL;
CREATE INDEX idx_accounts_net ON accounts (tenant_id, net_key, created_at) WHERE net_key IS NOT NULL;
CREATE INDEX idx_accounts_name ON accounts (tenant_id, name_key_h, created_at) WHERE name_key_h IS NOT NULL;
CREATE INDEX idx_accounts_created ON accounts (tenant_id, created_at);

-- One row per /api/v2/check call; deleted after 24 h (retention). An evaluate
-- check stays committable for 1 h (pending_until).
CREATE TABLE checks (
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    check_id TEXT NOT NULL,
    idempotency_key TEXT,
    -- HMAC(tk, canonical request): a replayed key must carry the same request.
    request_hmac TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('evaluate', 'commit')),
    created_at REAL NOT NULL,
    occurred_at REAL NOT NULL,
    pending_until REAL,
    committed_at REAL,
    account_id TEXT,
    -- The IP sealed under the tenant key (HMAC-CTR + tag) so a later commit can
    -- bump the shared counters; NULL once committed or when there is no IP.
    ip_sealed TEXT,
    -- What a commit writes (keys, verdict, referral); no plaintext.
    commit_json TEXT NOT NULL,
    result_json TEXT NOT NULL,
    latency_ms REAL,
    PRIMARY KEY (tenant_id, check_id)
);

CREATE UNIQUE INDEX uq_checks_idempotency ON checks (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX idx_checks_created ON checks (created_at);

CREATE TABLE referrals (
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    referred_account_id TEXT NOT NULL,
    referrer_account_id TEXT NOT NULL,
    ip_key TEXT,
    created_at REAL NOT NULL,
    suspicious INTEGER NOT NULL DEFAULT 0,
    reason TEXT,
    PRIMARY KEY (tenant_id, referred_account_id)
);

CREATE INDEX idx_referrals_referrer ON referrals (tenant_id, referrer_account_id, created_at);
CREATE INDEX idx_referrals_ip ON referrals (tenant_id, ip_key, created_at) WHERE ip_key IS NOT NULL;

-- Per-tenant IP decisions, keyed by HMAC of the address or of its /24.
CREATE TABLE ip_overrides (
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    target_key TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('ip', 'net24')),
    action TEXT NOT NULL CHECK (action IN ('allow', 'block')),
    reason TEXT,
    created_by TEXT,
    created_at REAL NOT NULL,
    PRIMARY KEY (tenant_id, target_key)
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL REFERENCES tenants (id),
    account_id TEXT NOT NULL,
    type TEXT NOT NULL,
    occurred_at REAL NOT NULL,
    recorded_at REAL NOT NULL,
    idempotency_key TEXT,
    data_json TEXT NOT NULL DEFAULT '{}'
);

CREATE UNIQUE INDEX uq_events_idempotency ON events (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX idx_events_account ON events (tenant_id, account_id, occurred_at);
CREATE INDEX idx_events_occurred ON events (occurred_at);
