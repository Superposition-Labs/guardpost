"""The keyed data migration: re-key 0.2/0.3 sha256 bans to per-tenant HMACs.

Phase 2 stored a ban as ``sha256(normalized email)``. Anyone holding the
database could test a list of addresses against that. From the first boot
with a real ``GUARDPOST_SECRET`` every ban is ``HMAC(tk, sha256(...))`` — the
same key the v2 ledger uses for ``accounts.email_key`` — and gp_meta records
which secret the keyed data belongs to (a fingerprint, not the secret).

SQL migrations cannot do this (they never see the secret), so it runs from
:meth:`guardpost.engine.Guardpost.initialize` and ``guardpost migrate``.
"""

from __future__ import annotations

import sqlite3

from guardpost.ledger.keys import TenantHasher, secret_fingerprint

FINGERPRINT_META_KEY = "keyed_secret_fingerprint"


class SecretMismatchError(RuntimeError):
    pass


def keyed_state(conn: sqlite3.Connection) -> str | None:
    row = conn.execute("SELECT value FROM gp_meta WHERE key = ?", (FINGERPRINT_META_KEY,)).fetchone()
    return row[0] if row else None


def ensure_keyed(conn: sqlite3.Connection, secret: str) -> int:
    """Re-key sha256 bans under ``secret`` once (call inside a write transaction).

    Returns the number of bans re-keyed (0 when already done). Raises
    SecretMismatchError when the keyed data belongs to a different secret.
    """
    fingerprint = secret_fingerprint(secret)
    stored = keyed_state(conn)
    if stored == fingerprint:
        return 0
    if stored is not None:
        raise SecretMismatchError(
            "GUARDPOST_SECRET is not the secret this database's keyed data (bans, the v2 ledger) was "
            "written with. Restore the original secret; keyed hashes cannot be converted to a new one "
            "(rotating the secret means re-importing the ledger).")
    rekeyed = 0
    for tenant_id, key_version in conn.execute("SELECT id, key_version FROM tenants").fetchall():
        hasher = TenantHasher(secret, tenant_id, key_version)
        rows = conn.execute(
            "SELECT email_hash, banned_at, banned_by, reason FROM bans WHERE tenant_id = ?", (tenant_id,)).fetchall()
        conn.execute("DELETE FROM bans WHERE tenant_id = ?", (tenant_id,))
        for email_hash, banned_at, banned_by, reason in rows:
            conn.execute(
                "INSERT OR IGNORE INTO bans (tenant_id, email_hash, banned_at, banned_by, reason) "
                "VALUES (?, ?, ?, ?, ?)",
                (tenant_id, hasher.email(email_hash), banned_at, banned_by, reason))
            rekeyed += 1
    conn.execute("INSERT INTO gp_meta (key, value) VALUES (?, ?)", (FINGERPRINT_META_KEY, fingerprint))
    return rekeyed
