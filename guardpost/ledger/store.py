"""The pseudonymous account ledger: synchronous SQL on one SQLite connection.

Every method runs inside the caller's ``SQLiteStorage.transaction()`` (or its
read lock) and is scoped to one tenant: :class:`LedgerView` is bound to a
``(connection, tenant_id)`` pair, so no query can read another tenant's rows.
It also implements the rule query protocols of :mod:`guardpost.rules`.

Window queries read ``created_at`` in ``[since, until)``.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime

from guardpost.email.banned import BannedEmailRecord
from guardpost.ip.reputation import IPReputationRecord
from guardpost.models import EVENT_TYPES  # noqa: F401  (re-exported)
from guardpost.storage.sqlite import SQLiteStorage
from guardpost.tenancy.models import format_ts

DAY = 86_400.0

# Lifecycle events: guardpost.models.EVENT_TYPES (re-exported here).
ACCOUNT_FLAGS = ("deleted_at", "banned_at", "paid_at", "flagged_at", "referral_code_retracted_at")


def _ts(value: float | None) -> str | None:
    return format_ts(datetime.fromtimestamp(value, UTC)) if value is not None else None


class LedgerView:
    """One tenant's ledger on an open connection."""

    def __init__(self, conn: sqlite3.Connection, tenant_id: str) -> None:
        self.conn = conn
        self.tenant_id = tenant_id

    def _one(self, sql: str, *params):
        return self.conn.execute(sql, (self.tenant_id, *params)).fetchone()

    @staticmethod
    def _not_self(exclude: str | None) -> tuple[str, tuple]:
        return (" AND account_id != ?", (exclude,)) if exclude else ("", ())

    # ------------------------------------------------------------------
    # Rule queries (guardpost.rules protocols)
    # ------------------------------------------------------------------

    def count_device(self, *, fp_key: str, net_key: str, since: float, until: float, exclude: str | None) -> int:
        clause, extra = self._not_self(exclude)
        return self._one(
            "SELECT count(*) FROM accounts WHERE tenant_id = ? AND fp_key = ? AND net_key = ? "
            f"AND created_at >= ? AND created_at < ?{clause}",
            fp_key, net_key, since, until, *extra)[0]

    def first_same_device(self, *, fp_key: str, ip_key: str, since: float, until: float,
                          exclude: str | None) -> str | None:
        clause, extra = self._not_self(exclude)
        row = self._one(
            "SELECT account_id FROM accounts WHERE tenant_id = ? AND fp_key = ? AND ip_key = ? "
            f"AND created_at >= ? AND created_at < ?{clause} ORDER BY created_at, account_id LIMIT 1",
            fp_key, ip_key, since, until, *extra)
        return row[0] if row else None

    def first_same_name(self, *, name_key: str, fp_key: str | None, net_key: str | None,
                        since: float, until: float, exclude: str | None) -> tuple[str, list[str]] | None:
        evidence, params = [], []
        if fp_key:
            evidence.append("fp_key = ?")
            params.append(fp_key)
        if net_key:
            evidence.append("net_key = ?")
            params.append(net_key)
        if not evidence:
            return None
        clause, extra = self._not_self(exclude)
        row = self._one(
            "SELECT account_id, fp_key, net_key FROM accounts WHERE tenant_id = ? AND name_key_h = ? "
            f"AND created_at >= ? AND created_at < ?{clause} AND ({' OR '.join(evidence)}) "
            "ORDER BY created_at, account_id LIMIT 1",
            name_key, since, until, *extra, *params)
        if row is None:
            return None
        matched = [label for label, key, stored in (("fingerprint", fp_key, row["fp_key"]),
                                                    ("network", net_key, row["net_key"]))
                   if key and key == stored]
        return row["account_id"], matched

    def count_referrals_from_ip(self, *, ip_key: str, since: float, until: float) -> int:
        return self._one(
            "SELECT count(*) FROM referrals WHERE tenant_id = ? AND ip_key = ? AND created_at >= ? AND created_at < ?",
            ip_key, since, until)[0]

    def count_referrer_referrals(self, *, referrer_account_id: str, since: float, until: float) -> int:
        return self._one(
            "SELECT count(*) FROM referrals WHERE tenant_id = ? AND referrer_account_id = ? AND suspicious = 0 "
            "AND created_at >= ? AND created_at < ?",
            referrer_account_id, since, until)[0]

    def referrer_code_retracted(self, referrer_account_id: str) -> bool:
        row = self._one("SELECT referral_code_retracted_at FROM accounts WHERE tenant_id = ? AND account_id = ?",
                        referrer_account_id)
        return bool(row and row[0] is not None)

    # ------------------------------------------------------------------
    # Gates
    # ------------------------------------------------------------------

    def is_banned(self, email_key: str) -> bool:
        return self._one("SELECT 1 FROM bans WHERE tenant_id = ? AND email_hash = ?", email_key) is not None

    def alias_collision(self, email_key: str, *, until: float, exclude: str | None) -> str | None:
        """A live account (not deleted) with the same normalized email, created before ``until``."""
        clause, extra = self._not_self(exclude)
        row = self._one(
            "SELECT account_id FROM accounts WHERE tenant_id = ? AND email_key = ? AND deleted_at IS NULL "
            f"AND created_at < ?{clause} ORDER BY created_at, account_id LIMIT 1",
            email_key, until, *extra)
        return row[0] if row else None

    def ip_override(self, ip_target: str | None, net_target: str | None) -> tuple[str, str] | None:
        """(action, kind) of the most specific override: the address before its /24."""
        for target in (ip_target, net_target):
            if target:
                row = self._one("SELECT action, kind FROM ip_overrides WHERE tenant_id = ? AND target_key = ?",
                                target)
                if row:
                    return row["action"], row["kind"]
        return None

    # ------------------------------------------------------------------
    # Shared IP reputation (all tenants; plaintext keys, no account link)
    # ------------------------------------------------------------------

    def load_ip(self, key: str) -> IPReputationRecord | None:
        return SQLiteStorage._load_ip(self.conn, key)

    def store_ip(self, record: IPReputationRecord) -> None:
        SQLiteStorage._store_ip(self.conn, record)

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def check_by_key(self, idempotency_key: str):
        return self._one("SELECT * FROM checks WHERE tenant_id = ? AND idempotency_key = ?", idempotency_key)

    def check_by_id(self, check_id: str):
        return self._one("SELECT * FROM checks WHERE tenant_id = ? AND check_id = ?", check_id)

    def insert_check(self, **row) -> None:
        row["tenant_id"] = self.tenant_id
        cols = ", ".join(row)
        self.conn.execute(f"INSERT INTO checks ({cols}) VALUES ({', '.join('?' * len(row))})", tuple(row.values()))

    def mark_committed(self, check_id: str, account_id: str, at: float) -> None:
        self.conn.execute(
            "UPDATE checks SET committed_at = ?, account_id = ?, ip_sealed = NULL WHERE tenant_id = ? AND check_id = ?",
            (at, account_id, self.tenant_id, check_id))

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    def account(self, account_id: str):
        return self._one("SELECT * FROM accounts WHERE tenant_id = ? AND account_id = ?", account_id)

    def insert_account(self, *, account_id: str, created_at: float, now: float, email_key: str | None = None,
                       fp_key: str | None = None, ip_key: str | None = None, net_key: str | None = None,
                       name_key_h: str | None = None, decision: str | None = None,
                       reasons: Iterable[str] = (), method: str | None = None, returning_user: bool = False,
                       source: str = "check", check_id: str | None = None) -> None:
        self.conn.execute(
            "INSERT INTO accounts (tenant_id, account_id, email_key, fp_key, ip_key, net_key, name_key_h, "
            "created_at, decision, reasons_json, method, returning_user, source, check_id, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (self.tenant_id, account_id, email_key, fp_key, ip_key, net_key, name_key_h, created_at, decision,
             json.dumps(list(reasons)), method, int(returning_user), source, check_id, now))

    def upsert_imported_account(self, *, account_id: str, created_at: float, now: float, keys: dict,
                                flags: dict, decision: str | None, reasons: list[str]) -> bool:
        """Insert or overwrite an imported account. Returns True when it was new."""
        existed = self.account(account_id) is not None
        email_key = None if flags.get("deleted_at") is not None else keys.get("email_key")
        self.conn.execute(
            "INSERT INTO accounts (tenant_id, account_id, email_key, fp_key, ip_key, net_key, name_key_h, created_at, "
            "decision, reasons_json, source, deleted_at, banned_at, paid_at, flagged_at, referral_code_retracted_at, "
            "updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'import', ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (tenant_id, account_id) DO UPDATE SET email_key = excluded.email_key, "
            "fp_key = excluded.fp_key, ip_key = excluded.ip_key, net_key = excluded.net_key, "
            "name_key_h = excluded.name_key_h, created_at = excluded.created_at, "
            "decision = COALESCE(excluded.decision, accounts.decision), "
            "reasons_json = CASE WHEN excluded.decision IS NULL THEN accounts.reasons_json "
            "ELSE excluded.reasons_json END, "
            "deleted_at = excluded.deleted_at, banned_at = excluded.banned_at, paid_at = excluded.paid_at, "
            "flagged_at = excluded.flagged_at, referral_code_retracted_at = excluded.referral_code_retracted_at, "
            "signals_purged_at = NULL, updated_at = excluded.updated_at",
            (self.tenant_id, account_id, email_key, keys.get("fp_key"), keys.get("ip_key"), keys.get("net_key"),
             keys.get("name_key_h"), created_at, decision, json.dumps(reasons),
             *(flags.get(f) for f in ACCOUNT_FLAGS), now))
        return not existed

    def set_account(self, account_id: str, now: float, **columns) -> None:
        sets = ", ".join(f"{c} = ?" for c in columns)
        self.conn.execute(
            f"UPDATE accounts SET {sets}, updated_at = ? WHERE tenant_id = ? AND account_id = ?",
            (*columns.values(), now, self.tenant_id, account_id))

    def referral_of(self, account_id: str):
        return self._one("SELECT * FROM referrals WHERE tenant_id = ? AND referred_account_id = ?", account_id)

    def referred_count(self, account_id: str) -> int:
        return self._one("SELECT count(*) FROM referrals WHERE tenant_id = ? AND referrer_account_id = ?",
                         account_id)[0]

    def upsert_referral(self, *, referred_account_id: str, referrer_account_id: str, ip_key: str | None,
                        created_at: float, suspicious: bool, reason: str | None) -> bool:
        existed = self.referral_of(referred_account_id) is not None
        self.conn.execute(
            "INSERT INTO referrals (tenant_id, referred_account_id, referrer_account_id, ip_key, created_at, "
            "suspicious, reason) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (tenant_id, referred_account_id) DO UPDATE "
            "SET referrer_account_id = excluded.referrer_account_id, ip_key = excluded.ip_key, "
            "created_at = excluded.created_at, suspicious = excluded.suspicious, reason = excluded.reason",
            (self.tenant_id, referred_account_id, referrer_account_id, ip_key, created_at, int(suspicious), reason))
        return not existed

    # ------------------------------------------------------------------
    # Events, bans, overrides
    # ------------------------------------------------------------------

    def event_by_key(self, idempotency_key: str):
        return self._one("SELECT * FROM events WHERE tenant_id = ? AND idempotency_key = ?", idempotency_key)

    def insert_event(self, *, account_id: str, type: str, occurred_at: float, now: float,
                     idempotency_key: str | None, data: dict) -> int:
        cur = self.conn.execute(
            "INSERT INTO events (tenant_id, account_id, type, occurred_at, recorded_at, idempotency_key, data_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (self.tenant_id, account_id, type, occurred_at, now, idempotency_key, json.dumps(data, sort_keys=True)))
        return cur.lastrowid

    def put_ban(self, email_key: str, *, banned_at: float, banned_by: str | None, reason: str | None) -> bool:
        """Insert a ban unless one exists (the first ban's metadata is kept). True when new."""
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO bans (tenant_id, email_hash, banned_at, banned_by, reason) VALUES (?, ?, ?, ?, ?)",
            (self.tenant_id, email_key, _ts(banned_at), banned_by, reason))
        return cur.rowcount > 0

    def delete_ban(self, email_key: str) -> bool:
        return self.conn.execute("DELETE FROM bans WHERE tenant_id = ? AND email_hash = ?",
                                 (self.tenant_id, email_key)).rowcount > 0

    def get_ban(self, email_key: str) -> BannedEmailRecord | None:
        row = self._one("SELECT * FROM bans WHERE tenant_id = ? AND email_hash = ?", email_key)
        if row is None:
            return None
        return BannedEmailRecord(normalized_email_hash=row["email_hash"],
                                 banned_at=datetime.fromisoformat(row["banned_at"]),
                                 banned_by=row["banned_by"], reason=row["reason"])

    def put_override(self, *, target_key: str, kind: str, action: str, reason: str | None,
                     created_by: str | None, now: float) -> None:
        self.conn.execute(
            "INSERT INTO ip_overrides (tenant_id, target_key, kind, action, reason, created_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (tenant_id, target_key) DO UPDATE SET kind = excluded.kind, "
            "action = excluded.action, reason = excluded.reason, created_by = excluded.created_by, "
            "created_at = excluded.created_at",
            (self.tenant_id, target_key, kind, action, reason, created_by, now))

    def delete_override(self, target_key: str) -> bool:
        return self.conn.execute("DELETE FROM ip_overrides WHERE tenant_id = ? AND target_key = ?",
                                 (self.tenant_id, target_key)).rowcount > 0

    # ------------------------------------------------------------------
    # Tenant stats (Phase 2 counters stay in step with v2 commits)
    # ------------------------------------------------------------------

    def record_registration_event(self, *, ts: float, suspicious: bool, ip_key: str | None,
                                  ip_status: str | None) -> None:
        self.conn.execute(
            "INSERT INTO registration_events (tenant_id, ts, suspicious, ip_key, ip_status) VALUES (?, ?, ?, ?, ?)",
            (self.tenant_id, ts, int(suspicious), ip_key, ip_status))
        self.conn.execute(
            "INSERT INTO tenant_counters (tenant_id, total_registrations, suspicious_registrations) "
            "VALUES (?, 1, ?) ON CONFLICT (tenant_id) DO UPDATE SET "
            "total_registrations = total_registrations + 1, "
            "suspicious_registrations = suspicious_registrations + excluded.suspicious_registrations",
            (self.tenant_id, int(suspicious)))

    def stats(self, *, since: float, now: float) -> dict:
        t = self.tenant_id
        q = self.conn.execute
        decisions = {"allow": 0, "degrade": 0, "block": 0}
        for row in q("SELECT decision, count(*) FROM accounts WHERE tenant_id = ? AND source = 'check' "
                     "AND created_at >= ? GROUP BY decision", (t, since)):
            if row[0] in decisions:
                decisions[row[0]] = row[1]
        histogram: dict[str, int] = {}
        for (reasons_json,) in q("SELECT reasons_json FROM accounts WHERE tenant_id = ? AND source = 'check' "
                                 "AND created_at >= ?", (t, since)):
            for code in json.loads(reasons_json or "[]"):
                kind = code.split(":", 1)[0]
                histogram[kind] = histogram.get(kind, 0) + 1
        degraded_paid = q("SELECT count(*) FROM accounts WHERE tenant_id = ? AND decision = 'degrade' "
                          "AND paid_at IS NOT NULL AND created_at >= ?", (t, since)).fetchone()[0]
        degraded = q("SELECT count(*) FROM accounts WHERE tenant_id = ? AND decision = 'degrade' AND created_at >= ?",
                     (t, since)).fetchone()[0]
        latencies = sorted(r[0] for r in q(
            "SELECT latency_ms FROM checks WHERE tenant_id = ? AND latency_ms IS NOT NULL", (t,)))
        referrals = q("SELECT count(*), coalesce(sum(suspicious), 0) FROM referrals WHERE tenant_id = ? "
                      "AND created_at >= ?", (t, since)).fetchone()
        pending = q("SELECT count(*) FROM checks WHERE tenant_id = ? AND committed_at IS NULL "
                    "AND pending_until > ?", (t, now)).fetchone()[0]
        return {
            "accounts": q("SELECT count(*) FROM accounts WHERE tenant_id = ?", (t,)).fetchone()[0],
            "decisions": decisions,
            "reasons": dict(sorted(histogram.items(), key=lambda kv: (-kv[1], kv[0]))),
            "degraded_then_paid": degraded_paid,
            "degraded": degraded,
            "referrals": {"total": referrals[0], "suspicious": referrals[1]},
            "bans": q("SELECT count(*) FROM bans WHERE tenant_id = ?", (t,)).fetchone()[0],
            "pending_checks": pending,
            "latency_ms": {
                "samples": len(latencies),
                "p50": _percentile(latencies, 0.50),
                "p95": _percentile(latencies, 0.95),
            },
        }


def _percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    index = min(len(values) - 1, max(0, int(round(q * (len(values) - 1)))))
    return round(values[index], 3)


# ---------------------------------------------------------------------------
# Retention (all tenants)
# ---------------------------------------------------------------------------

CHECK_RETENTION_SECONDS = DAY
IP_IDLE_DAYS = 90


def purge(conn: sqlite3.Connection, *, now: float, tenant_retention: dict[str, tuple[int, int]]) -> dict:
    """Apply retention. ``tenant_retention`` maps tenant -> (signals_days, events_days).

    - signals (the device, IP, network and name keys of accounts; the IP key of
      referrals) are nulled after ``signals_days`` (default 35); the email key
      of a live account stays, it is the alias/ban identity;
    - checks are deleted after 24 h;
    - events are deleted after ``events_days`` (default 400);
    - shared IP rows that are clean, not whitelisted and idle for 90 days go.
    """
    out = {"signals": 0, "referral_ips": 0, "checks": 0, "events": 0, "ip_rows": 0}
    for tenant_id, (signals_days, events_days) in tenant_retention.items():
        cutoff = now - signals_days * DAY
        out["signals"] += conn.execute(
            "UPDATE accounts SET fp_key = NULL, ip_key = NULL, net_key = NULL, name_key_h = NULL, "
            "signals_purged_at = ? WHERE tenant_id = ? AND created_at < ? AND signals_purged_at IS NULL "
            "AND (fp_key IS NOT NULL OR ip_key IS NOT NULL OR net_key IS NOT NULL OR name_key_h IS NOT NULL)",
            (now, tenant_id, cutoff)).rowcount
        out["referral_ips"] += conn.execute(
            "UPDATE referrals SET ip_key = NULL WHERE tenant_id = ? AND created_at < ? AND ip_key IS NOT NULL",
            (tenant_id, cutoff)).rowcount
        out["events"] += conn.execute(
            "DELETE FROM events WHERE tenant_id = ? AND occurred_at < ?",
            (tenant_id, now - events_days * DAY)).rowcount
    out["checks"] = conn.execute("DELETE FROM checks WHERE created_at < ?",
                                 (now - CHECK_RETENTION_SECONDS,)).rowcount
    idle_cutoff = datetime.fromtimestamp(now - IP_IDLE_DAYS * DAY, UTC)
    stale = []
    candidates = conn.execute(
        "SELECT ip_address, data FROM ip_reputation WHERE coalesce(json_extract(data, '$.status'), 'clean') = 'clean' "
        "AND coalesce(json_extract(data, '$.manually_whitelisted'), 0) = 0")
    for row in candidates:
        record = IPReputationRecord.from_dict(json.loads(row["data"]))
        if record.status != "clean" or record.manually_whitelisted:
            continue
        last = record.last_registration_at or record.first_registration_at
        if last is not None and last.tzinfo is None:
            last = last.replace(tzinfo=UTC)
        if last is None or last < idle_cutoff:
            stale.append(row["ip_address"])
    for key in stale:
        conn.execute("DELETE FROM ip_reputation WHERE ip_address = ?", (key,))
    out["ip_rows"] = len(stale)
    return out
