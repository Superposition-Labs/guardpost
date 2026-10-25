#!/usr/bin/env bash
# Restore drill: prove the Litestream replica can rebuild the database, without touching it.
#
#   /opt/guardpost/scripts/restore-drill.sh            # latest state
#   /opt/guardpost/scripts/restore-drill.sh -timestamp 2026-10-20T03:00:00Z
#
# 1. `litestream restore` of /data/guardpost.db's replica into /data/.restore-drill/ (a
#    throwaway copy in the same volume; the live database is only read);
# 2. checks the copy inside the guardpost container: integrity_check, schema version, row counts
#    next to the live ones, and that the keyed data belongs to this GUARDPOST_SECRET (a copy
#    restored onto a host with another secret would refuse to boot);
# 3. deletes the copy. Exit status 0 only when every check passed.
# Extra arguments go to `litestream restore` (e.g. -timestamp 2026-10-20T03:00:00Z).
set -euo pipefail

GUARDPOST_DIR=${GUARDPOST_DIR:-/opt/guardpost}
# GUARDPOST_COMPOSE_ARGS: extra compose flags (scripts/smoke.sh passes -p/--env-file/-f).
read -ra extra_args <<<"${GUARDPOST_COMPOSE_ARGS:-}"
compose=(docker compose --project-directory "$GUARDPOST_DIR" -f "$GUARDPOST_DIR/compose.yml"
         ${extra_args[@]+"${extra_args[@]}"})
log() { printf '%s restore-drill: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

container=$("${compose[@]}" ps -q guardpost)
[[ -n "$container" ]] || { log "the guardpost container is not running"; exit 1; }
drill=/data/.restore-drill
cleanup() { docker exec "$container" rm -rf "$drill" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker exec "$container" mkdir -p "$drill"

log "restoring the replica into $drill"
"${compose[@]}" --profile litestream run --rm --no-deps -T litestream \
  restore -config /etc/litestream.yml -o "$drill/guardpost.db" "$@" /data/guardpost.db

docker exec -i "$container" python - "$drill/guardpost.db" <<'PY'
import os
import sqlite3
import sys

from guardpost.ledger.keys import secret_fingerprint
from guardpost.ledger.rekey import FINGERPRINT_META_KEY

restored_path, live_path = sys.argv[1], os.environ.get("GUARDPOST_DB_PATH", "/data/guardpost.db")
TABLES = ("tenants", "api_keys", "accounts", "bans", "referrals", "events", "ip_reputation")
failures = []


def counts(conn):
    out = {}
    for table in TABLES:
        try:
            out[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except sqlite3.OperationalError:
            out[table] = None
    return out


restored = sqlite3.connect(f"file:{restored_path}?mode=ro", uri=True)
live = sqlite3.connect(f"file:{live_path}?mode=ro", uri=True, timeout=30)
integrity = restored.execute("PRAGMA integrity_check").fetchone()[0]
if integrity != "ok":
    failures.append(f"integrity_check: {integrity}")
version = restored.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
live_version = live.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
if version != live_version:
    failures.append(f"schema version {version}, live {live_version}")
row = restored.execute("SELECT value FROM gp_meta WHERE key = ?", (FINGERPRINT_META_KEY,)).fetchone()
secret = os.environ.get("GUARDPOST_SECRET", "")
if row is None:
    failures.append("no keyed-secret fingerprint (was GUARDPOST_SECRET ever set on this database?)")
elif not secret or row[0] != secret_fingerprint(secret):
    failures.append("the keyed data belongs to another GUARDPOST_SECRET")
size = os.path.getsize(restored_path)
print(f"restored: {size} bytes, schema version {version}, integrity {integrity}")
r, lv = counts(restored), counts(live)
for table in TABLES:
    print(f"  {table:14} restored {r[table]!s:>8}   live {lv[table]!s:>8}")
    # The replica lags by about the sync interval: a restored table may trail, never lead by much.
    if r[table] is None and lv[table] is not None:
        failures.append(f"table {table} missing from the restore")
if failures:
    sys.exit("FAILED: " + "; ".join(failures))
print("OK: the replica restores to a usable database for this secret")
PY
log "passed"
