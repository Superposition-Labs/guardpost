#!/usr/bin/env bash
# Nightly snapshot of the Guardpost database, independent of Litestream:
# VACUUM INTO a consistent copy (inside the running container; the image has Python's sqlite3,
# no sqlite3 CLI) -> PRAGMA integrity_check -> gzip -> age (when SNAPSHOT_AGE_RECIPIENT is set)
# -> SNAPSHOT_DIR, pruned after SNAPSHOT_KEEP_DAYS -> rclone (when SNAPSHOT_RCLONE_DEST is set).
#
# cron (root), e.g. /etc/cron.d/guardpost-backup:
#   17 3 * * * root /opt/guardpost/scripts/backup-snapshot.sh >> /var/log/guardpost-backup.log 2>&1
#
# Settings come from the environment, else from /opt/guardpost/.env (GUARDPOST_DIR):
#   SNAPSHOT_DIR (default $GUARDPOST_DIR/snapshots), SNAPSHOT_KEEP_DAYS (14),
#   SNAPSHOT_AGE_RECIPIENT (age public key), SNAPSHOT_RCLONE_DEST (rclone remote:path).
# A snapshot holds no email and no secret, but it does hold plaintext IPs (the shared reputation
# table) and keyed hashes that GUARDPOST_SECRET can test guesses against: encrypt off-host copies.
# Exit status is non-zero on any failure, so cron mail or a log alert sees it.
set -euo pipefail

GUARDPOST_DIR=${GUARDPOST_DIR:-/opt/guardpost}
env_file="$GUARDPOST_DIR/.env"

# Read one KEY=value from the .env without sourcing it (values are not shell-quoted).
setting() {
  local key=$1 default=${2:-} value=${!1:-}
  if [[ -z "$value" && -f "$env_file" ]]; then
    value=$(grep -E "^${key}=" "$env_file" | tail -n 1 | cut -d= -f2- || true)
  fi
  printf '%s' "${value:-$default}"
}

log() { printf '%s backup-snapshot: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

snapshot_dir=$(setting SNAPSHOT_DIR "$GUARDPOST_DIR/snapshots")
keep_days=$(setting SNAPSHOT_KEEP_DAYS 14)
age_recipient=$(setting SNAPSHOT_AGE_RECIPIENT)
rclone_dest=$(setting SNAPSHOT_RCLONE_DEST)
# GUARDPOST_COMPOSE_ARGS: extra compose flags (scripts/smoke.sh passes -p/--env-file/-f).
read -ra extra_args <<<"${GUARDPOST_COMPOSE_ARGS:-}"
compose=(docker compose --project-directory "$GUARDPOST_DIR" -f "$GUARDPOST_DIR/compose.yml"
         ${extra_args[@]+"${extra_args[@]}"})

[[ "$keep_days" =~ ^[0-9]+$ ]] || { log "SNAPSHOT_KEEP_DAYS must be a number"; exit 2; }
if [[ -n "$age_recipient" ]] && ! command -v age >/dev/null; then
  log "SNAPSHOT_AGE_RECIPIENT is set but age is not installed"; exit 2
fi
if [[ -n "$rclone_dest" ]] && ! command -v rclone >/dev/null; then
  log "SNAPSHOT_RCLONE_DEST is set but rclone is not installed"; exit 2
fi

container=$("${compose[@]}" ps -q guardpost)
[[ -n "$container" ]] || { log "the guardpost container is not running"; exit 1; }

ts=$(date -u +%Y%m%dT%H%M%SZ)
name="guardpost-$ts.db"
inside="/data/.snapshots/$name"
mkdir -p "$snapshot_dir"
chmod 700 "$snapshot_dir"
work=$(mktemp -d "$snapshot_dir/.work.XXXXXX")
cleanup() {
  rm -rf "$work"
  docker exec "$container" rm -f "$inside" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# VACUUM INTO writes a compacted, consistent copy while the app keeps serving (WAL readers
# never block). The copy is checked before it leaves the container.
docker exec -i "$container" python - "$inside" <<'PY'
import os
import sqlite3
import sys

src = os.environ.get("GUARDPOST_DB_PATH", "/data/guardpost.db")
dst = sys.argv[1]
os.makedirs(os.path.dirname(dst), exist_ok=True)
conn = sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=30)
try:
    conn.execute("VACUUM INTO ?", (dst,))
finally:
    conn.close()
check = sqlite3.connect(dst)
try:
    result = check.execute("PRAGMA integrity_check").fetchone()[0]
    version = check.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
finally:
    check.close()
if result != "ok":
    os.remove(dst)
    sys.exit(f"integrity_check failed: {result}")
print(f"schema version {version}, {os.path.getsize(dst)} bytes")
PY

docker cp "$container:$inside" "$work/$name" >/dev/null
gzip -9 "$work/$name"
file="$work/$name.gz"
if [[ -n "$age_recipient" ]]; then
  age -r "$age_recipient" -o "$file.age" "$file"
  rm -f "$file"
  file="$file.age"
fi
chmod 600 "$file"
mv "$file" "$snapshot_dir/"
final="$snapshot_dir/$(basename "$file")"
log "wrote $final ($(wc -c <"$final" | tr -d ' ') bytes)"

if [[ -n "$rclone_dest" ]]; then
  rclone copyto "$final" "$rclone_dest/$(basename "$final")"
  log "copied to $rclone_dest/"
fi

find "$snapshot_dir" -maxdepth 1 -type f -name 'guardpost-*.db.gz*' -mtime "+$keep_days" -print -delete |
  while read -r old; do log "pruned $old"; done
