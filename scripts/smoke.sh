#!/usr/bin/env bash
# Smoke test of the deployment kit (deploy/compose.yml) on a local Docker, with throwaway
# secrets, network and volume:
#   1. boot guardpost on its own network with a fresh secret and a legacy key;
#   2. first boot as docs/OPERATIONS.md: tenant config, a v2 key, a second tenant;
#   3. v1 /api/v1/check with the legacy key (Factory v1's call);
#   4. v2 check in commit mode (+ idempotent replay), a lifecycle event, stats, tenant isolation;
#   5. the API is reachable only through the network alias, nothing is published, and metrics
#      answer on 9100, not on 8000;
#   6. scripts/backup-snapshot.sh writes a snapshot;
#   7. with SMOKE_LITESTREAM=1: Litestream replicates to a local S3 mock and
#      deploy/scripts/restore-drill.sh restores it.
#
#   scripts/smoke.sh                       # builds the image from this checkout
#   SMOKE_IMAGE=ghcr.io/superposition-labs/guardpost:0.3 scripts/smoke.sh   # a released image
#   SMOKE_LITESTREAM=1 scripts/smoke.sh    # also replication + the restore drill
#   SMOKE_KEEP=1 scripts/smoke.sh          # leave everything running for a look
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
id=$(openssl rand -hex 4)
project="gp-smoke-$id"
network="gp-smoke-$id"
volume="gp-smoke-$id"
work=$(mktemp -d)
# A copy of deploy/, laid out as /opt/guardpost on a host (and inside Docker's file sharing).
DEPLOY="$work/opt-guardpost"
cp -R "$ROOT/deploy" "$DEPLOY"
s3mock="gp-smoke-s3-$id"
image=${SMOKE_IMAGE:-}
S3MOCK_IMAGE=${SMOKE_S3MOCK_IMAGE:-adobe/s3mock:5.2.2}

pass() { printf '  ok   %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

for tool in docker python3 openssl; do
  command -v "$tool" >/dev/null || { echo "smoke: $tool is required" >&2; exit 2; }
done

if [[ -z "$image" ]]; then
  image="guardpost:smoke"
  step "build $image from $ROOT"
  docker build -q --build-arg GUARDPOST_VERSION=0.0.0+smoke -t "$image" "$ROOT" >/dev/null
fi

secret=$(openssl rand -hex 32)
legacy_key="legacy-$(openssl rand -hex 16)"
cat >"$work/.env" <<EOF
GUARDPOST_IMAGE=$image
GUARDPOST_NETWORK=$network
GUARDPOST_VOLUME=$volume
GUARDPOST_SECRET=$secret
GUARDPOST_LEGACY_TENANT=factory
GUARDPOST_API_KEY=$legacy_key
GUARDPOST_TRUSTED_EXTRA_DOMAINS=factory.bot,deleted.local
GUARDPOST_PURGE_INTERVAL=3600
SNAPSHOT_DIR=$work/snapshots
SNAPSHOT_KEEP_DAYS=14
EOF
if [[ "${SMOKE_LITESTREAM:-}" == 1 ]]; then
  cat >>"$work/.env" <<EOF
COMPOSE_PROFILES=litestream
LITESTREAM_BUCKET=gp-smoke
LITESTREAM_PATH=guardpost
LITESTREAM_ENDPOINT=http://s3mock:9090
LITESTREAM_REGION=us-east-1
LITESTREAM_ACCESS_KEY_ID=smoke
LITESTREAM_SECRET_ACCESS_KEY=smoke
EOF
fi

# Deliver litestream.yml as an inline compose config instead of the bind mount: Docker Desktop
# shares only some host paths. Same file, same content; production keeps the bind mount.
python3 - "$DEPLOY/litestream.yml" >"$work/smoke.override.yml" <<'PY'
import json, sys
content = open(sys.argv[1]).read().replace("$", "$$")  # literal for Litestream to expand
print("services:\n  litestream:\n    volumes: !override\n      - data:/data\n"
      "    configs:\n      - source: litestream\n        target: /etc/litestream.yml\n"
      "configs:\n  litestream:\n    content: " + json.dumps(content))
PY
export GUARDPOST_COMPOSE_ARGS="-p $project --env-file $work/.env -f $work/smoke.override.yml"
compose=(docker compose --project-directory "$DEPLOY" -f "$DEPLOY/compose.yml" -p "$project" --env-file "$work/.env"
         -f "$work/smoke.override.yml")

cleanup() {
  if [[ "${SMOKE_KEEP:-}" == 1 ]]; then
    echo "SMOKE_KEEP=1: left running. Clean up with:"
    echo "  docker compose -p $project --env-file $work/.env -f $DEPLOY/compose.yml --profile litestream down -v"
    echo "  docker rm -f $s3mock; docker network rm $network"
    return
  fi
  "${compose[@]}" --profile litestream down -v --remove-orphans >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  docker rm -f "$s3mock" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

step "boot ($project, image $image)"
docker network create "$network" >/dev/null
if [[ "${SMOKE_LITESTREAM:-}" == 1 ]]; then
  docker run -d --name "$s3mock" --network "$network" --network-alias s3mock \
    -e COM_ADOBE_TESTING_S3MOCK_STORE_INITIAL_BUCKETS=gp-smoke "$S3MOCK_IMAGE" >/dev/null
fi
"${compose[@]}" up -d --wait --wait-timeout 120 >/dev/null 2>"$work/up.log" || { cat "$work/up.log" >&2; fail "compose up"; }
container=$("${compose[@]}" ps -q guardpost)
pass "guardpost is healthy"

gp() { docker exec -i "$container" guardpost "$@"; }

# api METHOD PATH KEY [BODY] -> prints the body, then the status on the last line.
# Runs curl inside the container against the network alias, as an app container would.
api() {
  local method=$1 path=$2 key=$3 body=${4:-}
  shift 4 || shift $#
  docker exec -i "$container" curl -sS -m 10 -X "$method" "http://guardpost:8000$path" \
    -H "Authorization: Bearer $key" -H "Content-Type: application/json" "$@" \
    ${body:+--data-binary "$body"} -w '\n%{http_code}'
}
# json EXPR: evaluate a Python expression over the response body `r` (stdin: body + status).
json() {
  python3 -c "
import json, sys
lines = sys.stdin.read().rstrip('\n').split('\n')
status, body = int(lines[-1]), '\n'.join(lines[:-1])
r = json.loads(body) if body else None
print($1)"
}
expect() {  # expect <description> <python condition over r and status>
  local desc=$1 cond=$2 out
  out=$(cat)
  if [[ $(printf '%s' "$out" | json "bool($cond)") == True ]]; then pass "$desc"; else
    printf '%s\n' "$out" >&2; fail "$desc"; fi
}

step "first boot: tenants and keys"
gp migrate --status | sed 's/^/  /'
grep -q '^factory' <<<"$(gp tenant list)" || fail "the legacy tenant factory was not created on boot"
gp tenant config-set factory region=global >/dev/null
pass "tenant factory (legacy) set to region global"
factory_key=$(gp key create --tenant factory --label smoke-v2 --scopes check,lifecycle,dashboard 2>/dev/null)
[[ "$factory_key" == gpk_* ]] || fail "key create printed $factory_key"
pass "v2 key for factory"
gp tenant create other --region global >/dev/null
other_key=$(gp key create --tenant other --label smoke-other --scopes check,dashboard 2>/dev/null)
pass "second tenant other with its own key"

step "v1 check with the legacy key"
api POST /api/v1/check "$legacy_key" \
  '{"email": "smoke.person@gmail.com", "ip_address": "198.51.100.20"}' -H "X-Api-Key: $legacy_key" |
  expect "v1 /check answers with the v1 keys (is_suspicious, risk_score, hard/soft/weak)" \
    "status == 200 and {'is_suspicious', 'risk_score', 'reasons', 'hard_reasons', 'soft_reasons', 'weak_reasons'} <= set(r)"
api GET /api/v1/health "$legacy_key" | expect "v1 /health" "status == 200 and r['status'] == 'ok'"

step "v2: check (commit), replay, event, stats"
body='{"mode": "commit", "email": "first.smoke@gmail.com", "ip": "198.51.100.21",
       "device": {"user_agent": "SmokeTest/1.0", "accept_language": "en"},
       "name": {"first": "Smoke", "last": "Person"}, "account": {"id": "smoke-1"}}'
first=$(api POST /api/v2/check "$factory_key" "$body" -H "Idempotency-Key: signup:smoke-1")
printf '%s' "$first" | expect "commit-mode check" \
  "status == 200 and r['committed'] and r['account_id'] == 'smoke-1' and r['decision'] == 'allow'"
check_id=$(printf '%s' "$first" | json "r['check_id']")
api POST /api/v2/check "$factory_key" "$body" -H "Idempotency-Key: signup:smoke-1" |
  expect "the idempotent replay returns the same check" "status == 200 and r['check_id'] == '$check_id'"
api POST /api/v2/accounts/smoke-1/events "$factory_key" '{"type": "paid", "idempotency_key": "paid:smoke-1"}' |
  expect "lifecycle event paid" "status == 200 and r['applied']"
api GET "/api/v2/stats?days=1" "$factory_key" |
  expect "stats count the account" "status == 200 and r['tenant_id'] == 'factory' and r['accounts'] == 1"
api GET /api/v2/stats "$other_key" |
  expect "the other tenant sees none of it" "status == 200 and r['tenant_id'] == 'other' and r['accounts'] == 0"
api GET /api/v2/accounts/smoke-1 "$other_key" | expect "nor its account ids (404)" \
  "status == 404"
api POST /api/v2/import/bans "$factory_key" '{"rows": [{"email": "x@gmail.com"}]}' |
  expect "a key without the backfill scope cannot import" "status == 403"

step "exposure"
[[ -z "$(docker port "$container")" ]] || fail "guardpost publishes ports: $(docker port "$container")"
pass "no published ports"
code=$(docker exec "$container" curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/metrics)
[[ "$code" == 404 ]] || fail "/metrics on the API port answered $code"
pass "/metrics is not on 8000 ($code)"
metrics=$(docker exec "$container" curl -fsS -m 5 http://guardpost:9100/metrics) || fail "nothing on 9100"
grep -q '^guardpost_' <<<"$metrics" || fail "no guardpost_ metrics on 9100"
pass "metrics on 9100, inside the network only"

step "nightly snapshot"
GUARDPOST_DIR="$DEPLOY" SNAPSHOT_DIR="$work/snapshots" "$DEPLOY/scripts/backup-snapshot.sh" | sed 's/^/  /'
ls "$work/snapshots"/guardpost-*.db.gz >/dev/null 2>&1 || fail "no snapshot written"
gunzip -c "$work"/snapshots/guardpost-*.db.gz >"$work/snapshot.db"
python3 - "$work/snapshot.db" <<'PY' || fail "the snapshot is not a usable database"
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
assert conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 1
# No plaintext email anywhere in the file.
assert b"smoke.person@gmail.com" not in open(sys.argv[1], "rb").read()
assert b"first.smoke@gmail.com" not in open(sys.argv[1], "rb").read()
PY
pass "snapshot passes integrity_check, holds the account and no plaintext email"

if [[ "${SMOKE_LITESTREAM:-}" == 1 ]]; then
  step "litestream replication and the restore drill"
  grep -q litestream <<<"$("${compose[@]}" ps --status running litestream)" || {
    "${compose[@]}" logs litestream | tail -30 >&2; fail "litestream is not running"; }
  sleep 5
  GUARDPOST_DIR="$DEPLOY" "$DEPLOY/scripts/restore-drill.sh" | sed 's/^/  /' || {
    "${compose[@]}" logs litestream | tail -30 >&2; fail "restore drill"; }
  pass "restore drill"
fi

printf '\nsmoke: all checks passed\n'
