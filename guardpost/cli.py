"""Guardpost CLI entry point."""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="guardpost",
        description="Self-hosted registration abuse detection",
    )
    sub = parser.add_subparsers(dest="command")

    # --- serve ---
    serve_parser = sub.add_parser("serve", help="Start the REST API server")
    serve_parser.add_argument(
        "--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    serve_parser.add_argument(
        "--port", type=int, default=8000, help="Bind port (default: 8000)")
    serve_parser.add_argument("--db", default=None,
                              help="SQLite database path")
    serve_parser.add_argument(
        "--redis-url", default=None,
        help="Redis URL for distributed storage + rate limiting "
             "(e.g. redis://localhost:6379)")
    serve_parser.add_argument(
        "--enable-smtp", action="store_true", help="Enable SMTP verification")
    serve_parser.add_argument(
        "--enable-proxy-detection", action="store_true", help="Enable VPN/proxy/datacenter detection"
    )
    serve_parser.add_argument("--maxmind-db", default=None,
                              help="Path to MaxMind GeoLite2 ASN database (.mmdb) file")
    serve_parser.add_argument(
        "--enable-ai", action="store_true", help="Enable AI email scoring (requires OPENROUTER_API_KEY env var)"
    )
    serve_parser.add_argument("--ai-model", default=None,
                              help="AI model to use (default: openai/gpt-4o-mini)")
    serve_parser.add_argument("--enable-patterns", action="store_true",
                              help="Enable registration pattern detection")
    serve_parser.add_argument(
        "--enable-enrichment", action="store_true", help="Enable email enrichment (Gravatar + HIBP)"
    )
    serve_parser.add_argument("--rate-limit", type=int, default=0,
                              help="Max requests per minute per IP (0 = disabled)")
    serve_parser.add_argument(
        "--trusted-proxies", default=None,
        help="Comma-separated CIDRs of reverse proxies allowed to set X-Forwarded-For "
             "(default: $GUARDPOST_TRUSTED_PROXIES; none = header ignored)")
    serve_parser.add_argument(
        "--enable-metrics", action="store_true",
        help="Serve Prometheus metrics on a separate port (also $GUARDPOST_ENABLE_METRICS)")
    serve_parser.add_argument(
        "--metrics-port", type=int, default=None,
        help="Metrics port (default: $GUARDPOST_METRICS_PORT or 9100)")
    serve_parser.add_argument(
        "--metrics-host", default=None,
        help="Metrics bind host (default: $GUARDPOST_METRICS_HOST, else --host). "
             "Never publish this port.")

    # --- check ---
    check_parser = sub.add_parser(
        "check", help="Check an email from the command line")
    check_parser.add_argument("email", help="Email address to check")
    check_parser.add_argument("--ip", default=None, help="IP address to check")
    check_parser.add_argument(
        "--smtp", action="store_true", help="Run SMTP verification")
    check_parser.add_argument(
        "--proxy", action="store_true", help="Check if IP is VPN/proxy/datacenter")

    # --- smtp ---
    smtp_parser = sub.add_parser("smtp", help="SMTP-verify an email address")
    smtp_parser.add_argument("email", help="Email address to verify")
    smtp_parser.add_argument(
        "--timeout", type=float, default=10.0, help="Per-command timeout (default: 10s)")

    # --- proxy ---
    proxy_parser = sub.add_parser(
        "proxy", help="Check if an IP is VPN/proxy/datacenter/Tor")
    proxy_parser.add_argument("ip_address", help="IP address to check")
    proxy_parser.add_argument("--maxmind-db", default=None,
                              help="Path to MaxMind GeoLite2 ASN database (.mmdb) file")

    _add_admin_commands(sub)

    args = parser.parse_args(argv)

    if args.command == "serve":
        _serve(args)
    elif args.command == "check":
        _check(args)
    elif args.command == "smtp":
        _smtp(args)
    elif args.command == "proxy":
        _proxy(args)
    elif args.command in _ADMIN_COMMANDS:
        sys.exit(_run_admin(args))
    else:
        parser.print_help()
        sys.exit(1)


# ---------------------------------------------------------------------------
# Admin commands: migrate, tenant, key, ip (operate on the SQLite database
# directly; a running server sees the changes on its next request)
# ---------------------------------------------------------------------------

_ADMIN_COMMANDS = ("migrate", "tenant", "key", "ip", "purge", "ip-reputation")


def _db_arg(p) -> None:
    p.add_argument("--db", default=None,
                   help="SQLite database path (default: $GUARDPOST_DB_PATH or ~/.guardpost/guardpost.db)")


def _add_admin_commands(sub) -> None:
    migrate = sub.add_parser("migrate", help="Apply pending database migrations")
    _db_arg(migrate)
    migrate.add_argument("--status", action="store_true", help="Only show the schema version and pending migrations")

    tenant = sub.add_parser("tenant", help="Manage tenants").add_subparsers(dest="action", required=True)
    t = tenant.add_parser("create", help="Create a tenant")
    t.add_argument("tenant_id", help="Tenant id: lowercase letters, digits, '-' or '_'")
    t.add_argument("--name", default=None, help="Display name (default: the id)")
    t.add_argument("--region", default=None, help="Region, e.g. global or ru (ru enables the ua_domain rule)")
    t.add_argument("--config", default=None, help="Initial config as JSON")
    _db_arg(t)
    t = tenant.add_parser("list", help="List tenants")
    _db_arg(t)
    t = tenant.add_parser("show", help="Show a tenant, its effective config and its keys")
    t.add_argument("tenant_id")
    _db_arg(t)
    t = tenant.add_parser("config-set", help="Change a tenant's config (validated)")
    t.add_argument("tenant_id")
    t.add_argument("assignments", nargs="*", metavar="key.path=value",
                   help="e.g. region=ru  email.reason_tiers.typo_domain=hard  rate_limit_per_minute=600  "
                        "(values are JSON when valid JSON; null unsets)")
    t.add_argument("--json", dest="patch_json", default=None, help="A JSON merge patch")
    t.add_argument("--replace", action="store_true", help="Replace the whole config with --json instead of merging")
    _db_arg(t)
    t = tenant.add_parser("set-status", help="Suspend or reactivate a tenant (suspended: every key gets 403)")
    t.add_argument("tenant_id")
    t.add_argument("status", choices=["active", "suspended"])
    _db_arg(t)

    key = sub.add_parser("key", help="Manage API keys").add_subparsers(dest="action", required=True)
    k = key.add_parser("create", help="Create an API key (printed once)")
    k.add_argument("--tenant", required=True)
    k.add_argument("--label", required=True, help="What uses the key, e.g. factory-v2-prod")
    k.add_argument("--scopes", required=True,
                   help="Comma-separated: check, lifecycle, dashboard, backfill, admin, legacy")
    k.add_argument("--expires", default=None, help="Lifetime, e.g. 90d, 12h, 2w (default: never)")
    _db_arg(k)
    k = key.add_parser("list", help="List API keys (never the secrets)")
    k.add_argument("--tenant", default=None)
    _db_arg(k)
    k = key.add_parser("revoke", help="Revoke an API key now")
    k.add_argument("key_id")
    _db_arg(k)
    k = key.add_parser("rotate", help="Issue a replacement key; the old one expires after --grace")
    k.add_argument("key_id")
    k.add_argument("--grace", default="7d", help="How long the old key keeps working (default: 7d)")
    _db_arg(k)

    ip = sub.add_parser("ip", help="Shared IP reputation").add_subparsers(dest="action", required=True)
    i = ip.add_parser("whitelist", help="Whitelist an IP or /24 for every tenant")
    i.add_argument("--global", dest="is_global", action="store_true",
                   help="Required: the shared reputation table is global (per-tenant overrides come with v2)")
    i.add_argument("target", metavar="ip|cidr", help="An address, or an IPv4 /24 such as 203.0.113.0/24")
    i.add_argument("--by", default="cli", help="Who is whitelisting (recorded)")
    i.add_argument("--reason", default="manual", help="Why (recorded)")
    _db_arg(i)

    purge = sub.add_parser(
        "purge",
        help="Apply retention now: ledger signals (35 d), checks (24 h), events (400 d), idle clean IPs (90 d)")
    _db_arg(purge)

    rep = sub.add_parser("ip-reputation", help="Shared IP reputation data").add_subparsers(
        dest="action", required=True)
    r = rep.add_parser("import", help="Merge a JSON array (or JSON lines) of reputation rows into the shared table")
    r.add_argument("file", help="Rows with ip_address, total_registrations, suspicious_registrations, "
                                "first_registration_at, last_registration_at, status, status_reason, "
                                "manually_whitelisted (Factory v2 ip_reputation columns); '-' reads stdin")
    r.add_argument("--dry-run", action="store_true", help="Validate and count, write nothing")
    _db_arg(r)


class _CLIError(Exception):
    pass


def _run_admin(args) -> int:
    import asyncio

    try:
        asyncio.run(_admin(args))
    except (_CLIError, ValueError, LookupError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def _storage_for(args):
    import os

    from guardpost.storage.sqlite import DEFAULT_LEGACY_TENANT, SQLiteStorage
    from guardpost.tenancy.models import validate_tenant_id

    db = args.db or os.environ.get("GUARDPOST_DB_PATH")
    legacy = validate_tenant_id(os.environ.get("GUARDPOST_LEGACY_TENANT") or DEFAULT_LEGACY_TENANT)
    return SQLiteStorage(db, legacy_tenant=legacy)


async def _admin(args) -> None:
    import json

    from guardpost.storage.migrations import pending_sqlite_migrations, schema_version

    storage = _storage_for(args)
    try:
        if args.command == "migrate":
            with storage._lock:
                conn = storage._get_conn()
                pending = pending_sqlite_migrations(conn)
                current = schema_version(conn)
            if args.status:
                print(f"{storage.db_path}: schema version {current}")
                for m in pending:
                    print(f"pending: {m.version:04d}_{m.name}")
                return
            applied = storage.migrate()
            await storage.ensure_tenant(storage.legacy_tenant)
            rekeyed = _rekey_if_secret(storage)
            if rekeyed:
                print(f"{storage.db_path}: re-keyed {rekeyed} bans to per-tenant HMACs")
            if applied:
                print(f"{storage.db_path}: applied {', '.join(f'{v:04d}' for v in applied)}; "
                      f"now at version {max(applied)}")
            else:
                print(f"{storage.db_path}: up to date (version {current})")
            return

        with storage._lock:
            pending = pending_sqlite_migrations(storage._get_conn())
        if pending:
            raise _CLIError(f"{storage.db_path} needs migrating ({len(pending)} pending): run `guardpost migrate`")

        if args.command == "tenant":
            await _tenant(storage, args, json)
        elif args.command == "key":
            await _key(storage, args)
        elif args.command == "ip":
            await _ip(storage, args)
        elif args.command == "purge":
            await _purge(storage)
        elif args.command == "ip-reputation":
            await _ip_reputation_import(storage, args)
    finally:
        await storage.close()


def _rekey_if_secret(storage) -> int:
    """The keyed data migration (guardpost/ledger/rekey.py), when GUARDPOST_SECRET is set."""
    import os

    from guardpost.ledger import rekey
    from guardpost.tenancy.crypto import SECRET_ENV

    secret = os.environ.get(SECRET_ENV)
    if not secret:
        return 0
    with storage.transaction() as conn:
        return rekey.ensure_keyed(conn, secret)


async def _purge(storage) -> None:
    import time

    from guardpost.ledger import store

    tenants = await storage.list_tenants()
    retention = {t.id: (t.config.retention.signals_days, t.config.retention.events_days) for t in tenants}
    with storage.transaction() as conn:
        counts = store.purge(conn, now=time.time(), tenant_retention=retention)
    counts["registration_events"] = sum([
        await storage.purge_registration_events(t.id, time.time() - t.config.retention.signals_days * store.DAY)
        for t in tenants])
    print(", ".join(f"{k}: {v}" for k, v in counts.items()))


def _read_rows(path: str) -> list[dict]:
    import json

    text = sys.stdin.read() if path == "-" else open(path, encoding="utf-8").read()
    stripped = text.lstrip()
    if stripped.startswith("["):
        rows = json.loads(stripped)
    else:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        raise _CLIError("expected a JSON array of objects, or one JSON object per line")
    return rows


async def _ip_reputation_import(storage, args) -> None:
    from pydantic import ValidationError

    from guardpost.api.v2 import IPReputationImport
    from guardpost.ledger.service import ip_record_from_import, merge_ip_records
    from guardpost.ledger.store import LedgerView

    raw = _read_rows(args.file)
    try:
        records = [ip_record_from_import(IPReputationImport.model_validate(r)) for r in raw]
    except ValidationError as exc:
        raise _CLIError(f"invalid row: {exc}") from exc
    inserted = 0
    if not args.dry_run:
        with storage.transaction() as conn:
            view = LedgerView(conn, "")
            for record in records:
                existing = view.load_ip(record.ip_address)
                inserted += existing is None
                view.store_ip(merge_ip_records(existing, record))
    verb = "would merge" if args.dry_run else "merged"
    print(f"{verb} {len(records)} rows into the shared IP reputation table "
          f"({inserted} new, {len(records) - inserted} updated)")


async def _tenant(storage, args, json) -> None:
    from guardpost.tenancy.config import TenantConfig, apply_patch, parse_assignment
    from guardpost.tenancy.models import Tenant, utcnow, validate_tenant_id

    if args.action == "create":
        config = json.loads(args.config) if args.config else {}
        if args.region:
            config["region"] = args.region
        tenant = Tenant(id=validate_tenant_id(args.tenant_id), name=args.name or args.tenant_id,
                        config=TenantConfig.model_validate(config))
        await storage.create_tenant(tenant)
        print(json.dumps(tenant.to_dict(), indent=2))
        return
    if args.action == "list":
        tenants = await storage.list_tenants()
        keys_by_tenant: dict[str, int] = {}
        now = utcnow()
        for k in await storage.list_api_keys():
            if k.usable(now):
                keys_by_tenant[k.tenant_id] = keys_by_tenant.get(k.tenant_id, 0) + 1
        print(f"{'ID':<24} {'STATUS':<10} {'REGION':<8} {'KEYS':>4}  NAME")
        for t in tenants:
            print(f"{t.id:<24} {t.status:<10} {t.config.region or '-':<8} {keys_by_tenant.get(t.id, 0):>4}  {t.name}")
        return

    tenant = await storage.get_tenant(args.tenant_id)
    if tenant is None:
        raise LookupError(f"no such tenant: {args.tenant_id}")
    if args.action == "show":
        out = tenant.to_dict()
        out["keys"] = [k.to_dict() for k in await storage.list_api_keys(tenant.id)]
        print(json.dumps(out, indent=2))
        return
    if args.action == "config-set":
        patches: list[dict] = []
        if args.patch_json:
            patch = json.loads(args.patch_json)
            if not isinstance(patch, dict):
                raise _CLIError("--json must be a JSON object")
            patches.append(patch)
        patches.extend(parse_assignment(a) for a in args.assignments)
        if not patches and not args.replace:
            raise _CLIError("nothing to set: pass key.path=value assignments or --json")
        config = TenantConfig() if args.replace else tenant.config
        for patch in patches:
            config = apply_patch(config, patch)
        tenant.config = config
    elif args.action == "set-status":
        tenant.status = args.status
    tenant.updated_at = utcnow()
    await storage.save_tenant(tenant)
    print(json.dumps(tenant.to_dict(), indent=2))


async def _key(storage, args) -> None:
    from guardpost.tenancy import keys
    from guardpost.tenancy.models import format_ts, utcnow

    if args.action == "create":
        expires = keys.parse_duration(args.expires) if args.expires else None
        plaintext, record = await keys.create_key(storage, args.tenant, args.scopes, label=args.label,
                                                  expires_in=expires)
        # The key alone on stdout (KEY=$(guardpost key create ...)); details on stderr.
        print(plaintext)
        print(f"Created key {record.id} for tenant {record.tenant_id} (scopes: {','.join(sorted(record.scopes))}, "
              f"expires: {format_ts(record.expires_at) or 'never'}). It is shown only this once.", file=sys.stderr)
        return
    if args.action == "list":
        now = utcnow()
        print(f"{'ID':<14} {'TENANT':<20} {'STATE':<8} {'SCOPES':<28} {'EXPIRES':<26} {'LAST USED':<26} LABEL")
        for k in await storage.list_api_keys(args.tenant):
            print(f"{k.id:<14} {k.tenant_id:<20} {k.state(now):<8} {','.join(sorted(k.scopes)):<28} "
                  f"{format_ts(k.expires_at) or '-':<26} {format_ts(k.last_used_at) or '-':<26} {k.label or ''}")
        return
    if args.action == "revoke":
        record = await keys.revoke_key(storage, args.key_id)
        print(f"Revoked key {record.id} (tenant {record.tenant_id}) at {format_ts(record.revoked_at)}",
              file=sys.stderr)
        return
    if args.action == "rotate":
        plaintext, new, old = await keys.rotate_key(storage, args.key_id, grace=keys.parse_duration(args.grace))
        print(plaintext)
        print(f"Created key {new.id} for tenant {new.tenant_id}; old key {old.id} expires at "
              f"{format_ts(old.expires_at)}. The new key is shown only this once.", file=sys.stderr)


async def _ip(storage, args) -> None:
    import ipaddress

    from guardpost.ip.reputation import IPReputationEngine

    if not args.is_global:
        raise _CLIError("pass --global: IP reputation is shared by every tenant (per-tenant overrides come with v2)")
    target = args.target.strip()
    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        if net.version != 4 or net.prefixlen != 24:
            raise _CLIError("only single addresses and IPv4 /24 networks are tracked")
        key = str(net)
    else:
        key = str(ipaddress.ip_address(target))
    record = await IPReputationEngine(storage).whitelist_ip(key, args.by, args.reason)
    print(f"Whitelisted {record.ip_address} for all tenants (by {record.whitelisted_by}: {record.whitelist_reason})")


def _serve(args) -> None:
    try:
        import uvicorn
    except ImportError:
        print("uvicorn is required to run the API server.")
        print("Install it with: pip install guardpost[api]")
        sys.exit(1)

    import os

    from guardpost.api.server import create_app

    app = create_app(
        db_path=args.db,
        redis_url=args.redis_url,
        enable_smtp=args.enable_smtp,
        enable_proxy_detection=args.enable_proxy_detection,
        enable_ai=args.enable_ai,
        ai_model=args.ai_model,
        enable_patterns=args.enable_patterns,
        enable_enrichment=args.enable_enrichment,
        rate_limit=args.rate_limit,
        maxmind_db_path=args.maxmind_db,
        trusted_proxies=args.trusted_proxies,
        enable_metrics=args.enable_metrics,
        metrics_port=args.metrics_port,
        metrics_host=args.metrics_host or os.environ.get("GUARDPOST_METRICS_HOST") or args.host,
    )
    # proxy_headers=False: uvicorn would otherwise rewrite the peer address
    # from X-Forwarded-For on its own (FORWARDED_ALLOW_IPS), bypassing
    # GUARDPOST_TRUSTED_PROXIES. Guardpost resolves the client IP itself.
    uvicorn.run(app, host=args.host, port=args.port, proxy_headers=False)


def _check(args) -> None:
    import asyncio
    import json

    from guardpost.engine import Guardpost

    async def run():
        smtp_verifier = None
        proxy_detector = None

        if args.smtp:
            from guardpost.email.smtp import SMTPVerifier

            smtp_verifier = SMTPVerifier()

        if args.proxy and args.ip:
            from guardpost.ip.proxy import ProxyDetector

            proxy_detector = ProxyDetector()

        gp = Guardpost(
            smtp_verifier=smtp_verifier,
            proxy_detector=proxy_detector,
        )
        await gp.initialize()
        result = await gp.check(
            args.email,
            ip_address=args.ip,
            record_ip=False,
            smtp_verify=args.smtp,
            check_proxy=args.proxy,
        )
        print(json.dumps(result.to_dict(), indent=2))
        await gp.close()

    asyncio.run(run())


def _smtp(args) -> None:
    import asyncio
    import json

    from guardpost.email.smtp import SMTPVerifier

    async def run():
        verifier = SMTPVerifier(timeout=args.timeout)
        result = await verifier.verify(args.email)
        print(json.dumps(result.to_dict(), indent=2))

    asyncio.run(run())


def _proxy(args) -> None:
    import asyncio
    import json

    from guardpost.ip.proxy import ProxyDetector

    async def run():
        detector = ProxyDetector(maxmind_db_path=args.maxmind_db)
        result = await detector.check(args.ip_address)
        print(json.dumps(result.to_dict(), indent=2))

    asyncio.run(run())


if __name__ == "__main__":
    main()
