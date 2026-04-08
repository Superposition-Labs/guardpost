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

    args = parser.parse_args(argv)

    if args.command == "serve":
        _serve(args)
    elif args.command == "check":
        _check(args)
    elif args.command == "smtp":
        _smtp(args)
    elif args.command == "proxy":
        _proxy(args)
    else:
        parser.print_help()
        sys.exit(1)


def _serve(args) -> None:
    try:
        import uvicorn
    except ImportError:
        print("uvicorn is required to run the API server.")
        print("Install it with: pip install guardpost[api]")
        sys.exit(1)

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
    )
    uvicorn.run(app, host=args.host, port=args.port)


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
