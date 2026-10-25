"""Multi-tenancy: tenants, API keys, per-tenant configuration.

Tenants share network and domain intel (IP and /24 reputation, disposable
domains, MX). Everything else — bans, stats, registration events, pattern
analysis — is scoped to the tenant that the request's API key belongs to.

Only the SQLite backend (and the in-memory one, for tests) stores tenants.
"""
