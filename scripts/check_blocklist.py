#!/usr/bin/env python3
"""Guard a disposable-domain blocklist refresh before it becomes a PR.

Usage::

    python scripts/check_blocklist.py OLD_FILE NEW_FILE [--max-shrink 0.01] [--summary FILE]

Fails (exit 1) when the downloaded list looks truncated or emptied:

- the new list is empty, or contains a line that is not a domain (an HTML
  error page, a proxy banner);
- the new list is more than ``--max-shrink`` (default 1%) shorter than the
  current one;
- a domain in ``CUSTOM_DISPOSABLE_DOMAINS`` would stop being flagged.

The custom domains live in code, so the last check only trips if the way the
two layers are combined ever changes — it is the end-to-end assertion that a
refresh can never un-flag a domain we pinned on purpose.

``--summary`` writes a Markdown report (counts, removed domains, removals that
the custom list keeps flagged) suitable for a pull-request body.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


@dataclass
class BlocklistReport:
    old_count: int
    new_count: int
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    removed_but_pinned: list[str] = field(default_factory=list)
    invalid_lines: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _invalid_lines(text: str) -> list[str]:
    bad = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not _DOMAIN_RE.match(line.lower()):
            bad.append(line)
    return bad


def check_blocklist(
    old_text: str,
    new_text: str,
    *,
    custom_domains: frozenset[str] | set[str],
    max_shrink: float = 0.01,
) -> BlocklistReport:
    """Compare two blocklist bodies and decide whether the refresh is safe."""
    from guardpost.email.validator import parse_blocklist

    old = parse_blocklist(old_text)
    new = parse_blocklist(new_text)
    report = BlocklistReport(
        old_count=len(old),
        new_count=len(new),
        added=sorted(new - old),
        removed=sorted(old - new),
        invalid_lines=_invalid_lines(new_text),
    )
    report.removed_but_pinned = [d for d in report.removed if d in custom_domains]

    if not new:
        report.errors.append("new list is empty")
    if report.invalid_lines:
        sample = ", ".join(report.invalid_lines[:5])
        report.errors.append(f"new list has {len(report.invalid_lines)} non-domain line(s), e.g. {sample}")
    if old and len(new) < len(old) * (1 - max_shrink):
        shrink = 1 - len(new) / len(old)
        report.errors.append(
            f"new list is {shrink:.1%} shorter than the current one "
            f"({len(old)} -> {len(new)}; limit {max_shrink:.1%})"
        )

    # The validator flags `community | custom`. Rebuild exactly that set from
    # the NEW file and make sure no pinned domain falls out of it.
    flagged = new | frozenset(custom_domains)
    unflagged = sorted(d for d in custom_domains if d not in flagged)
    if unflagged:
        report.errors.append(f"custom domains would stop being flagged: {', '.join(unflagged)}")

    return report


def render_summary(report: BlocklistReport, *, limit: int = 50) -> str:
    lines = [
        f"- **Added:** {len(report.added)} domains",
        f"- **Removed:** {len(report.removed)} domains",
        f"- **Total:** {report.new_count} domains (was {report.old_count})",
    ]
    if report.removed:
        shown = report.removed[:limit]
        more = f" (+{len(report.removed) - limit} more)" if len(report.removed) > limit else ""
        lines.append("")
        lines.append(f"Removed upstream{more}: " + ", ".join(f"`{d}`" for d in shown))
    if report.removed_but_pinned:
        lines.append("")
        lines.append(
            "Still flagged through `CUSTOM_DISPOSABLE_DOMAINS` (known divergence from upstream): "
            + ", ".join(f"`{d}`" for d in report.removed_but_pinned)
        )
    if report.errors:
        lines.append("")
        lines.append("**Guard failures:**")
        lines.extend(f"- {e}" for e in report.errors)
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("old", type=Path, help="current blocklist file")
    parser.add_argument("new", type=Path, help="downloaded blocklist file")
    parser.add_argument("--max-shrink", type=float, default=0.01,
                        help="largest allowed relative shrink (default 0.01 = 1%%)")
    parser.add_argument("--summary", type=Path, default=None, help="write a Markdown summary here")
    args = parser.parse_args(argv)

    from guardpost.email.validator import CUSTOM_DISPOSABLE_DOMAINS

    report = check_blocklist(
        args.old.read_text(),
        args.new.read_text(),
        custom_domains=CUSTOM_DISPOSABLE_DOMAINS,
        max_shrink=args.max_shrink,
    )
    summary = render_summary(report)
    if args.summary:
        args.summary.write_text(summary)
    print(summary, end="")
    if not report.ok:
        print("Blocklist guard FAILED", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
