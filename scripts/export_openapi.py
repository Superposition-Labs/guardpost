#!/usr/bin/env python3
"""Write the API's OpenAPI document to openapi/guardpost.json, or check it is current.

    python scripts/export_openapi.py          # regenerate
    python scripts/export_openapi.py --check  # exit 1 when the file is stale (CI)

The TypeScript client's types are generated from this file, so a route or
model change must regenerate it in the same commit. ``info.version`` is the
API contract version, not the package version, so a release alone never
changes the file. Generate it with the FastAPI/pydantic versions in uv.lock
(``uv run``): other versions may render the same API differently.
"""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

OUT = ROOT / "openapi" / "guardpost.json"
API_CONTRACT_VERSION = "2"


def render() -> str:
    from guardpost.api.app import create_app

    app = create_app(trusted_proxies="", enable_metrics=False)
    schema = app.openapi()
    schema["info"]["version"] = API_CONTRACT_VERSION
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="Fail if the file differs from the app's schema")
    args = parser.parse_args(argv)
    current = render()
    if args.check:
        existing = OUT.read_text("utf-8") if OUT.exists() else ""
        if existing == current:
            print(f"{OUT.relative_to(ROOT)} is up to date")
            return 0
        diff = difflib.unified_diff(existing.splitlines(), current.splitlines(), "committed", "generated",
                                    lineterm="", n=2)
        print("\n".join(list(diff)[:200]))
        print(f"\n{OUT.relative_to(ROOT)} is stale: run `python scripts/export_openapi.py` and commit it",
              file=sys.stderr)
        return 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(current, "utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
