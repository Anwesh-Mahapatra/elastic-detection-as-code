"""Regenerate schemas/ecs_fields_<version>.json from the official ECS release.

Why vendor a compact copy instead of downloading ecs_flat.yml in CI?
  * CI stays deterministic and offline-capable (no network flake = no false failures).
  * The diff of this file in a PR shows exactly which fields changed on an ECS upgrade.

Usage:
    python scripts/build_ecs_schema.py 9.5.0
Then point config/dac.yml -> ecs.schema_file at the new file.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

import yaml

URL = "https://raw.githubusercontent.com/elastic/ecs/v{version}/generated/ecs/ecs_flat.yml"
REPO_ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    version = sys.argv[1].lstrip("v")
    with urllib.request.urlopen(URL.format(version=version), timeout=60) as resp:
        flat = yaml.safe_load(resp.read())

    fields = {}
    for name, spec in sorted(flat.items()):
        entry = {"type": spec["type"]}
        multi = {m["name"]: m["type"] for m in spec.get("multi_fields", [])}
        if multi:
            entry["multi_fields"] = multi
        fields[name] = entry

    out = REPO_ROOT / "schemas" / f"ecs_fields_{version}.json"
    out.write_text(
        json.dumps({"ecs_version": version, "source": URL.format(version=version), "fields": fields},
                   indent=0, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {out.relative_to(REPO_ROOT)} ({len(fields)} fields)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
