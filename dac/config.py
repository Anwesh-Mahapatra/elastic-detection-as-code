"""Repo paths, settings and secrets.

Tunables live in config/dac.yml (reviewed in PRs like code). Secrets only come from
environment variables, or a local, git-ignored .env file for laptop runs.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


@lru_cache(maxsize=1)
def settings() -> dict:
    with open(REPO_ROOT / "config" / "dac.yml", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@lru_cache(maxsize=1)
def _dotenv() -> dict[str, str]:
    """Minimal .env reader so local runs need no extra dependency. Real env vars win."""
    path = REPO_ROOT / ".env"
    values: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            values[key.strip()] = val.strip().strip('"').strip("'")
    return values


def env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value in (None, ""):
        value = _dotenv().get(name)
    return value if value not in (None, "") else default


def repo_path(relative: str | Path) -> Path:
    return (REPO_ROOT / relative).resolve()
