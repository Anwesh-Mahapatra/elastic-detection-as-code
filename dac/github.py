"""Minimal GitHub REST helpers for the PR comment (GITHUB_TOKEN from Actions, no extra deps)."""
from __future__ import annotations

import json
import os

import requests

API_VERSION = "2022-11-28"
MAX_COMMENT = 65_000   # GitHub rejects bodies over 65,536 characters


def pr_context() -> dict:
    """Read the PR number and labels from the event payload GitHub Actions writes to disk."""
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path or not os.path.isfile(path):
        return {"number": os.environ.get("PR_NUMBER"), "labels": []}
    with open(path, encoding="utf-8") as fh:
        event = json.load(fh)
    pr = event.get("pull_request") or {}
    return {"number": pr.get("number") or os.environ.get("PR_NUMBER"),
            "labels": [lbl["name"] for lbl in pr.get("labels", [])]}


def upsert_pr_comment(body: str, marker: str) -> str:
    """Create the judge comment, or edit the previous one, so each PR has a single, current review."""
    token, repo = os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_REPOSITORY")
    number = pr_context()["number"]
    if not (token and repo and number):
        return "skipped (GITHUB_TOKEN, GITHUB_REPOSITORY or PR number not available)"
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": API_VERSION}
    if len(body) > MAX_COMMENT:
        body = body[:MAX_COMMENT - 200] + "\n\n…truncated. Full report: workflow run artifacts (judge-report).\n"

    existing, page = None, 1
    while existing is None:
        r = requests.get(f"{api}/repos/{repo}/issues/{number}/comments", headers=headers,
                         params={"per_page": 100, "page": page}, timeout=30)
        r.raise_for_status()
        batch = r.json()
        existing = next((c for c in batch if marker in (c.get("body") or "")
                         and (c.get("user") or {}).get("type") == "Bot"), None)
        if len(batch) < 100:
            break
        page += 1

    if existing:
        r = requests.patch(existing["url"], headers=headers, json={"body": body}, timeout=30)
    else:
        r = requests.post(f"{api}/repos/{repo}/issues/{number}/comments", headers=headers,
                          json={"body": body}, timeout=30)
    r.raise_for_status()
    return f"{'updated' if existing else 'created'} {r.json().get('html_url')}"
