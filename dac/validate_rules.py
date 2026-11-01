"""CLI for Stage 1 (lint), Stage 2 (replay) and deployment.

    python -m dac.validate_rules lint                 # all rules, no cluster needed
    python -m dac.validate_rules replay               # needs Elasticsearch (docker compose up)
    python -m dac.validate_rules bootstrap            # turn on the Kibana detection engine
    python -m dac.validate_rules deploy               # bulk import into Kibana
    python -m dac.validate_rules build                # write build/rules.ndjson (deploy artifact)

Add --files a.toml b.yml to limit to specific rules (CI passes the PR's changed rules).
Exit code 1 = gate failed. Writes a Markdown summary to $GITHUB_STEP_SUMMARY when set.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .config import REPO_ROOT, settings
from .lint import lint_rules
from .loader import load_rules
from .models import SEVERITY_RANK, Finding


def _gh_escape(text: str, prop: bool = False) -> str:
    text = str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return text.replace(":", "%3A").replace(",", "%2C") if prop else text


def annotate(path: str, f: Finding) -> None:
    """GitHub workflow commands -> findings appear inline on the PR's 'Files changed' tab."""
    if os.environ.get("GITHUB_ACTIONS") != "true" or f.severity not in ("critical", "major"):
        return
    level = "error" if f.severity == "critical" else "warning"
    msg = f"{f.title}. {f.detail} {('Fix: ' + f.fix) if f.fix else ''}".strip()
    print(f"::{level} file={_gh_escape(path, True)},title={_gh_escape(f.check + ' ' + f.title, True)}::{_gh_escape(msg)}")


def write_summary(markdown: str) -> None:
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(markdown + "\n")


def cmd_lint(args) -> int:
    all_rules = load_rules()
    rules = load_rules(args.files) if args.files else all_rules
    results = lint_rules(rules, all_rules)
    failed = 0
    md = ["## Stage 1 · Deterministic lint", "", "| Rule | ❌ critical | ⚠️ major | 🔸 minor |", "|---|---:|---:|---:|"]
    for path, findings in results.items():
        findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.check))
        counts = {s: sum(f.severity == s for f in findings) for s in ("critical", "major", "minor")}
        failed += counts["critical"] > 0
        status = "FAIL" if counts["critical"] else "ok  "
        print(f"[{status}] {path}  critical={counts['critical']} major={counts['major']} minor={counts['minor']}")
        for f in findings:
            if f.severity in ("critical", "major") or args.verbose:
                print(f"    {f.severity:<8} {f.check}  {f.title}" + (f"  [{f.evidence}]" if f.evidence else ""))
            annotate(path, f)
        md.append(f"| `{path}` | {counts['critical']} | {counts['major']} | {counts['minor']} |")
    write_summary("\n".join(md))
    if args.report:
        _write_json(args.report, {p: [f.to_dict() for f in fs] for p, fs in results.items()})
    print(f"\nStage 1: {len(results)} rule(s), {failed} failing")
    return 1 if failed else 0


def cmd_replay(args) -> int:
    from .elastic import ElasticClient
    from .replay import replay, results_to_dicts

    rules = load_rules(args.files)
    results = replay(rules, ElasticClient(), keep=args.keep)
    md = ["## Stage 2 · Log replay (Elasticsearch)", "",
          "| Rule | Case | Data | Expected | Hits | Result |", "|---|---|---|---|---:|:---:|"]
    for r in results:
        verdict = "PASS" if r.passed else "FAIL"
        print(f"[{verdict}] {r.rule}  {r.case:<8} {Path(r.data).name}: hits={r.hits} expected {r.expected}"
              + (f"  ERROR: {r.error}" if r.error else ""))
        md.append(f"| `{Path(r.rule).name}` | {r.case} | `{Path(r.data).name}` | {r.expected} | {r.hits} | "
                  f"{'✅' if r.passed else '❌'}{' ' + r.error if r.error else ''} |")
        if not r.passed and os.environ.get("GITHUB_ACTIONS") == "true":
            print(f"::error file={_gh_escape(r.rule, True)},title=Replay {r.case} failed::"
                  f"{_gh_escape(r.error or f'{r.hits} hits on {r.data}, expected {r.expected}')}")
    write_summary("\n".join(md))
    if args.report:
        _write_json(args.report, results_to_dicts(results))
    failed = sum(not r.passed for r in results)
    print(f"\nStage 2: {len(results)} replay(s), {failed} failing")
    return 1 if failed or not results else 0


def cmd_bootstrap(args) -> int:
    from .deploy import bootstrap
    from .elastic import ElasticClient

    print(json.dumps(bootstrap(ElasticClient(space=settings()["deploy"]["space"])), indent=2))
    return 0


def cmd_deploy(args) -> int:
    from .deploy import deploy, verify_deployed
    from .elastic import ElasticClient

    rules = [r for r in load_rules(args.files) if not r.load_errors]
    client = ElasticClient(space=settings()["deploy"]["space"])
    summary = deploy(rules, client, batch_size=settings()["deploy"]["batch_size"])
    missing = verify_deployed(rules, client) if not summary["errors"] else []
    summary["missing_after_import"] = missing
    print(json.dumps(summary, indent=2))
    write_summary(f"## Deploy\n\nImported **{summary['imported']}/{summary['requested']}** rule(s) into Kibana"
                  + (f", {len(summary['errors'])} error(s)" if summary["errors"] else "") + ".")
    return 1 if summary["errors"] or missing else 0


def cmd_build(args) -> int:
    from .deploy import to_ndjson

    rules = [r for r in load_rules(args.files) if not r.load_errors]
    out = REPO_ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(to_ndjson(rules), encoding="utf-8")
    print(f"wrote {out.relative_to(REPO_ROOT)} ({len(rules)} rules)")
    return 0


def _write_json(path: str, data) -> None:
    target = REPO_ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dac.validate_rules", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, fn in [("lint", cmd_lint), ("replay", cmd_replay), ("bootstrap", cmd_bootstrap),
                     ("deploy", cmd_deploy), ("build", cmd_build)]:
        p = sub.add_parser(name)
        p.set_defaults(fn=fn)
        p.add_argument("--files", nargs="*", help="limit to these rule files")
        p.add_argument("--report", help="write a JSON report to this path")
        p.add_argument("--verbose", "-v", action="store_true", help="also print minor findings")
        p.add_argument("--keep", action="store_true", help="replay: keep test indices for debugging")
        p.add_argument("--out", default="build/rules.ndjson", help="build: output path")
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
