"""Load rules from disk into one shape, whatever format the author used.

* rules/elastic/*.toml  native Elastic Security TOML (same layout as elastic/detection-rules)
* rules/sigma/*.yml     Sigma v2, compiled to EQL (or Lucene) with pySigma

Both end up as a Kibana detection-rule payload, so every later stage (lint, replay,
judge, deploy) handles a single format.
"""
from __future__ import annotations

import tomllib
import uuid
from functools import lru_cache
from pathlib import Path

from .config import REPO_ROOT, repo_path, settings
from .models import Rule

# Keys Kibana's detection engine accepts from a TOML [rule] table. Anything else is
# repo-only metadata and is dropped (and reported) instead of failing the import.
KIBANA_RULE_KEYS = {
    "actions", "alert_suppression", "author", "building_block_type", "data_view_id", "description",
    "enabled", "event_category_override", "exceptions_list", "false_positives", "filters", "from",
    "history_window_start", "index", "interval", "investigation_fields", "language", "license",
    "max_signals", "meta", "name", "new_terms_fields", "note", "query", "references",
    "related_integrations", "required_fields", "risk_score", "risk_score_mapping", "rule_id",
    "rule_name_override", "setup", "severity", "severity_mapping", "tags", "threat", "threshold",
    "tiebreaker_field", "timeline_id", "timeline_title", "timestamp_field", "timestamp_override",
    "to", "type", "version",
}
SIGMA_LEVEL = {  # Sigma level -> (Elastic severity, risk score) using Elastic's own conventions
    "informational": ("low", 21), "low": ("low", 21), "medium": ("medium", 47),
    "high": ("high", 73), "critical": ("critical", 99),
}


def discover(paths: list[str] | None = None) -> list[Path]:
    """All rule files, or only the given ones (CI passes the PR's changed files)."""
    if paths:
        files = [Path(p) if Path(p).is_absolute() else REPO_ROOT / p for p in paths]
        return sorted(p for p in files if p.suffix in (".toml", ".yml", ".yaml") and p.is_file())
    root = repo_path(settings()["rules_dir"])
    return sorted([*root.rglob("*.toml"), *root.rglob("*.yml"), *root.rglob("*.yaml")])


def load_rules(paths: list[str] | None = None) -> list[Rule]:
    return [load_rule(p) for p in discover(paths)]


def load_rule(path: Path) -> Rule:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".toml":
        return _load_toml(path, text)
    return _load_sigma(path, text)


# --------------------------------------------------------------------------- TOML
def _load_toml(path: Path, text: str) -> Rule:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return _broken(path, "toml", text, f"TOML syntax error: {exc}")
    body = data.get("rule", {})
    payload = {k: v for k, v in body.items() if k in KIBANA_RULE_KEYS}
    dropped = sorted(k for k in body if k not in KIBANA_RULE_KEYS)
    payload.setdefault("enabled", True)
    payload.setdefault("interval", "5m")
    return Rule(
        path=path, fmt="toml",
        rule_id=str(body.get("rule_id", "")), name=str(body.get("name", path.stem)),
        language=str(body.get("language", "")).lower(), query=str(body.get("query", "")),
        index=list(body.get("index", []) or []), payload=payload, source_text=text,
        dropped_keys=dropped,
    )


# -------------------------------------------------------------------------- Sigma
@lru_cache(maxsize=4)
def _sigma_backend(target: str):
    from sigma.backends.elasticsearch import EqlBackend, LuceneBackend
    from sigma.plugins import InstalledSigmaPlugins

    specs = [s if not s.endswith((".yml", ".yaml")) else str(repo_path(s))
             for s in settings()["sigma"]["pipelines"][target]]
    pipeline = InstalledSigmaPlugins.autodiscover().get_pipeline_resolver().resolve(specs, target=target)
    return {"eql": EqlBackend, "lucene": LuceneBackend}[target](pipeline)


def _load_sigma(path: Path, text: str) -> Rule:
    from sigma.collection import SigmaCollection

    cfg = settings()["sigma"]
    target = cfg["target"]
    try:
        collection = SigmaCollection.from_yaml(text)
        if len(collection.rules) != 1:
            return _broken(path, "sigma", text, "one Sigma rule per file is required")
        sigma_rule = collection.rules[0]
        queries = _sigma_backend(target).convert(collection)
    except Exception as exc:  # pySigma raises many error types for bad rules
        return _broken(path, "sigma", text, f"Sigma conversion failed: {type(exc).__name__}: {exc}")
    if len(queries) != 1:
        return _broken(path, "sigma", text, f"expected 1 query, pySigma returned {len(queries)}")

    level = sigma_rule.level.name.lower() if sigma_rule.level else "medium"
    severity, risk = SIGMA_LEVEL.get(level, ("medium", 47))
    ls = sigma_rule.logsource
    index = cfg["index_by_logsource"].get(f"{ls.product}/{ls.category}", [])
    author = [a.strip() for a in (sigma_rule.author or "").split(",") if a.strip()] or ["unknown"]

    payload = {
        "rule_id": str(sigma_rule.id),
        "name": sigma_rule.title,
        "description": (sigma_rule.description or "").strip(),
        "author": author,
        "references": list(sigma_rule.references or []),
        "false_positives": list(sigma_rule.falsepositives or []),
        "severity": severity,
        "risk_score": risk,
        "type": "eql" if target == "eql" else "query",
        "language": target,
        "query": queries[0],
        "index": index,
        "tags": ["Sigma", f"OS: {str(ls.product).title()}"] + [f"{t.namespace}.{t.name}" for t in sigma_rule.tags],
        "threat": sigma_tags_to_threat([(t.namespace, t.name) for t in sigma_rule.tags]),
        "enabled": True,
        **cfg["rule_defaults"],
    }
    # Optional per-rule overrides, e.g. a top-level `elastic: {risk_score: 80, index: [...]}`.
    overrides = (sigma_rule.custom_attributes or {}).get("elastic") or {}
    payload.update({k: v for k, v in overrides.items() if k in KIBANA_RULE_KEYS})
    return Rule(
        path=path, fmt="sigma", rule_id=payload["rule_id"], name=payload["name"],
        language=target, query=payload["query"], index=payload["index"], payload=payload,
        source_text=text,
    )


@lru_cache(maxsize=1)
def mitre_catalog() -> dict:
    import json
    return json.loads(repo_path(settings()["mitre"]["file"]).read_text(encoding="utf-8"))


def sigma_tags_to_threat(tags: list[tuple[str, str]]) -> list[dict]:
    """attack.t1003.001 (+ optional tactic tags) -> Kibana `threat` array.

    Names and technique->tactic links come from the vendored ATT&CK catalog, so a
    technique always lands under its real tactic (e.g. T1036.003 under Stealth), even
    when the Sigma author only tagged one tactic."""
    cat = mitre_catalog()
    techs, by_short = cat["techniques"], {v["shortname"]: k for k, v in cat["tactics"].items()}
    wanted = [n.upper() for ns, n in tags if ns == "attack" and n.upper() in techs]

    grouped: dict[str, dict[str, list[str]]] = {}  # tactic id -> parent technique -> subtechniques
    for tid in wanted:
        parent = tid.split(".")[0]
        for short in techs[tid]["tactics"]:
            subs = grouped.setdefault(by_short[short], {}).setdefault(parent, [])
            if "." in tid and tid not in subs:
                subs.append(tid)

    threat = []
    for tactic_id in sorted(grouped):
        threat.append({
            "framework": "MITRE ATT&CK",
            "tactic": {"id": tactic_id, "name": cat["tactics"][tactic_id]["name"],
                       "reference": f"https://attack.mitre.org/tactics/{tactic_id}/"},
            "technique": [{
                "id": parent, "name": techs[parent]["name"],
                "reference": f"https://attack.mitre.org/techniques/{parent}/",
                "subtechnique": [{"id": s, "name": techs[s]["name"],
                                  "reference": f"https://attack.mitre.org/techniques/{s.replace('.', '/')}/"}
                                 for s in subs],
            } for parent, subs in grouped[tactic_id].items()],
        })
    return threat


def _broken(path: Path, fmt: str, text: str, error: str) -> Rule:
    return Rule(path=path, fmt=fmt, rule_id="", name=path.stem, language="", query="", index=[],
                payload={}, source_text=text, load_errors=[error])


def is_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False
