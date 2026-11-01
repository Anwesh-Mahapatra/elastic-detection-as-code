"""Stage 2 - replay ECS logs through Elasticsearch and check every rule fires (or stays quiet).

Why a real Elasticsearch instead of a Python re-implementation of EQL?
Only Elasticsearch decides what Elasticsearch matches: case rules, wildcard semantics,
"Unknown column" errors, sequence state machines. Re-implementing those would test the
re-implementation, not the rule.

Fidelity detail that matters: test indices get ECS-accurate mappings (keyword vs wildcard
vs date...). With default dynamic mapping, strings become `text` + `.keyword`, which makes
`.keyword` rules pass here and fail in production - the exact bug we want to catch.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .config import repo_path, settings
from .ecs import ECSSchema
from .elastic import ElasticClient, error_reason
from .lint import load_test_cases
from .models import Finding, Rule
from .query_analysis import analyze

SKIP_TYPES = {"object", "nested"}
TYPE_MAP = {"scaled_float": "float", "constant_keyword": "keyword"}  # avoid per-field params in test indices


@dataclass
class ReplayResult:
    rule: str
    rule_id: str
    name: str
    case: str                     # positive | negative
    data: str
    expected: str
    hits: int = 0
    matched_ids: list[str] = field(default_factory=list)
    passed: bool = False
    error: str | None = None


def load_events(path: Path) -> list[dict]:
    """A JSON array, a single JSON object, or NDJSON (one event per line)."""
    text = path.read_text(encoding="utf-8").strip()
    if text.startswith("["):
        return json.loads(text)
    if text.startswith("{") and "\n{" not in text:
        return [json.loads(text)]
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def flatten(doc: dict, prefix: str = "") -> dict[str, object]:
    out = {}
    for key, value in doc.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(flatten(value, f"{name}."))
        else:
            out[name] = value
    return out


def build_mapping(field_names: set[str], schema: ECSSchema) -> dict:
    props: dict = {}
    for fname in sorted(field_names):
        info = schema.fields.get(fname)
        if not info or info["type"] in SKIP_TYPES:
            continue   # non-ECS fields fall through to the dynamic template (keyword)
        leaf = {"type": TYPE_MAP.get(info["type"], info["type"])}
        if leaf["type"] == "keyword":
            leaf["ignore_above"] = 1024
        if info.get("multi_fields"):
            leaf["fields"] = {k: {"type": TYPE_MAP.get(t, t)} for k, t in info["multi_fields"].items()}
        node = props
        parts = fname.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {"properties": {}}).setdefault("properties", {})
        node[parts[-1]] = leaf
    return {
        "dynamic_templates": [{"strings_as_keyword": {
            "match_mapping_type": "string", "mapping": {"type": "keyword", "ignore_above": 1024}}}],
        "properties": props,
    }


class Replayer:
    def __init__(self, client: ElasticClient, keep: bool = False):
        self.client = client
        self.keep = keep
        self.cfg = settings()["replay"]
        self.schema = ECSSchema.load()
        self.run_id = uuid.uuid4().hex[:8]
        self.indices: dict[str, str] = {}   # data file -> test index

    def prepare(self, data_files: set[str], rule_fields: set[str]) -> None:
        """One index per data file, shared by every rule that replays it (scales to many rules)."""
        for rel in sorted(data_files):
            path = repo_path(rel)
            events = load_events(path)
            doc_fields = set()
            for ev in events:
                doc_fields.update(flatten(ev))
            # Test data must itself be ECS-clean, or it could "prove" a hallucinated field works.
            bad = sorted(f for f in doc_fields if self.schema.check(f).status not in ("ecs", "allowlisted"))
            if bad:
                raise RuntimeError(f"{rel} contains non-ECS fields {bad[:5]}; fix the test data")
            fields = doc_fields | set(rule_fields)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()[:10]
            index = f"{self.cfg['index_prefix']}-{self.run_id}-{digest}"
            body = {"settings": {"number_of_shards": 1, "number_of_replicas": 0,
                                 "index.mapping.total_fields.limit": 5000},
                    "mappings": build_mapping(fields, self.schema)}
            r = self.client.es("PUT", index, json=body)
            if not r.ok:
                raise RuntimeError(f"create {index}: {error_reason(r)}")
            lines = []
            for i, ev in enumerate(events):
                doc_id = (ev.get("event") or {}).get("id") or f"{Path(rel).stem}-{i}"
                lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
                lines.append(json.dumps(ev))
            r = self.client.es("POST", "_bulk?refresh=wait_for", data="\n".join(lines) + "\n",
                               headers={"Content-Type": "application/x-ndjson"})
            if not r.ok or r.json().get("errors"):
                bad = [it for it in r.json().get("items", []) if it["index"].get("error")][:2] if r.ok else []
                raise RuntimeError(f"bulk {rel}: {error_reason(r) if not r.ok else bad}")
            self.indices[rel] = index

    def cleanup(self) -> None:
        if not self.keep:
            for index in self.indices.values():
                self.client.es("DELETE", index)

    def run_query(self, rule: Rule, index: str) -> tuple[int, list[str]]:
        cap = self.cfg["max_hits"]
        if rule.language == "eql":
            r = self.client.es("POST", f"{index}/_eql/search", json={"query": rule.query, "size": cap})
            if not r.ok:
                raise RuntimeError(error_reason(r))
            hits = r.json()["hits"]
            if "sequences" in hits:
                return len(hits["sequences"]), [e["_id"] for s in hits["sequences"] for e in s["events"]]
            return len(hits.get("events", [])), [e["_id"] for e in hits.get("events", [])]
        if rule.language == "lucene":
            body = {"size": cap, "query": {"query_string": {"query": rule.query, "analyze_wildcard": True}}}
            r = self.client.es("POST", f"{index}/_search", json=body)
            if not r.ok:
                raise RuntimeError(error_reason(r))
            hits = r.json()["hits"]["hits"]
            return len(hits), [h["_id"] for h in hits]
        if rule.language == "esql":
            query = re.sub(r"(?is)^\s*FROM\s+[^|]+?(\s+METADATA\s+[^|]+)?(?=\||$)",
                           lambda m: f"FROM {index}{m.group(1) or ''} ", rule.query, count=1)
            r = self.client.es("POST", "_query", json={"query": query})
            if not r.ok:
                raise RuntimeError(error_reason(r))
            body = r.json()
            cols = [c["name"] for c in body.get("columns", [])]
            ids = [row[cols.index("_id")] for row in body.get("values", [])] if "_id" in cols else []
            return len(body.get("values", [])), ids
        raise RuntimeError(f"language {rule.language!r} cannot be replayed")


def replay(rules: list[Rule], client: ElasticClient, keep: bool = False) -> list[ReplayResult]:
    cases = load_test_cases()
    plan = []
    for rule in rules:
        if rule.load_errors:
            continue
        tc = cases.by_rule.get(rule.rule_id)
        if not tc:
            continue   # Stage 1 (G004) already fails untested rules
        for case in ("positive", "negative"):
            for spec in tc.get(case) or []:
                plan.append((rule, case, spec))

    # Map every ECS field a rule references, so a valid ECS field that the test data
    # happens not to contain still behaves like production (exists, no "Unknown column").
    schema, rule_fields = ECSSchema.load(), set()
    for rule in rules:
        if not rule.load_errors:
            rule_fields.update(f for f in analyze(rule.query, rule.language).fields if f in schema.fields)

    rep = Replayer(client, keep=keep)
    try:
        rep.prepare({spec["data"] for _, _, spec in plan}, rule_fields)

        def execute(item):
            rule, case, spec = item
            exp_min = int(spec.get("min_hits", 1)) if case == "positive" else 0
            exp_max = spec.get("max_hits", 0 if case == "negative" else None)
            exp_max = None if exp_max is None else int(exp_max)
            if case == "negative":
                expected = f"<= {exp_max}"
            else:
                expected = f"== {exp_min}" if exp_max == exp_min else f">= {exp_min}" + (f", <= {exp_max}" if exp_max is not None else "")
            if spec.get("expect_ids"):
                expected += f" incl. {len(spec['expect_ids'])} listed ids"
            res = ReplayResult(rule.rel_path, rule.rule_id, rule.name, case, spec["data"], expected)
            try:
                res.hits, res.matched_ids = rep.run_query(rule, rep.indices[spec["data"]])
            except RuntimeError as exc:
                res.error = str(exc)
                return res
            ids_ok = set(spec.get("expect_ids") or []) <= set(res.matched_ids)
            res.passed = ids_ok and res.hits >= exp_min and (exp_max is None or res.hits <= exp_max)
            return res

        with ThreadPoolExecutor(max_workers=settings()["replay"]["parallelism"]) as pool:
            return list(pool.map(execute, plan))
    finally:
        rep.cleanup()


def results_to_findings(results: list[ReplayResult]) -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = {}
    for r in results:
        if r.passed:
            continue
        if r.error:
            title, detail = "Query failed in Elasticsearch", r.error
        elif r.case == "positive":
            title, detail = "Rule missed the attack data", f"{r.hits} hit(s) on {r.data}, expected {r.expected}"
        else:
            title, detail = "Rule fired on benign data", f"{r.hits} hit(s) on {r.data}, expected {r.expected}"
        out.setdefault(r.rule, []).append(Finding(
            "R001" if r.error else ("R002" if r.case == "positive" else "R003"), "gate", "critical",
            title, detail=detail, evidence=r.data, kind="replay_failure", source="replay"))
    return out


def results_to_dicts(results: list[ReplayResult]) -> list[dict]:
    return [asdict(r) for r in results]
