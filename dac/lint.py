"""Stage 1 - deterministic lint.

Same input -> same findings: no network, no LLM. Anything a script can decide for
certain is decided here, so the AI judge (Stage 3) only spends effort on judgement calls.
Severity policy: any `critical` finding fails Stage 1. `major`/`minor` are warnings here,
and become score deductions in Stage 3.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import yaml

from .config import repo_path, settings
from .ecs import ECSSchema
from .loader import is_uuid, mitre_catalog
from .models import Finding, Rule
from .query_analysis import QueryProfile, analyze, to_seconds

SUPPORTED = {("eql", "eql"), ("query", "lucene"), ("esql", "esql")}   # (type, language) we can replay
SEVERITY_RISK = {"low": (0, 21), "medium": (22, 47), "high": (48, 73), "critical": (74, 100)}
INJECTION_PATTERNS = [
    r"ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|prompts?|rules)",
    r"disregard (the |all )?(system|previous|prior) (prompt|instructions)",
    r"\b(ai|llm|model)[ -](judge|reviewer|grader)\b",
    r"\b(score|rate|grade|mark)\b.{0,40}\b(100|perfect|full marks|as passing)\b",
    r"\bsystem prompt\b",
    r"</?\s*(system|instructions|rule_under_review|verified_facts)\s*>",
]
SWITCH_RE = re.compile(r"(?:^|[\s*\"'])[-/–—―]([A-Za-z][\w]{0,15})(?=$|[\s*\"'])")


@dataclass
class ReplayCases:
    by_rule: dict[str, dict] = field(default_factory=dict)   # rule_id -> {"positive": [...], "negative": [...]}
    errors: list[str] = field(default_factory=list)


def load_test_cases() -> ReplayCases:
    cases = ReplayCases()
    folder = repo_path(settings()["tests_dir"])
    for path in sorted(folder.glob("*.y*ml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            cases.errors.append(f"{path.name}: {exc}")
            continue
        rid = str(doc.get("rule_id", ""))
        if rid:
            cases.by_rule[rid] = {"file": path, **doc}
    return cases


def lint_rules(rules: list[Rule], all_rules: list[Rule] | None = None) -> dict[str, list[Finding]]:
    """Lint `rules`; duplicate-id detection looks across `all_rules` (the whole repo)."""
    schema, cases = ECSSchema.load(), load_test_cases()
    id_counts = Counter(r.rule_id for r in (all_rules or rules) if r.rule_id)
    return {r.rel_path: lint_rule(r, schema, cases, id_counts) for r in rules}


def lint_rule(rule: Rule, schema: ECSSchema, cases: ReplayCases, id_counts: Counter) -> list[Finding]:
    cfg = settings()["lint"]
    out: list[Finding] = []
    add = out.append

    if rule.load_errors:
        return [Finding("G001", "gate", "critical", "Rule failed to load or compile",
                        detail="; ".join(rule.load_errors), kind="load_error")]

    # ---------------------------------------------------------------- integrity gate
    p = rule.payload
    required = ["rule_id", "name", "description", "risk_score", "severity", "type", "language", "query"]
    if rule.language != "esql":
        required.append("index")          # ES|QL declares its indices inside the query (FROM ...)
    missing = [k for k in required if p.get(k) in (None, "", [])]
    if missing:
        add(Finding("G002", "gate", "critical", "Missing required rule fields",
                    detail=", ".join(missing), kind="schema"))
    if rule.rule_id and id_counts.get(rule.rule_id, 0) > 1:
        add(Finding("G003", "gate", "critical", "Duplicate rule_id", evidence=rule.rule_id,
                    detail="rule_id must be unique: Kibana import would silently overwrite one rule with the other.",
                    kind="duplicate_id"))
    if rule.rule_id and not is_uuid(rule.rule_id):
        add(Finding("G005", "gate", "major", "rule_id is not a UUID", evidence=rule.rule_id,
                    fix='Generate one: python -c "import uuid; print(uuid.uuid4())"', kind="schema"))
    tc = cases.by_rule.get(rule.rule_id, {})
    if not tc.get("positive") or not tc.get("negative"):
        add(Finding("G004", "gate", "critical", "No replay tests for this rule",
                    detail="Add tests/cases/<rule>.yml with at least one positive (attack) and one "
                           "negative (benign) data set. Untested rules don't merge.", kind="untested"))
    if (p.get("type"), rule.language) not in SUPPORTED:
        add(Finding("G006", "gate", "critical", "Rule type/language cannot be replay-tested",
                    detail=f"type={p.get('type')!r} language={rule.language!r}. Supported: EQL rules, "
                           "Lucene query rules, ES|QL rules. KQL is a Kibana-only language that "
                           "Elasticsearch can't execute directly, so it can't be replayed here.",
                    kind="unsupported"))
    if rule.dropped_keys:
        add(Finding("G008", "gate", "minor", "TOML keys not sent to Kibana",
                    detail=", ".join(rule.dropped_keys), kind="schema"))
    for pattern in INJECTION_PATTERNS:
        m = re.search(pattern, rule.source_text, flags=re.I)
        if m:
            add(Finding("G009", "gate", "critical", "Text that tries to instruct the AI reviewer",
                        evidence=m.group(0), kind="prompt_injection",
                        detail="Rule files are untrusted input to the judge. Remove reviewer-directed text."))
            break
    risk, sev = p.get("risk_score"), str(p.get("severity", "")).lower()
    if isinstance(risk, int) and sev in SEVERITY_RISK and not (SEVERITY_RISK[sev][0] <= risk <= SEVERITY_RISK[sev][1]):
        lo, hi = SEVERITY_RISK[sev]
        add(Finding("G013", "gate", "minor", "risk_score does not match severity",
                    evidence=f"severity={sev}, risk_score={risk}", fix=f"Use a risk_score in {lo}-{hi} for {sev}",
                    kind="metadata"))
    out.extend(_check_mitre(p.get("threat") or []))

    prof = analyze(rule.query, rule.language)
    if prof.parse_error:
        add(Finding("G007", "gate", "major", "Local parser could not read the query",
                    detail=f"{prof.parse_error}. Elasticsearch decides in Stage 2; field checks below "
                           "used a fallback extractor.", kind="parse"))

    out.extend(_check_ecs(rule, prof, schema, cfg))
    out.extend(_check_performance(rule, prof, schema, cfg))
    out.extend(_check_evasion(rule, prof, cfg))
    return out


# ------------------------------------------------------------------------- MITRE
def _check_mitre(threat: list[dict]) -> list[Finding]:
    if not threat:
        return [Finding("G010", "gate", "major", "No MITRE ATT&CK mapping", kind="mitre",
                        fix="Add [[rule.threat]] with tactic + technique (+ subtechnique).")]
    cat = mitre_catalog()
    tactics, techs, version = cat["tactics"], cat["techniques"], cat["attack_version"]
    out = []
    for entry in threat:
        tac = entry.get("tactic", {})
        tac_id = tac.get("id", "")
        if tac_id not in tactics:
            out.append(Finding("G011", "gate", "critical", "Unknown ATT&CK tactic id", evidence=tac_id, kind="mitre"))
        elif tac.get("name") != tactics[tac_id]["name"]:
            out.append(Finding("G012", "gate", "minor", f"Tactic name differs from ATT&CK v{version}",
                               evidence=f'{tac_id} "{tac.get("name")}"', fix=f'"{tactics[tac_id]["name"]}"', kind="mitre"))
        for tech in entry.get("technique", []) or []:
            items = [tech, *(tech.get("subtechnique") or [])]
            for item in items:
                tid = item.get("id", "")
                if tid not in techs:
                    out.append(Finding("G011", "gate", "critical", "Unknown ATT&CK technique id",
                                       evidence=tid, kind="mitre",
                                       detail=f"Not in ATT&CK v{version} (revoked/deprecated ids are excluded)."))
                    continue
                if item.get("name") != techs[tid]["name"]:
                    out.append(Finding("G012", "gate", "minor", f"Technique name differs from ATT&CK v{version}",
                                       evidence=f'{tid} "{item.get("name")}"', fix=f'"{techs[tid]["name"]}"',
                                       kind="mitre"))
                if tac_id in tactics and tactics[tac_id]["shortname"] not in techs[tid]["tactics"]:
                    out.append(Finding("G014", "gate", "minor", "Technique listed under the wrong tactic",
                                       evidence=f"{tid} under {tac_id}",
                                       fix=f"{tid} belongs to: {', '.join(techs[tid]['tactics'])}", kind="mitre"))
    return out


# --------------------------------------------------------------------------- ECS
def _check_ecs(rule: Rule, prof: QueryProfile, schema: ECSSchema, cfg: dict) -> list[Finding]:
    out = []
    for fname in prof.fields:
        v = schema.check(fname)
        if v.status == "unknown":
            out.append(Finding(
                "E001", "ecs_field_accuracy", "critical", f"`{fname}` is not an ECS {schema.version} field",
                evidence=fname, kind="unknown_field",
                detail="In EQL this fails with 'Unknown column'; in KQL/Lucene it silently matches nothing.",
                fix=f"Use `{v.suggestion}`" if v.suggestion else "Use the ECS field for this concept "
                    "(https://www.elastic.co/docs/reference/ecs)"))
        elif v.status == "keyword_suffix":
            out.append(Finding("E002", "ecs_field_accuracy", "critical", f"`.keyword` suffix on `{v.base_field}`",
                               evidence=fname, detail=v.reason, fix=f"Use `{v.base_field}`", kind="keyword_suffix"))
        elif v.status == "non_ecs_multi_field":
            out.append(Finding("E003", "ecs_field_accuracy", "major", f"Integration-specific sub-field `{fname}`",
                               evidence=fname, detail=v.reason, fix=f"Use `{v.base_field}` (EQL `:` is already "
                               "case-insensitive)", kind="non_ecs_multi_field"))
        elif rule.language == "eql" and v.es_type in ("match_only_text", "text"):
            out.append(Finding("E004", "ecs_field_accuracy", "critical", f"EQL cannot query text field `{fname}`",
                               evidence=fname, kind="text_field",
                               detail="Elasticsearch EQL does not support text fields.",
                               fix=f"Use the keyword/wildcard field `{v.base_field or fname}`"))
        if (rule.language == "eql" and fname not in prof.optional_fields
                and any(fname.startswith(pfx) for pfx in cfg["optional_field_prefixes"])):
            out.append(Finding("E005", "ecs_field_accuracy", "minor", f"`{fname}` is not marked optional",
                               evidence=fname, kind="optional_field",
                               detail="Some data sources (e.g. Security 4688 events) lack this field; EQL errors "
                                      "when no searched index maps it.",
                               fix=f"Write `?{fname}`"))
    return out


# ------------------------------------------------------------------- performance
def _check_performance(rule: Rule, prof: QueryProfile, schema: ECSSchema, cfg: dict) -> list[Finding]:
    out = []
    p = rule.payload
    for pattern in rule.index:
        if pattern in ("*", "*:*"):
            out.append(Finding("P007", "query_performance", "critical", "Rule searches every index",
                               evidence=pattern, kind="broad_index",
                               fix="List the integration data streams, e.g. logs-endpoint.events.process-*"))
        elif pattern in cfg["broad_index_patterns"]:
            out.append(Finding("P007", "query_performance", "minor", "Very broad index pattern",
                               evidence=pattern, kind="broad_index",
                               fix="Scope to the data streams that carry this telemetry."))

    seq = prof.sequence
    if seq:
        limit = to_seconds(cfg["max_sequence_maxspan"])
        if seq.maxspan is None:
            out.append(Finding("P001", "query_performance", "critical", "Sequence without maxspan",
                               evidence="sequence", kind="unbounded_sequence",
                               detail="Partial matches are kept forever: memory grows and unrelated events chain.",
                               fix=f"Add `with maxspan=` (policy max {cfg['max_sequence_maxspan']})"))
        elif seq.maxspan_seconds and seq.maxspan_seconds >= 86400:
            out.append(Finding("P002", "query_performance", "critical", "Sequence window is effectively unbounded",
                               evidence=f"maxspan={seq.maxspan}", kind="unbounded_sequence",
                               fix=f"Use the shortest window the behavior needs (policy max {cfg['max_sequence_maxspan']})"))
        elif limit and seq.maxspan_seconds and seq.maxspan_seconds > limit:
            out.append(Finding("P002", "query_performance", "major", "Sequence maxspan above policy",
                               evidence=f"maxspan={seq.maxspan}", kind="unbounded_sequence",
                               fix=f"maxspan <= {cfg['max_sequence_maxspan']}"))
        if not any(seq.join_keys):
            out.append(Finding("P003", "query_performance", "critical", "Sequence has no join keys (`by`)",
                               evidence="sequence", kind="missing_join_key",
                               detail="Events from different hosts/processes are correlated with each other.",
                               fix="Join on host.id and an entity id, e.g. `sequence by host.id, process.entity_id`"))
        elif all(set(k) <= {"process.pid", "host.id", "host.name"} for k in seq.join_keys if k) \
                and any("process.pid" in k for k in seq.join_keys) and not seq.has_until:
            out.append(Finding("P004", "query_performance", "minor", "Sequence joined on PID without `until`",
                               evidence="process.pid", kind="pid_reuse",
                               fix='Join on process.entity_id, or add `until [process where event.type == "end"]`'))
    if "any" in prof.event_categories:
        out.append(Finding("P005", "query_performance", "major", "`any where` scans every event category",
                           evidence="any where", kind="any_category",
                           fix="Use the real category, e.g. `process where`"))

    by_field: dict[str, list[str]] = defaultdict(list)
    for w in prof.wildcards:
        if w.pattern.startswith(("*", "?")):
            by_field[w.field].append(w.pattern)
    for fname, patterns in by_field.items():
        es_type = schema.check(fname).es_type
        if es_type is None or es_type == "wildcard":
            # unknown field: E001 already fails it. `wildcard` type (e.g. process.command_line
            # in ECS) is built for leading wildcards, so no penalty.
            continue
        # "*foo*" / "*foo*bar" (several wildcards) cost more than a pure suffix match "*foo".
        multi = any(pt.count("*") + pt.count("?") > 1 for pt in patterns)
        out.append(Finding(
            "P006", "query_performance", "major" if multi else "minor",
            f"Leading wildcard on {es_type or 'non-wildcard'} field `{fname}`",
            evidence=", ".join(f'"{pt}"' for pt in patterns[:3]), kind="leading_wildcard",
            detail="A leading wildcard on a keyword field makes every shard walk the field's whole term "
                   "dictionary. Fields mapped as `wildcard` in ECS (e.g. process.command_line) are exempt.",
            fix="Match exact values (e.g. process.name) or move the substring match to a wildcard-type field."))

    lookback = to_seconds(str(p.get("from", "")).replace("now-", "")) if str(p.get("from", "")).startswith("now-") else None
    interval = to_seconds(str(p.get("interval", "5m")))
    if lookback and interval and lookback <= interval:
        out.append(Finding("P008", "query_performance", "major", "No look-back overlap between rule runs",
                           evidence=f"from={p.get('from')}, interval={p.get('interval', '5m')}", kind="schedule_gap",
                           detail="Events that arrive late (ingest delay) fall between two runs and are never seen.",
                           fix="Set `from` = interval + look-back (e.g. now-9m for 5m) and timestamp_override = event.ingested"))

    norm = {_strip_keyword(f) for f in prof.fields}
    windows_rule = any(lit.lower().endswith(".exe") or "\\" in lit for lit in prof.literals) \
        or any("windows" in i or "endpoint" in i for i in rule.index)
    if ("process" in prof.event_categories or any(f.startswith("process.") for f in norm)) and windows_rule \
            and "host.os.type" not in norm and rule.language == "eql":
        out.append(Finding("P009", "query_performance", "minor", "No OS scoping", evidence="host.os.type",
                           kind="missing_scoping", fix='Add `host.os.type == "windows"`'))
    if norm & {"process.command_line", "process.args"} and not norm & set(cfg["binary_identity_fields"]):
        out.append(Finding("P010", "query_performance", "major", "Command-line match without binary scoping",
                           evidence="process.executable", kind="missing_scoping",
                           detail="Every process event's command line gets pattern-matched, and any binary "
                                  "with similar arguments fires.",
                           fix="Anchor on process.executable / process.name / ?process.pe.original_file_name"))
    return out


# ------------------------------------------------------------- evasion & FP hygiene
def _check_evasion(rule: Rule, prof: QueryProfile, cfg: dict) -> list[Finding]:
    out = []
    schema = ECSSchema.load()
    norm = {_strip_keyword(f) for f in prof.fields}
    # Read through hallucinated names to what the author meant (process.cmd -> process.command_line),
    # so intent-level checks (windash, renamed binaries) still run on a broken rule.
    norm |= {s for f in prof.fields if (s := schema.check(f).suggestion)}
    ci_fields = set(cfg["case_insensitive_fields"])

    flagged = {}
    for op in prof.case_sensitive_ops:
        base = _strip_keyword(op.field)
        if base in ci_fields and base not in flagged:
            flagged[base] = op
    for base, op in flagged.items():
        out.append(Finding("V001", "evasion_fp_hygiene", "major", f"Case-sensitive match on `{base}`",
                           evidence=f'{op.field} {op.op} "{op.literal}"', kind="case_sensitivity",
                           detail="Windows names and paths are case-insensitive: `ProcDump.exe` bypasses it.",
                           fix=f'Use `:` (case-insensitive), e.g. `{base} : "{op.literal}"`'))

    exe_literals = [lit for lit in prof.literals if lit.lower().endswith(".exe")]
    if exe_literals and norm & {"process.name", "process.executable"} and "process.pe.original_file_name" not in norm:
        out.append(Finding("V002", "evasion_fp_hygiene", "major", "Renamed-binary evasion not covered",
                           evidence="process.pe.original_file_name", kind="renamed_binary",
                           detail=f"Matches only the file name ({exe_literals[0]}); a copied/renamed binary keeps "
                                  "its PE OriginalFileName.",
                           fix='Add `?process.pe.original_file_name : "<OriginalFileName>"` as an alternative'))

    if norm & {"process.args", "process.command_line"}:
        switches = {}
        for lit in prof.literals:
            for m in SWITCH_RE.finditer(lit):
                switches.setdefault(m.group(1).lower(), set()).add(m.group(0).strip(" *\"'")[0])
        missing = sorted(sw for sw, prefixes in switches.items() if "-" in prefixes and "/" not in prefixes)
        if missing:
            out.append(Finding("V003", "evasion_fp_hygiene", "major", "Command-line switch without windash variants",
                               evidence=", ".join(f"-{sw}" for sw in missing), kind="windash",
                               detail="Windows tools usually accept /flag and Unicode dashes (– — ―) as well as -flag.",
                               fix="List every prefix: " + ", ".join(f'"{c}{missing[0]}"' for c in "-/–—―")))

    if "process" in prof.event_categories and "event.type" not in norm and "event.action" not in norm:
        out.append(Finding("V004", "evasion_fp_hygiene", "major", "Process rule not limited to start events",
                           evidence='event.type == "start"', kind="duplicate_alerts",
                           detail="Process events include start AND end; the rule alerts twice per process.",
                           fix='Add `event.type == "start"`'))

    spoofable = set(cfg["spoofable_exclusion_fields"])
    for fname in prof.negated_fields:
        base = _strip_keyword(fname)
        if base in spoofable:
            out.append(Finding("V006", "evasion_fp_hygiene", "major", f"Exclusion anchored on `{base}`",
                               evidence=base, kind="weak_exclusion",
                               detail="Names and user names are attacker-controlled or too broad; an attacker who "
                                      "matches the exclusion is invisible.",
                               fix="Exclude a reviewed workflow via a Kibana exception on process.executable + "
                                   "process.code_signature.subject_name (+ parent), not on names"))

    p = rule.payload
    if not p.get("false_positives") and not p.get("note"):
        out.append(Finding("V009", "evasion_fp_hygiene", "minor", "No false-positive guidance",
                           evidence="false_positives", kind="fp_docs",
                           fix="Document expected benign triggers and how to triage them (false_positives / note)."))
    return out


def _strip_keyword(fname: str) -> str:
    return fname[:-8] if fname.endswith(".keyword") else fname
