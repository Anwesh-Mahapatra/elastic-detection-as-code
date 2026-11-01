"""Stage 3 - AI-as-a-Judge pull-request gate.

    python -m dac.ai_judge_elastic --base origin/main --post-comment     # in CI
    python -m dac.ai_judge_elastic --files rules/elastic/x.toml           # locally (needs Ollama)
    python -m dac.ai_judge_elastic --provider replay --files ...          # offline, recorded answers

Design rules (why the LLM can't be talked into a pass):
  1. The LLM never scores. It returns evidence-backed findings; code turns them into points.
  2. Every LLM finding must quote the rule verbatim or name a token that is really absent,
     and must not contradict the ECS schema. Anything else is discarded and listed.
  3. Deterministic lint + Elasticsearch replay results go in as <verified_facts> the LLM
     must not contradict, and their deductions apply no matter what the LLM says.
  4. Rule text is untrusted input (prompt injection is linted AND reported by the judge),
     and every string rendered into the PR comment is HTML-escaped.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import jsonschema
import requests
import yaml

from .config import REPO_ROOT, env, repo_path, settings
from .ecs import ECSSchema
from .lint import lint_rules
from .loader import load_rules, mitre_catalog
from .models import SEVERITY_RANK, Finding, Rule
from .query_analysis import IDENT, analyze

MARKER = "<!-- ai-judge-elastic -->"
SCORED = ("ecs_field_accuracy", "query_performance", "evasion_fp_hygiene")
ICON = {"critical": "❌", "major": "⚠️", "minor": "🔸", "info": "ℹ️"}
SHORT = {"ecs_field_accuracy": "ECS", "query_performance": "Perf", "evasion_fp_hygiene": "Evasion/FP", "gate": "Gate"}


class JudgeError(RuntimeError):
    pass


@dataclass
class Verdict:
    rule: Rule
    findings: list[Finding] = field(default_factory=list)
    discarded: list[dict] = field(default_factory=list)
    category_scores: dict[str, int] = field(default_factory=dict)
    score: int = 0
    passed: bool = False
    summary: str = ""
    strengths: list[str] = field(default_factory=list)
    suggested_query: str = ""
    suggestion_check: str = ""
    error: str | None = None
    cached: bool = False
    seconds: float = 0.0


# =============================================================================== providers
class Provider:
    name = "base"

    def __init__(self, model: str):
        self.model = model

    def complete(self, system: str, user: str, schema: dict, rule: Rule) -> str:  # pragma: no cover
        raise NotImplementedError


class OllamaProvider(Provider):
    """Local, free, open-weight models. Structured outputs: JSON schema in `format`."""
    name = "ollama"

    def __init__(self, model: str, host: str, cfg: dict):
        super().__init__(model)
        self.host, self.cfg = host.rstrip("/"), cfg

    def complete(self, system, user, schema, rule):
        body = {"model": self.model, "stream": False, "format": schema, "keep_alive": "15m",
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "options": {"temperature": self.cfg["temperature"], "seed": self.cfg["seed"],
                            "num_ctx": self.cfg["num_ctx"]}}
        r = requests.post(f"{self.host}/api/chat", json=body, timeout=self.cfg["timeout_seconds"])
        if not r.ok:
            raise JudgeError(f"ollama HTTP {r.status_code}: {r.text[:300]}")
        try:
            return r.json()["message"]["content"]
        except (KeyError, ValueError) as exc:
            raise JudgeError(f"unexpected ollama response: {r.text[:300]}") from exc


class OpenAICompatProvider(Provider):
    """Any OpenAI-compatible endpoint: GitHub Models (GITHUB_TOKEN + `models: read`), vLLM, LM Studio..."""
    name = "openai_compat"

    def __init__(self, model: str, base_url: str, api_key: str, cfg: dict):
        super().__init__(model)
        self.base_url, self.api_key, self.cfg = base_url.rstrip("/"), api_key, cfg

    def complete(self, system, user, schema, rule):
        strict = _strict_schema(schema)
        formats = [{"type": "json_schema", "json_schema": {"name": "scorecard", "strict": True, "schema": strict}},
                   {"type": "json_object"}]   # fallback for servers without json_schema support
        last = ""
        for fmt in formats:
            body = {"model": self.model, "temperature": self.cfg["temperature"], "response_format": fmt,
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
            r = requests.post(f"{self.base_url}/chat/completions", json=body, timeout=self.cfg["timeout_seconds"],
                              headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"})
            if r.ok:
                try:
                    return r.json()["choices"][0]["message"]["content"]
                except (KeyError, IndexError, ValueError) as exc:
                    raise JudgeError(f"unexpected response: {r.text[:300]}") from exc
            last = f"HTTP {r.status_code}: {r.text[:300]}"
            if r.status_code != 400:
                break
        raise JudgeError(f"openai_compat {last}")


class ReplayProvider(Provider):
    """Returns recorded LLM answers (demo/judge_responses/<rule_id>.json): deterministic demos + tests."""
    name = "replay"

    def __init__(self, model: str, folder: Path):
        super().__init__(model)
        self.folder = folder

    def complete(self, system, user, schema, rule):
        path = self.folder / f"{rule.rule_id}.json"
        if not path.is_file():
            raise JudgeError(f"no recorded response at {path.relative_to(REPO_ROOT)}")
        return path.read_text(encoding="utf-8")


def make_provider(name: str, model: str) -> Provider:
    cfg = settings()["judge"]
    if name == "ollama":
        return OllamaProvider(model, env("OLLAMA_HOST", cfg["ollama_host"]), cfg)
    if name == "openai_compat":
        key = env("JUDGE_API_KEY") or env("GITHUB_TOKEN")
        if not key:
            raise JudgeError("openai_compat needs JUDGE_API_KEY (or GITHUB_TOKEN for GitHub Models)")
        return OpenAICompatProvider(model, env("JUDGE_BASE_URL", cfg["openai_base_url"]), key, cfg)
    if name == "replay":
        return ReplayProvider(model, repo_path(cfg["replay_dir"]))
    raise JudgeError(f"unknown provider {name!r}")


def _strict_schema(node):
    """OpenAI strict mode rejects some JSON-schema keywords; drop them (code re-validates anyway)."""
    if isinstance(node, dict):
        return {k: _strict_schema(v) for k, v in node.items()
                if k not in ("$schema", "title", "maxLength", "maxItems", "description")}
    if isinstance(node, list):
        return [_strict_schema(v) for v in node]
    return node


# ================================================================================== prompt
def _defang(text: str) -> str:
    """Stop untrusted rule text from closing or faking the prompt's own delimiter tags."""
    return re.sub(r"<(/?)\s*(verified_facts|rule_under_review|compiled_query)",
                  r"[\1\2 tag removed]", text, flags=re.I)


def build_user_prompt(rule: Rule, det: list[Finding], replay: list[dict], schema: dict) -> str:
    ecs = ECSSchema.load()
    prof = analyze(rule.query, rule.language)
    lines = [f"ECS {ecs.version} lookup for every field the query uses:"]
    for fname in prof.fields:
        v = ecs.check(fname)
        if v.status == "ecs":
            lines.append(f"- {fname}: ECS, type `{v.es_type}`")
        elif v.status == "multi_field":
            lines.append(f"- {fname}: ECS multi-field of {v.base_field}, type `{v.es_type}`")
        elif v.status == "allowlisted":
            lines.append(f"- {fname}: not core ECS, allowed integration field ({v.reason})")
        else:
            hint = f"; the ECS field is `{v.suggestion}`" if v.suggestion else ""
            lines.append(f"- {fname}: NOT ECS{(' - ' + v.reason) if v.reason else ''}{hint}")
    wild = sorted({f for f in prof.fields if ecs.check(f).es_type == "wildcard"})
    lines.append(f"Fields of ECS type `wildcard` here (leading wildcards are fine on them): {', '.join(wild) or 'none'}")
    lines.append("")
    lines.append("Findings already reported by the deterministic linter (do NOT repeat them):")
    lines += [f"- [{f.severity}] {f.check} {f.title}" + (f" (evidence: {f.evidence})" if f.evidence else "")
              for f in sorted(det, key=lambda f: SEVERITY_RANK[f.severity])] or ["- none"]
    lines.append("")
    lines.append("Elasticsearch replay results (Stage 2):")
    mine = [r for r in replay if r.get("rule") == rule.rel_path]
    lines += [f"- {r['case']} {Path(r['data']).name}: {'ERROR ' + r['error'] if r.get('error') else str(r['hits']) + ' hit(s), expected ' + r['expected']}"
              f" -> {'PASS' if r['passed'] else 'FAIL'}" for r in mine] or ["- not available in this run"]

    parts = ["<verified_facts>", *lines, "</verified_facts>", "",
             f'<rule_under_review path="{rule.rel_path}" format="{rule.fmt}">', _defang(rule.source_text.strip()),
             "</rule_under_review>"]
    if rule.fmt == "sigma":
        parts += ["", f'<compiled_query language="{rule.language}">', _defang(rule.query), "</compiled_query>"]
    parts += ["", "Review the rule. Return only a JSON object matching this JSON schema:",
              json.dumps(schema, separators=(",", ":"))]
    return "\n".join(parts)


# ============================================================================= grounding
def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def _clean(evidence: str) -> str:
    """Remove one layer of wrapping backticks/quotes only when they wrap the whole snippet,
    so `file.name : "*lsass*.dmp"` keeps its closing quote."""
    ev = evidence.strip()
    if len(ev) >= 2 and ev[0] == ev[-1] and ev[0] in "`'\"":
        ev = ev[1:-1].strip()
    return ev


def _fields_in(text: str, base: bool = False) -> list[str]:
    """Dotted field names mentioned in a string. base=True folds `x.keyword` into `x`."""
    found = [m.lstrip("?") for m in re.findall(r"\??" + IDENT, text) if "." in m]
    return [f[:-8] if base and f.endswith(".keyword") else f for f in found]


# Kinds that describe something PRESENT in the rule. Small models sometimes tag such a quote
# as "absence"; if the snippet is verifiably in the rule we read it as the quote it is.
PRESENCE_KINDS = {"unknown_field", "keyword_suffix", "wrong_field", "text_field", "leading_wildcard",
                  "unbounded_sequence", "any_category", "regex_cost", "broad_index", "schedule_gap",
                  "case_sensitivity", "weak_exclusion", "prompt_injection"}
# Titles that are praise, not problems ("Robust windash coverage"). Seen in live runs with small models.
PRAISE_RE = re.compile(r"^\s*(correct|robust|good|great|proper|properly|well[- ]|excellent|strong|solid|"
                       r"comprehensive|effective|appropriate|nice)\b", re.I)


def ground(rule: Rule, raw: list[dict], det: list[Finding], dedupe_kinds: set[str]) -> tuple[list[Finding], list[dict]]:
    """Keep only LLM findings that are anchored in the rule and consistent with the ECS schema."""
    ecs = ECSSchema.load()
    haystack = _norm(rule.source_text + "\n" + rule.query)
    query_fields = set(analyze(rule.query, rule.language).fields)
    det_by_kind: dict[str, set[str]] = {}
    for f in det:
        det_by_kind.setdefault(f.kind, set()).update(_fields_in(f.evidence, base=True) or ["*"])
    # Fields the linter already failed on ECS grounds: any further ECS complaint about them is a repeat.
    det_ecs_fields = {fld for f in det if f.category == "ecs_field_accuracy"
                      for fld in _fields_in(f.evidence, base=True)}

    kept, dropped = [], []
    for item in raw:
        ev = _clean(item.get("evidence", ""))
        etype = item["evidence_type"]
        if etype == "absence" and item["kind"] in PRESENCE_KINDS and ev and _norm(ev) in haystack:
            etype = "quote"
        reason = None
        if PRAISE_RE.match(item.get("title", "")):
            reason = "describes a strength, not a problem"
        elif not ev:
            reason = "no evidence"
        elif etype == "quote":
            variants = {ev, ev.replace("\\\\", "\\"), ev.replace("\\", "\\\\")}
            if not any(_norm(v) in haystack for v in variants):
                reason = "quoted evidence is not in the rule"
        else:  # absence
            fields = _fields_in(ev)
            if fields and all(f in query_fields for f in fields):
                reason = f"claims {', '.join(fields)} is missing, but the query uses it"
            elif not fields and _norm(ev) in _norm(rule.query):
                reason = "claims a token is missing, but it is in the query"

        fields = _fields_in(ev)
        if reason is None and item["kind"] in ("unknown_field", "keyword_suffix") and fields \
                and all(ecs.check(f).status == "ecs" for f in fields):
            reason = f"contradicts ECS {ecs.version}: {', '.join(fields)} is a valid ECS field"
        if reason is None and item["kind"] == "leading_wildcard" and fields \
                and all(ecs.check(f).es_type == "wildcard" for f in fields):
            reason = f"{', '.join(fields)} is ECS type `wildcard`, built for leading wildcards"
        mine = set(_fields_in(ev, base=True))
        if reason is None and item["kind"] in dedupe_kinds and item["kind"] in det_by_kind:
            known = det_by_kind[item["kind"]]
            if "*" in known or not mine or mine & known:
                reason = "duplicate of a deterministic lint finding"
        if reason is None and item["category"] == "ecs_field_accuracy" and mine and mine <= det_ecs_fields:
            reason = "duplicate of a deterministic lint finding"
        if reason:
            dropped.append({"title": item.get("title", ""), "kind": item.get("kind"), "evidence": ev, "reason": reason})
            continue
        severity = "critical" if item["kind"] == "prompt_injection" else item["severity"]
        kept.append(Finding(f"AI-{item['kind']}", item["category"], severity, item["title"],
                            detail=item.get("explanation", ""), evidence=ev, fix=item.get("recommendation", ""),
                            kind=item["kind"], source="ai_judge"))
    return kept, dropped


def check_suggestion(query: str) -> str:
    """Deterministically sanity-check the LLM's rewritten query before showing it to humans."""
    if not query.strip():
        return ""
    prof = analyze(query, "eql")
    if prof.parse_error:
        return "does not parse locally"
    ecs = ECSSchema.load()
    bad = [f for f in prof.fields if ecs.check(f).status not in ("ecs", "allowlisted", "multi_field")]
    return f"uses non-ECS fields: {', '.join(bad)}" if bad else "parses, ECS-clean"


# ================================================================================= scoring
def score(findings: list[Finding], rubric: dict) -> tuple[dict[str, int], int]:
    cats = {c: spec["weight"] for c, spec in rubric["categories"].items()}
    for f in findings:
        if f.category in cats:
            cats[f.category] -= rubric["deductions"][f.severity]
    cats = {c: max(0, v) for c, v in cats.items()}
    total = sum(cats.values())
    if any(f.severity == "critical" for f in findings):
        total = min(total, rubric["critical_cap"])
    return cats, total


# ================================================================================== judge
def parse_llm_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in model output")
    return json.loads(text[start:end + 1])


def judge_rule(rule: Rule, det_all: list[Finding], replay: list[dict], provider: Provider,
               system: str, schema: dict, rubric: dict, cache_dir: Path | None) -> Verdict:
    started = time.time()
    v = Verdict(rule=rule)
    det_scored = [f for f in det_all if f.category in SCORED]
    det_gate_critical = [f for f in det_all if f.category == "gate" and f.severity == "critical"]
    user = build_user_prompt(rule, det_all, replay, schema)

    key = hashlib.sha256(json.dumps([rubric["prompt_version"], provider.name, provider.model, system, user]).encode()).hexdigest()
    cache_file = cache_dir / f"{key}.json" if cache_dir else None
    data, errors = None, []
    if cache_file and cache_file.is_file():
        data, v.cached = json.loads(cache_file.read_text(encoding="utf-8")), True
    else:
        prompt = user
        for _attempt in range(settings()["judge"]["max_retries"] + 1):
            try:
                candidate = parse_llm_json(provider.complete(system, prompt, schema, rule))
                jsonschema.validate(candidate, schema)
                data = candidate
                break
            except (ValueError, jsonschema.ValidationError) as exc:
                errors.append(str(exc).splitlines()[0][:300])
                prompt = (user + "\n\nYour previous answer was rejected: " + errors[-1] +
                          "\nReturn ONLY a JSON object that matches the schema.")
            except (JudgeError, requests.RequestException) as exc:
                errors.append(str(exc)[:300])
                break
        if data is not None and cache_file:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    if data is None:
        v.error = "; ".join(errors) or "no answer"
        v.findings = det_all
        v.category_scores, v.score = score(det_scored + det_gate_critical, rubric)
        v.passed = settings()["judge"]["fail_mode"] == "open" and v.score >= rubric["pass_score"]
        v.seconds = round(time.time() - started, 1)
        return v

    llm_kept, v.discarded = ground(rule, data["findings"], det_all, set(rubric["deterministic_kinds"]))
    v.findings = det_all + llm_kept
    v.category_scores, v.score = score(det_scored + det_gate_critical + llm_kept, rubric)
    v.passed = v.score >= rubric["pass_score"]
    v.summary, v.strengths = data.get("rule_summary", ""), data.get("strengths", [])
    v.suggested_query = data.get("suggested_query", "") if rule.language == "eql" else ""
    v.suggestion_check = check_suggestion(v.suggested_query)
    v.seconds = round(time.time() - started, 1)
    return v


# =============================================================================== rendering
def _esc(text: str) -> str:
    return html.escape(text, quote=False).replace("|", "&#124;").replace("\n", "<br>")


def _cell(text: str, limit: int = 400) -> str:
    """Render untrusted text (rule content, LLM output) safely inside a Markdown table cell.
    `code` spans become <code> elements: GitHub shows HTML entities literally inside backtick
    spans, but decodes them inside <code>, so escaping stays correct everywhere."""
    text = str(text or "")
    text = text if len(text) <= limit else text[:limit - 1] + "…"
    parts = text.split("`")
    if len(parts) % 2 == 0:            # unbalanced backticks: treat everything as plain text
        return _esc(text)
    return "".join(f"<code>{_esc(p)}</code>" if i % 2 else _esc(p) for i, p in enumerate(parts))


def _code(text: str, limit: int = 160) -> str:
    return f"<code>{_esc(text if len(text) <= limit else text[:limit - 1] + '…')}</code>" if text else ""


def render_comment(verdicts: list[Verdict], meta: dict) -> str:
    rubric = meta["rubric"]
    failed = [v for v in verdicts if not v.passed]
    w = {c: s["weight"] for c, s in rubric["categories"].items()}
    head = "✅ PASS" if not failed else ("🟡 OVERRIDDEN" if meta.get("overridden") else "❌ FAIL")
    out = [MARKER, "## 🧑‍⚖️ AI Judge · Detection rule review", ""]
    if failed:
        out.append(f"**{head}**: {len(failed)} of {len(verdicts)} changed rule(s) below **{rubric['pass_score']}/100**."
                   + (" A maintainer applied the override label." if meta.get("overridden") else ""))
    else:
        out.append(f"**{head}**: all {len(verdicts)} changed rule(s) scored **{rubric['pass_score']}+/100**.")
    via = "recorded answers (replay mode)" if meta["provider"] == "replay" else meta["provider"]
    out += ["", f"<sub>model <code>{html.escape(meta['model'])}</code> via {via} · prompt v{rubric['prompt_version']}"
                f" · ECS {meta['ecs']} · ATT&amp;CK v{meta['attack']} · the LLM reports evidence, code computes the score</sub>", "",
            f"| Rule | Score | ECS ({w['ecs_field_accuracy']}) | Perf ({w['query_performance']}) | Evasion/FP ({w['evasion_fp_hygiene']}) | |",
            "|---|---:|---:|---:|---:|:---:|"]
    for v in verdicts:
        c = v.category_scores
        if v.error:   # no judge answer: don't print a score that looks like a review
            out.append(f"| <code>{html.escape(v.rule.path.name)}</code> | **n/a** | – | – | – | {'✅' if v.passed else '⚠️'} |")
            continue
        out.append(f"| <code>{html.escape(v.rule.path.name)}</code> | **{v.score}** | {c.get('ecs_field_accuracy', 0)} | "
                   f"{c.get('query_performance', 0)} | {c.get('evasion_fp_hygiene', 0)} | {'✅' if v.passed else '❌'} |")

    for v in verdicts:
        shown = "judge error" if v.error else f"{v.score}/100"
        out += ["", f"<details{' open' if not v.passed else ''}><summary><b>{'✅' if v.passed else '❌'} "
                    f"{html.escape(v.rule.name)}</b> · {shown} · <code>{html.escape(v.rule.rel_path)}</code></summary>", ""]
        if v.error:
            out += [f"> ⚠️ **Judge error** ({'fail closed' if not v.passed else 'fail open'}): {_cell(v.error)}", ""]
        if v.summary:
            out += [f"> {_cell(v.summary)}", ""]
        gate, seen = [], set()
        for f in v.findings:   # one line per distinct problem (e.g. same ES error on two data sets)
            if f.category == "gate" and f.severity in ("critical", "major") and (f.title, f.detail) not in seen:
                seen.add((f.title, f.detail))
                gate.append(f)
        if gate:
            out.append("**Integrity gate (Stages 1-2)**")
            out += [f"- {ICON[f.severity]} {_cell(f.title)}" + (f": {_cell(f.detail, 220)}" if f.detail else "")
                    + (f" {_code(f.evidence, 80)}" if f.evidence and f.kind != "replay_failure" else "")
                    for f in sorted(gate, key=lambda f: SEVERITY_RANK[f.severity])]
            out.append("")
        scored = sorted([f for f in v.findings if f.category in SCORED],
                        key=lambda f: (SEVERITY_RANK[f.severity], list(SCORED).index(f.category)))
        if scored:
            out += ["| | Area | Finding | Evidence | Fix | By |", "|:-:|---|---|---|---|:-:|"]
            for f in scored:
                out.append(f"| {ICON[f.severity]} | {SHORT[f.category]} | {_cell(f.title, 140)} | {_code(f.evidence)} | "
                           f"{_cell(f.fix, 260)} | {'🤖' if f.source == 'ai_judge' else '🔧'} |")
            out.append("")
        else:
            out += ["No scored findings.", ""]
        if v.strengths:
            out += ["**Strengths:** " + "; ".join(_cell(s, 200) for s in v.strengths), ""]
        if v.suggested_query:
            out += [f"<details><summary>Suggested rewrite from the judge · deterministic check: {html.escape(v.suggestion_check)}</summary>",
                    "", "```eql", v.suggested_query.replace("```", "ˋˋˋ"), "```", "</details>", ""]
        if v.discarded:
            out += [f"<details><summary>Self-check: {len(v.discarded)} judge finding(s) discarded</summary>", ""]
            out += [f"- {_cell(d['title'], 120)}: {_cell(d['reason'], 160)}" for d in v.discarded]
            out += ["", "</details>", ""]
        out.append("</details>")

    out += ["", f"<sub>🔧 deterministic lint / replay · 🤖 AI judge (evidence-checked) · deductions per finding: "
                f"critical −{rubric['deductions']['critical']}, major −{rubric['deductions']['major']}, "
                f"minor −{rubric['deductions']['minor']} · any critical caps the score at {rubric['critical_cap']}"
                f" · override label: <code>{html.escape(meta['override_label'])}</code></sub>"]
    return "\n".join(out) + "\n"


# ===================================================================================== CLI
def changed_rule_files(base: str) -> list[str]:
    out = subprocess.run(["git", "diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD", "--",
                          settings()["rules_dir"]], cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    return [line for line in out.stdout.splitlines() if line.endswith((".toml", ".yml", ".yaml"))]


def main(argv: list[str] | None = None) -> int:
    from .github import pr_context, upsert_pr_comment

    cfg = settings()["judge"]
    ap = argparse.ArgumentParser(prog="dac.ai_judge_elastic", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--files", nargs="*", help="rule files to judge")
    ap.add_argument("--base", help="judge rules changed between this git ref and HEAD (e.g. origin/main)")
    ap.add_argument("--provider", default=env("JUDGE_PROVIDER", cfg["provider"]))
    ap.add_argument("--model", default=env("JUDGE_MODEL", cfg["model"]))
    ap.add_argument("--replay-report", default="reports/replay.json", help="Stage 2 JSON report, if available")
    ap.add_argument("--report", default="reports/judge.json")
    ap.add_argument("--markdown", default="reports/pr_comment.md")
    ap.add_argument("--post-comment", action="store_true", help="create/update the PR comment via GITHUB_TOKEN")
    ap.add_argument("--no-cache", action="store_true")
    args = ap.parse_args(argv)

    files = args.files or (changed_rule_files(args.base) if args.base else None)
    if files is not None and not files:
        print("No rule files changed: nothing to judge.")
        return 0
    all_rules = load_rules()
    rules = load_rules(files) if files else all_rules
    rubric = yaml.safe_load(repo_path(cfg["rubric_file"]).read_text(encoding="utf-8"))
    system = repo_path(cfg["prompt_file"]).read_text(encoding="utf-8")
    schema = json.loads(repo_path(cfg["schema_file"]).read_text(encoding="utf-8"))
    replay_path = REPO_ROOT / args.replay_report
    replay = json.loads(replay_path.read_text(encoding="utf-8")) if replay_path.is_file() else []
    lint = lint_rules(rules, all_rules)
    provider = make_provider(args.provider, args.model)
    cache = None if args.no_cache or args.provider == "replay" else REPO_ROOT / cfg["cache_dir"]

    def run(rule: Rule) -> Verdict:
        det = list(lint.get(rule.rel_path, []))
        for r in replay:
            if r.get("rule") == rule.rel_path and not r.get("passed"):
                det.append(Finding("R001" if r.get("error") else "R002", "gate", "critical",
                                   "Query failed in Elasticsearch" if r.get("error") else f"Replay {r['case']} test failed",
                                   detail=r.get("error") or f"{r['hits']} hit(s) on {r['data']}, expected {r['expected']}",
                                   evidence=r["data"], kind="replay_failure", source="replay"))
        try:
            return judge_rule(rule, det, replay, provider, system, schema, rubric, cache)
        except Exception as exc:  # one broken rule must not hide the verdicts of the others
            return Verdict(rule=rule, findings=det, error=f"{type(exc).__name__}: {exc}", passed=False)

    with ThreadPoolExecutor(max_workers=max(1, int(cfg["concurrency"]))) as pool:
        verdicts = list(pool.map(run, rules))

    ctx = pr_context()
    overridden = cfg["override_label"] in ctx["labels"]
    meta = {"rubric": rubric, "model": provider.model, "provider": provider.name,
            "ecs": ECSSchema.load().version, "attack": mitre_catalog()["attack_version"],
            "override_label": cfg["override_label"], "overridden": overridden}
    comment = render_comment(verdicts, meta)

    for target, content in ((args.markdown, comment), (args.report, json.dumps({
            "meta": {k: v for k, v in meta.items() if k != "rubric"} | {"prompt_version": rubric["prompt_version"]},
            "verdicts": [{"rule": v.rule.rel_path, "rule_id": v.rule.rule_id, "score": None if v.error else v.score, "passed": v.passed,
                          "category_scores": v.category_scores, "error": v.error, "cached": v.cached,
                          "seconds": v.seconds, "summary": v.summary,
                          "findings": [f.to_dict() for f in v.findings], "discarded": v.discarded,
                          "suggested_query": v.suggested_query, "suggestion_check": v.suggestion_check}
                         for v in verdicts]}, indent=2, ensure_ascii=False))):
        path = REPO_ROOT / target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    for v in verdicts:
        status = "ERROR" if v.error else ("PASS" if v.passed else "FAIL")
        print(f"[{status}] {'n/a' if v.error else v.score:>3}{'' if v.error else '/100'}  {v.rule.rel_path}"
              f"  ({v.seconds}s{', cached' if v.cached else ''}{', ERROR: ' + v.error if v.error else ''})")
    from .validate_rules import write_summary
    write_summary(comment.replace(MARKER, ""))
    if args.post_comment:
        try:
            print("PR comment:", upsert_pr_comment(comment, MARKER))
        except requests.RequestException as exc:
            # e.g. PRs from forks get a read-only token: keep the verdict, report via job summary only
            print(f"::warning::Could not post the PR comment ({exc}); see the job summary instead.")

    failed = any(not v.passed for v in verdicts)
    if failed and overridden:
        print(f"Judge failed but '{cfg['override_label']}' label is set: passing (human override).")
        return 0
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
