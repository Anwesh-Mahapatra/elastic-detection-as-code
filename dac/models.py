"""Shared data types: a loaded rule and a finding about it."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path

from .config import REPO_ROOT

SEVERITIES = ("critical", "major", "minor", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# The three scored categories requested for the AI judge, plus "gate" for
# pass/fail integrity checks (tests exist, ids unique, MITRE ids real...) that are
# enforced directly by Stage 1 and are not part of the 0-100 quality score.
CATEGORIES = {
    "ecs_field_accuracy": "ECS Field Accuracy",
    "query_performance": "Query Performance",
    "evasion_fp_hygiene": "Evasion & FP Hygiene",
    "gate": "Integrity Gate",
}


@dataclass
class Finding:
    check: str                 # stable id, e.g. "E001" (lint) or "AI-ECS" (judge)
    category: str              # key of CATEGORIES
    severity: str              # one of SEVERITIES
    title: str
    detail: str = ""
    evidence: str = ""         # exact snippet / field the finding is about
    fix: str = ""
    kind: str = "other"        # machine-readable type, used to dedupe lint vs judge findings
    source: str = "lint"       # lint | replay | ai_judge

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Rule:
    path: Path
    fmt: str                   # "toml" (native Elastic) | "sigma"
    rule_id: str
    name: str
    language: str              # eql | lucene | esql | kuery
    query: str
    index: list[str]
    payload: dict              # body accepted by Kibana /api/detection_engine/rules(_import)
    source_text: str           # the file as written by the author (what the judge reviews)
    load_errors: list[str] = field(default_factory=list)
    dropped_keys: list[str] = field(default_factory=list)

    @property
    def rel_path(self) -> str:
        try:
            return self.path.resolve().relative_to(REPO_ROOT).as_posix()
        except ValueError:
            return self.path.as_posix()
