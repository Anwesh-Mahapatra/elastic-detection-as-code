"""Static analysis of rule queries (EQL first-class; Lucene/KQL/ES|QL best-effort).

Two layers, on purpose:
  1. The `eql` library (Elastic's own parser) gives the structure: fields, sequences,
     maxspan, join keys, wildcard patterns.
  2. A string-aware token scan of the raw query recovers what that AST erases:
     `==` vs `:` (case sensitivity), `like` vs `like~`, and `?optional` fields.
Elasticsearch itself stays the final authority on syntax (Stage 2 runs every query).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import eql
from eql.parser import elasticsearch_syntax, elasticsearch_validate_optional_fields, ignore_missing_functions

IDENT = r"[A-Za-z_@][\w@]*(?:\.[\w@]+)*"
PLACEHOLDER = "__S{}__"
PLACEHOLDER_RE = re.compile(r"__S(\d+)__")
TIME_UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}
EQL_KEYWORDS = {"and", "or", "not", "where", "in", "like", "regex", "sequence", "sample", "by",
                "with", "maxspan", "until", "true", "false", "null", "any", "runs"}


@dataclass
class WildcardUse:
    field: str
    pattern: str


@dataclass
class StringOp:
    field: str
    op: str          # ==, !=, like, regex, in, not in  (all case-sensitive in Elasticsearch EQL)
    literal: str


@dataclass
class SequenceInfo:
    maxspan: str | None
    maxspan_seconds: float | None
    join_keys: list[list[str]]
    has_until: bool


@dataclass
class QueryProfile:
    language: str
    fields: list[str] = field(default_factory=list)
    optional_fields: set[str] = field(default_factory=set)
    event_categories: list[str] = field(default_factory=list)
    wildcards: list[WildcardUse] = field(default_factory=list)
    case_sensitive_ops: list[StringOp] = field(default_factory=list)
    literals: list[str] = field(default_factory=list)
    negated_fields: list[str] = field(default_factory=list)
    sequence: SequenceInfo | None = None
    parse_error: str | None = None


def _string_end(query: str, i: int) -> int:
    """Index just past the string literal starting at i (raw \"\"\"...\"\"\" or \"...\" with escapes)."""
    n = len(query)
    if query.startswith('"""', i):
        end = query.find('"""', i + 3)
        return n if end == -1 else end + 3
    j = i + 1
    while j < n and query[j] != '"':
        j += 2 if query[j] == "\\" else 1
    return min(j + 1, n)


def mask_strings(query: str) -> tuple[str, list[str]]:
    """Replace every double-quoted literal with a placeholder so regexes never match inside
    strings. Returns the masked text and the (unescaped) literal values in order."""
    out, literals, i, n = [], [], 0, len(query)
    while i < n:
        if query[i] == '"':
            end = _string_end(query, i)
            raw = query[i:end]
            if raw.startswith('"""'):
                value = raw[3:-3]
            else:
                value = re.sub(r"\\(.)", r"\1", raw[1:-1])
            literals.append(value)
            out.append(PLACEHOLDER.format(len(literals) - 1))
            i = end
        else:
            out.append(query[i])
            i += 1
    return "".join(out), literals


def strip_comments(query: str) -> str:
    """Drop /* */ and // comments (both valid in EQL) while copying string literals verbatim."""
    out, i, n = [], 0, len(query)
    while i < n:
        if query[i] == '"':
            end = _string_end(query, i)
            out.append(query[i:end])
            i = end
        elif query.startswith("/*", i):
            end = query.find("*/", i + 2)
            i = n if end == -1 else end + 2
            out.append(" ")
        elif query.startswith("//", i):
            end = query.find("\n", i)
            i = n if end == -1 else end
        else:
            out.append(query[i])
            i += 1
    return "".join(out)


def to_seconds(span: str) -> float | None:
    m = re.fullmatch(r"\s*(\d+)\s*(ms|s|m|h|d)\s*", span or "")
    return int(m.group(1)) * TIME_UNITS[m.group(2)] if m else None


def _unique(seq):
    seen, out = set(), []
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def analyze(query: str, language: str) -> QueryProfile:
    language = (language or "").lower()
    if language == "eql":
        return _analyze_eql(query)
    if language in ("lucene", "kuery"):
        return _analyze_lucene_like(query, language)
    if language == "esql":
        return _analyze_esql(query)
    return QueryProfile(language=language, parse_error=f"unsupported language '{language}'")


# ----------------------------------------------------------------------------- EQL
def _analyze_eql(query: str) -> QueryProfile:
    prof = QueryProfile(language="eql")
    clean = strip_comments(query)
    masked, literals = mask_strings(clean)
    prof.literals = literals

    def lit(token: str) -> str:
        m = PLACEHOLDER_RE.fullmatch(token)
        return literals[int(m.group(1))] if m else token

    prof.optional_fields = set(re.findall(r"\?(" + IDENT + r")", masked))

    # Case-sensitive string comparisons (Elasticsearch EQL: ==, !=, like, regex, in are case-sensitive).
    for m in re.finditer(r"\??(" + IDENT + r")\s*(==|!=)\s*(__S\d+__)", masked):
        prof.case_sensitive_ops.append(StringOp(m.group(1), m.group(2), lit(m.group(3))))
    for m in re.finditer(r"\??(" + IDENT + r")\s+(not\s+)?(like|regex|in)(?!~)\s*(\(|__S\d+__)", masked):
        op = ("not " if m.group(2) else "") + m.group(3)
        after = masked[m.end(4) - len(m.group(4)):]
        first = PLACEHOLDER_RE.search(after)
        prof.case_sensitive_ops.append(StringOp(m.group(1), op, lit(first.group(0)) if first else ""))

    # Fields used as the first operand after `not`, or compared with !=, are exclusions.
    negated = re.findall(r"\bnot\s*\(?\s*\??(" + IDENT + r")", masked)
    negated += [op.field for op in prof.case_sensitive_ops if op.op in ("!=", "not in", "not like")]
    prof.negated_fields = _unique([f for f in negated if f.lower() not in EQL_KEYWORDS])

    seq_m = re.match(r"\s*sequence\b", masked)
    try:
        with elasticsearch_syntax, ignore_missing_functions, elasticsearch_validate_optional_fields:
            tree = eql.parse_query(clean)
    except Exception as exc:  # eql raises several error types; all mean "could not parse"
        prof.parse_error = f"{type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}"
        tree = None

    if tree is not None:
        fields, cats = [], []
        for node in tree:
            kind = type(node).__name__
            if kind == "Field":
                path = [str(p) for p in node.path if not isinstance(p, int)]
                fields.append(".".join([node.base, *path]))
            elif kind == "EventQuery":
                cats.append(node.event_type)
            elif kind == "FunctionCall" and node.name == "wildcard" and node.arguments:
                target = node.arguments[0]
                if type(target).__name__ == "Field":
                    fname = ".".join([target.base, *[str(p) for p in target.path if not isinstance(p, int)]])
                    for arg in node.arguments[1:]:
                        if type(arg).__name__ == "String":
                            prof.wildcards.append(WildcardUse(fname, arg.value))
            elif kind == "Sequence":
                span = str(node.max_span) if getattr(node, "max_span", None) is not None else None
                joins = [[_field_name(f) for f in (q.join_values or [])] for q in node.queries]
                prof.sequence = SequenceInfo(span, to_seconds(span) if span else None, joins,
                                             getattr(node, "close", None) is not None)
        prof.fields = _unique(fields)
        prof.event_categories = _unique(cats)
    else:
        # Fallback so ECS checks still run when the local parser rejects the query.
        idents = re.findall(r"(?<![\w.@])\??(" + IDENT + r")(?!\s*\()", masked)
        prof.fields = _unique([i for i in idents if "." in i and i.lower() not in EQL_KEYWORDS])
        if seq_m:
            span = re.search(r"maxspan\s*=\s*(\d+\s*(?:ms|s|m|h|d))", masked)
            prof.sequence = SequenceInfo(span.group(1) if span else None,
                                         to_seconds(span.group(1)) if span else None,
                                         [[]] if " by " not in masked else [["?"]], "until" in masked)
        cats = re.findall(r"(?:^|\[)\s*([a-z_]+)\s+where\b", masked)
        prof.event_categories = _unique(cats)
    return prof


def _field_name(node) -> str:
    if type(node).__name__ == "Field":
        return ".".join([node.base, *[str(p) for p in node.path if not isinstance(p, int)]])
    return str(node)


# ------------------------------------------------------------------- Lucene / KQL
def _analyze_lucene_like(query: str, language: str) -> QueryProfile:
    prof = QueryProfile(language=language)
    masked, literals = mask_strings(query)
    prof.literals = literals
    fields = []
    for m in re.finditer(r"(?<![\w.@\\])(" + IDENT + r")\s*:\s*", masked):
        fname = m.group(1)
        if fname.upper() in ("AND", "OR", "NOT"):
            continue
        fields.append(fname)
        rest = masked[m.end():]
        if rest.startswith("("):
            depth, j = 0, 0
            for j, ch in enumerate(rest):
                depth += ch == "("
                depth -= ch == ")"
                if depth == 0:
                    break
            values = re.split(r"\s+(?:OR|AND|or|and)\s+|\s+", rest[1:j])
        else:
            values = [re.split(r"(?<!\\)[\s)]", rest, maxsplit=1)[0]]
        for value in values:
            value = value.strip()
            if value and not PLACEHOLDER_RE.fullmatch(value) and value.startswith(("*", "?")):
                prof.wildcards.append(WildcardUse(fname, value.replace("\\", "")))
    prof.fields = _unique(fields)
    prof.negated_fields = _unique(re.findall(r"\bNOT\s+\(?\s*(" + IDENT + r")\s*:", masked, flags=re.I))
    return prof


# -------------------------------------------------------------------------- ES|QL
def _analyze_esql(query: str) -> QueryProfile:
    prof = QueryProfile(language="esql")
    masked, literals = mask_strings(query)
    prof.literals = literals
    body = re.sub(r"(?is)^\s*FROM\s+[^|]+", " ", masked)  # index names are not fields
    idents = re.findall(r"(?<![\w.@])(" + IDENT + r")(?!\s*\()", body)
    prof.fields = _unique([i for i in idents if "." in i])
    for m in re.finditer(r"(" + IDENT + r")\s+(?:RLIKE|LIKE)\s+(__S\d+__)", masked, flags=re.I):
        pattern = literals[int(PLACEHOLDER_RE.fullmatch(m.group(2)).group(1))]
        prof.wildcards.append(WildcardUse(m.group(1), pattern))
    return prof
