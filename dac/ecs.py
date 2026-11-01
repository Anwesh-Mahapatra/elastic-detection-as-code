"""ECS field lookups: is a field real, what type is it, and what did the author probably mean?"""
from __future__ import annotations

import difflib
import fnmatch
import json
from dataclasses import dataclass
from functools import lru_cache

import yaml

from .config import repo_path, settings

# Fields LLMs and humans commonly invent, mapped to the real ECS field.
# Checked before fuzzy matching because difflib suggests look-alikes, not meanings.
COMMON_MISTAKES = {
    "process.cmd": "process.command_line",
    "process.cmdline": "process.command_line",
    "process.commandline": "process.command_line",
    "process.command": "process.command_line",
    "process.path": "process.executable",
    "process.image": "process.executable",
    "process.exe": "process.executable",
    "process.original_file_name": "process.pe.original_file_name",
    "process.originalfilename": "process.pe.original_file_name",
    "process.parent_name": "process.parent.name",
    "process.parent_image": "process.parent.executable",
    "process.parent.image": "process.parent.executable",
    "process.parent.path": "process.parent.executable",
    "process.parent.cmd": "process.parent.command_line",
    "process.user": "user.name",
    "process.username": "user.name",
    "file.filename": "file.name",
    "file.fullpath": "file.path",
    "file.hash": "file.hash.sha256",
    "process.hash": "process.hash.sha256",
    "src_ip": "source.ip",
    "dst_ip": "destination.ip",
    "source_ip": "source.ip",
    "destination_ip": "destination.ip",
    # Raw Sysmon / Sigma names that leak through when a pipeline mapping is missing.
    "CommandLine": "process.command_line",
    "Image": "process.executable",
    "ParentImage": "process.parent.executable",
    "ParentCommandLine": "process.parent.command_line",
    "OriginalFileName": "process.pe.original_file_name",
    "TargetFilename": "file.path",
    "User": "user.name",
}


@dataclass(frozen=True)
class FieldVerdict:
    status: str            # ecs | multi_field | keyword_suffix | non_ecs_multi_field | allowlisted | unknown
    field: str
    es_type: str | None = None     # Elasticsearch mapping type when known
    base_field: str | None = None  # for multi-fields / bad suffixes
    suggestion: str | None = None
    reason: str = ""


class ECSSchema:
    def __init__(self, version: str, fields: dict[str, dict], allowlist: list[dict]):
        self.version = version
        self.fields = fields
        self.allowlist = allowlist

    @classmethod
    @lru_cache(maxsize=1)
    def load(cls) -> "ECSSchema":
        cfg = settings()["ecs"]
        data = json.loads(repo_path(cfg["schema_file"]).read_text(encoding="utf-8"))
        allow = yaml.safe_load(repo_path(cfg["allowlist_file"]).read_text(encoding="utf-8")) or []
        return cls(data["ecs_version"], data["fields"], allow)

    def es_type(self, field: str) -> str | None:
        verdict = self.check(field)
        return verdict.es_type

    def allowlist_reason(self, field: str) -> str | None:
        for entry in self.allowlist:
            if fnmatch.fnmatchcase(field, entry["pattern"]):
                return entry.get("why", "allowlisted")
        return None

    def check(self, field: str) -> FieldVerdict:
        if field in self.fields:
            return FieldVerdict("ecs", field, self.fields[field]["type"])

        base, _, leaf = field.rpartition(".")
        if base in self.fields:
            multi = self.fields[base].get("multi_fields", {})
            if leaf in multi:
                return FieldVerdict("multi_field", field, multi[leaf], base_field=base)
            if leaf == "keyword":
                return FieldVerdict(
                    "keyword_suffix", field, None, base_field=base, suggestion=base,
                    reason=f"ECS maps {base} as '{self.fields[base]['type']}' with no .keyword sub-field; "
                           ".keyword only exists on dynamically-mapped (non-ECS) data",
                )
            if leaf == "caseless":
                return FieldVerdict(
                    "non_ecs_multi_field", field, "keyword", base_field=base, suggestion=base,
                    reason=".caseless exists only in Elastic Defend mappings, not in ECS or Sysmon/winlogbeat data",
                )

        why = self.allowlist_reason(field)
        if why:
            return FieldVerdict("allowlisted", field, None, reason=why)

        return FieldVerdict("unknown", field, None, suggestion=self.suggest(field))

    def suggest(self, field: str) -> str | None:
        if field in COMMON_MISTAKES:
            return COMMON_MISTAKES[field]
        lowered = field.lower()
        for wrong, right in COMMON_MISTAKES.items():
            if wrong.lower() == lowered:
                return right
        prefix = field.split(".")[0] + "."
        candidates = [f for f in self.fields if f.startswith(prefix)] or list(self.fields)
        match = difflib.get_close_matches(field, candidates, n=1, cutoff=0.75)
        return match[0] if match else None
