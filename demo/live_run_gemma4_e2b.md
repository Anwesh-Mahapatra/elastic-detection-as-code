<!-- Unedited output of a LIVE judge run, 30 Oct 2026: Gemma 4 E2B (hf.co/unsloth/gemma-4-E2B-it-GGUF:Q4_K_M) on Ollama 0.40.13,
     CPU only, 2 vCPU / 8 GB sandbox, ~5 min per rule. The larger default (gemma4:e4b) did not fit in 8 GB RAM there.
     Result: valid JSON both times, but every model finding was a repeat of a lint finding or quoted text that is not
     in the rule, so the guardrails discarded all of them and the scores come from deterministic findings only.
     Compare with demo/pr_comment.md, rendered from reference answers written for the demo. -->
<!-- ai-judge-elastic -->
## 🧑‍⚖️ AI Judge · Detection rule review

**❌ FAIL**: 1 of 2 changed rule(s) below **80/100**.

<sub>model <code>hf.co/unsloth/gemma-4-E2B-it-GGUF:Q4_K_M</code> via ollama · prompt v1.1.0 · ECS 9.5.0 · ATT&amp;CK v20.0 · the LLM reports evidence, code computes the score</sub>

| Rule | Score | ECS (35) | Perf (30) | Evasion/FP (35) | |
|---|---:|---:|---:|---:|:---:|
| <code>credential_access_lsass_dump_ai_draft.toml</code> | **0** | 0 | 0 | 0 | ❌ |
| <code>credential_access_lsass_dump_procdump_comsvcs.toml</code> | **100** | 35 | 30 | 35 | ✅ |

<details open><summary><b>❌ LSASS Credential Dumping via ProcDump</b> · 0/100 · <code>rules/elastic/credential_access_lsass_dump_ai_draft.toml</code></summary>

> This rule attempts to detect credential dumping from LSASS by correlating a specific process execution with the creation of a dump file on disk.

**Integrity gate (Stages 1-2)**
- ❌ Query failed in Elasticsearch: HTTP 400: Found 2 problems<br>line 2:18: Unknown column [process.name.keyword]<br>line 2:61: Unknown column [process.cmd]
- ⚠️ rule_id is not a UUID <code>lsass-dump-001</code>

| | Area | Finding | Evidence | Fix | By |
|:-:|---|---|---|---|:-:|
| ❌ | ECS | <code>.keyword</code> suffix on <code>process.name</code> | <code>process.name.keyword</code> | Use <code>process.name</code> | 🔧 |
| ❌ | ECS | <code>process.cmd</code> is not an ECS 9.5.0 field | <code>process.cmd</code> | Use <code>process.command_line</code> | 🔧 |
| ❌ | Perf | Sequence window is effectively unbounded | <code>maxspan=1d</code> | Use the shortest window the behavior needs (policy max 1h) | 🔧 |
| ❌ | Perf | Sequence has no join keys (<code>by</code>) | <code>sequence</code> | Join on host.id and an entity id, e.g. <code>sequence by host.id, process.entity_id</code> | 🔧 |
| ⚠️ | Perf | Leading wildcard on keyword field <code>file.name</code> | <code>"*lsass*.dmp"</code> | Match exact values (e.g. process.name) or move the substring match to a wildcard-type field. | 🔧 |
| ⚠️ | Perf | No look-back overlap between rule runs | <code>from=now-5m, interval=5m</code> | Set <code>from</code> = interval + look-back (e.g. now-9m for 5m) and timestamp_override = event.ingested | 🔧 |
| ⚠️ | Evasion/FP | Case-sensitive match on <code>process.name</code> | <code>process.name.keyword == "procdump.exe"</code> | Use <code>:</code> (case-insensitive), e.g. <code>process.name : "procdump.exe"</code> | 🔧 |
| ⚠️ | Evasion/FP | Renamed-binary evasion not covered | <code>process.pe.original_file_name</code> | Add <code>?process.pe.original_file_name : "&lt;OriginalFileName&gt;"</code> as an alternative | 🔧 |
| ⚠️ | Evasion/FP | Command-line switch without windash variants | <code>-ma</code> | List every prefix: "-ma", "/ma", "–ma", "—ma", "―ma" | 🔧 |
| ⚠️ | Evasion/FP | Process rule not limited to start events | <code>event.type == "start"</code> | Add <code>event.type == "start"</code> | 🔧 |
| ⚠️ | Evasion/FP | Exclusion anchored on <code>user.name</code> | <code>user.name</code> | Exclude a reviewed workflow via a Kibana exception on process.executable + process.code_signature.subject_name (+ parent), not on names | 🔧 |
| 🔸 | Perf | Very broad index pattern | <code>logs-*</code> | Scope to the data streams that carry this telemetry. | 🔧 |
| 🔸 | Perf | No OS scoping | <code>host.os.type</code> | Add <code>host.os.type == "windows"</code> | 🔧 |
| 🔸 | Evasion/FP | No false-positive guidance | <code>false_positives</code> | Document expected benign triggers and how to triage them (false_positives / note). | 🔧 |

**Strengths:** The rule correctly identifies the target technique (T1003) and tactic (TA0006).; The use of a sequence with a time window (<code>maxspan=1d</code>) is appropriate for correlating related events.

<details><summary>Suggested rewrite from the judge · deterministic check: parses, ECS-clean</summary>

```eql
sequence with maxspan=1d
  [process where process.name == "procdump.exe" and process.command_line : "*-ma*"]
  [file where file.name : "*lsass*.dmp"]
```
</details>

<details><summary>Self-check: 5 judge finding(s) discarded</summary>

- Incorrect ECS field usage for process name: duplicate of a deterministic lint finding
- Incorrect ECS field usage for command line: duplicate of a deterministic lint finding
- Leading wildcard on file name: duplicate of a deterministic lint finding
- Missing windash variants in command line matching: duplicate of a deterministic lint finding
- Weak exclusion anchored on user name: duplicate of a deterministic lint finding

</details>

</details>

<details><summary><b>✅ LSASS Memory Dump via ProcDump or Comsvcs.dll</b> · 100/100 · <code>rules/elastic/credential_access_lsass_dump_procdump_comsvcs.toml</code></summary>

> This rule identifies credential dumping techniques using Sysinternals ProcDump or <code>comsvcs.dll</code> MiniDump exports, targeting LSASS memory.

No scored findings.

**Strengths:** Correctly uses <code>process.pe.original_file_name</code> to detect renamed binaries.; Includes comprehensive handling for Windows windash variants in ProcDump arguments.; Explicitly targets common LSASS/KeyIso/SamSs strings in the command line.; Includes specific checks for known <code>comsvcs</code> MiniDump ordinal variants.; Includes a documented section for false positives and scoping exceptions.

<details><summary>Self-check: 1 judge finding(s) discarded</summary>

- Complex command-line matching: quoted evidence is not in the rule

</details>

</details>

<sub>🔧 deterministic lint / replay · 🤖 AI judge (evidence-checked) · deductions per finding: critical −20, major −10, minor −4 · any critical caps the score at 79 · override label: <code>ai-judge-override</code></sub>
