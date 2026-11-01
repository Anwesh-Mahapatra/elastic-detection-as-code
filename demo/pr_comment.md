<!-- ai-judge-elastic -->
## 🧑‍⚖️ AI Judge · Detection rule review

**❌ FAIL**: 1 of 2 changed rule(s) below **80/100**.

<sub>model <code>gemma4:e4b</code> via recorded answers (replay mode) · prompt v1.1.0 · ECS 9.5.0 · ATT&amp;CK v20.0 · the LLM reports evidence, code computes the score</sub>

| Rule | Score | ECS (35) | Perf (30) | Evasion/FP (35) | |
|---|---:|---:|---:|---:|:---:|
| <code>credential_access_lsass_dump_ai_draft.toml</code> | **0** | 0 | 0 | 0 | ❌ |
| <code>credential_access_lsass_dump_procdump_comsvcs.toml</code> | **92** | 35 | 30 | 27 | ✅ |

<details open><summary><b>❌ LSASS Credential Dumping via ProcDump</b> · 0/100 · <code>rules/elastic/credential_access_lsass_dump_ai_draft.toml</code></summary>

> Two-step EQL sequence: a ProcDump process whose command line contains -ma, followed within a day by any file event whose name contains lsass and ends in .dmp, excluding users named admin*.

**Integrity gate (Stages 1-2)**
- ❌ Query failed in Elasticsearch: HTTP 400: Found 2 problems<br>line 2:18: Unknown column [process.name.keyword]<br>line 2:61: Unknown column [process.cmd]
- ⚠️ rule_id is not a UUID <code>lsass-dump-001</code>

| | Area | Finding | Evidence | Fix | By |
|:-:|---|---|---|---|:-:|
| ❌ | ECS | <code>.keyword</code> suffix on <code>process.name</code> | <code>process.name.keyword</code> | Use <code>process.name</code> | 🔧 |
| ❌ | ECS | <code>process.cmd</code> is not an ECS 9.5.0 field | <code>process.cmd</code> | Use <code>process.command_line</code> | 🔧 |
| ❌ | Perf | Sequence window is effectively unbounded | <code>maxspan=1d</code> | Use the shortest window the behavior needs (policy max 1h) | 🔧 |
| ❌ | Perf | Sequence has no join keys (<code>by</code>) | <code>sequence</code> | Join on host.id and an entity id, e.g. <code>sequence by host.id, process.entity_id</code> | 🔧 |
| ❌ | Evasion/FP | Detection hinges on the attacker-chosen dump file name | <code>file.name : "*lsass*.dmp"</code> | Alert on the dumping process itself (target + dump switch) and drop the file stage, or keep a file stage only as enrichment joined on process.entity_id. | 🤖 |
| ⚠️ | Perf | Leading wildcard on keyword field <code>file.name</code> | <code>"*lsass*.dmp"</code> | Match exact values (e.g. process.name) or move the substring match to a wildcard-type field. | 🔧 |
| ⚠️ | Perf | No look-back overlap between rule runs | <code>from=now-5m, interval=5m</code> | Set <code>from</code> = interval + look-back (e.g. now-9m for 5m) and timestamp_override = event.ingested | 🔧 |
| ⚠️ | Evasion/FP | Case-sensitive match on <code>process.name</code> | <code>process.name.keyword == "procdump.exe"</code> | Use <code>:</code> (case-insensitive), e.g. <code>process.name : "procdump.exe"</code> | 🔧 |
| ⚠️ | Evasion/FP | Renamed-binary evasion not covered | <code>process.pe.original_file_name</code> | Add <code>?process.pe.original_file_name : "&lt;OriginalFileName&gt;"</code> as an alternative | 🔧 |
| ⚠️ | Evasion/FP | Command-line switch without windash variants | <code>-ma</code> | List every prefix: "-ma", "/ma", "–ma", "—ma", "―ma" | 🔧 |
| ⚠️ | Evasion/FP | Process rule not limited to start events | <code>event.type == "start"</code> | Add <code>event.type == "start"</code> | 🔧 |
| ⚠️ | Evasion/FP | Exclusion anchored on <code>user.name</code> | <code>user.name</code> | Exclude a reviewed workflow via a Kibana exception on process.executable + process.code_signature.subject_name (+ parent), not on names | 🔧 |
| ⚠️ | Evasion/FP | comsvcs.dll MiniDump (Atomic T1003.001 #2) is not covered | <code>comsvcs</code> | Add: (?process.pe.original_file_name : "RUNDLL32.EXE" or process.name : "rundll32.exe") and process.command_line : "*comsvcs*" and process.command_line : ("*MiniDump*", "*#24*") | 🤖 |
| ⚠️ | Evasion/FP | ProcDump MiniPlus (-mp) dumps are not covered | <code>-mp</code> | process.args : ("-ma", "/ma", "–ma", "—ma", "―ma", "-mp", "/mp", "–mp", "—mp", "―mp") | 🤖 |
| 🔸 | Perf | Very broad index pattern | <code>logs-*</code> | Scope to the data streams that carry this telemetry. | 🔧 |
| 🔸 | Perf | No OS scoping | <code>host.os.type</code> | Add <code>host.os.type == "windows"</code> | 🔧 |
| 🔸 | Evasion/FP | No false-positive guidance | <code>false_positives</code> | Document expected benign triggers and how to triage them (false_positives / note). | 🔧 |

**Strengths:** Maps to the right ATT&amp;CK tactic (TA0006 Credential Access); Targets ProcDump's full-memory switch, the most common LSASS dump flag

<details><summary>Suggested rewrite from the judge · deterministic check: parses, ECS-clean</summary>

```eql
process where host.os.type == "windows" and event.type == "start" and
(
  (
    (?process.pe.original_file_name : "procdump" or process.name : ("procdump.exe", "procdump64.exe")) and
    process.args : ("-ma", "/ma", "–ma", "—ma", "―ma", "-mp", "/mp", "–mp", "—mp", "―mp") and
    process.command_line : "*lsass*"
  ) or
  (
    (?process.pe.original_file_name : "RUNDLL32.EXE" or process.name : "rundll32.exe") and
    process.command_line : "*comsvcs*" and process.command_line : ("*MiniDump*", "*#24*")
  )
)
```
</details>

<details><summary>Self-check: 1 judge finding(s) discarded</summary>

- Drop the .keyword suffix on process.name: duplicate of a deterministic lint finding

</details>

</details>

<details><summary><b>✅ LSASS Memory Dump via ProcDump or Comsvcs.dll</b> · 92/100 · <code>rules/elastic/credential_access_lsass_dump_procdump_comsvcs.toml</code></summary>

> Single-event EQL rule for LSASS dumping with ProcDump (renamed copies and every dash prefix included) or with comsvcs.dll MiniDump through rundll32 (by export name or ordinal), limited to Windows process start events.

| | Area | Finding | Evidence | Fix | By |
|:-:|---|---|---|---|:-:|
| 🔸 | Evasion/FP | ProcDump targeting LSASS by PID is not matched | <code>process.command_line : ("*lsass*", "* keyiso*", "* samss*")</code> | Keep as documented, and make sure the companion LSASS handle-access rule is deployed alongside this one. | 🤖 |
| 🔸 | Evasion/FP | Security 4688 and Defender XDR process data not searched | <code>index = ["logs-endpoint.events.process-*", "logs-windows.sysmon_operational-*", "winlogbeat-*"]</code> | Add "logs-system.security*" and "logs-m365_defender.event-*" after confirming they carry process.args and process.command_line. | 🤖 |

**Strengths:** Catches renamed ProcDump and rundll32 through ?process.pe.original_file_name; Lists every windash variant of the dump switches; Covers comsvcs MiniDump by name and by ordinal (#24, #+24, #-, #65560); Scoped to Windows process start events, so one alert per execution; No exclusions on spoofable fields; FP guidance points to scoped exceptions

<details><summary>Self-check: 1 judge finding(s) discarded</summary>

- Leading wildcard in comsvcs match: process.command_line is ECS type <code>wildcard</code>, built for leading wildcards

</details>

</details>

<sub>🔧 deterministic lint / replay · 🤖 AI judge (evidence-checked) · deductions per finding: critical −20, major −10, minor −4 · any critical caps the score at 79 · override label: <code>ai-judge-override</code></sub>
