# Changelog

All notable changes to bastiontrace are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.1] - 2026-10-09

Fixes from an independent security review of 0.6.0. **Anyone analyzing fuse trip
snapshots with 0.6.0 should upgrade:** it could report a real, unblocked exfiltration as
contained.

- **A fuse trip no longer masks an earlier, unblocked landing** (the serious one). 0.6.0
  returned the fuse landing without comparing seqs, so a `send_email` that actually went
  out at `#1`, followed by a harmless call that tripped the fuse at `#2`, reported
  `LANDED (contained)` with the exfil left unmarked. A fuse blocks the call it trips on;
  it cannot vouch for calls it allowed earlier. Earliest-wins now holds across all three
  kinds, `contained` is only claimed for the landing the fuse actually blocked, and a
  later trip is reported as a note ("the fuse tripped later, at #N; it did not block this
  landing"). No attacker needed — any exfil that succeeded before a trip hit this.
- **The human report can no longer be forged by trace content.** Every
  attacker-influenceable string it prints (the fuse `reason`, tool-result content, agent
  names, notes, `source`, args) goes through one escaper: control characters become
  visible escapes and each field is capped. A `reason` containing a newline could
  previously print its own `note   :` / `blast  :` lines and emit terminal escape
  sequences (clear-screen, set-window-title). The JSON output was never affected.
- **A `fuse` block with no call marked `tripped` is no longer silently CLEAN.** A snapshot
  exists only because a tripwire fired, so an unlocatable trip (truncated or evicted ring)
  now reports `ATTEMPTED` with `Finding.fuse_unresolved` and a note, instead of nothing.
- **Hostile header values raise `ValueError` naming the field**, as the schema contract
  always promised: non-object `policy` (was `AttributeError`), non-list or nested
  `forbidden_tools` / `canary_tokens` (was an unnamed `TypeError` from `set()`), non-string
  `canary` / `trace_id` / `source`, and lone surrogates anywhere (they survive JSON parsing
  and then crash printing). A string `forbidden_tools` is refused rather than silently split
  into single-character tool names, which had made a real landing read as CLEAN. The CLI
  reports these as exit 2 (bad input), never a traceback — exit 1 means LANDED.
- **The "contained" wording is hedged to what the trace proves**: "the trace's fuse block
  records this call as blocked". The block is a field in a file, and whoever wrote the file
  wrote it; nothing here verifies it. Snapshots are not signed (noted in Limits).
- Printing is no longer O(n²): the event index is built once instead of a linear scan per
  event, and oversized `args` are capped.

## [0.6.0] - 2026-10-08

A bastionfuse trip is a landing.

- **New landing kind `fuse`.** bastionfuse writes a trace on every trip; `analyze`
  scored those files CLEAN unless the tripped tool happened to be a canary tool,
  because the honeytoken that caused the trip is redacted out of the snapshot on
  purpose. The containment leg's evidence now scores: the call with
  `verdict:"tripped"` is the landing, with the fuse's own rule and reason as the
  signal.
- **`Finding.contained`.** True on a fuse landing: the payload reached a forbidden
  action *and* the fuse blocked the call. The verdict stays `LANDED` (the existing
  vocabulary is unchanged for consumers that enforce on it); the human report adds
  `(contained: the fuse blocked the call)` and the JSON gains the field.
- **Schema: a `fuse` header block** (`rule`, `reason`, `session_sha256`,
  `honeytoken_sha256`) and an optional `verdict` on `tool_call`
  (`allowed` | `blocked` | `tripped`). Both additive, both already written by
  bastionfuse 0.1.0 and until now dropped on read. Hostile values raise a
  `ValueError` naming the field. A trace without them is read, scored and
  serialized exactly as before.
- The fuse's decision is **read, not re-derived**: a snapshot carries only a hash
  of the honeytoken, so there is nothing to match on, and a report that re-derived
  it would risk echoing live decoy strings.
- Known ceilings (README): a snapshot yields a landing but no inject site and no
  causal path, because the ring holds calls with redacted args rather than the
  content the agent read. `contained` reports what the fuse recorded; bastiontrace
  does not verify the block independently.

## [0.5.0] - 2026-09-30

Multi-agent forensics — schema **v2 → v3** (additive) — and an OpenTelemetry import.

- **Schema v3.** An optional `agent` field on every event. A new `agent_message`
  event (`from_agent`, `to_agent`, `kind`, `derived_from`): content one agent handed
  another, both an inject site and a propagation edge. A header `provenance`
  (`explicit` | `inferred`). Traces without v3 features are still written as
  `v:2`, byte-identical, so the bastionprobe contract golden is unchanged.
- **Cascade findings.** `patient_zero`, `agents_reached`, `hops` and `replicated`
  (the worm signal: the injection re-sent by 2 or more agents, explicit provenance
  only). The human output gains a `cascade:` line.
- **`from_otel` / `analyze --otel FILE`.** OTel GenAI spans (OTLP/JSON or Collector
  JSONL) become v3 traces:
  - events are ordered by span start/end, and provenance is inferred from the
    span tree (so findings are never `linked`);
  - system parts are skipped;
  - `--forbid` / `--canary` supply the policy;
  - a stderr warning and `content_captured: false` when the export has no content;
  - 200k-span cap, cycle-safe, malformed spans skipped.
- **Stricter reads.** Provenance edges must point to an earlier seq. A header
  `v` newer than this reader, or an unknown event type, fails with an upgrade hint.
- **CLI.** `--example cascade|session-smuggling|clean-multiagent|otel-cascade|exfil`
  runs bundled samples (now shipped in the wheel). `analyze` takes exactly one of
  trace files, `--otel` or `--example`. Bad input is one line on stderr with exit 2,
  not a traceback.
- **Faster.** Edges are indexed once and a combined pre-filter skips clean text.
  A 200k-event trace analyzes in well under a second; the OTel import is linear.
- **Review fixes.**
  - OTel ordering:
    - at equal timestamps, results and replies sort before new delegations;
    - a span with a missing or backwards end time is stretched to its last descendant.
  - OTel content:
    - delegations carry the parent's whole context, not just its reads since the
      last delegation;
    - JSON-shaped strings, `kvlistValue`/`bytesValue` attributes and non-`content`
      message parts are read, not dropped;
    - unnamed agents stay distinct.
  - Analysis:
    - `replicated` counts only messages downstream of the injection;
    - a forbidden call that happened *before* the first located injection is
      reported as a landing that is not attributed to it.
  - Input handling:
    - hostile field types in a trace are a one-line error (exit 2);
    - an unknown header `provenance` is rejected;
    - a loaded `v:1` header is written back as `v:1`.
- Next: bastionprobe multi-agent attack scenarios that emit v3 traces; OTel
  sample apps with content capture; per-agent drift baselines (deferred).

## [0.4.0] - 2026-09-29

`harden` emits a `policy_version: 2` policy.yaml.

- Same decisions (default allow + the tools an injection got called on a deny list);
  the file now starts with `policy_version: 2`, and an empty deny list is written
  `deny: []`. Every agentbastion and bastiongate version reads it (it uses only the
  shared core), so no consumer upgrade is needed.

## [0.3.0] - 2026-09-21

Added `memory` as a second inject-point type — schema **v1 → v2** (BASTION_INTEL A1).

- New `MemoryNote` event (`type: "memory"`, `kind`: summary|memory|note) models the
  agent's own memory/summary layer, where compaction-summary injections hide without
  passing through a `tool_result`. The analyzer scans it as a candidate inject site
  and honors its `source_seq` for causal-path + blast-radius provenance.
- CLI renders memory events; `SCHEMA.md` documents the type. Backward-compatible:
  v1 traces (no memory events) parse unchanged.

## [0.2.0] - 2026-09-11

Depend on [bastioncorpus](https://github.com/Rinkia/bastioncorpus), the shared
trilogy corpus, for injection signatures. The built-in `_PATTERNS` markers stay
as an always-available fallback; when bastioncorpus is installed, `to_trace`
signatures extend recall. No API change.

## [0.1.0] - 2026-09-11

Initial release. The investigate side of the bastion trilogy (agentbastion
prevent, bastionprobe attack, bastiontrace investigate).

### Added
- **Trace schema (v1)** — portable JSONL format: a `trace` header then ordered
  `message` / `tool_result` / `tool_call` events, seq-addressed, with
  `args_from` provenance and `policy` (forbidden tools + canary tokens). Full
  spec in `SCHEMA.md`.
- **`from_bastionprobe()`** — maps a bastionprobe `AttackResult` into a
  replayable trace (duck-typed, no bastionprobe import).
- **Analyzer** — derives inject point, landing (forbidden call or leaked
  canary, earliest wins), causal path (`linked` via `args_from`, else
  `inferred`), and blast radius (forward taint closure). Verdicts: `LANDED`,
  `ATTEMPTED`, `CLEAN`.
- **`harden`** — turns findings into agentbastion `policy.yaml` + injection
  corpus `injections.jsonl`, wire-compatible with `bastionprobe harden`; canary
  scaffolding stripped from learned templates.
- **CLI** — `bastiontrace analyze` (human timeline + verdict, `--format json`,
  non-zero exit on a landed injection for CI) and `bastiontrace harden --out`.
- Zero runtime dependencies, no LLM, fully offline.

[0.1.0]: https://github.com/Rinkia/bastiontrace/releases/tag/v0.1.0
