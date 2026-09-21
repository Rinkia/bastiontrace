# Changelog

All notable changes to bastiontrace are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
