"""bastiontrace CLI.

  bastiontrace analyze trace.jsonl [trace2.jsonl ...]   # timeline + verdict
  bastiontrace analyze trace.jsonl --format json        # machine-readable
  bastiontrace harden trace*.jsonl --out hardening/     # emit agentbastion rules
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .analyzer import Finding, analyze
from .harden import analyze_files, build_hardening, render_report, write_hardening
from .trace_schema import MemoryNote, Message, ToolCall, ToolResult, Trace, from_jsonl

_VERDICT_MARK = {"LANDED": "[LANDED]", "ATTEMPTED": "[attempted]", "CLEAN": "[clean]"}


def _fmt_event(trace: Trace, f: Finding, seq: int) -> str:
    e = trace.by_seq(seq)
    tag = ""
    if seq == f.inject_seq:
        tag = "  <== INJECT"
    elif seq == f.landing_seq:
        tag = f"  <== LANDING ({f.landing_kind})"
    elif seq in f.blast_radius:
        tag = "  .. tainted"
    if isinstance(e, Message):
        body = f"{e.role}: {e.content[:80]}"
    elif isinstance(e, ToolResult):
        body = f"tool_result {e.tool!r}: {e.content[:70]}"
    elif isinstance(e, MemoryNote):
        body = f"memory({e.kind}): {e.content[:66]}"
    elif isinstance(e, ToolCall):
        body = f"tool_call {e.tool!r} args={e.args}"
    else:
        body = str(e)
    return f"  #{seq:<3} {body}{tag}"


def _print_human(trace: Trace, f: Finding) -> None:
    print(f"\ntrace {trace.trace_id!r} (source={trace.source or '?'})  "
          f"{_VERDICT_MARK.get(f.verdict, f.verdict)}")
    for e in trace.events:
        print(_fmt_event(trace, f, e.seq))
    if f.inject_seq is not None:
        print(f"\n  inject : #{f.inject_seq} - {f.inject_signal}")
    if f.landing_seq is not None:
        print(f"  landing: #{f.landing_seq} - {f.landing_signal}")
    if f.causal_path:
        link = "linked" if f.linked else "inferred"
        print(f"  path   : {' -> '.join('#' + str(s) for s in f.causal_path)}  ({link})")
    if f.blast_radius:
        print(f"  blast  : {', '.join('#' + str(s) for s in f.blast_radius)}")
    for n in f.notes:
        print(f"  note   : {n}")


def _cmd_analyze(args: argparse.Namespace) -> int:
    results = []
    for p in args.traces:
        trace = from_jsonl(Path(p).read_text(encoding="utf-8"))
        results.append((trace, analyze(trace)))
    if args.format == "json":
        payload = [
            {"trace_id": t.trace_id, "verdict": f.verdict, **asdict(f)}
            for t, f in results
        ]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for t, f in results:
            _print_human(t, f)
    # exit 1 if any landed - useful as a CI gate
    return 1 if any(f.landed for _, f in results) else 0


def _cmd_harden(args: argparse.Namespace) -> int:
    analyzed = analyze_files([Path(p) for p in args.traces])
    h = build_hardening(analyzed)
    out = Path(args.out)
    policy, inj = write_hardening(h, out)
    print(render_report(h, policy, inj))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bastiontrace", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="locate the injection and its blast radius")
    a.add_argument("traces", nargs="+", help="trace JSONL file(s)")
    a.add_argument("--format", choices=("human", "json"), default="human")
    a.set_defaults(func=_cmd_analyze)

    h = sub.add_parser("harden", help="emit agentbastion rules from landed traces")
    h.add_argument("traces", nargs="+", help="trace JSONL file(s)")
    h.add_argument("--out", default="hardening", help="output dir (default: hardening/)")
    h.set_defaults(func=_cmd_harden)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
