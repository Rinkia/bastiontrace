"""bastiontrace CLI.

  bastiontrace analyze trace.jsonl [trace2.jsonl ...]   # timeline + verdict
  bastiontrace analyze trace.jsonl --format json        # machine-readable
  bastiontrace analyze --otel spans.json --forbid send_email   # an OTel GenAI export
  bastiontrace analyze --example cascade                # a bundled sample
  bastiontrace harden trace*.jsonl --out hardening/     # emit agentbastion rules
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict
from pathlib import Path

from .analyzer import Finding, analyze
from .harden import analyze_files, build_hardening, render_report, write_hardening
from .trace_schema import AgentMessage, MemoryNote, Message, ToolCall, ToolResult, Trace, from_jsonl

_CAPTURE_HINT = ("enable content capture in your OTel GenAI instrumentation "
                 "(e.g. OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true)")

_VERDICT_MARK = {"LANDED": "[LANDED]", "ATTEMPTED": "[attempted]", "CLEAN": "[clean]"}


_CTRL = re.compile("[\x00-\x1f\x7f-\x9f]")


def _safe(value, cap: int = 300) -> str:
    """Make a trace-controlled string safe to print on one line.

    Everything in a trace is content an agent READ, so an attacker may control
    it. Printed raw, such a string can forge report lines (an embedded newline
    plus `  note   : ...`) or emit terminal escape sequences. Control characters
    become visible escapes, undecodable surrogates are replaced, and the result
    is capped so one huge field can't bury the report. The JSON output needs
    none of this: `json.dumps` escapes control characters itself."""
    text = value if isinstance(value, str) else str(value)
    text = text.encode("utf-8", "replace").decode("utf-8")
    text = _CTRL.sub(lambda m: "\\x%02x" % ord(m.group()), text)
    if len(text) <= cap:
        return text
    return text[:cap] + f"...[+{len(text) - cap} chars]"


def _fmt_event(trace: Trace, f: Finding, seq: int, by_seq: dict | None = None) -> str:
    # by_seq: prebuilt index. trace.by_seq() is a linear scan, so calling it per
    # event made printing O(n^2) and a 100k-event trace take minutes.
    e = by_seq.get(seq) if by_seq is not None else trace.by_seq(seq)
    tag = ""
    if seq == f.inject_seq:
        tag = "  <== INJECT"
    elif seq == f.landing_seq:
        tag = f"  <== LANDING ({f.landing_kind})"
    elif seq in f.blast_radius:
        tag = "  .. tainted"
    if isinstance(e, Message):
        body = f"{_safe(e.role, 40)}: {_safe(e.content, 80)}"
    elif isinstance(e, ToolResult):
        body = f"tool_result {e.tool!r}: {_safe(e.content, 70)}"
    elif isinstance(e, MemoryNote):
        body = f"memory({_safe(e.kind, 20)}): {_safe(e.content, 66)}"
    elif isinstance(e, ToolCall):
        body = f"tool_call {e.tool!r} args={_safe(e.args, 120)}"
    elif isinstance(e, AgentMessage):
        body = (f"{_safe(e.kind, 20)} {_safe(e.from_agent, 40)} -> {_safe(e.to_agent, 40)}: "
                f"{_safe(e.content, 60)}")
    else:
        body = _safe(e, 160)
    who = _safe(getattr(e, "agent", ""), 40) if not isinstance(e, AgentMessage) else ""
    return f"  #{seq:<3} {'[' + who + '] ' if who else ''}{body}{tag}"


def _print_human(trace: Trace, f: Finding) -> None:
    # Deliberately hedged: the `fuse` block is a field in the file, and whoever
    # wrote the file wrote it. Say what the trace records, not what we verified.
    contained = "  (contained: the trace's fuse block records this call as blocked)" \
        if f.contained else ""
    print(f"\ntrace {trace.trace_id!r} (source={_safe(trace.source, 60) or '?'})  "
          f"{_VERDICT_MARK.get(f.verdict, f.verdict)}{contained}")
    by_seq = {e.seq: e for e in trace.events}
    for e in trace.events:
        print(_fmt_event(trace, f, e.seq, by_seq))
    if f.inject_seq is not None:
        print(f"\n  inject : #{f.inject_seq} - {_safe(f.inject_signal)}")
    if f.landing_seq is not None:
        print(f"  landing: #{f.landing_seq} - {_safe(f.landing_signal)}")
    if f.causal_path:
        link = "linked" if f.linked else "inferred"
        print(f"  path   : {' -> '.join('#' + str(s) for s in f.causal_path)}  ({link})")
    if f.blast_radius:
        print(f"  blast  : {', '.join('#' + str(s) for s in f.blast_radius)}")
    if f.agents_reached:
        extra = f", {f.hops} hop(s)" if f.landed else ""
        worm = ", replicated by 2+ agents (worm signal)" if f.replicated else ""
        print(f"  cascade: {' -> '.join(_safe(a, 40) for a in f.agents_reached)}  "
              f"(patient zero: {_safe(f.patient_zero, 40)}{extra}{worm})")
    for n in f.notes:
        print(f"  note   : {_safe(n, 400)}")


def _example_dir():
    from importlib.resources import files

    return files("bastiontrace") / "fixtures"


def _example_names() -> list[str]:
    return sorted(p.name.rsplit(".", 1)[0] for p in _example_dir().iterdir()
                  if p.name.endswith((".jsonl", ".json")))


def _resolve_target(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Exactly one of: positional traces, --otel FILE, --example NAME."""
    given = sum(bool(x) for x in (args.traces, args.otel, args.example))
    if given != 1:
        parser.error("give exactly one of: trace file(s), --otel FILE, or --example NAME")
    if args.example:
        name = args.example
        path = next((_example_dir() / f"{name}{ext}" for ext in (".jsonl", ".json")
                     if (_example_dir() / f"{name}{ext}").is_file()), None)
        if path is None:
            parser.error(f"no example {name!r}; available: {', '.join(_example_names())}")
        if name.startswith("otel-"):
            args.otel = str(path)
        else:
            args.traces = [str(path)]
    if (args.forbid or args.canary) and not args.otel:
        parser.error("--forbid/--canary apply to --otel imports (a trace file carries its own policy)")


def _load_otel(args: argparse.Namespace):
    from .otel import from_otel

    text = Path(args.otel).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:  # Collector file exporter: one export object per line
        data = [json.loads(line) for line in text.splitlines() if line.strip()]
    imp = from_otel(data, forbid=args.forbid, canaries=args.canary)
    if not imp.content_captured:
        print(f"bastiontrace: WARNING: no captured content in {args.otel}; injection sites "
              f"cannot be located. {_CAPTURE_HINT}", file=sys.stderr)
    if imp.truncated:
        print("bastiontrace: WARNING: span cap reached; the rest of the export was not read",
              file=sys.stderr)
    return imp


def _cmd_analyze(args: argparse.Namespace) -> int:
    where = args.otel or ", ".join(args.traces)
    extra: dict = {}
    try:
        if args.otel:
            imp = _load_otel(args)
            traces = list(imp.traces)
            extra = {"content_captured": imp.content_captured, "skipped_spans": imp.skipped_spans,
                     "truncated": imp.truncated}
        else:
            traces = []
            for p in args.traces:
                where = p
                traces.append(from_jsonl(Path(p).read_text(encoding="utf-8")))
    except json.JSONDecodeError as e:
        print(f"bastiontrace: {where}: not valid JSON ({e.msg} at line {e.lineno}); "
              "expected a JSONL trace or an OTLP/JSON export", file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, RecursionError) as e:
        print(f"bastiontrace: {where}: {e}", file=sys.stderr)
        return 2
    results = [(t, analyze(t)) for t in traces]
    if args.format == "json":
        payload = [
            {"trace_id": t.trace_id, "verdict": f.verdict, "provenance": t.provenance,
             **extra, **asdict(f)}
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
    a.add_argument("traces", nargs="*", help="trace JSONL file(s)")
    a.add_argument("--otel", metavar="FILE", help="an OTel GenAI export (OTLP/JSON, or JSONL)")
    a.add_argument("--example", metavar="NAME",
                   help="a bundled sample: " + ", ".join(_example_names()))
    a.add_argument("--forbid", action="append", default=[], metavar="TOOL",
                   help="with --otel: a tool the agents must not call (repeatable)")
    a.add_argument("--canary", action="append", default=[], metavar="TOKEN",
                   help="with --otel: a secret token that must not leak (repeatable)")
    a.add_argument("--format", choices=("human", "json"), default="human")
    a.set_defaults(func=_cmd_analyze, parser=a)

    h = sub.add_parser("harden", help="emit agentbastion rules from landed traces")
    h.add_argument("traces", nargs="+", help="trace JSONL file(s)")
    h.add_argument("--out", default="hardening", help="output dir (default: hardening/)")
    h.set_defaults(func=_cmd_harden)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.func is _cmd_analyze:
        _resolve_target(args, args.parser)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
