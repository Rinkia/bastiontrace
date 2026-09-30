"""OpenTelemetry GenAI import: OTLP/JSON spans -> v3 multi-agent traces.

Most agent frameworks can export OTel GenAI spans (`invoke_agent`, `execute_tool`,
with `gen_ai.agent.id|name` and `gen_ai.tool.name`). This turns such an export
(a single OTLP/JSON object, or the Collector file exporter's JSONL, one object per
line) into bastiontrace traces, one per OTel traceId:

    root invoke_agent start / end   -> message(user) / message(assistant)
    child invoke_agent start / end  -> agent_message delegate (parent -> child)
                                       / agent_message reply (child -> parent)
    execute_tool start / end        -> tool_call / tool_result

Events are ordered by the time they happened: calls and delegations at span
start, results and replies at span end; at equal timestamps an end sorts before
a start (a result that finished when a delegation began was already read). A
span with a missing or backwards end time is stretched to its last descendant.

Provenance is INFERRED from the span tree, so the trace is marked
`provenance: inferred` and every finding is `linked=False`:

    delegate.derived_from = everything the parent agent read so far (its context persists)
    reply.derived_from    = every event of the child agent
    child tool_call.args_from = the delegation that started the child
    tool_result.source_seq    = its tool_call

Content (tool arguments/results, agent input/output messages) is opt-in in most
OTel instrumentations; without it an import can only ever be CLEAN, and
`ImportResult.content_captured` says so. System-role message parts are skipped:
they are the agent's own instructions, not something it was fed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .trace_schema import AgentMessage, Message, Policy, ToolCall, ToolResult, Trace

# ponytail: fixed caps per import against hostile exports; raise if real ones hit them
MAX_SPANS = 200_000
MAX_EDGES = 1_000_000  # provenance edges per trace; past it a delegation keeps its last _TAIL reads
_TAIL = 1_000

_TEXT_EVENT_NAMES = {
    "input": ("gen_ai.user.message", "gen_ai.tool.message"),
    "output": ("gen_ai.choice", "gen_ai.assistant.message"),
}


@dataclass(frozen=True)
class ImportResult:
    traces: tuple[Trace, ...]
    content_captured: bool  # any span carried message/tool content
    skipped_spans: int = 0  # malformed spans ignored
    truncated: bool = False  # a span or edge cap was reached; some input was not used


# --- OTLP/JSON plumbing ------------------------------------------------------

def _value(v):
    """Decode an OTLP AnyValue (every variant, so structured content is not dropped)."""
    if not isinstance(v, dict):
        return None
    for key in ("stringValue", "boolValue", "doubleValue", "bytesValue"):
        if key in v:
            return v[key]
    if "intValue" in v:
        try:
            return int(v["intValue"])
        except (TypeError, ValueError):
            return None
    if isinstance(v.get("arrayValue"), dict):
        values = v["arrayValue"].get("values")
        return [_value(x) for x in values] if isinstance(values, list) else []
    if isinstance(v.get("kvlistValue"), dict):
        values = v["kvlistValue"].get("values")
        return _kv(values)
    return None


def _kv(raw) -> dict:
    out = {}
    if isinstance(raw, list):
        for a in raw:
            if isinstance(a, dict) and isinstance(a.get("key"), str):
                out[a["key"]] = _value(a.get("value"))
    return out


def _attrs(obj) -> dict:
    return _kv(obj.get("attributes")) if isinstance(obj, dict) else {}


def _nanos(v) -> int | None:
    if isinstance(v, bool):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _iter_spans(data):
    """Yield raw span dicts from an OTLP export object or a list of them."""
    exports = data if isinstance(data, list) else [data]
    for export in exports:
        rs_list = export.get("resourceSpans") if isinstance(export, dict) else None
        if not isinstance(rs_list, list):
            continue
        for rs in rs_list:
            ss_list = rs.get("scopeSpans") if isinstance(rs, dict) else None
            if not isinstance(ss_list, list):
                continue
            for ss in ss_list:
                spans = ss.get("spans") if isinstance(ss, dict) else None
                if isinstance(spans, list):
                    yield from spans


@dataclass(frozen=True)
class _Span:
    trace_id: str
    span_id: str
    parent_id: str
    start: int
    end: int
    attrs: dict
    events: tuple


def _parse(raw) -> _Span | None:
    if not isinstance(raw, dict):
        return None
    tid, sid = raw.get("traceId"), raw.get("spanId")
    start, end = _nanos(raw.get("startTimeUnixNano")), _nanos(raw.get("endTimeUnixNano"))
    if not (isinstance(tid, str) and tid and isinstance(sid, str) and sid) or start is None:
        return None
    parent = raw.get("parentSpanId")
    evs = raw.get("events")
    return _Span(tid, sid, parent if isinstance(parent, str) else "", start,
                 end if end is not None and end >= start else start, _attrs(raw),
                 tuple(e for e in evs if isinstance(e, dict)) if isinstance(evs, list) else ())


# --- content extraction ------------------------------------------------------

def _as_text(v) -> str:
    if isinstance(v, str):
        return v
    return "" if v is None else json.dumps(v, ensure_ascii=False)


def _part_text(part: dict) -> str:
    """A message part's text: `content`, else its other fields (tool_call_response
    `response`, tool_call `arguments`, ...) so no part shape hides content."""
    if isinstance(part.get("content"), str):
        return part["content"]
    rest = {k: v for k, v in part.items() if k != "type"}
    return _as_text(rest) if rest else ""


def _message_text(raw) -> str:
    """Text of non-system parts from a gen_ai.*.messages value. Anything that is not
    a message list is kept as-is: a JSON-shaped string must never read as empty."""
    parsed = raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except ValueError:
            return raw
    if not isinstance(parsed, list):
        return raw if isinstance(raw, str) else _as_text(raw)
    texts = []
    for msg in parsed:
        if not isinstance(msg, dict):
            texts.append(_as_text(msg))
            continue
        if msg.get("role") == "system":
            continue
        parts = msg.get("parts")
        if isinstance(parts, list):
            texts += [_part_text(p) if isinstance(p, dict) else _as_text(p) for p in parts]
        else:
            texts.append(_as_text(msg.get("content")))
    return "\n".join(t for t in texts if t)


def _event_text(span: _Span, names: tuple[str, ...]) -> str:
    texts = []
    for ev in span.events:
        if ev.get("name") in names:
            a = _attrs(ev)
            texts.append(_as_text(a.get("content", a.get("gen_ai.event.content"))))
    return "\n".join(t for t in texts if t)


def _text(span: _Span, attr: str, direction: str) -> str:
    parts = [_message_text(span.attrs.get(attr)) if attr in span.attrs else "",
             _event_text(span, _TEXT_EVENT_NAMES[direction])]
    return "\n".join(p for p in parts if p)


def _tool_args(span: _Span) -> dict:
    raw = span.attrs.get("gen_ai.tool.call.arguments")
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except ValueError:
            return {"raw": raw}
        return parsed if isinstance(parsed, dict) else {"raw": raw}
    return raw if isinstance(raw, dict) else {}


def _tool_result(span: _Span) -> str:
    text = _as_text(span.attrs.get("gen_ai.tool.call.result"))
    extra = _event_text(span, ("gen_ai.tool.message", "gen_ai.choice"))
    return "\n".join(p for p in (text, extra) if p)


# --- span tree -> events -----------------------------------------------------

def _op(span: _Span) -> str:
    op = span.attrs.get("gen_ai.operation.name")
    return op if isinstance(op, str) else ""


def _agent_name(span: _Span) -> str:
    for key in ("gen_ai.agent.id", "gen_ai.agent.name"):
        v = span.attrs.get(key)
        if isinstance(v, str) and v:
            return v
    return f"agent-{span.span_id[:8]}"  # unnamed agents stay distinct


def _depths(spans: list[_Span], by_id: dict) -> dict[str, int]:
    """Depth of each span in its tree, memoized (O(n)); a cycle counts as a root."""
    depth: dict[str, int] = {}
    for s in spans:
        chain, cur, seen = [], s, set()
        while cur is not None and cur.span_id not in depth and cur.span_id not in seen:
            seen.add(cur.span_id)
            chain.append(cur)
            cur = by_id.get(cur.parent_id)
        base = depth[cur.span_id] + 1 if cur is not None and cur.span_id in depth else 0
        for i, span in enumerate(reversed(chain)):
            depth[span.span_id] = base + i
    return depth


def _effective_ends(spans: list[_Span], by_id: dict, depth: dict[str, int]) -> dict[str, int]:
    """A span ends no earlier than its last descendant (fixes missing/backwards ends).
    One deepest-first pass pushes each end up to the parent: O(n log n)."""
    ends = {s.span_id: s.end for s in spans}
    for s in sorted(spans, key=lambda x: -depth[x.span_id]):
        parent = by_id.get(s.parent_id)
        if parent is not None and depth[parent.span_id] < depth[s.span_id]:
            ends[parent.span_id] = max(ends[parent.span_id], ends[s.span_id])
    return ends


class _Budget:
    def __init__(self) -> None:
        self.used = 0
        self.capped = False

    def take(self, seqs: list[int]) -> tuple[int, ...]:
        if self.used + len(seqs) > MAX_EDGES:
            self.capped = True
            seqs = seqs[-_TAIL:]
        self.used += len(seqs)
        return tuple(seqs)


def _build_trace(trace_id: str, spans: list[_Span], policy: Policy) -> tuple[Trace, bool, bool]:
    by_id = {s.span_id: s for s in spans}
    depths = _depths(spans, by_id)
    ends = _effective_ends(spans, by_id, depths)

    def agent_span(span: _Span | None) -> _Span | None:
        """Nearest invoke_agent span at or above `span` (visited set: cycles end)."""
        seen = set()
        while span is not None and span.span_id not in seen:
            seen.add(span.span_id)
            if _op(span) == "invoke_agent":
                return span
            span = by_id.get(span.parent_id)
        return None

    # at equal times: ends of real spans (0) before starts (1) before zero-length
    # ends (2); ends deepest-first (a child's result before its parent's reply),
    # starts shallowest-first (a delegation before the child's first call)
    moments = []
    for s in spans:
        if _op(s) in ("invoke_agent", "execute_tool"):
            end, d = ends[s.span_id], depths[s.span_id]
            moments.append((s.start, 1, d, s.span_id, 0, s))
            moments.append((end, 0 if end > s.start else 2, -d, s.span_id, 1, s))
    moments.sort(key=lambda m: m[:4])

    events: list = []
    captured = False
    budget = _Budget()
    call_seq: dict[str, int] = {}       # execute_tool span -> its tool_call seq
    delegate_seq: dict[str, int] = {}   # child invoke_agent span -> its delegate seq
    reads: dict[str, list[int]] = {}    # agent span -> seqs of content it read (cumulative)
    own: dict[str, list[int]] = {}      # agent span -> seqs of all its own events

    def mark(agent_sp: _Span | None, seq: int, read: bool) -> None:
        if agent_sp is not None:
            own.setdefault(agent_sp.span_id, []).append(seq)
            if read:
                reads.setdefault(agent_sp.span_id, []).append(seq)

    for *_key, phase, s in moments:
        seq = len(events)
        if _op(s) == "execute_tool":
            owner = agent_span(by_id.get(s.parent_id))
            agent = _agent_name(owner) if owner is not None else ""
            tool = s.attrs.get("gen_ai.tool.name")
            tool = tool if isinstance(tool, str) and tool else "tool"
            if phase == 0:
                args = _tool_args(s)
                captured = captured or bool(args)
                origin = delegate_seq.get(owner.span_id) if owner is not None else None
                events.append(ToolCall(seq, tool, args=args, agent=agent,
                                       args_from=(origin,) if origin is not None else None))
                call_seq[s.span_id] = seq
                mark(owner, seq, read=False)
            else:
                content = _tool_result(s)
                captured = captured or bool(content)
                events.append(ToolResult(seq, tool, content, source_seq=call_seq.get(s.span_id), agent=agent))
                mark(owner, seq, read=True)
            continue

        # invoke_agent
        me = _agent_name(s)
        parent_sp = agent_span(by_id.get(s.parent_id))
        if parent_sp is None or parent_sp.span_id == s.span_id:
            text = _text(s, "gen_ai.input.messages" if phase == 0 else "gen_ai.output.messages",
                         "input" if phase == 0 else "output")
            captured = captured or bool(text)
            if text:
                events.append(Message(seq, "user" if phase == 0 else "assistant", text, agent=me))
                mark(s, seq, read=phase == 0)
            continue
        parent = _agent_name(parent_sp)
        if phase == 0:
            text = _text(s, "gen_ai.input.messages", "input")
            derived = budget.take(reads.get(parent_sp.span_id, []))
            events.append(AgentMessage(seq, parent, me, text, kind="delegate", derived_from=derived or None))
            delegate_seq[s.span_id] = seq
            mark(s, seq, read=True)  # the child read its task
        else:
            text = _text(s, "gen_ai.output.messages", "output")
            derived = budget.take(own.get(s.span_id, []))
            events.append(AgentMessage(seq, me, parent, text, kind="reply", derived_from=derived or None))
            mark(parent_sp, seq, read=True)  # the parent read the reply
        captured = captured or bool(text)

    trace = Trace(trace_id=trace_id, events=tuple(events), source="otel", policy=policy, provenance="inferred")
    return trace, captured, budget.capped


def from_otel(data, forbid=(), canaries=()) -> ImportResult:
    """Import an OTLP/JSON export (dict) or a list of them (JSONL lines).

    `forbid` / `canaries` fill each trace's policy: an OTel export carries none, so
    without them an import can find an injection (ATTEMPTED) but never a landing.
    """
    if not isinstance(data, (dict, list)):
        raise ValueError("not an OTLP/JSON export (expected an object with resourceSpans, or a list of them)")
    grouped: dict[str, list[_Span]] = {}
    skipped = count = 0
    truncated = False
    for raw in _iter_spans(data):
        if count >= MAX_SPANS:
            truncated = True
            break
        span = _parse(raw)
        if span is None:
            skipped += 1
            continue
        count += 1
        grouped.setdefault(span.trace_id, []).append(span)
    policy = Policy(forbidden_tools=tuple(forbid), canary_tokens=tuple(canaries))
    traces, captured = [], False
    for tid, spans in grouped.items():
        trace, c, capped = _build_trace(tid, spans, policy)
        traces.append(trace)
        captured = captured or c
        truncated = truncated or capped
    return ImportResult(tuple(traces), captured, skipped, truncated)
