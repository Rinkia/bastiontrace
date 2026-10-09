"""A trace file is attacker-influenceable input.

Everything in a trace is content an agent READ: web pages, documents, MCP tool
results, messages from other agents. Traces also travel — produced on one
machine, analyzed on another, attached to a ticket. So the loader and the human
report both have to survive hostile strings.

Regression tests for the 2026-10-09 security review of 0.6.0.
"""

from __future__ import annotations

import json

import pytest

from bastiontrace.analyzer import analyze
from bastiontrace.cli import _safe, main
from bastiontrace.trace_schema import from_jsonl


def _trace(header_extra: dict, *events: dict) -> str:
    header = {"type": "trace", "v": 1, "trace_id": "t", **header_extra}
    return "\n".join([json.dumps(header)] + [json.dumps(e) for e in events]) + "\n"


# --- finding 2: the human report must not be forgeable ----------------------

def test_safe_escapes_control_characters_and_keeps_text_readable():
    assert _safe("plain text") == "plain text"
    assert "\n" not in _safe("two\nlines")
    assert _safe("two\nlines") == "two\\x0alines"
    assert _safe("\x1b[2J") == "\\x1b[2J", "no raw ESC reaches the terminal"
    assert _safe("accented: é ü 日本") == "accented: é ü 日本", "real text is untouched"


def test_safe_caps_length():
    out = _safe("A" * 5000, cap=100)
    assert len(out) < 200 and out.startswith("A" * 100) and "+4900 chars" in out


def test_fuse_reason_cannot_forge_report_lines(capsys, tmp_path):
    """The fuse `reason` is copied verbatim into the landing signal. A newline
    in it used to let an attacker print their own `note   :` / `blast  :` lines
    and emit terminal escapes."""
    reason = "benign\n  note   : FORGED, nothing was blocked\n  blast  : #0\x1b[31m"
    p = tmp_path / "t.jsonl"
    p.write_text(_trace({"source": "bastionfuse", "fuse": {"rule": "honeytoken", "reason": reason}},
                        {"type": "tool_call", "seq": 0, "tool": "x", "args": {},
                         "verdict": "tripped"}), encoding="utf-8")
    main(["analyze", str(p)])
    out = capsys.readouterr().out
    assert "\x1b" not in out, "no raw escape sequence"
    assert "FORGED" in out, "the text is still shown, just neutralised"
    forged = [ln for ln in out.splitlines() if ln.startswith("  note   : FORGED")]
    assert not forged, "the forged line must not render as its own report line"
    assert sum(ln.startswith("  blast  :") for ln in out.splitlines()) <= 1


def test_tool_result_content_cannot_forge_report_lines(capsys, tmp_path):
    """Same hazard on the pre-0.6.0 paths: tool_result content, agent names."""
    p = tmp_path / "t.jsonl"
    p.write_text(_trace({"policy": {"forbidden_tools": ["send_email"]}},
                        {"type": "tool_result", "seq": 0, "tool": "fetch",
                         "content": "x\n  landing: #99 - nothing happened\x1b[0m",
                         "agent": "a\nb"},
                        {"type": "tool_call", "seq": 1, "tool": "send_email",
                         "args": {}, "args_from": [0]}), encoding="utf-8")
    main(["analyze", str(p)])
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert sum(ln.startswith("  landing:") for ln in out.splitlines()) == 1


def test_huge_args_do_not_bury_the_report(capsys, tmp_path):
    p = tmp_path / "t.jsonl"
    p.write_text(_trace({}, {"type": "tool_call", "seq": 0, "tool": "x",
                             "args": {"blob": "A" * 200_000}}), encoding="utf-8")
    main(["analyze", str(p)])
    out = capsys.readouterr().out
    assert len(out) < 4000, f"report ballooned to {len(out)} chars"


# --- finding 3: hostile header values raise ValueError naming the field -----

@pytest.mark.parametrize("header,where", [
    ({"policy": [1]}, "policy"),
    ({"policy": "send_email"}, "policy"),
    ({"policy": {"forbidden_tools": [[1]]}}, "forbidden_tools"),
    ({"policy": {"forbidden_tools": "send_email"}}, "forbidden_tools"),
    ({"policy": {"canary_tokens": [5]}}, "canary_tokens"),
    ({"canary": 5}, "canary"),
    ({"trace_id": 7}, "trace_id"),
    ({"source": {}}, "source"),
])
def test_hostile_header_values_raise_named_value_error(header, where):
    with pytest.raises(ValueError, match=where):
        from_jsonl(_trace(header))


@pytest.mark.parametrize("payload,where", [
    ({"canary": "\ud800"}, "canary"),
    ({"policy": {"forbidden_tools": ["\ud800"]}}, "forbidden_tools"),
])
def test_lone_surrogate_in_header_is_refused(payload, where):
    """It survives JSON parsing but crashes any attempt to print or re-encode
    it, so it has to die at the boundary, not mid-report."""
    with pytest.raises(ValueError, match=where):
        from_jsonl(_trace(payload))


def test_lone_surrogate_in_event_is_refused():
    with pytest.raises(ValueError, match="content"):
        from_jsonl(_trace({}, {"type": "tool_result", "seq": 0, "tool": "f",
                               "content": "\ud800"}))


def test_cli_reports_hostile_input_as_an_error_not_a_traceback(capsys, tmp_path):
    """Exit 2 is "bad input". Exit 1 means LANDED, so a crash must never look
    like a finding."""
    p = tmp_path / "t.jsonl"
    p.write_text(_trace({"policy": [1]}), encoding="utf-8")
    assert main(["analyze", str(p)]) == 2
    assert "policy" in capsys.readouterr().err


def test_a_string_policy_is_not_silently_split_into_characters():
    """`forbidden_tools: "send_email"` used to become 11 single-character tool
    names, so nothing matched and a real landing read as CLEAN."""
    with pytest.raises(ValueError, match="forbidden_tools"):
        from_jsonl(_trace({"policy": {"forbidden_tools": "send_email"}},
                          {"type": "tool_call", "seq": 0, "tool": "send_email", "args": {}}))


def test_clean_trace_is_unaffected_by_the_new_validation():
    t = from_jsonl(_trace({"policy": {"forbidden_tools": ["send_email"]}, "canary": "AGP-1"},
                          {"type": "tool_result", "seq": 0, "tool": "fetch", "content": "ok"},
                          {"type": "tool_call", "seq": 1, "tool": "search", "args": {}}))
    assert analyze(t).verdict == "CLEAN"
    assert t.policy.forbidden_tools == ("send_email",) and t.canary == "AGP-1"
