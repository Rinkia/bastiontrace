"""End-to-end CLI: analyze exits non-zero on a landed trace, harden writes the
agentbastion artifacts with the canary scaffolding stripped."""

import json
from pathlib import Path

from bastiontrace.cli import main

EXAMPLE = Path(__file__).parent.parent / "examples" / "exfil.jsonl"


def test_analyze_landed_exits_nonzero(capsys):
    code = main(["analyze", str(EXAMPLE)])
    out = capsys.readouterr().out
    assert code == 1  # landed -> CI gate trips
    assert "LANDED" in out
    assert "INJECT" in out and "LANDING" in out


def test_analyze_json(capsys):
    main(["analyze", str(EXAMPLE), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["verdict"] == "LANDED"
    assert data[0]["causal_path"] == [1, 2, 3, 4]
    assert data[0]["linked"] is True


def test_harden_writes_stripped_artifacts(tmp_path, capsys):
    out = tmp_path / "hardening"
    main(["harden", str(EXAMPLE), "--out", str(out)])
    policy = (out / "policy.yaml").read_text(encoding="utf-8")
    assert "- send_email" in policy
    rows = [json.loads(l) for l in (out / "injections.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    assert rows and rows[0]["label"] == "malicious"
    assert "AGP-" not in rows[0]["text"]  # canary stripped from learned template
