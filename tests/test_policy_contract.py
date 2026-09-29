"""Producer shape-lock: bastiontrace harden emits the tool-policy contract (PRP §1.3).

bastiontrace's `harden` emits a policy.yaml (default + deny-list) that agentbastion
and bastiongate load — the same contract vocabulary bastionsupply's byte-golden
freezes. This locks the keys so a rename fails loudly at the producer.
"""

from __future__ import annotations

from bastiontrace.harden import _policy_yaml


def test_policy_has_contract_keys():
    out = _policy_yaml(["send_email", "http_post"])
    assert out.count("policy_version: 2") == 1
    assert "default: allow" in out
    assert "deny:" in out
    assert "- send_email" in out and "- http_post" in out


def test_empty_denylist_still_valid_shape():
    out = _policy_yaml([])
    assert "policy_version: 2" in out and "default: allow" in out
    assert "deny: []" in out  # an empty list, not YAML null
