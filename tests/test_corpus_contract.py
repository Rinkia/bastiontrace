"""Consumer contract: bastiontrace still parses the shared corpus (PRP §1.3).

bastiontrace's analyzer appends bastioncorpus `to_trace` signatures to its
built-in marker patterns. `_load_patterns` swallows any error and falls back to
built-ins alone — recall degrades silently. This test asserts the corpus
signatures were actually added and each one regex-compiles.
"""

from __future__ import annotations

import re

from bastioncorpus import load_corpus, to_trace

from bastiontrace.analyzer import _BUILTIN_PATTERNS, _load_patterns


def test_trace_signatures_shape():
    sigs = to_trace(load_corpus())
    assert sigs, "corpus produced zero trace signatures"
    for s in sigs:
        assert set(s) == {"id", "category", "severity", "match", "pattern"}
        assert s["match"] == "substring"
        re.compile(re.escape(s["pattern"]))  # must be regex-safe after escape


def test_patterns_include_corpus_not_just_builtins():
    patterns = _load_patterns()
    assert len(patterns) > len(_BUILTIN_PATTERNS), (
        "bastiontrace fell back to built-in patterns only — the corpus to_trace "
        "contract broke and enrichment is silently off"
    )
    for pat, _cat in patterns:
        re.compile(pat, re.I)  # every pattern compiles
