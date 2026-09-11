"""Promote each module's runnable self-check into the pytest suite. The `_demo`
functions are assert-based; if any invariant breaks they raise."""

from bastiontrace import analyzer, harden, trace_schema


def test_trace_schema_selfcheck():
    trace_schema._demo()


def test_analyzer_selfcheck():
    analyzer._demo()


def test_harden_selfcheck():
    harden._demo()
