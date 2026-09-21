"""bastiontrace - the investigate side of the bastion trilogy.

Read an agent's tool-call trace, locate the prompt injection, and map what it
caused. Pairs with agentbastion (prevent) and bastionprobe (attack): a landed
attack serializes to a trace, bastiontrace locates it, and `harden` turns the
finding back into agentbastion defenses.
"""

from .analyzer import Finding, analyze
from .harden import Hardening, analyze_files, build_hardening, write_hardening
from .trace_schema import (
    Message,
    Policy,
    ToolCall,
    ToolResult,
    Trace,
    from_bastionprobe,
    from_jsonl,
)

__version__ = "0.3.0"

__all__ = [
    "analyze",
    "Finding",
    "Trace",
    "Policy",
    "Message",
    "ToolResult",
    "ToolCall",
    "from_jsonl",
    "from_bastionprobe",
    "Hardening",
    "build_hardening",
    "write_hardening",
    "analyze_files",
]
