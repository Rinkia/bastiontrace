# Launch blurbs

Pick per channel. All link to the repo / PyPI.

---

## Hacker News (Show HN)

**Title:**
Show HN: bastiontrace – forensics for prompt-injected AI agents

**Body:**

An agent read a poisoned document and emailed your customer list to a stranger.
Now what? You have a transcript of tool calls and no fast way to say *where* the
injection got in or *what* it touched.

bastiontrace reads an agent's tool-call trace (JSONL) and answers that in one
shot: the inject point, the landing (a forbidden tool call, or a secret leaked
into a reply), the causal path between them, and the blast radius — every call
the injection tainted. No LLM, no dependencies, runs offline.

It's the last piece of a trilogy I've been building:

- agentbastion — a runtime firewall for agents (prevent)
- bastionprobe — fires indirect prompt-injection payloads and reports which land (attack)
- bastiontrace — reads the trace after the fact (investigate)

They share one dataflow. A bastionprobe run that lands serializes into a trace;
bastiontrace locates it; `bastiontrace harden` emits an agentbastion policy +
detector corpus that blocks it next time. Same file shapes across all three.

Provenance is the trick that makes the causal path exact: if the trace records
`args_from` (which prior outputs a call's arguments came from), bastiontrace
walks it backward from the forbidden call to the poisoned tool output and marks
the path `linked`. No provenance? It falls back to canary/pattern matching and
marks it `inferred`, so you always know how much to trust the chain.

`analyze` exits non-zero on a landed injection, so it works as a CI gate on
recorded agent runs.

    pip install bastiontrace

Repo: https://github.com/Rinkia/bastiontrace
Schema spec, examples, and the trilogy write-up are in the README. Feedback
welcome — especially on the trace schema, since getting other agent frameworks
to emit it is the thing that makes this useful beyond my own tools.

---

## Reddit (r/netsec, r/LocalLLaMA)

**Title:**
bastiontrace: open-source forensics for prompt-injected AI agents (find the inject, map the blast radius)

**Body:**

When an agent gets prompt-injected through a tool output — a fetched doc, a
search result, a ticket — the aftermath is a pile of tool calls and no quick way
to see which output carried the injection or how far it spread.

bastiontrace takes an agent's tool-call trace and pins down four things: the
inject point, the landing (forbidden tool call or leaked secret), the causal
path linking them (via recorded argument provenance, or inferred), and the blast
radius. Pure Python, zero deps, no model calls.

It pairs with two tools I already shipped — agentbastion (runtime firewall) and
bastionprobe (injection red-teamer) — and `harden` turns a finding into a
firewall policy + detector corpus, so attack → investigate → defend is one loop.

MIT, `pip install bastiontrace`. https://github.com/Rinkia/bastiontrace

---

## X / short

Shipped bastiontrace: forensics for prompt-injected AI agents.

Feed it an agent's tool-call trace → it finds where the injection got in, what
forbidden action it caused, and everything it tainted along the way.

No LLM, no deps. Third leg of the trilogy: prevent (agentbastion), attack
(bastionprobe), investigate (bastiontrace).

pip install bastiontrace
