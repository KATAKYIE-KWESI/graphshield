"""Investigator agent: an LLM digs into the cases the Gatekeeper leaves open.

The two agents coordinate only through the graph:
  Gatekeeper   writes (:Decision {needs_investigation: true})
  Investigator reads open decisions, explores the graph with its own read-only
               Cypher, may flag maintainer accounts, and writes an
               (:Investigation)-[:INVESTIGATED]->(:Decision) report.
  Gatekeeper   reads those flags on the account's next release.

Graph access is read-only (GRAPH.RO_QUERY, enforced by FalkorDB) except for one
narrow write tool, flag_maintainer. Every tool call is traced like the
Gatekeeper's steps.

The LLM is any OpenAI-compatible chat API, picked with LLM_PROVIDER
(groq, gemini, huggingface, ollama). All of them have a free option.
"""
import json
import os
import time
import uuid
from dataclasses import dataclass, field

from openai import OpenAI

from graphshield import queries as Q
from graphshield.agent import Step
from graphshield.db import get_graph

# provider -> (base URL, env var holding the key, default model)
PROVIDERS = {
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY", "openai/gpt-oss-120b"),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai/", "GEMINI_API_KEY", "gemini-2.5-flash"),
    "huggingface": ("https://router.huggingface.co/v1", "HF_TOKEN", "meta-llama/Llama-3.3-70B-Instruct"),
    "ollama": ("http://localhost:11434/v1", None, "qwen2.5:3b"),
}

MAX_TURNS = 15
MAX_ROWS = 25
MAX_RESULT_CHARS = 6000  # keeps each request inside free-tier token limits

SYSTEM = """You are the Investigator agent in GraphShield, a supply-chain security system \
for a package registry stored in a FalkorDB graph. A separate Gatekeeper agent has just \
blocked or quarantined a release. Your job is to work out what is really going on and \
what the security team should do next.

Graph schema (FalkorDB Cypher; timestamps are epoch milliseconds, compare with timestamp(); \
one day is 86400000 ms):
(:Maintainer {handle, created_at, last_active_at, verified, mfa, flagged, flag_reason})
(:Maintainer)-[:MAINTAINS {since}]->(:Package {name, kind: 'app'|'library', tier, weekly_downloads})
(:Maintainer)-[:PUBLISHED {at}]->(:Version {id, number, published_at, prev_active_at, has_install_script, status})
(:Version)-[:PART_OF]->(:Package)
(:Package)-[:DEPENDS_ON]->(:Package)        // dependent -> dependency
(:Decision {id, verdict, risk, impact, reasons, at, needs_investigation})-[:EVALUATED]->(:Version)
(:Decision)-[:CITED]->(:Maintainer), (:Decision)-[:CITED]->(:Package)
(:Investigation)-[:INVESTIGATED]->(:Decision), (:Investigation)-[:FLAGGED]->(:Maintainer)
Version.status is 'released', 'pending', 'quarantined' or 'blocked'. Tier 0 packages are \
core utilities; apps are tier 3.

Investigate with run_cypher, one focused query at a time; return properties \
(m.handle, p.name) rather than whole nodes. Useful questions: what else does this account \
maintain or have access to, and since when; were other packages staged for a follow-up \
attack; has this account or package been flagged before; which downstream apps are exposed. \
Base every finding on query results, not assumptions, and cite the numbers you saw. \
Compute ages in Cypher, e.g. (timestamp() - m.created_at) / 86400000 AS days_ago, and in \
the report write "2 days ago", never raw epoch numbers or decision ids. \
packages_at_risk should lead with any other package the account can publish to.

If the evidence shows an account is compromised or malicious, flag it yourself with \
flag_maintainer before submitting the report; do not just recommend flagging it. That flag \
is how you warn the Gatekeeper. Flag only on evidence. \
A flag raises the risk of every future release by that account, so do not flag an \
established maintainer just for being near the incident.

Always respond by calling a tool. When you are done (usually after 3-6 queries), call \
submit_report."""


def _fn(name, description, properties, required):
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties, "required": required}}}


_STR_LIST = {"type": "array", "items": {"type": "string"}}
TOOLS = [
    _fn("run_cypher",
        f"Run a read-only Cypher query against the registry graph and get the rows back as JSON "
        f"(at most {MAX_ROWS} rows). Writes are rejected. Pass values inline; there are no parameters.",
        {"query": {"type": "string", "description": "A read-only Cypher query."},
         "purpose": {"type": "string", "description": "One short line: what this query checks."}},
        ["query", "purpose"]),
    _fn("flag_maintainer",
        "Flag a maintainer account as compromised or malicious. The Gatekeeper adds risk to "
        "every future release by a flagged account.",
        {"handle": {"type": "string"},
         "reason": {"type": "string", "description": "One sentence, citing the evidence."}},
        ["handle", "reason"]),
    _fn("submit_report", "Submit the final incident report. This ends the investigation.",
        {"severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
         "headline": {"type": "string", "description": "One line, under 15 words."},
         "summary": {"type": "string", "description": "2-4 sentences for the security team."},
         "findings": {**_STR_LIST, "description": "Evidence-backed findings, each citing graph facts."},
         "packages_at_risk": {**_STR_LIST, "description": "Other packages that need attention, not the blocked one."},
         "recommended_actions": _STR_LIST},
        ["severity", "headline", "summary", "findings", "packages_at_risk", "recommended_actions"]),
]
REPORT_FIELDS = TOOLS[2]["function"]["parameters"]["required"]


def llm_settings() -> tuple[str, str, str | None]:
    """(base_url, model, api_key) from LLM_PROVIDER / LLM_MODEL / LLM_BASE_URL and the provider's key."""
    provider = (os.getenv("LLM_PROVIDER") or "groq").lower()
    if provider not in PROVIDERS:
        raise ValueError(f"LLM_PROVIDER must be one of {', '.join(PROVIDERS)}, not {provider!r}")
    base_url, key_env, model = PROVIDERS[provider]
    key = os.getenv(key_env) if key_env else "ollama"
    if not key:
        raise RuntimeError(f"Set {key_env} in your .env file to use LLM_PROVIDER={provider} (see .env.example).")
    return os.getenv("LLM_BASE_URL") or base_url, os.getenv("LLM_MODEL") or model, key


@dataclass
class Investigation:
    decision_id: str
    model: str = ""
    case: dict = field(default_factory=dict)
    report: dict = field(default_factory=dict)
    flagged: list = field(default_factory=list)
    steps: list = field(default_factory=list)
    turns: int = 0
    seconds: float = 0.0


def _plain(value):
    """FalkorDB nodes/edges/paths -> JSON-friendly values."""
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if hasattr(value, "labels"):  # Node
        return {"labels": value.labels, **value.properties}
    if hasattr(value, "relation"):  # Edge
        return {"type": value.relation, **value.properties}
    if hasattr(value, "nodes") and callable(value.nodes):  # Path
        return [_plain(n) for n in value.nodes()]
    return value


class InvestigatorAgent:
    def __init__(self, graph=None, client=None, model=None):
        self.g = graph or get_graph()
        self.client, self.model = client, model  # resolved on first investigation, so listing cases needs no key

    def open_cases(self) -> list:
        return [r[0] for r in self.g.ro_query(Q.OPEN_CASES).result_set]

    def _tool(self, out: Investigation, name: str, args: dict) -> tuple[str, bool]:
        if name == "run_cypher":
            query, purpose = args.get("query", ""), args.get("purpose", "query")
            try:
                res = self.g.ro_query(query, timeout=5000)
            except Exception as e:
                out.steps.append(Step(f"LLM: {purpose} (error)", query, {}, [], 0.0))
                return f"Query failed: {e}", True
            cols = [h[1] if isinstance(h, (list, tuple)) else h for h in res.header]
            rows = [dict(zip(cols, _plain(r))) for r in res.result_set[:MAX_ROWS]]
            out.steps.append(Step(f"LLM: {purpose}", query, {}, rows, float(res.run_time_ms)))
            text = json.dumps(rows, default=str)
            if len(res.result_set) > MAX_ROWS:
                text += f" (first {MAX_ROWS} of {len(res.result_set)} rows)"
            if len(text) > MAX_RESULT_CHARS:
                text = text[:MAX_RESULT_CHARS] + " ...(truncated; return fewer columns or rows)"
            return text, False
        if name == "flag_maintainer":
            params = {"handle": args.get("handle", ""), "reason": args.get("reason", "")}
            res = self.g.query(Q.FLAG_MAINTAINER, params)
            out.steps.append(Step(f"LLM: flag {params['handle']}", Q.FLAG_MAINTAINER.strip(), params,
                                  [{"flagged": r[0]} for r in res.result_set], float(res.run_time_ms)))
            if not res.result_set:
                return f"No maintainer with handle {params['handle']!r}.", True
            if params["handle"] not in out.flagged:
                out.flagged.append(params["handle"])
            return f"Flagged {params['handle']}.", False
        return f"Unknown tool {name}", True

    def investigate(self, decision_id: str, on_step=None) -> Investigation:
        """on_step(step) is called after each graph tool call, for live progress in the UI."""
        if self.client is None:
            base_url, model, key = llm_settings()
            self.client = OpenAI(base_url=base_url, api_key=key, max_retries=5)  # retries ride out free-tier rate limits
            self.model = self.model or model
        out = Investigation(decision_id, model=self.model)
        started = time.time()
        rows = self.g.ro_query(Q.CASE_FILE, {"did": decision_id}).result_set
        if not rows:
            raise ValueError(f"Unknown decision {decision_id}")
        cols = ["decision_id", "verdict", "risk", "impact", "gatekeeper_reasons", "version_id",
                "package", "publisher", "has_install_script"]
        out.case = dict(zip(cols, rows[0]))

        messages = [{"role": "system", "content": SYSTEM},
                    {"role": "user", "content": "Case file from the Gatekeeper agent:\n" + json.dumps(out.case, indent=2)}]
        while not out.report:
            out.turns += 1
            if out.turns > MAX_TURNS:
                raise RuntimeError(f"Investigator did not submit a report within {MAX_TURNS} turns")
            msg = self.client.chat.completions.create(
                model=self.model, messages=messages, tools=TOOLS, temperature=0.2,
            ).choices[0].message

            if not msg.tool_calls:
                messages.append({"role": "assistant", "content": msg.content or ""})
                messages.append({"role": "user", "content": "Respond by calling a tool. If you have "
                                 "enough evidence, call submit_report."})
                continue

            messages.append({"role": "assistant", "content": msg.content or "", "tool_calls": [
                {"id": c.id, "type": "function",
                 "function": {"name": c.function.name, "arguments": c.function.arguments}}
                for c in msg.tool_calls]})
            for call in msg.tool_calls:
                try:
                    args = json.loads(call.function.arguments or "{}")
                except json.JSONDecodeError:
                    text, is_error = "Arguments were not valid JSON. Try again.", True
                else:
                    if call.function.name == "submit_report":
                        missing = [f for f in REPORT_FIELDS if f not in args]
                        if missing:
                            text, is_error = f"Report is missing: {', '.join(missing)}", True
                        else:
                            out.report = args
                            text, is_error = "Report received.", False
                    else:
                        text, is_error = self._tool(out, call.function.name, args)
                        if on_step and out.steps:
                            on_step(out.steps[-1])
                messages.append({"role": "tool", "tool_call_id": call.id,
                                 "content": ("ERROR: " if is_error else "") + text})

        out.seconds = time.time() - started
        # Smaller models are loose with types; normalise before storing.
        r = out.report
        for k in ("findings", "packages_at_risk", "recommended_actions"):
            r[k] = [str(x) for x in r[k]] if isinstance(r[k], list) else [str(r[k])]
        r["severity"] = str(r["severity"]).lower()
        if r["severity"] not in ("low", "medium", "high", "critical"):
            r["severity"] = "high"
        self.g.query(Q.RECORD_INVESTIGATION, {
            "did": decision_id, "iid": str(uuid.uuid4()), "model": self.model,
            "severity": r["severity"], "headline": str(r["headline"]), "summary": str(r["summary"]),
            "findings": r["findings"], "actions": r["recommended_actions"],
            "packages_at_risk": r["packages_at_risk"], "flagged": out.flagged,
        })
        return out
