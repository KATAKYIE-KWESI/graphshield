"""Gatekeeper agent: evaluates a newly published version by walking the graph.

Every step records the Cypher it ran, its parameters, the server-side run time
and the rows it got back, so each verdict can be traced to the evidence.
The verdict is written back into the graph as a :Decision node, which later
evaluations read as memory. BLOCK / QUARANTINE decisions are left open
(needs_investigation) for the Investigator agent to pick up.
"""
import uuid
from dataclasses import dataclass, field

from graphshield import queries as Q
from graphshield.db import get_graph


@dataclass
class Step:
    name: str
    cypher: str
    params: dict
    rows: list
    ms: float


@dataclass
class Verdict:
    version_id: str
    decision_id: str = ""
    verdict: str = "ALLOW"
    risk: int = 0
    impact: str = "low"
    reasons: list = field(default_factory=list)
    steps: list = field(default_factory=list)
    context: dict = field(default_factory=dict)

    @property
    def total_ms(self) -> float:
        return sum(s.ms for s in self.steps)


class GatekeeperAgent:
    def __init__(self, graph=None):
        self.g = graph or get_graph()

    def _run(self, out: Verdict, name: str, cypher: str, params: dict, write=False) -> list:
        res = (self.g.query if write else self.g.ro_query)(cypher, params)
        cols = [h[1] if isinstance(h, (list, tuple)) else h for h in res.header]
        rows = [dict(zip(cols, r)) for r in res.result_set]
        out.steps.append(Step(name, cypher.strip(), params, rows, float(res.run_time_ms)))
        return rows

    def evaluate(self, version_id: str) -> Verdict:
        out = Verdict(version_id)

        ctx = self._run(out, "Identify publisher and package", Q.PUBLISH_CONTEXT, {"vid": version_id})
        if not ctx:
            raise ValueError(f"Unknown version {version_id}")
        ctx = ctx[0]
        out.context = ctx
        h, pkg = ctx["maintainer"], ctx["package"]
        p = {"handle": h, "pkg": pkg}

        trust = self._run(out, "Score maintainer trust", Q.MAINTAINER_TRUST, p)[0]
        vouch = self._run(out, "Propagate trust from peers", Q.PEER_VOUCHES, p)[0]
        blast = self._run(out, "Compute blast radius (1..5 hops)", Q.BLAST_RADIUS, {"pkg": pkg})[0]
        self._run(out, "Trace deepest app -> package chains", Q.ATTACK_PATHS, {"pkg": pkg})
        memory = self._run(out, "Recall prior decisions", Q.PRIOR_DECISIONS, p)
        memory = memory[0] if memory else {"maintainer_flags": 0, "package_flags": 0}
        out.context.update(trust, **vouch, **blast, **memory)

        self._score(out, ctx, trust, vouch, blast, memory)

        out.decision_id = str(uuid.uuid4())
        status = {"BLOCK": "blocked", "QUARANTINE": "quarantined"}.get(out.verdict, "released")
        self._run(out, "Record decision in graph memory", Q.RECORD_DECISION, {
            "handle": h, "vid": version_id, "did": out.decision_id,
            "verdict": out.verdict, "risk": out.risk, "impact": out.impact,
            "reasons": out.reasons, "status": status,
            "needs_investigation": out.verdict != "ALLOW",
        }, write=True)
        return out

    @staticmethod
    def _score(out, ctx, trust, vouch, blast, memory):
        risk, why = 0, out.reasons
        age = trust["account_age_days"] or 0
        tenure = trust["days_as_maintainer"]

        if trust["flagged"]:
            risk += 30; why.append(f"Flagged by the Investigator agent: {trust['flag_reason']}")
        if age < 30:
            risk += 35; why.append(f"Publisher account is {age} days old (< 30)")
        elif age < 90:
            risk += 15; why.append(f"Publisher account is {age} days old (< 90)")
        if not trust["verified"]:
            risk += 10; why.append("Publisher is not verified")
        if not trust["mfa"]:
            risk += 10; why.append("Publisher has no MFA")
        if tenure is not None and tenure < 30:
            risk += 15; why.append(f"Became a maintainer of {ctx['package']} {tenure} days ago")
        if vouch["vouching_peers"] == 0:
            risk += 10; why.append("No established maintainer vouches for them on any other package")
        if ctx["dormant_days"] >= 180:
            risk += 20; why.append(f"Account was dormant for {ctx['dormant_days']} days before this release "
                                   "(possible account takeover)")
        if ctx["has_install_script"]:
            risk += 15; why.append("New version adds an install script")
        if memory["maintainer_flags"]:
            risk += 20; why.append(f"Publisher was flagged {memory['maintainer_flags']} time(s) before")
        if memory["package_flags"]:
            why.append(f"Package had {memory['package_flags']} earlier flagged release(s)")

        apps = blast["apps_affected"]
        out.impact = "critical" if apps >= 50 else "high" if apps >= 10 else "low"
        why.append(f"Blast radius: {blast['total_dependents']} dependents, {apps} apps ({out.impact})")

        out.risk = min(risk, 100)
        if out.risk >= 50 and out.impact in ("high", "critical"):
            out.verdict = "BLOCK"
        elif out.risk >= 50 or (out.risk >= 30 and out.impact == "critical"):
            out.verdict = "QUARANTINE"
        else:
            out.verdict = "ALLOW"
