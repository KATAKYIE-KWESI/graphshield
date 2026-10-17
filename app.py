"""GraphShield: Streamlit demo UI.   Run:  streamlit run app.py"""
import json
import os
from datetime import datetime
from html import escape

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network

from graphshield import queries as Q
from graphshield.agent import GatekeeperAgent
from graphshield.db import get_graph
from graphshield.investigator import InvestigatorAgent, llm_settings
from graphshield.seed import TARGET, seed
from graphshield.simulate import (SECOND_TARGET, simulate_attack, simulate_legit_release,
                                  simulate_repeat_attack, simulate_takeover)

VERDICT_COLOUR = {"BLOCK": "#f43f5e", "QUARANTINE": "#f59e0b", "ALLOW": "#22c55e"}
SEVERITY_COLOUR = {"critical": "#f43f5e", "high": "#fb923c", "medium": "#f59e0b", "low": "#38bdf8"}

CSS = """
<style>
.block-container {padding-top: 3.5rem; max-width: 1400px;}
/* Keep the page sharp while Streamlit reruns; spinners show progress instead. */
[data-stale="true"], .stale-element {opacity: 1 !important; filter: none !important; transition: none !important;}
h1, h2, h3 {letter-spacing: -0.01em;}
.gs-hero {display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:1rem;
          padding:1.2rem 1.4rem; border-radius:16px; margin-bottom:1.2rem;
          background:linear-gradient(135deg,#131a2e 0%,#0f2a3d 100%); border:1px solid #1f2a44;}
.gs-hero h1 {margin:0; font-size:1.9rem;}
.gs-hero p {margin:.2rem 0 0; color:#94a3b8;}
.gs-chips {display:flex; gap:.5rem; flex-wrap:wrap;}
.gs-chip {display:inline-flex; align-items:center; gap:.4rem; padding:.25rem .7rem; border-radius:999px;
          font-size:.8rem; background:#0b1020; border:1px solid #1f2a44; color:#cbd5e1;}
.gs-dot {width:8px; height:8px; border-radius:50%; display:inline-block;}
.gs-section {font-size:.75rem; text-transform:uppercase; letter-spacing:.12em; color:#64748b;
             margin:1.4rem 0 .6rem; font-weight:600;}
.gs-card {background:#131a2e; border:1px solid #1f2a44; border-radius:14px; padding:1rem 1.1rem; height:100%;}
.gs-scenario {min-height:118px; margin-bottom:.5rem;}
.gs-scenario b {font-size:1rem;}
.gs-scenario p {color:#94a3b8; font-size:.85rem; margin:.35rem 0 0;}
.gs-verdict {display:flex; gap:1.4rem; align-items:center; flex-wrap:wrap; border-left:6px solid var(--c);}
.gs-pill {font-size:1.6rem; font-weight:800; color:var(--c); letter-spacing:.04em;}
.gs-meta {color:#cbd5e1; font-size:.95rem;}
.gs-meta code {background:#0b1020; padding:.1rem .35rem; border-radius:6px; color:#e5e9f2;}
.gs-meter {flex:1; min-width:220px;}
.gs-meter-track {height:10px; background:#0b1020; border-radius:999px; overflow:hidden; border:1px solid #1f2a44;}
.gs-meter-fill {height:100%; background:var(--c); border-radius:999px;}
.gs-meter-label {display:flex; justify-content:space-between; font-size:.8rem; color:#94a3b8; margin-bottom:.3rem;}
.gs-kpi .v {font-size:1.7rem; font-weight:700; color:#f8fafc;}
.gs-kpi .l {font-size:.78rem; color:#94a3b8; text-transform:uppercase; letter-spacing:.08em;}
.gs-reason {display:flex; gap:.6rem; padding:.55rem .2rem; border-bottom:1px solid #1f2a44; color:#e2e8f0;}
.gs-reason:last-child {border-bottom:none;}
.gs-steps {display:flex; flex-wrap:wrap; gap:.4rem; margin-bottom:.8rem;}
.gs-step {font-size:.78rem; padding:.3rem .6rem; border-radius:8px; background:#0b1020;
          border:1px solid #1f2a44; color:#cbd5e1;}
.gs-step b {color:#38bdf8;}
.gs-tag {display:inline-block; margin:.15rem .25rem .15rem 0; padding:.15rem .55rem; border-radius:6px;
         font-size:.8rem; background:#0b1020; border:1px solid #1f2a44; color:#e2e8f0;}
.gs-tag.red {border-color:#f43f5e; color:#fda4af;}
.gs-chain {font-family:ui-monospace,monospace; font-size:.82rem; padding:.45rem .6rem; margin-bottom:.35rem;
           background:#0b1020; border-radius:8px; border:1px solid #1f2a44; color:#cbd5e1; overflow-x:auto;}
.gs-chain .t {color:#f43f5e; font-weight:700;}
.gs-report h3 {margin:.2rem 0 .4rem;}
.gs-report ul {margin:.2rem 0 0 1.1rem; padding:0;}
.gs-report li {margin-bottom:.35rem; color:#e2e8f0;}
.gs-sev {font-weight:800; color:var(--c); font-size:.8rem; letter-spacing:.1em;}
.gs-muted {color:#94a3b8; font-size:.85rem;}
.gs-sidebar-stat {display:flex; justify-content:space-between; padding:.35rem 0; border-bottom:1px solid #1f2a44;}
</style>
"""


def html(s: str):
    st.markdown(s, unsafe_allow_html=True)


def section(title: str):
    html(f'<div class="gs-section">{title}</div>')


def kpi(col, value, label):
    col.markdown(f'<div class="gs-card gs-kpi"><div class="v">{value}</div><div class="l">{label}</div></div>',
                 unsafe_allow_html=True)


def show_trace(steps):
    html('<div class="gs-steps">' + "".join(
        f'<span class="gs-step"><b>{i}</b> {escape(s.name)} · {s.ms:.2f} ms</span>'
        for i, s in enumerate(steps, 1)) + "</div>")
    for i, s in enumerate(steps, 1):
        with st.expander(f"{i}. {s.name} · {s.ms:.3f} ms · {len(s.rows)} rows"):
            st.code(s.cypher, language="cypher")
            if s.params:
                st.caption("params: " + json.dumps(s.params, default=str))
            st.dataframe(pd.DataFrame(s.rows), width="stretch")


def colour_cells(mapping):
    return lambda val: f"color: {mapping.get(val, '#e5e9f2')}; font-weight: 700"


st.set_page_config(page_title="GraphShield", page_icon="🛡️", layout="wide")
html(CSS)

try:
    g = get_graph()
    stats = {r[0]: r[1] for r in g.ro_query(Q.GRAPH_STATS).result_set}
    db_ok = True
except Exception as e:
    db_ok, db_error = False, e

try:
    _, llm_model, _ = llm_settings()
    llm_chip = f'<span class="gs-chip"><span class="gs-dot" style="background:#22c55e"></span>LLM · {escape(llm_model)}</span>'
except Exception:
    llm_chip = '<span class="gs-chip"><span class="gs-dot" style="background:#f59e0b"></span>LLM not configured</span>'
db_chip = ('<span class="gs-chip"><span class="gs-dot" style="background:#22c55e"></span>FalkorDB connected</span>'
           if db_ok else
           '<span class="gs-chip"><span class="gs-dot" style="background:#f43f5e"></span>FalkorDB offline</span>')
html(f"""<div class="gs-hero"><div><h1>🛡️ GraphShield</h1>
<p>Two agents on a FalkorDB graph that stop supply-chain attacks before a poisoned release reaches production.</p></div>
<div class="gs-chips">{db_chip}{llm_chip}</div></div>""")

if not db_ok:
    st.error(f"Cannot reach FalkorDB: {db_error}. Start it with `docker compose up -d`.")
    st.stop()

with st.sidebar:
    st.markdown("### 🗄️ Registry graph")
    if stats:
        html("".join(f'<div class="gs-sidebar-stat"><span>{escape(str(k))}</span><b>{n:,}</b></div>'
                     for k, n in stats.items()))
    else:
        st.info("Graph is empty. Seed it first.")
    st.write("")
    if st.button("♻️ Seed / reset registry", width="stretch"):
        with st.spinner("Seeding..."):
            seed()
        st.session_state.pop("verdict", None)
        st.session_state.pop("investigation", None)
        st.rerun()
    if os.getenv("FALKORDB_HOST", "localhost") in ("localhost", "127.0.0.1"):
        st.markdown("[Open FalkorDB Browser ↗](http://localhost:3000)")
    else:
        st.markdown("[Open FalkorDB Cloud ↗](https://app.falkordb.cloud)")
    st.divider()
    st.markdown("### How it works")
    st.caption("**1. Gatekeeper** scores every release from graph facts: trust, vouching, blast radius "
               "and memory. Deterministic and traceable.")
    st.caption("**2. Investigator** (LLM) takes open cases, writes its own read-only Cypher, flags "
               "accounts and files a report.")
    st.caption("**3. Coordination**: they talk only through the graph. Flags from the Investigator "
               "change the Gatekeeper's next verdict.")

section("Simulate a release")
scenarios = [
    ("🚨 New-account attack", f"A 2-day-old, unverified account is added to <code>{TARGET}</code> and ships an install script.",
     simulate_attack, "primary"),
    ("🕵️ Account takeover", f"The trusted but 700-day-dormant maintainer of <code>{TARGET}</code> suddenly ships an install script.",
     simulate_takeover, "secondary"),
    ("🔁 Attacker strikes again", f"The latest attacker account publishes on <code>{SECOND_TARGET}</code>, where it was quietly staged.",
     simulate_repeat_attack, "secondary"),
    ("✅ Legit release", "An established, verified maintainer ships a normal patch to <code>semver-check</code>.",
     simulate_legit_release, "secondary"),
]
chosen = None
for col, (title, desc, fn, kind) in zip(st.columns(4), scenarios):
    with col:
        html(f'<div class="gs-card gs-scenario"><b>{title}</b><p>{desc}</p></div>')
        if st.button("Run", key=title, type=kind, width="stretch"):
            chosen = (title, fn)
if chosen:
    title, fn = chosen
    try:
        with st.spinner(f"{title}: publishing the release and running the Gatekeeper on the graph..."):
            event = fn()
            st.session_state.verdict = GatekeeperAgent(g).evaluate(event)
        st.session_state.pop("investigation", None)
        icon = {"BLOCK": "⛔", "QUARANTINE": "⚠️", "ALLOW": "✅"}[st.session_state.verdict.verdict]
        st.toast(f"{icon} {st.session_state.verdict.verdict}: {event}")
    except ValueError as e:
        st.warning(str(e))

v = st.session_state.get("verdict")
if v:
    c = VERDICT_COLOUR[v.verdict]
    ctx = v.context
    section("Gatekeeper verdict")
    html(f"""<div class="gs-card gs-verdict" style="--c:{c}">
<div class="gs-pill">{v.verdict}</div>
<div class="gs-meta"><code>{escape(v.version_id)}</code> published by <code>{escape(ctx['maintainer'])}</code><br>
<span class="gs-muted">impact <b style="color:{c}">{v.impact}</b> · {len(v.steps)} graph queries · {v.total_ms:.2f} ms server time</span></div>
<div class="gs-meter"><div class="gs-meter-label"><span>Risk score</span><b style="color:{c}">{v.risk}/100</b></div>
<div class="gs-meter-track"><div class="gs-meter-fill" style="width:{max(v.risk, 2)}%"></div></div></div>
</div>""")
    st.write("")
    k1, k2, k3, k4 = st.columns(4)
    kpi(k1, ctx["apps_affected"], "Apps affected")
    kpi(k2, ctx["total_dependents"], "Total dependents")
    kpi(k3, f"{ctx['account_age_days']} d", "Publisher account age")
    kpi(k4, f"{ctx['weekly_downloads_at_risk']:,}", "Weekly downloads at risk")
    st.write("")

    t_why, t_blast, t_paths, t_trace = st.tabs(["🧾 Why", "💥 Blast radius", "🧬 Attack paths", "🔍 Agent trace"])
    with t_why:
        icons = {"Blast radius": "💥", "Flagged": "🚩", "dormant": "💤", "install script": "📦",
                 "MFA": "🔓", "verified": "❔", "days old": "🆕", "maintainer of": "🔑", "vouches": "🤝",
                 "flagged": "🧠", "earlier flagged": "🧠"}
        rows = []
        for r in v.reasons:
            icon = next((i for k, i in icons.items() if k in r), "•")
            rows.append(f'<div class="gs-reason"><span>{icon}</span><span>{escape(r)}</span></div>')
        html('<div class="gs-card">' + "".join(rows) + "</div>")
    with t_blast:
        pkg = ctx["package"]
        st.caption(f"Every package and app that transitively depends on `{pkg}` (red). "
                   "Blue nodes are apps; hover for names.")
        edges = g.ro_query(Q.UPSTREAM_SUBGRAPH, {"pkg": pkg}).result_set
        net = Network(height="560px", width="100%", directed=True, bgcolor="#0b1020", font_color="#cbd5e1")
        net.barnes_hut(gravity=-4000, spring_length=120)
        colours = {"app": "#38bdf8", "library": "#64748b"}
        for src, sk, dst, dk in edges:
            for name, kind in ((src, sk), (dst, dk)):
                is_target = name == pkg
                net.add_node(name, label=name if is_target or kind != "app" else " ",
                             title=name, size=32 if is_target else 10,
                             color="#f43f5e" if is_target else colours[kind])
            net.add_edge(src, dst, color="#334155", arrows="to")
        page = net.generate_html().replace("<head>", "<head><style>body{margin:0;background:#0b1020}"
                                           "#mynetwork{border:none!important;background:#0b1020!important}"
                                           ".card{border:none!important;background:#0b1020!important}</style>", 1)
        components.html(page, height=570)
    with t_paths:
        st.caption("The deepest chains from a production app down to the released package.")
        step = next((s for s in v.steps if s.name.startswith("Trace deepest")), None)
        for row in (step.rows if step else []):
            chain = " → ".join(f'<span class="t">{escape(n)}</span>' if n == ctx["package"] else escape(n)
                               for n in row["chain"])
            html(f'<div class="gs-chain">{chain} <span class="gs-muted">· {row["hops"]} hops</span></div>')
    with t_trace:
        show_trace(v.steps)

if v and v.verdict != "ALLOW":
    section("Investigator agent")
    inv = st.session_state.get("investigation")
    if (inv is None or inv.decision_id != v.decision_id) and v.decision_id in InvestigatorAgent(g).open_cases():
        a, b = st.columns([3, 1])
        a.markdown('<div class="gs-muted">The Gatekeeper left this decision open in the graph. The Investigator '
                   'picks it up, explores the graph with its own read-only Cypher, can flag accounts, and files '
                   'an <code>:Investigation</code> report the Gatekeeper reads on the next release. '
                   'This usually takes 1–2 minutes on a free model.</div>', unsafe_allow_html=True)
        if b.button("🔎 Investigate this case", type="primary", width="stretch"):
            with st.status("🔎 The Investigator is reading the case file...", expanded=True) as status:
                def on_step(s):
                    status.update(label=f"🔎 Investigating: {s.name.removeprefix('LLM: ')}")
                    status.write(f"✓ {s.name.removeprefix('LLM: ')} · {len(s.rows)} rows")
                try:
                    st.session_state.investigation = InvestigatorAgent(g).investigate(v.decision_id, on_step=on_step)
                except Exception as e:
                    status.update(label="Investigation failed", state="error")
                    st.error(f"Investigation failed: {e}")
                    if "key" in str(e).lower() or "auth" in str(e).lower() or "401" in str(e):
                        st.info("Set LLM_PROVIDER and its free API key in a `.env` file in the "
                                "project folder (see `.env.example`), then restart Streamlit.")
                else:
                    status.update(label="Investigation complete", state="complete")
                    st.rerun()
    inv = st.session_state.get("investigation")
    if inv and inv.decision_id == v.decision_id:
        r = inv.report
        c = SEVERITY_COLOUR[r["severity"]]
        tags = "".join(f'<span class="gs-tag">{escape(x)}</span>' for x in r["packages_at_risk"]) or '<span class="gs-muted">none</span>'
        flags = "".join(f'<span class="gs-tag red">🚩 {escape(x)}</span>' for x in inv.flagged) or '<span class="gs-muted">none</span>'
        findings = "".join(f"<li>{escape(x)}</li>" for x in r["findings"])
        actions = "".join(f"<li>{escape(x)}</li>" for x in r["recommended_actions"])
        html(f"""<div class="gs-card gs-report" style="--c:{c}; border-left:6px solid {c}">
<div class="gs-sev">{r['severity'].upper()} SEVERITY</div>
<h3>{escape(r['headline'])}</h3>
<div style="color:#cbd5e1">{escape(r['summary'])}</div></div>""")
        st.write("")
        a, b = st.columns(2)
        a.markdown(f'<div class="gs-card gs-report"><b>Findings</b><ul>{findings}</ul></div>', unsafe_allow_html=True)
        b.markdown(f'<div class="gs-card gs-report"><b>Recommended actions</b><ul>{actions}</ul></div>',
                   unsafe_allow_html=True)
        st.write("")
        a, b = st.columns(2)
        a.markdown(f'<div class="gs-card"><b>Other packages at risk</b><br>{tags}</div>', unsafe_allow_html=True)
        b.markdown(f'<div class="gs-card"><b>Accounts flagged</b><br>{flags}</div>', unsafe_allow_html=True)
        st.caption(f"{inv.model} · {len(inv.steps)} graph tool calls · {inv.turns} model turns · {inv.seconds:.1f} s")
        with st.expander("🔍 Investigator trace: every query the LLM wrote"):
            show_trace(inv.steps)

section("Agent memory")
t_dec, t_inv = st.tabs(["🧠 Decisions", "📁 Investigations"])
with t_dec:
    log = g.ro_query(Q.DECISION_LOG).result_set
    if log:
        df = pd.DataFrame(log, columns=["at", "verdict", "risk", "impact", "package", "version", "maintainer"])
        df["at"] = df["at"].map(lambda ms: datetime.fromtimestamp(ms / 1000).strftime("%H:%M:%S"))
        st.dataframe(df.style.map(colour_cells(VERDICT_COLOUR), subset=["verdict"]),
                     width="stretch", hide_index=True,
                     column_config={"risk": st.column_config.ProgressColumn("risk", min_value=0, max_value=100,
                                                                             format="%d")})
    else:
        st.caption("No decisions yet. Run a scenario above.")
with t_inv:
    log = g.ro_query(Q.INVESTIGATION_LOG).result_set
    if log:
        df = pd.DataFrame(log, columns=["at", "severity", "version", "headline", "flagged"])
        df["at"] = df["at"].map(lambda ms: datetime.fromtimestamp(ms / 1000).strftime("%H:%M:%S"))
        st.dataframe(df.style.map(colour_cells(SEVERITY_COLOUR), subset=["severity"]),
                     width="stretch", hide_index=True)
    else:
        st.caption("No investigations yet.")
