"""GraphShield: Streamlit demo UI.   Run:  streamlit run app.py"""
import json
import os
from datetime import datetime
from html import escape

import altair as alt
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

VERDICT_COLOUR = {"BLOCK": "#f43f5e", "QUARANTINE": "#f59e0b", "ALLOW": "#10b981"}
SEVERITY_COLOUR = {"critical": "#f43f5e", "high": "#fb923c", "medium": "#f59e0b", "low": "#38bdf8"}

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
}

code, pre, .stCode, [data-testid="stMarkdownContainer"] code {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Base Layout Tweaks */
.block-container {
    padding-top: 2rem;
    padding-bottom: 4rem;
    max-width: 1400px;
}

[data-stale="true"], .stale-element {
    opacity: 1 !important;
    filter: none !important;
    transition: none !important;
}

/* Glassmorphic Top Hero Header */
.gs-hero {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1.2rem;
    padding: 1.75rem 2rem;
    border-radius: 20px;
    margin-bottom: 2rem;
    background: radial-gradient(120% 120% at 50% 10%, #1e293b 0%, #0f172a 100%);
    border: 1px solid rgba(255, 255, 255, 0.08);
    box-shadow: 0 20px 40px -15px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.1);
}

.gs-hero-brand {
    display: flex;
    align-items: center;
    gap: 1rem;
}

.gs-hero-icon {
    font-size: 2.8rem;
    background: linear-gradient(135deg, #38bdf8, #818cf8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    filter: drop-shadow(0 4px 12px rgba(56, 189, 248, 0.3));
}

.gs-hero h1 {
    margin: 0;
    font-size: 2.2rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    background: linear-gradient(180deg, #ffffff 0%, #cbd5e1 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.gs-hero p {
    margin: 0.3rem 0 0;
    color: #94a3b8;
    font-size: 0.95rem;
    font-weight: 500;
}

.gs-chips {
    display: flex;
    gap: 0.6rem;
    flex-wrap: wrap;
}

.gs-chip {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.4rem 0.9rem;
    border-radius: 999px;
    font-size: 0.82rem;
    font-weight: 600;
    background: rgba(15, 23, 42, 0.8);
    border: 1px solid rgba(255, 255, 255, 0.08);
    color: #e2e8f0;
    backdrop-filter: blur(8px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.2);
}

.gs-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
    box-shadow: 0 0 10px currentColor;
}

/* Section Dividers */
.gs-section {
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    color: #38bdf8;
    margin: 2.2rem 0 1rem;
    font-weight: 700;
    display: flex;
    align-items: center;
    gap: 0.6rem;
}

.gs-section::after {
    content: "";
    flex: 1;
    height: 1px;
    background: linear-gradient(90deg, rgba(56, 189, 248, 0.2) 0%, rgba(255, 255, 255, 0) 100%);
}

/* General Cards & Containers */
.gs-card {
    background: #0f172a;
    border: 1px solid rgba(255, 255, 255, 0.07);
    border-radius: 16px;
    padding: 1.25rem 1.4rem;
    box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.3);
    transition: transform 0.2s ease, border-color 0.2s ease;
}

/* Scenario Cards & Buttons */
.gs-scenario {
    min-height: 155px;
    margin-bottom: 0.8rem;
    background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
    border: 1px solid rgba(255, 255, 255, 0.08);
    display: flex;
    flex-direction: column;
    justify-content: flex-start;
}

.gs-scenario:hover {
    border-color: rgba(56, 189, 248, 0.4);
}

.gs-scenario b {
    font-size: 1.05rem;
    color: #f8fafc;
    font-weight: 700;
}

.gs-scenario p {
    color: #94a3b8;
    font-size: 0.88rem;
    margin: 0.5rem 0 0;
    line-height: 1.4;
}

.stButton > button {
    border-radius: 10px !important;
    font-weight: 600 !important;
    transition: all 0.2s ease !important;
}

/* Verdict Display Card */
.gs-verdict {
    display: flex;
    gap: 2rem;
    align-items: center;
    flex-wrap: wrap;
    border-left: 6px solid var(--c);
    background: radial-gradient(100% 100% at 0% 0%, rgba(15, 23, 42, 0.95) 0%, #090d16 100%);
    padding: 1.6rem 2rem;
    position: relative;
    overflow: hidden;
}

.gs-verdict::before {
    content: "";
    position: absolute;
    top: 0; left: 0; bottom: 0; width: 200px;
    background: linear-gradient(90deg, var(--c) 0%, transparent 100%);
    opacity: 0.08;
    pointer-events: none;
}

.gs-pill {
    font-size: 2.2rem;
    font-weight: 800;
    color: var(--c);
    letter-spacing: 0.02em;
    text-shadow: 0 0 20px rgba(0,0,0,0.5);
    line-height: 1;
}

.gs-meta {
    color: #cbd5e1;
    font-size: 1rem;
    line-height: 1.5;
}

.gs-meta code {
    background: #1e293b;
    padding: 0.2rem 0.5rem;
    border-radius: 6px;
    color: #38bdf8;
    font-weight: 500;
    border: 1px solid rgba(255, 255, 255, 0.05);
}

.gs-meter {
    flex: 1;
    min-width: 240px;
}

.gs-meter-track {
    height: 12px;
    background: #1e293b;
    border-radius: 999px;
    overflow: hidden;
    border: 1px solid rgba(255, 255, 255, 0.05);
    padding: 2px;
}

.gs-meter-fill {
    height: 100%;
    background: var(--c);
    border-radius: 999px;
    box-shadow: 0 0 12px var(--c);
    transition: width 0.6s cubic-bezier(0.16, 1, 0.3, 1);
}

.gs-meter-label {
    display: flex;
    justify-content: space-between;
    font-size: 0.85rem;
    font-weight: 600;
    color: #94a3b8;
    margin-bottom: 0.4rem;
}

/* KPI Cards */
.gs-kpi {
    text-align: center;
    background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
    border: 1px solid rgba(255, 255, 255, 0.06);
    padding: 1.1rem 1rem;
}

.gs-kpi .v {
    font-size: 1.9rem;
    font-weight: 800;
    color: #f8fafc;
    letter-spacing: -0.02em;
}

.gs-kpi .l {
    font-size: 0.75rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-weight: 700;
    margin-top: 0.3rem;
}

/* Reason List Item */
.gs-reason {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    padding: 0.75rem 0.5rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    color: #e2e8f0;
    font-size: 0.95rem;
}

.gs-reason:last-child {
    border-bottom: none;
}

/* Tracing & Steps */
.gs-steps {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-bottom: 1rem;
}

.gs-step {
    font-size: 0.8rem;
    padding: 0.4rem 0.8rem;
    border-radius: 8px;
    background: #1e293b;
    border: 1px solid rgba(255, 255, 255, 0.08);
    color: #cbd5e1;
    font-family: 'JetBrains Mono', monospace;
}

.gs-step b {
    color: #38bdf8;
}

/* Tags & Chains */
.gs-tag {
    display: inline-block;
    margin: 0.2rem 0.3rem 0.2rem 0;
    padding: 0.25rem 0.7rem;
    border-radius: 8px;
    font-size: 0.82rem;
    font-weight: 500;
    background: #1e293b;
    border: 1px solid rgba(255, 255, 255, 0.08);
    color: #e2e8f0;
}

.gs-tag.red {
    background: rgba(244, 63, 94, 0.15);
    border-color: rgba(244, 63, 94, 0.3);
    color: #fda4af;
}

.gs-chain {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
    padding: 0.65rem 0.85rem;
    margin-bottom: 0.5rem;
    background: #090d16;
    border-radius: 10px;
    border: 1px solid rgba(255, 255, 255, 0.06);
    color: #cbd5e1;
    overflow-x: auto;
}

.gs-chain .t {
    color: #f43f5e;
    font-weight: 700;
}

/* Report Styles */
.gs-report {
    background: #0f172a;
}

.gs-report h3 {
    margin: 0.3rem 0 0.6rem;
    font-size: 1.2rem;
    font-weight: 700;
    color: #f8fafc;
}

.gs-report ul {
    margin: 0.4rem 0 0 1.2rem;
    padding: 0;
}

.gs-report li {
    margin-bottom: 0.5rem;
    color: #cbd5e1;
    line-height: 1.5;
    font-size: 0.92rem;
}

.gs-sev {
    font-weight: 800;
    color: var(--c);
    font-size: 0.75rem;
    letter-spacing: 0.12em;
}

.gs-muted {
    color: #64748b;
    font-size: 0.88rem;
}

.gs-sidebar-stat {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 0;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    font-size: 0.9rem;
    color: #cbd5e1;
}

.gs-sidebar-stat b {
    color: #38bdf8;
    font-family: 'JetBrains Mono', monospace;
}

/* Customizing Streamlit Native Components */
[data-testid="stSidebar"] {
    background-color: #0b101d;
    border-right: 1px solid rgba(255, 255, 255, 0.05);
}

[data-testid="stExpander"] {
    background: #0f172a;
    border: 1px solid rgba(255, 255, 255, 0.06) !important;
    border-radius: 12px !important;
}

.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    background-color: transparent;
}

.stTabs [data-baseweb="tab"] {
    height: 42px;
    white-space: pre;
    border-radius: 10px;
    color: #94a3b8;
    font-size: 0.9rem;
    font-weight: 600;
    background-color: #0f172a;
    border: 1px solid rgba(255, 255, 255, 0.05);
    padding: 0 16px;
}

.stTabs [aria-selected="true"] {
    background-color: #1e293b !important;
    color: #38bdf8 !important;
    border-color: rgba(56, 189, 248, 0.3) !important;
}
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
            st.dataframe(pd.DataFrame(s.rows), use_container_width=True)


def colour_cells(mapping):
    return lambda val: f"color: {mapping.get(val, '#e5e9f2')}; font-weight: 700"


st.set_page_config(page_title="GraphShield", page_icon="🛡️", layout="wide")
html(CSS)

# On Streamlit Community Cloud, settings come from the app's Secrets instead of .env.
# Accepts top-level keys and keys inside one [section].
try:
    for key, value in st.secrets.items():
        items = value.items() if hasattr(value, "items") else [(key, value)]
        for k, val in items:
            if isinstance(val, (str, int, float)):
                os.environ.setdefault(k.upper(), str(val))
except Exception:
    pass  # no secrets file locally: .env is used

try:
    g = get_graph()
    stats = {r[0]: r[1] for r in g.ro_query(Q.GRAPH_STATS).result_set}
    db_ok = True
except Exception as e:
    db_ok, db_error = False, e

try:
    _, llm_model, _ = llm_settings()
    llm_chip = f'<span class="gs-chip"><span class="gs-dot" style="background:#10b981; color:#10b981"></span>LLM · {escape(llm_model)}</span>'
except Exception:
    llm_chip = '<span class="gs-chip"><span class="gs-dot" style="background:#f59e0b; color:#f59e0b"></span>LLM not configured</span>'
db_chip = ('<span class="gs-chip"><span class="gs-dot" style="background:#10b981; color:#10b981"></span>FalkorDB connected</span>'
           if db_ok else
           '<span class="gs-chip"><span class="gs-dot" style="background:#f43f5e; color:#f43f5e"></span>FalkorDB offline</span>')

html(f"""<div class="gs-hero">
    <div class="gs-hero-brand">
        <div class="gs-hero-icon">🛡️</div>
        <div>
            <h1>GraphShield</h1>
            <p>Two graph-native agents on FalkorDB stopping supply-chain attacks in real time.</p>
        </div>
    </div>
    <div class="gs-chips">{db_chip}{llm_chip}</div>
</div>""")

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
    if st.button("♻️ Seed / reset registry", use_container_width=True):
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
        if st.button("Run", key=title, type=kind, use_container_width=True):
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
        if b.button("🔎 Investigate this case", type="primary", use_container_width=True):
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
        pie_col, table_col = st.columns([1, 2])
        with pie_col:
            mix = pd.DataFrame(g.ro_query(Q.VERDICT_MIX).result_set, columns=["verdict", "decisions"])
            mix["share"] = mix["decisions"] / mix["decisions"].sum()
            order = [k for k in VERDICT_COLOUR if k in set(mix["verdict"])]
            donut = alt.Chart(mix).mark_arc(innerRadius=62, outerRadius=105, cornerRadius=4,
                                            stroke="#0b1020", strokeWidth=2).encode(
                theta=alt.Theta("decisions:Q", stack=True),
                order=alt.Order("verdict:N", sort="ascending"),
                color=alt.Color("verdict:N", title=None,
                                scale=alt.Scale(domain=order, range=[VERDICT_COLOUR[k] for k in order]),
                                legend=alt.Legend(orient="bottom", labelColor="#cbd5e1", symbolType="circle")),
                tooltip=[alt.Tooltip("verdict:N", title="Verdict"),
                         alt.Tooltip("decisions:Q", title="Decisions"),
                         alt.Tooltip("share:Q", title="Share", format=".0%")],
            )
            total = alt.Chart(pd.DataFrame({"t": [f"{int(mix['decisions'].sum())}"]})).mark_text(
                fontSize=28, fontWeight="bold", color="#f8fafc", dy=-6).encode(text="t:N")
            caption = alt.Chart(pd.DataFrame({"t": ["decisions"]})).mark_text(
                fontSize=12, color="#94a3b8", dy=16).encode(text="t:N")
            st.markdown("**Verdict mix**")
            st.altair_chart((donut + total + caption).properties(height=280).configure_view(strokeWidth=0)
                            .configure(background="transparent"), use_container_width=True)
        with table_col:
            df = pd.DataFrame(log, columns=["at", "verdict", "risk", "impact", "package", "version", "maintainer"])
            df["at"] = df["at"].map(lambda ms: datetime.fromtimestamp(ms / 1000).strftime("%H:%M:%S"))
            st.dataframe(df.style.map(colour_cells(VERDICT_COLOUR), subset=["verdict"]),
                         use_container_width=True, hide_index=True,
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
                     use_container_width=True)
    else:
        st.caption("No investigations yet.")