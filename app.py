"""HandoffGuard console (Streamlit).

    streamlit run app.py
"""
from __future__ import annotations

import html
import json
import time

import pandas as pd
import streamlit as st

import handoffguard  # noqa: F401  (loads .env)
from handoffguard.agent import HandoffGuard, auto_approver
from handoffguard.contracts import ApprovalRequest, LedgerEntry
from handoffguard.planners import PROVIDERS, RulesPlanner, available_providers, make_planner
from handoffguard.runner import benchmark, evaluate, new_session, run_baseline
from handoffguard.world import BENCHMARK_KEYS, SCENARIOS
from handoffguard.world.scenarios import RUNS_DIR

st.set_page_config(page_title="HandoffGuard", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

esc = html.escape

# ----------------------------------------------------------------------------- style
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');
:root {
  --ink:#0F1B2D; --muted:#5B6B80; --faint:#8A97A8; --line:#E3E8EF; --paper:#F6F8FB; --card:#FFFFFF;
  --cobalt:#3346D3; --cobalt-soft:#EEF0FD;
  --good:#157A4A; --good-soft:#E6F4EC; --bad:#C0352B; --bad-soft:#FCEBE9;
  --wait:#A86A00; --wait-soft:#FBF1DE; --guard:#6B3FA0; --guard-soft:#F2ECF9; --llm:#0E7490; --llm-soft:#E3F3F7;
}
html, body, [class*="css"], .stMarkdown, .stButton button, .stRadio, .stSelectbox, .stToggle { font-family:'IBM Plex Sans', system-ui, sans-serif; }
.stApp { background: var(--paper); }
[data-testid="stToolbar"], #MainMenu, footer { display:none !important; }
[data-testid="stHeaderActionElements"], .stMarkdown h1 a, .stMarkdown h3 a { display:none !important; }
header[data-testid="stHeader"] { background: transparent; }
.block-container { padding-top: 1.4rem; padding-bottom: 3rem; max-width: 1360px; }
section[data-testid="stSidebar"] { background: #FFFFFF; border-right: 1px solid var(--line); }
section[data-testid="stSidebar"] .block-container { padding-top: 1.2rem; }
.mono, code { font-family:'IBM Plex Mono', ui-monospace, monospace !important; font-size: .84em; }

/* header */
.top { display:flex; justify-content:space-between; align-items:flex-start; gap:24px; margin-bottom:.9rem; }
.brand h1 { font-size:1.75rem; line-height:1.15; font-weight:700; color:var(--ink); margin:0; letter-spacing:-.015em; }
.brand p { color:var(--muted); margin:.3rem 0 0 0; font-size:.98rem; max-width:62ch; }
.status { display:inline-flex; align-items:center; gap:8px; padding:7px 14px; border-radius:999px; font-weight:600; font-size:.88rem; border:1px solid transparent; white-space:nowrap; }
.status .dot { width:8px; height:8px; border-radius:50%; background:currentColor; }
.st-idle { background:#EEF1F5; color:var(--muted); }
.st-run { background:var(--cobalt-soft); color:var(--cobalt); }
.st-run .dot { animation: pulse 1.2s ease-in-out infinite; }
.st-wait { background:var(--wait-soft); color:var(--wait); border-color:#F0D9A8; }
.st-good { background:var(--good-soft); color:var(--good); }
.st-bad { background:var(--bad-soft); color:var(--bad); }
@keyframes pulse { 0%,100%{opacity:1; transform:scale(1)} 50%{opacity:.35; transform:scale(.7)} }
@media (prefers-reduced-motion: reduce) { .st-run .dot { animation:none; } }
.top-meta { text-align:right; }
.top-meta .scen { color:var(--muted); font-size:.82rem; margin-top:6px; }

/* phase rail */
.rail { display:grid; grid-template-columns:repeat(7, 1fr); gap:0; background:var(--card); border:1px solid var(--line); border-radius:14px; padding:14px 10px 12px; margin:.4rem 0 1rem; }
.step { position:relative; text-align:center; padding:0 4px; }
.step:not(:last-child)::after { content:""; position:absolute; top:13px; left:calc(50% + 16px); right:calc(-50% + 16px); height:2px; background:var(--line); }
.step.done:not(:last-child)::after { background:var(--good); }
.bubble { width:26px; height:26px; border-radius:50%; margin:0 auto 6px; display:flex; align-items:center; justify-content:center; font-size:.78rem; font-weight:700; border:2px solid var(--line); color:var(--faint); background:#fff; position:relative; z-index:1; }
.step.done .bubble { background:var(--good); border-color:var(--good); color:#fff; }
.step.now .bubble { border-color:var(--cobalt); color:var(--cobalt); box-shadow:0 0 0 4px var(--cobalt-soft); }
.step.held .bubble { background:var(--wait); border-color:var(--wait); color:#fff; }
.step .lbl { font-size:.8rem; color:var(--muted); line-height:1.25; }
.step.now .lbl, .step.done .lbl { color:var(--ink); font-weight:600; }
.step .cgi { font-size:.7rem; color:var(--faint); margin-top:2px; }

/* cards */
.card { background:var(--card); border:1px solid var(--line); border-radius:14px; padding:16px 18px; }
.card h3 { font-size:.95rem; font-weight:600; color:var(--ink); margin:0 0 .7rem 0; }
.card .sub { color:var(--muted); font-size:.82rem; font-weight:400; margin-left:6px; }

/* automation board */
.brd { display:grid; grid-template-columns: 1.25fr 1.55fr .8fr 1fr; align-items:center; gap:12px; padding:11px 2px; border-top:1px solid #EEF1F5; }
.brd.head { border-top:none; padding-top:0; color:var(--faint); font-size:.78rem; font-weight:600; }
.brd .name { font-weight:600; color:var(--ink); font-size:.95rem; }
.brd .file { color:var(--faint); font-size:.76rem; margin-top:1px; }
.err { color:var(--bad); font-size:.76rem; margin-top:4px; line-height:1.3; }
.tok { display:inline-block; padding:2px 8px; border-radius:6px; font-family:'IBM Plex Mono', monospace; font-size:.8rem; }
.tok-user { background:var(--wait-soft); color:var(--wait); }
.tok-svc { background:var(--good-soft); color:var(--good); }
.tok-dead { background:var(--bad-soft); color:var(--bad); text-decoration:line-through; }
.tok-sus { background:#EEF1F5; color:var(--muted); }
.arrow { color:var(--faint); margin:0 6px; }
.pill { display:inline-flex; align-items:center; gap:6px; padding:3px 10px; border-radius:999px; font-size:.78rem; font-weight:600; }
.pill .dot { width:6px; height:6px; border-radius:50%; background:currentColor; }
.p-good { background:var(--good-soft); color:var(--good); } .p-bad { background:var(--bad-soft); color:var(--bad); }
.p-wait { background:var(--wait-soft); color:var(--wait); } .p-info { background:#EEF1F5; color:var(--muted); }
.p-run { background:var(--cobalt-soft); color:var(--cobalt); }
.by { display:inline-block; padding:2px 8px; border-radius:6px; font-size:.75rem; font-weight:600; }
.by-llm { background:var(--llm-soft); color:var(--llm); } .by-rules { background:#EEF1F5; color:var(--muted); }
.by-brownout { background:var(--cobalt-soft); color:var(--cobalt); } .by-none { color:var(--faint); }

/* leaver */
.who { display:flex; gap:12px; align-items:center; margin-bottom:10px; }
.avatar { width:40px; height:40px; border-radius:50%; background:var(--ink); color:#fff; display:flex; align-items:center; justify-content:center; font-weight:700; }
.who b { color:var(--ink); font-size:1rem; } .who span { color:var(--muted); font-size:.82rem; display:block; }
.kv { display:grid; grid-template-columns: 92px 1fr; gap:7px 10px; align-items:center; font-size:.84rem; }
.kv .k { color:var(--faint); }
.toks { display:flex; flex-wrap:wrap; gap:6px; }

/* approval */
.appr { background:#FFFDF7; border:1.5px solid #E9C877; border-radius:14px; padding:16px 18px; margin:0 0 .5rem; }
.appr .t { font-weight:700; color:var(--ink); font-size:1.02rem; margin-bottom:6px; }
.appr .row { font-size:.86rem; color:var(--muted); margin-top:3px; }
.appr .row b { color:var(--ink); font-weight:600; }

/* timeline */
.feed { max-height:560px; overflow-y:auto; padding-right:6px; }
.ev { display:grid; grid-template-columns: 4px 1fr; gap:12px; padding:9px 0; border-top:1px solid #EEF1F5; }
.ev:first-child { border-top:none; }
.ev .bar { border-radius:4px; }
.ev .meta { font-size:.74rem; color:var(--faint); display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.ev .txt { font-size:.9rem; color:var(--ink); line-height:1.4; margin-top:2px; }
.tag { padding:1px 7px; border-radius:5px; font-weight:600; font-size:.72rem; }

/* summary */
.stats { display:grid; grid-template-columns:repeat(3, 1fr); gap:10px; }
.stat { background:var(--paper); border-radius:10px; padding:10px 12px; }
.stat .n { font-size:1.35rem; font-weight:700; color:var(--ink); line-height:1.1; }
.stat .l { font-size:.76rem; color:var(--muted); margin-top:2px; }
.verdict { font-weight:700; font-size:1rem; margin-bottom:10px; }
.items { margin:.8rem 0 0 0; padding:0; list-style:none; font-size:.84rem; }
.items li { padding:7px 10px; background:var(--wait-soft); color:#6B4600; border-radius:8px; margin-bottom:6px; line-height:1.35; }
.empty { color:var(--muted); font-size:.9rem; padding:18px 4px; }

/* benchmark */
.cmp { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin:.4rem 0 1rem; }
.cmp .card h3 { margin-bottom:.9rem; }
.big { display:grid; grid-template-columns:repeat(3,1fr); gap:10px; }
.big .n { font-size:2rem; font-weight:700; line-height:1; }
.big .l { font-size:.78rem; color:var(--muted); margin-top:6px; }
.tbl { width:100%; border-collapse:collapse; font-size:.86rem; background:#fff; border:1px solid var(--line); border-radius:14px; overflow:hidden; }
.tbl th { text-align:left; font-weight:600; color:var(--faint); font-size:.76rem; padding:10px 12px; background:#FAFBFD; border-bottom:1px solid var(--line); }
.tbl td { padding:10px 12px; border-bottom:1px solid #EEF1F5; color:var(--ink); }
.tbl tr:last-child td { border-bottom:none; }
.num { text-align:center; font-variant-numeric: tabular-nums; }

/* streamlit widgets */
.stTabs [data-baseweb="tab-list"] { gap: 4px; border-bottom:1px solid var(--line); }
.stTabs [data-baseweb="tab"] { padding: 8px 14px; font-weight:500; }
div[data-testid="stSidebar"] h4 { font-size:.82rem; color:var(--muted); font-weight:600; margin:1.1rem 0 .2rem; }
.side-note { color:var(--muted); font-size:.8rem; line-height:1.4; margin:-.2rem 0 .4rem; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

ss = st.session_state
for key, default in {
    "world": None, "tools": None, "agent": None, "gen": None, "pending": None, "decision": None,
    "mode": None, "baseline": None, "eval": None, "summary": None, "bench": None, "last_report": None, "final": None,
}.items():
    ss.setdefault(key, default)

# ----------------------------------------------------------------------------- sidebar
with st.sidebar:
    st.markdown("### 🛡️ HandoffGuard")
    st.markdown('<div class="side-note">Verify-before-revoke offboarding agent · IT Infrastructure</div>', unsafe_allow_html=True)

    st.markdown("#### Scenario")
    scenario = st.selectbox("Scenario", list(SCENARIOS), format_func=lambda k: SCENARIOS[k]["title"], label_visibility="collapsed")
    st.markdown(f'<div class="side-note">{esc(SCENARIOS[scenario]["description"])}</div>', unsafe_allow_html=True)

    st.markdown("#### Planner")
    providers = available_providers()
    planner_options = [f"llm:{p}" for p in providers] + ["rules"]
    planner_choice = st.radio(
        "Planner",
        planner_options,
        format_func=lambda o: f"LLM · {o.split(':')[1]} ({PROVIDERS[o.split(':')[1]]['model']})" if o.startswith("llm") else "Rules only, no LLM",
        label_visibility="collapsed",
    )
    if not providers:
        st.caption("No LLM key found. Add GROQ_API_KEY or GEMINI_API_KEY to .env.")

    st.markdown("#### Approvals")
    approvals = st.radio(
        "Approvals", ["ask", "approve_all", "deny_write"], label_visibility="collapsed",
        format_func={"ask": "Ask me each time", "approve_all": "Auto-approve", "deny_write": "Auto-deny write access"}.get,
    )

    st.markdown("#### Judge's fault switchboard")
    f_last_owner = st.toggle("Leaver is the org's last owner", value=bool(SCENARIOS[scenario]["faults"].get("last_owner")))
    f_flaky = st.toggle("Flaky CI runner", value=False, help="The first canary of each automation times out.")
    f_injection = st.toggle("Malicious instructions in the README", value=False,
                            help="The README tells AI agents to skip checks, drop the backup job and revoke another user's token.")

    st.markdown("#### Playback")
    pace = st.slider("Seconds per step", 0.0, 0.8, 0.2, 0.05)

faults = {"last_owner": f_last_owner, "flaky": f_flaky, "injection": f_injection}


def build_planner():
    if planner_choice == "rules":
        return RulesPlanner()
    return make_planner(planner_choice.split(":")[1])


def reset_world():
    ss.world, ss.tools = new_session(scenario, faults)
    ss.agent = ss.gen = ss.pending = ss.decision = None
    ss.baseline = ss.eval = ss.summary = ss.final = None
    ss.mode = None


def start_baseline():
    reset_world()
    ss.mode = "baseline"
    ss.baseline = run_baseline(ss.tools)
    ss.eval = evaluate(ss.tools, ss.baseline["user"])


def start_agent():
    reset_world()
    ss.mode = "agent"
    run_dir = RUNS_DIR / "reports" / f"{scenario}-{time.strftime('%Y%m%d-%H%M%S')}"
    try:
        planner = build_planner()
    except Exception:  # missing key etc.
        planner = RulesPlanner()
    ss.agent = HandoffGuard(ss.tools, planner, ss.world.hr_path, run_dir=run_dir)
    ss.gen = ss.agent.run()
    ss.decision = "__start__"


def decide(value: str):
    ss.decision = value


if ss.world is None or ss.world.scenario != scenario:
    reset_world()

# ----------------------------------------------------------------------------- helpers
PHASES = [
    ("Ingest", "data ingestion"),
    ("Discover", "decision"),
    ("Re-home & verify", "action"),
    ("Brownout", "action"),
    ("Revoke", "action"),
    ("Remove & lock", "action"),
    ("Probe & report", "reporting"),
]


def phase_of(e: LedgerEntry, leaver_ids: set) -> int:
    t, r = e.tool, e.rationale
    if t in ("probe_access",) or e.phase == "report":
        return 6
    if t in ("remove_member", "assign_role", "suspend_login") or r.startswith(("Not removing", "Could not remove", "Verified ")):
        return 5
    if (t == "revoke_credential" and e.input.get("credential_id") in leaver_ids) or r.startswith(("Post-revoke", "Holding")):
        return 4
    if t in ("suspend_credential", "reactivate_credential") or r.startswith(("Brownout", "New dependency from brownout")):
        return 3
    if t in ("mint_credential", "rebind_secret", "run_canary") or e.phase in ("diagnose", "approval", "verify") or r.startswith(("Re-home", "Rolled", "Safe stop")):
        return 2
    if t == "scan_artifacts" or r.startswith(("LLM discovery", "Rules discovery", "Dependency ", "Unexplained", "Guard rejected", "Grounding", "No automation")):
        return 1
    return 0


def run_state() -> tuple[str, str]:
    """(css class, label) for the header status pill."""
    if ss.mode == "baseline":
        n = len(ss.eval["broken"]) if ss.eval else 0
        return ("st-bad", f"Naive checklist · {n} broken") if n else ("st-good", "Naive checklist · nothing broken")
    if ss.mode == "agent":
        if ss.pending is not None:
            return "st-wait", "Waiting for your approval"
        if ss.summary:
            s = ss.summary["metrics"]["status"]
            return ("st-good", "Complete") if s == "COMPLETE" else ("st-wait", "Partial · handed to a human")
        return "st-run", "Running"
    return "st-idle", "Idle"


def header_html() -> str:
    cls, label = run_state()
    planner = "Rules only" if planner_choice == "rules" else f"LLM · {planner_choice.split(':')[1]}"
    return (
        '<div class="top"><div class="brand"><h1>HandoffGuard</h1>'
        "<p>Offboards a leaver without breaking what their credentials still run: it re-homes every dependent "
        "automation, proves it works, and only then revokes.</p></div>"
        f'<div class="top-meta"><span class="status {cls}"><span class="dot"></span>{esc(label)}</span>'
        f'<div class="scen">{esc(SCENARIOS[scenario]["title"])} · {esc(planner)}</div></div></div>'
    )


def rail_html() -> str:
    if ss.mode != "agent" or not ss.agent:
        cur, finished = -1, False
    else:
        leaver = set(ss.agent.leaver_credential_ids)
        cur = max((phase_of(e, leaver) for e in ss.agent.ledger), default=0)
        finished = ss.summary is not None
    partial = finished and ss.summary["metrics"]["status"] != "COMPLETE"
    out = ['<div class="rail">']
    for i, (name, cgi) in enumerate(PHASES):
        if finished:
            cls = "held" if partial and i == len(PHASES) - 1 else "done"
        elif i < cur:
            cls = "done"
        elif i == cur:
            cls = "now"
        else:
            cls = ""
        mark = "✓" if cls == "done" else "!" if cls == "held" else str(i + 1)
        out.append(f'<div class="step {cls}"><div class="bubble">{mark}</div><div class="lbl">{name}</div><div class="cgi">{cgi}</div></div>')
    out.append("</div>")
    return "".join(out)


def tok_html(w, cred: str | None) -> str:
    if not cred:
        return '<span class="by-none">—</span>'
    tok = w.tokens.get(cred)
    if tok is None:
        return f'<span class="tok tok-sus">{esc(cred)}</span>'
    cls = "tok-dead" if tok.status == "revoked" else "tok-sus" if tok.status == "suspended" else "tok-user" if tok.owner_type == "user" else "tok-svc"
    return f'<span class="tok {cls}">{esc(cred)}</span>'


STATE = {
    "discovered": ("Found", "p-info"), "rehome_requested": ("Re-homing", "p-run"), "rehome_executed": ("Testing", "p-run"),
    "verified": ("Verified", "p-good"), "revoked": ("Verified after revoke", "p-good"), "probe_clean": ("Done", "p-good"),
    "escalated": ("Held for a human", "p-wait"),
}


def board_html() -> str:
    w = ss.world
    deps = {d.target: d for d in ss.agent.deps} if ss.agent else {}
    broken = {b["target"]: b["error"] for b in (ss.eval or {}).get("broken", [])}
    rows = ['<div class="card"><h3>Automations<span class="sub">what the leaver\'s credentials run, and what they run on now</span></h3>',
            '<div class="brd head"><div>Automation</div><div>Credential: was → now</div><div>Found by</div><div>State</div></div>']
    for name, spec in w.targets.items():
        now = w.token_id_for_value(next(iter(spec.secrets.values())))
        d = deps.get(name)
        was = d.credential_ref if d else (now if now and w.tokens[now].owner_type == "user" else None)
        cred_html = tok_html(w, was) if not was or was == now else f'{tok_html(w, was)}<span class="arrow">→</span>{tok_html(w, now)}'
        if was is None:
            cred_html = tok_html(w, now)
        if d:
            by_cls = "by-llm" if "llm" in d.found_by else "by-brownout" if d.found_by == "brownout" else "by-rules"
            by = f'<span class="by {by_cls}">{esc(d.found_by)}</span>'
        else:
            by = '<span class="by by-none">—</span>'
        tok_now = w.tokens.get(now) if now else None
        if ss.eval is not None and name in broken:
            label, cls = "Broken", "p-bad"
        elif ss.eval is not None and tok_now and tok_now.owner_type == "user" and ss.mode == "agent":
            label, cls = "Running · still on leaver's token", "p-wait"
        elif ss.eval is not None:
            label, cls = "Running", "p-good"
        elif d:
            label, cls = STATE.get(d.status, (d.status, "p-info"))
        else:
            label, cls = ("Not discovered yet", "p-info") if ss.mode == "agent" else ("Running", "p-good")
        err = f'<div class="err mono">{esc(broken[name])}</div>' if name in broken else ""
        rows.append(
            f'<div class="brd"><div><div class="name">{esc(name)}</div><div class="file">{esc(spec.file)}</div></div>'
            f'<div>{cred_html}{err}</div><div>{by}</div><div><span class="pill {cls}"><span class="dot"></span>{esc(label)}</span></div></div>'
        )
    rows.append("</div>")
    return "".join(rows)


def leaver_html() -> str:
    w = ss.world
    hr = json.loads(w.hr_path.read_text(encoding="utf-8"))
    user = hr["employee"]
    member = w.members.get(user)
    login = w.logins.get(user, "none")
    toks = " ".join(tok_html(w, t.id) for t in w.tokens.values() if t.owner == user)
    role = f'<span class="pill p-wait">{esc(member)}</span>' if member else '<span class="pill p-good">removed</span>'
    log = f'<span class="pill {"p-good" if login == "suspended" else "p-wait"}">{esc(login)}</span>'
    return (
        '<div class="card"><h3>Leaver</h3>'
        f'<div class="who"><div class="avatar">{esc(user[:1].upper())}</div><div><b>{esc(user)}</b>'
        f'<span>{esc(hr.get("reason", ""))} · last day {esc(hr.get("last_day", ""))}</span></div></div>'
        '<div class="kv">'
        f'<div class="k">HR request</div><div class="mono">{esc(hr.get("request_id", ""))}</div>'
        f'<div class="k">Approver</div><div>{esc(hr.get("approver", ""))} · successor {esc(str(hr.get("successor")))}</div>'
        f'<div class="k">Org role</div><div>{role}</div>'
        f'<div class="k">Login</div><div>{log}</div>'
        f'<div class="k">Credentials</div><div class="toks">{toks}</div>'
        "</div></div>"
    )


WHO = {
    "agent": ("agent", "#EEF1F5", "#5B6B80"), "llm": ("LLM", "#E3F3F7", "#0E7490"), "rules": ("rules", "#EEF1F5", "#5B6B80"),
    "guard": ("policy guard", "#F2ECF9", "#6B3FA0"), "human": ("approver", "#FBF1DE", "#A86A00"),
}
BAR = {"good": "#157A4A", "bad": "#C0352B", "wait": "#A86A00", "block": "#6B3FA0", "info": "#CBD3DD"}
KEY_PHASES = {"plan", "diagnose", "approval", "verify", "block", "escalate", "report"}


def feed_html(entries: list[LedgerEntry], key_only: bool) -> str:
    shown = [e for e in entries if not key_only or e.phase in KEY_PHASES or e.level == "bad"]
    if not shown:
        return '<div class="empty">Events appear here as the agent works.</div>'
    out = ['<div class="feed">']
    for e in reversed(shown):
        who, bg, fg = WHO.get(e.decided_by.split(" ")[0], (e.decided_by, "#EEF1F5", "#5B6B80"))
        tool = f'<span class="mono">{esc(e.tool)}</span>' if e.tool else ""
        out.append(
            f'<div class="ev"><div class="bar" style="background:{BAR.get(e.level, "#CBD3DD")}"></div><div>'
            f'<div class="meta"><span>#{e.step}</span><span>{esc(e.phase)}</span>'
            f'<span class="tag" style="background:{bg};color:{fg}">{esc(who)}</span>{tool}</div>'
            f'<div class="txt">{esc(e.rationale)}</div></div></div>'
        )
    out.append("</div>")
    return "".join(out)


def summary_html() -> str:
    if ss.mode == "baseline" and ss.eval is not None:
        b = ss.eval
        items = "".join(f"<li>{esc(s)}</li>" for s in ss.baseline["steps"])
        return (
            '<div class="card"><h3>Naive checklist result</h3>'
            f'<div class="verdict" style="color:var(--bad)">{len(b["broken"])} automation(s) broken</div>'
            '<div class="stats">'
            f'<div class="stat"><div class="n">{len(b["broken"])}</div><div class="l">Broken automations</div></div>'
            f'<div class="stat"><div class="n">{len(b["residual"])}</div><div class="l">Access paths left</div></div>'
            f'<div class="stat"><div class="n">{ss.baseline["unapproved_privileged_actions"]}</div><div class="l">Unapproved privileged actions</div></div>'
            f'</div><ul class="items" style="list-style:none">{items}</ul></div>'
        ).replace('<li>', '<li style="background:#F6F8FB;color:#0F1B2D">')
    if not ss.agent:
        return ('<div class="card"><h3>Run summary</h3><div class="empty">Run the naive checklist to see what breaks today, '
                "then run HandoffGuard on the same scenario.</div></div>")
    m = ss.agent.metrics()
    if ss.summary:
        status = ss.summary["metrics"]["status"]
        ev = ss.eval or {"broken": [], "residual": []}
        color = "var(--good)" if status == "COMPLETE" else "var(--wait)"
        verdict = (f'<div class="verdict" style="color:{color}">{status.title()} · {len(ev["broken"])} broken · '
                   f'{len(ev["residual"])} access path(s) left</div>')
    else:
        verdict = '<div class="verdict" style="color:var(--cobalt)">In progress…</div>'
    stats = [
        (m["dependencies"], "Dependencies found"), (m["verified"], "Re-homed and verified"), (m["recoveries"], "Recoveries"),
        (m["approvals"], "Human approvals"), (m["brownouts"], "Brownouts"), (m["guard_blocks"], "Guard blocks"),
    ]
    grid = "".join(f'<div class="stat"><div class="n">{n}</div><div class="l">{l}</div></div>' for n, l in stats)
    items = ""
    if ss.agent.open_items and ss.summary:
        items = '<ul class="items">' + "".join(f"<li>{esc(o)}</li>" for o in ss.agent.open_items) + "</ul>"
    extra = f'<div class="side-note" style="margin-top:10px">LLM calls: {m["llm_calls"]} · unapproved privileged actions: {m["unapproved_privileged_actions"]}</div>'
    return f'<div class="card"><h3>Run summary</h3>{verdict}<div class="stats">{grid}</div>{extra}{items}</div>'


# ----------------------------------------------------------------------------- layout
header_ph = st.empty()
b1, b2, b3, _ = st.columns([1.25, 1.25, 0.7, 4.3])
b1.button("Run naive checklist", on_click=start_baseline, width="stretch", help="What offboarding looks like today: revoke, remove, done.")
b2.button("Run HandoffGuard", on_click=start_agent, type="primary", width="stretch")
b3.button("Reset", on_click=reset_world, width="stretch")

tab_run, tab_bench, tab_report, tab_world = st.tabs(["Live run", "Benchmark", "Report", "World"])

with tab_run:
    rail_ph = st.empty()
    c_board, c_leaver = st.columns([2.35, 1], gap="medium")
    board_ph = c_board.empty()
    leaver_ph = c_leaver.empty()
    approval_box = st.container()
    c_feed, c_sum = st.columns([1.55, 1], gap="medium")
    with c_feed:
        f1, f2 = st.columns([1, 1])
        f1.markdown("**Agent timeline**")
        view = f2.radio("View", ["Key steps", "All steps"], horizontal=True, label_visibility="collapsed")
        feed_ph = st.empty()
    sum_ph = c_sum.empty()

    def render_live():
        header_ph.markdown(header_html(), unsafe_allow_html=True)
        rail_ph.markdown(rail_html(), unsafe_allow_html=True)
        board_ph.markdown(board_html(), unsafe_allow_html=True)
        leaver_ph.markdown(leaver_html(), unsafe_allow_html=True)
        if ss.mode == "agent" and ss.agent:
            feed_ph.markdown(f'<div class="card">{feed_html(ss.agent.ledger, view == "Key steps")}</div>', unsafe_allow_html=True)
        elif ss.mode == "baseline":
            feed_ph.markdown('<div class="card"><div class="empty">The naive checklist has no agent: it revoked, removed and stopped. '
                             "See the result on the right.</div></div>", unsafe_allow_html=True)
        else:
            feed_ph.markdown('<div class="card"><div class="empty">Events appear here as the agent works.</div></div>', unsafe_allow_html=True)
        sum_ph.markdown(summary_html(), unsafe_allow_html=True)

    def pump(first_value):
        """Advance the agent until it needs a human or finishes. Safe to call again after an interrupted rerun."""
        if ss.gen is None:
            return
        value = None if first_value in (None, "__start__") else first_value
        try:
            while True:
                event = ss.gen.send(value)
                value = None
                if isinstance(event, ApprovalRequest):
                    if approvals == "ask":
                        ss.pending = event
                        return
                    value = auto_approver(approvals)(event)
                    continue
                render_live()
                if pace:
                    time.sleep(pace)
        except StopIteration as stop:
            ss.gen = None
            ss.pending = None
            ss.final = stop.value or {}

    def finalize():
        """Measure the finished run once. Idempotent, so an interrupted rerun simply finishes it next time."""
        if ss.mode == "agent" and ss.agent and ss.gen is None and ss.summary is None and ss.final is not None:
            ss.eval = evaluate(ss.tools, ss.agent.employee)
            ss.last_report = ss.final.get("report")
            ss.summary = ss.final

    if ss.gen is not None:
        if ss.pending is None:  # starting, or resuming a run a rerun interrupted
            decision, ss.decision = ss.decision, None
            pump(decision)
        elif ss.decision is not None:  # the human answered the approval
            decision, ss.decision, ss.pending = ss.decision, None, None
            pump(decision)
    finalize()

    render_live()

    if ss.pending is not None:
        req: ApprovalRequest = ss.pending
        args = {k: v for k, v in req.args.items() if k != "dep_id"}
        with approval_box:
            st.markdown(
                f'<div class="appr"><div class="t">Approval needed: {esc(req.reason)}</div>'
                f'<div class="row"><b>Why:</b> privileged or write-level change during offboarding</div>'
                f'<div class="row"><b>Risk:</b> {esc(req.risk)}</div>'
                f'<div class="row"><b>Action:</b> <span class="mono">{esc(req.action)} {esc(json.dumps(args))}</span></div></div>',
                unsafe_allow_html=True,
            )
            a1, a2, _ = st.columns([1, 1, 5])
            a1.button("Approve", type="primary", on_click=decide, args=("approved",), width="stretch")
            a2.button("Deny", on_click=decide, args=("denied",), width="stretch")

# ----------------------------------------------------------------------------- benchmark
with tab_bench:
    st.markdown(f"Runs all {len(BENCHMARK_KEYS)} scenarios on fresh worlds, once with the naive checklist and once with HandoffGuard, "
                "and measures both the same way: does every automation still run, and is any access left?")
    if st.button("Run benchmark", key="bench_btn"):
        prog = st.progress(0.0)
        done = []

        def tick(key):
            done.append(key)
            prog.progress(len(done) / len(BENCHMARK_KEYS), text=SCENARIOS[key]["title"])

        planner = RulesPlanner() if planner_choice == "rules" else build_planner()
        ss.bench = {"planner": getattr(planner, "label", planner.name),
                    "rows": benchmark(planner, BENCHMARK_KEYS, {"flaky": f_flaky, "injection": f_injection}, tick)}
        ss.world, ss.tools = new_session(scenario, faults)
        prog.empty()
    if ss.bench:
        df = pd.DataFrame(ss.bench["rows"])
        tot = df.sum(numeric_only=True)
        complete = int((df["HandoffGuard: status"] == "COMPLETE").sum())

        def panel(title, color, a, b, c, note):
            return (f'<div class="card"><h3>{title}</h3><div class="big">'
                    f'<div><div class="n" style="color:{color}">{a}</div><div class="l">Broken automations</div></div>'
                    f'<div><div class="n" style="color:{color}">{b}</div><div class="l">Unapproved privileged actions</div></div>'
                    f'<div><div class="n" style="color:{color}">{c}</div><div class="l">{note}</div></div></div></div>')

        st.markdown(
            '<div class="cmp">'
            + panel("Naive checklist", "var(--bad)", int(tot["baseline: broken automations"]), int(tot["baseline: unapproved privileged"]),
                    int(tot["baseline: residual access"]), "Access paths left")
            + panel("HandoffGuard", "var(--good)", int(tot["HandoffGuard: broken automations"]), int(tot["HandoffGuard: unapproved privileged"]),
                    f"{complete}/{len(df)}", "Completed; the rest stopped safely")
            + "</div>",
            unsafe_allow_html=True,
        )
        rows = []
        for r in ss.bench["rows"]:
            res = r["HandoffGuard: status"]
            pill = f'<span class="pill {"p-good" if res == "COMPLETE" else "p-wait"}"><span class="dot"></span>{"Complete" if res == "COMPLETE" else "Safe stop"}</span>'
            rows.append(
                f'<tr><td>{esc(r["scenario"])}</td><td class="num">{r["baseline: broken automations"]}</td>'
                f'<td class="num">{r["baseline: residual access"]}</td><td class="num">{r["HandoffGuard: broken automations"]}</td>'
                f'<td class="num">{r["HandoffGuard: residual access"]}</td><td>{pill}</td><td class="num">{r["recoveries"]}</td></tr>'
            )
        st.markdown(
            '<table class="tbl"><tr><th>Scenario</th><th class="num">Checklist: broken</th><th class="num">Checklist: access left</th>'
            '<th class="num">HandoffGuard: broken</th><th class="num">HandoffGuard: access left</th><th>HandoffGuard result</th>'
            f'<th class="num">Recoveries</th></tr>{"".join(rows)}</table>',
            unsafe_allow_html=True,
        )
        st.caption(f"Planner: {ss.bench['planner']}. A safe stop means the agent kept everything running and handed the decision to a human.")
        st.download_button("Download results (CSV)", df.to_csv(index=False), file_name="handoffguard-benchmark.csv")

# ----------------------------------------------------------------------------- report
with tab_report:
    if ss.last_report:
        st.download_button("Download report (Markdown)", ss.last_report, file_name="offboarding-report.md")
        with st.container(border=True):
            st.markdown(ss.last_report)
    else:
        st.markdown('<div class="card"><div class="empty">Run HandoffGuard to generate the completion report.</div></div>', unsafe_allow_html=True)

# ----------------------------------------------------------------------------- world
with tab_world:
    w = ss.world
    st.markdown(f"The simulated organisation for **{SCENARIOS[w.scenario]['title']}**. Everything the agent sees and changes lives here.")
    c1, c2 = st.columns(2, gap="medium")
    with c1:
        st.markdown("**Org members**")
        st.dataframe(pd.DataFrame([{"user": u, "role": r, "login": w.logins.get(u)} for u, r in w.members.items()]), hide_index=True, width="stretch")
    with c2:
        st.markdown("**Credentials**")
        st.dataframe(pd.DataFrame([{"id": t.id, "owner": t.owner, "type": t.owner_type, "scopes": ", ".join(sorted(t.scopes)), "status": t.status}
                                   for t in w.tokens.values()]), hide_index=True, width="stretch")
    st.markdown("**Automation secret stores** · names are listable, values never shown")
    st.dataframe(pd.DataFrame([{"automation": s.name, "secret": k, "credential": w.token_id_for_value(v), "runs on": s.host}
                               for s in w.targets.values() for k, v in s.secrets.items()]), hide_index=True, width="stretch")
    st.markdown("**Audit log** · latest 15 token uses")
    st.dataframe(pd.DataFrame(w.audit[-15:][::-1]), hide_index=True, width="stretch")
    with st.expander("Repository files the agent scans"):
        for p in sorted(w.repo_dir.rglob("*")):
            if p.is_file():
                st.markdown(f"`{p.relative_to(w.repo_dir).as_posix()}`")
                st.code(p.read_text(encoding="utf-8"), language="yaml" if p.suffix in (".yml", ".yaml") else "python" if p.suffix == ".py" else "bash")
