"""HandoffGuard console (Streamlit).

    streamlit run app.py
"""
from __future__ import annotations

import html
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

st.set_page_config(page_title="HandoffGuard", page_icon="🛡️", layout="wide")

COLORS = {"good": "#1E7A4C", "bad": "#B42318", "wait": "#9A6200", "block": "#7A2E8E", "info": "#5A6878"}
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');
html, body, [class*="css"], .stMarkdown, .stButton button { font-family: 'IBM Plex Sans', system-ui, sans-serif; }
code, .mono { font-family: 'IBM Plex Mono', ui-monospace, monospace !important; font-size: 0.86em; }
.block-container { padding-top: 1.6rem; max-width: 1400px; }
h1.hg { font-size: 1.9rem; font-weight: 700; color: #16202B; margin: 0 0 .15rem 0; letter-spacing: -0.01em; }
p.hg-sub { color: #5A6878; margin: 0 0 1rem 0; font-size: 1rem; }
.board { border: 1px solid #D5DCE3; border-radius: 10px; overflow: hidden; background: #fff; }
.board-row { display: grid; grid-template-columns: 1.3fr 1.5fr 1fr; gap: 12px; align-items: center;
             padding: 10px 14px; border-top: 1px solid #EEF1F4; }
.board-row:first-child { border-top: none; }
.board-head { background: #F4F6F8; color: #5A6878; font-size: .82rem; font-weight: 600; }
.board-name { font-weight: 600; color: #16202B; }
.cred-leaver { color: #9A6200; } .cred-svc { color: #1E7A4C; }
.state { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: .82rem; font-weight: 600; }
.s-good { background: #E3F2EA; color: #1E7A4C; } .s-bad { background: #FBE7E5; color: #B42318; }
.s-wait { background: #FBF0DC; color: #9A6200; } .s-info { background: #EDF0F4; color: #5A6878; }
.leaver { border: 1px solid #D5DCE3; border-radius: 10px; padding: 12px 14px; background: #fff; }
.leaver b { color: #16202B; }
.tl { max-height: 560px; overflow-y: auto; padding-right: 6px; }
.tl-row { border-left: 3px solid #5A6878; padding: 5px 10px; margin: 0 0 6px 0; background: #fff; border-radius: 0 6px 6px 0; }
.tl-meta { font-size: .76rem; color: #5A6878; }
.tl-who { font-weight: 600; }
.tl-text { font-size: .9rem; color: #16202B; line-height: 1.35; }
.approval { border: 2px solid #9A6200; border-radius: 10px; padding: 14px 16px; background: #FFFBF3; }
.approval h4 { margin: 0 0 .3rem 0; color: #16202B; font-size: 1.05rem; }
.status-big { font-size: 1.05rem; font-weight: 700; margin: .9rem 0 .4rem 0; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

ss = st.session_state
for key, default in {
    "world": None, "tools": None, "agent": None, "gen": None, "pending": None, "decision": None,
    "mode": None, "baseline": None, "eval": None, "summary": None, "bench": None, "last_report": None,
}.items():
    ss.setdefault(key, default)

# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.markdown("### HandoffGuard")
    scenario = st.selectbox("Scenario", list(SCENARIOS), format_func=lambda k: SCENARIOS[k]["title"])
    st.caption(SCENARIOS[scenario]["description"])

    providers = available_providers()
    planner_options = [f"llm:{p}" for p in providers] + ["rules"]
    planner_choice = st.radio(
        "Planner",
        planner_options,
        format_func=lambda o: f"LLM ({o.split(':')[1]}, {PROVIDERS[o.split(':')[1]]['model']})" if o.startswith("llm") else "Rules only (no LLM)",
    )
    if not providers:
        st.info("No LLM key found. Add GROQ_API_KEY or GEMINI_API_KEY to .env to enable LLM discovery.")

    st.markdown("**Judge's fault switchboard**")
    f_last_owner = st.toggle("Leaver is the org's last owner", value=bool(SCENARIOS[scenario]["faults"].get("last_owner")))
    f_flaky = st.toggle("Flaky CI runner (first canary times out)", value=False)

    approvals = st.radio("Approvals", ["ask", "approve_all", "deny_write"],
                         format_func={"ask": "Ask me", "approve_all": "Auto-approve", "deny_write": "Auto-deny write access"}.get)
    pace = st.slider("Timeline pace (seconds per step)", 0.0, 0.8, 0.2, 0.05)

faults = {"last_owner": f_last_owner, "flaky": f_flaky}


def build_planner():
    if planner_choice == "rules":
        return RulesPlanner()
    return make_planner(planner_choice.split(":")[1])


def reset_world():
    ss.world, ss.tools = new_session(scenario, faults)
    ss.agent = ss.gen = ss.pending = ss.decision = None
    ss.baseline = ss.eval = ss.summary = None
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
    except Exception as exc:  # missing key etc.
        st.session_state["planner_error"] = str(exc)
        planner = RulesPlanner()
    ss.agent = HandoffGuard(ss.tools, planner, ss.world.hr_path, run_dir=run_dir)
    ss.gen = ss.agent.run()
    ss.decision = "__start__"


def decide(value: str):
    ss.decision = value


if ss.world is None or ss.world.scenario != scenario:
    reset_world()

# ---------------------------------------------------------------- header
st.markdown('<h1 class="hg">HandoffGuard</h1>', unsafe_allow_html=True)
st.markdown(
    '<p class="hg-sub">An IT Infrastructure agent for safe employee offboarding: it re-homes everything the leaver\'s '
    "credentials run, proves it still works, and only then revokes.</p>",
    unsafe_allow_html=True,
)

b1, b2, b3, _ = st.columns([1.2, 1.2, 0.8, 3])
b1.button("Run naive checklist", on_click=start_baseline, width="stretch", help="What offboarding looks like today: revoke, remove, done.")
b2.button("Run HandoffGuard", on_click=start_agent, type="primary", width="stretch")
b3.button("Reset", on_click=reset_world, width="stretch")

tab_run, tab_bench, tab_report, tab_world = st.tabs(["Live run", "Benchmark", "Report", "World"])


# ---------------------------------------------------------------- renderers
def board_html() -> str:
    w = ss.world
    dep_by_target = {d.target: d for d in ss.agent.deps} if ss.agent else {}
    broken = {b["target"]: b["error"] for b in (ss.eval or {}).get("broken", [])}
    rows = ['<div class="board"><div class="board-row board-head"><div>Automation</div><div>Runs on credential</div><div>State</div></div>']
    for name, spec in w.targets.items():
        cred = w.token_id_for_value(next(iter(spec.secrets.values()))) or "?"
        tok = w.tokens.get(cred)
        cred_cls = "cred-leaver" if tok and tok.owner_type == "user" else "cred-svc"
        if ss.eval is not None:
            if name in broken:
                state, cls = "Broken", "s-bad"
            elif tok and tok.owner_type == "user" and ss.mode == "agent":
                state, cls = "Running, still on leaver's token (held)", "s-wait"
            else:
                state, cls = "Running", "s-good"
        elif name in dep_by_target:
            d = dep_by_target[name]
            state = {"discovered": "Found", "rehome_requested": "Re-homing", "rehome_executed": "Testing",
                     "verified": "Verified", "revoked": "Verified after revoke", "probe_clean": "Done",
                     "escalated": "Held for a human"}.get(d.status, d.status)
            cls = "s-good" if d.status in ("verified", "revoked", "probe_clean") else "s-wait" if d.status == "escalated" else "s-info"
        else:
            state, cls = ("Not yet discovered", "s-info") if ss.mode == "agent" else ("Running", "s-good")
        detail = f'<div class="tl-meta mono">{html.escape(broken[name])}</div>' if name in broken else ""
        rows.append(
            f'<div class="board-row"><div><div class="board-name">{html.escape(name)}</div>'
            f'<div class="tl-meta">{html.escape(spec.file)}</div></div>'
            f'<div><span class="mono {cred_cls}">{html.escape(cred)}</span>{detail}</div>'
            f'<div><span class="state {cls}">{state}</span></div></div>'
        )
    rows.append("</div>")
    return "".join(rows)


def leaver_html() -> str:
    w = ss.world
    user = "riya"
    toks = [t for t in w.tokens.values() if t.owner == user]
    tok_txt = " ".join(
        f'<span class="state {"s-bad" if t.status == "revoked" else "s-wait"} mono">{t.id}: {t.status}</span>' for t in toks
    )
    member = w.members.get(user, "removed")
    return (
        f'<div class="leaver"><b>Leaver: riya</b> · graduating tech lead<br>'
        f'<span class="tl-meta">Org role</span> <span class="state {"s-good" if member == "removed" else "s-wait"}">{member}</span> '
        f'<span class="tl-meta">Login</span> <span class="state {"s-good" if w.logins.get(user) == "suspended" else "s-wait"}">{w.logins.get(user)}</span><br>'
        f'<span class="tl-meta">Credentials</span> {tok_txt}</div>'
    )


WHO = {"agent": "agent", "llm": "LLM", "rules": "rules", "guard": "policy guard", "human": "approver"}


def timeline_html(entries: list[LedgerEntry]) -> str:
    out = ['<div class="tl">']
    for e in reversed(entries):
        who = WHO.get(e.decided_by.split(" ")[0], e.decided_by)
        color = COLORS.get(e.level, "#5A6878")
        tool = f" · <span class='mono'>{html.escape(e.tool)}</span>" if e.tool else ""
        out.append(
            f'<div class="tl-row" style="border-left-color:{color}"><div class="tl-meta">#{e.step} {e.phase} · '
            f'<span class="tl-who" style="color:{color}">{html.escape(who)}</span>{tool}</div>'
            f'<div class="tl-text">{html.escape(e.rationale)}</div></div>'
        )
    out.append("</div>")
    return "".join(out)


# ---------------------------------------------------------------- live run tab
with tab_run:
    top_l, top_r = st.columns([2.2, 1])
    board_ph = top_l.empty()
    leaver_ph = top_r.empty()
    status_ph = st.empty()
    approval_ph = st.empty()
    col_tl, col_deps = st.columns([1.35, 1])
    with col_tl:
        st.markdown("**Agent timeline** (newest first)")
        timeline_ph = st.empty()
    with col_deps:
        st.markdown("**Dependencies**")
        deps_ph = st.empty()
        metrics_ph = st.empty()

    def render_live():
        board_ph.markdown(board_html(), unsafe_allow_html=True)
        leaver_ph.markdown(leaver_html(), unsafe_allow_html=True)
        if ss.agent:
            timeline_ph.markdown(timeline_html(ss.agent.ledger), unsafe_allow_html=True)
            if ss.agent.deps:
                deps_ph.dataframe(
                    pd.DataFrame([{k: d.row()[k] for k in ("dependency", "found by", "new credential", "status")} for d in ss.agent.deps]),
                    hide_index=True, width="stretch")

    def pump(first_value):
        """Advance the agent until it needs a human or finishes."""
        value = None if first_value == "__start__" else first_value
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
            ss.summary = stop.value
            ss.gen = None
            ss.pending = None
            ss.eval = evaluate(ss.tools, ss.agent.employee)
            ss.last_report = stop.value.get("report")

    if ss.gen is not None and ss.decision is not None:
        decision, ss.decision, ss.pending = ss.decision, None, None
        pump(decision)

    render_live()

    if ss.mode is None:
        timeline_ph.info("Run the naive checklist first to see what breaks today, then run HandoffGuard on the same scenario.")
    elif ss.mode == "baseline":
        broken = ss.eval["broken"]
        status_ph.markdown(
            f'<p class="status-big" style="color:#B42318">Naive checklist: {len(broken)} automation(s) broken, '
            f'{len(ss.eval["residual"])} access path(s) left, 1 privileged action without approval.</p>',
            unsafe_allow_html=True,
        )
        timeline_ph.markdown("\n".join(f"- {s}" for s in ss.baseline["steps"]))
    if ss.pending is not None:
        req: ApprovalRequest = ss.pending
        with approval_ph.container():
            args = {k: v for k, v in req.args.items() if k != "dep_id"}
            st.markdown(
                f'<div class="approval"><h4>Approval needed: {html.escape(req.reason)}</h4>'
                f'<div class="tl-meta">Risk: {html.escape(req.risk)} · Action <span class="mono">{req.action}</span> '
                f'<span class="mono">{html.escape(str(args))}</span></div></div>',
                unsafe_allow_html=True,
            )
            a1, a2, _ = st.columns([1, 1, 4])
            a1.button("Approve", type="primary", on_click=decide, args=("approved",), width="stretch")
            a2.button("Deny", on_click=decide, args=("denied",), width="stretch")
    if ss.mode == "agent" and ss.summary:
        m = ss.summary["metrics"]
        color = "#1E7A4C" if m["status"] == "COMPLETE" else "#9A6200"
        status_ph.markdown(
            f'<p class="status-big" style="color:{color}">HandoffGuard: {m["status"]} · {len(ss.eval["broken"])} broken · '
            f'{len(ss.eval["residual"])} access path(s) left · {m["unapproved_privileged_actions"]} unapproved privileged actions</p>',
            unsafe_allow_html=True,
        )
        with metrics_ph.container():
            c1, c2, c3 = st.columns(3)
            c1.metric("Recoveries", m["recoveries"])
            c2.metric("Guard blocks", m["guard_blocks"])
            c3.metric("Approvals", m["approvals"])
            if ss.agent.open_items:
                st.markdown("**Open items for a human**\n" + "\n".join(f"- {o}" for o in ss.agent.open_items))

# ---------------------------------------------------------------- benchmark tab
with tab_bench:
    st.markdown("Runs all six scenarios twice on fresh worlds: once with the naive checklist, once with HandoffGuard. Same yardstick for both.")
    if st.button("Run benchmark", key="bench_btn"):
        prog = st.progress(0.0)
        done = []

        def tick(key):
            done.append(key)
            prog.progress(len(done) / len(BENCHMARK_KEYS), text=SCENARIOS[key]["title"])

        planner = RulesPlanner() if planner_choice == "rules" else build_planner()
        ss.bench = {"planner": getattr(planner, "label", planner.name), "rows": benchmark(planner, BENCHMARK_KEYS, {"flaky": f_flaky}, tick)}
        ss.world, ss.tools = new_session(scenario, faults)
    if ss.bench:
        df = pd.DataFrame(ss.bench["rows"])
        st.caption(f"Planner: {ss.bench['planner']}")
        st.dataframe(df, hide_index=True, width="stretch")
        tot = df.sum(numeric_only=True)
        st.markdown(
            f"**Totals.** Naive checklist broke **{int(tot['baseline: broken automations'])}** automations; "
            f"HandoffGuard broke **{int(tot['HandoffGuard: broken automations'])}**. "
            f"Unapproved privileged actions: {int(tot['baseline: unapproved privileged'])} vs "
            f"{int(tot['HandoffGuard: unapproved privileged'])}."
        )

# ---------------------------------------------------------------- report tab
with tab_report:
    if ss.last_report:
        st.download_button("Download report (Markdown)", ss.last_report, file_name="offboarding-report.md")
        st.markdown(ss.last_report)
    else:
        st.info("Run HandoffGuard to generate the completion report.")

# ---------------------------------------------------------------- world tab
with tab_world:
    w = ss.world
    st.markdown(f"Scenario **{SCENARIOS[w.scenario]['title']}** · repo files in `{w.repo_dir}`")
    c1, c2 = st.columns(2)
    c1.markdown("**Org members**")
    c1.dataframe(pd.DataFrame([{"user": u, "role": r, "login": w.logins.get(u)} for u, r in w.members.items()]), hide_index=True)
    c2.markdown("**Credentials**")
    c2.dataframe(
        pd.DataFrame([{"id": t.id, "owner": t.owner, "type": t.owner_type, "scopes": ", ".join(sorted(t.scopes)), "status": t.status} for t in w.tokens.values()]),
        hide_index=True,
    )
    st.markdown("**Automation secret stores** (names are listable; values never shown)")
    st.dataframe(
        pd.DataFrame([{"target": s.name, "secret": k, "credential": w.token_id_for_value(v), "runs on": s.host} for s in w.targets.values() for k, v in s.secrets.items()]),
        hide_index=True,
    )
    st.markdown("**Audit log** (latest 15)")
    st.dataframe(pd.DataFrame(w.audit[-15:][::-1]), hide_index=True, width="stretch")
    with st.expander("Repository files the agent scans"):
        for p in sorted(w.repo_dir.rglob("*")):
            if p.is_file():
                st.markdown(f"`{p.relative_to(w.repo_dir).as_posix()}`")
                st.code(p.read_text(), language="yaml" if p.suffix in (".yml", ".yaml") else "python" if p.suffix == ".py" else "bash")
