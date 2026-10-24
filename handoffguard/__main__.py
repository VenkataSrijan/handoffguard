"""Command line: python -m handoffguard run|bench|scenarios

  python -m handoffguard run --scenario demo --planner auto --approvals ask
  python -m handoffguard bench --planner rules
"""
from __future__ import annotations

import argparse
import sys

from .agent import HandoffGuard, auto_approver, drive
from .planners import make_planner
from .runner import benchmark, evaluate, new_session, run_baseline
from .world import BENCHMARK_KEYS, SCENARIOS
from .world.scenarios import RUNS_DIR

ICON = {"good": "✔", "bad": "✘", "wait": "…", "block": "⛔", "info": "·"}


def ask(req) -> str:
    print(f"\n  APPROVAL NEEDED: {req.reason}\n  risk: {req.risk}")
    while True:
        a = input("  approve? [y/n] ").strip().lower()
        if a in ("y", "n"):
            return "approved" if a == "y" else "denied"


def cmd_run(args) -> int:
    planner = make_planner(args.planner)
    print(f"Scenario: {SCENARIOS[args.scenario]['title']}\nPlanner:  {getattr(planner, 'label', planner.name)}\n")
    faults = {"last_owner": True if args.last_owner else None, "flaky": True if args.flaky else None}
    if args.baseline:
        _, tools = new_session(args.scenario, faults)
        base = run_baseline(tools)
        ev = evaluate(tools, base["user"])
        print("Naive checklist:\n  " + "\n  ".join(base["steps"]))
        print(f"\nBroken automations: {[b['target'] for b in ev['broken']]}\nResidual access: {ev['residual']}\n")
        return 0
    world, tools = new_session(args.scenario, faults)
    import time

    agent = HandoffGuard(tools, planner, world.hr_path, run_dir=RUNS_DIR / "reports" / f"{args.scenario}-{time.strftime('%Y%m%d-%H%M%S')}")
    approver = ask if args.approvals == "ask" else auto_approver(args.approvals or SCENARIOS[args.scenario]["approvals"])
    summary = drive(agent, approver, lambda e: print(f"{e.step:>3} {ICON.get(e.level, '·')} [{e.decided_by}] {e.rationale}"))
    ev = evaluate(tools, agent.employee)
    print(f"\nStatus: {summary['metrics']['status']} · broken: {len(ev['broken'])} · residual access: {len(ev['residual'])}")
    print(f"Report: {summary.get('run_dir')}/report.md")
    return 0


def cmd_bench(args) -> int:
    planner = make_planner(args.planner)
    rows = benchmark(planner, BENCHMARK_KEYS, progress=lambda k: print(f"running {k} ..."))
    cols = ["baseline: broken automations", "baseline: residual access", "HandoffGuard: broken automations", "HandoffGuard: residual access", "HandoffGuard: status"]
    print(f"\nPlanner: {getattr(planner, 'label', planner.name)}")
    print(f"{'scenario':<46} | base broken | base residual | HG broken | HG residual | HG status")
    for r in rows:
        print(f"{r['scenario'][:46]:<46} | {r[cols[0]]:^11} | {r[cols[1]]:^13} | {r[cols[2]]:^9} | {r[cols[3]]:^11} | {r[cols[4]]}")
    return 0


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):  # Windows consoles default to cp1252
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(prog="handoffguard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="offboard the leaver in one scenario")
    r.add_argument("--scenario", default="demo", choices=list(SCENARIOS))
    r.add_argument("--planner", default="auto", help="auto | llm | rules | groq | gemini")
    r.add_argument("--approvals", default=None, choices=["ask", "approve_all", "deny_write", "deny_all"])
    r.add_argument("--baseline", action="store_true", help="run the naive checklist instead")
    r.add_argument("--last-owner", action="store_true")
    r.add_argument("--flaky", action="store_true")
    b = sub.add_parser("bench", help="6 scenarios, baseline vs agent")
    b.add_argument("--planner", default="auto")
    sub.add_parser("scenarios", help="list scenarios")
    args = ap.parse_args(argv)
    if args.cmd == "run":
        return cmd_run(args)
    if args.cmd == "bench":
        return cmd_bench(args)
    for k, v in SCENARIOS.items():
        print(f"{k:<18} {v['title']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
