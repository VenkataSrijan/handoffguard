"""Runs the naive baseline and HandoffGuard on a scenario, and measures both the same way."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Optional

from .agent import HandoffGuard, auto_approver, drive
from .tools import Tools
from .world import SCENARIOS, build_world, ensure_service
from .world.scenarios import RUNS_DIR


def new_session(scenario: str, faults: Optional[dict] = None):
    base_url = ensure_service()
    world = build_world(scenario, faults)
    return world, Tools(world, base_url)


def run_baseline(tools: Tools) -> dict:
    """What a checklist does today: revoke everything, remove the member, suspend. No checks."""
    steps = []
    req = tools.read_hr_request(str(tools.world.hr_path)).data
    user = req["employee"]
    inv = tools.inventory_identity(user).data
    for t in inv["tokens"]:
        if t["status"] == "active":
            tools.revoke_credential(t["id"])
            steps.append(f"Revoked {t['id']}")
    r = tools.remove_member(inv["org"], user)
    steps.append(f"Removed {user} from {inv['org']}" if r.ok else f"Tried to remove {user}: {r.error}")
    tools.suspend_login(user)
    steps.append(f"Suspended login for {user}")
    return {"steps": steps, "unapproved_privileged_actions": 1, "user": user}


def evaluate(tools: Tools, user: str) -> dict:
    """Same yardstick for both: does every automation still run, and is any access left?"""
    world = tools.world
    flaky = world.faults.get("flaky")
    world.faults["flaky"] = False
    broken = []
    for name in world.targets:
        res = tools.run_canary(name)
        if not res.ok:
            broken.append({"target": name, "error": (res.error or "").splitlines()[-1]})
    world.faults["flaky"] = flaky
    paths = tools.probe_access(user).data["paths"]
    return {"broken": broken, "residual": paths}


def run_agent(scenario: str, planner, faults: Optional[dict] = None, approvals: Optional[str] = None,
              on_event: Optional[Callable] = None) -> dict:
    world, tools = new_session(scenario, faults)
    run_dir = RUNS_DIR / "reports" / f"{scenario}-{time.strftime('%Y%m%d-%H%M%S')}"
    agent = HandoffGuard(tools, planner, world.hr_path, run_dir=run_dir)
    summary = drive(agent, auto_approver(approvals or SCENARIOS[scenario]["approvals"]), on_event)
    ev = evaluate(tools, agent.employee)
    return {"agent": agent, "summary": summary, "eval": ev, "world": world}


def benchmark(planner, keys: list[str], faults: Optional[dict] = None, progress: Optional[Callable[[str], None]] = None) -> list[dict]:
    rows = []
    for key in keys:
        if progress:
            progress(key)
        _, tools = new_session(key, faults)
        base = run_baseline(tools)
        base_ev = evaluate(tools, base["user"])
        out = run_agent(key, planner, faults)
        m = out["agent"].metrics()
        rows.append(
            {
                "scenario": SCENARIOS[key]["title"],
                "baseline: broken automations": len(base_ev["broken"]),
                "baseline: residual access": len(base_ev["residual"]),
                "baseline: unapproved privileged": base["unapproved_privileged_actions"],
                "HandoffGuard: broken automations": len(out["eval"]["broken"]),
                "HandoffGuard: residual access": len(out["eval"]["residual"]),
                "HandoffGuard: unapproved privileged": m["unapproved_privileged_actions"],
                "HandoffGuard: status": m["status"],
                "recoveries": m["recoveries"],
                "guard blocks": m["guard_blocks"],
            }
        )
    return rows


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent
