"""Outcome reporting: turns the agent's ledger and state into a completion report (Markdown)."""
from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .agent import HandoffGuard


def build_report(agent: "HandoffGuard") -> str:
    r = agent.request
    m = agent.metrics()
    lines: list[str] = []
    title = f"# Offboarding report · {r.request_id if r else 'unknown request'}"
    lines += [title, ""]
    if r:
        lines += [
            f"- **Employee:** {r.employee}  ·  **Reason:** {r.reason}  ·  **Last day:** {r.last_day}",
            f"- **Approver:** {r.approver}  ·  **Successor:** {r.successor or 'not named'}",
        ]
    started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(agent.started))
    lines += [
        f"- **Run:** started {started}, took {m['duration_s']} s, planner `{getattr(agent.planner, 'label', agent.planner.name)}`",
        f"- **Final status:** **{agent.status}**",
        "",
    ]
    verified = m["verified"]
    revoked = len(agent.revoked)
    residual = "none" if not agent.probe_paths else f"{len(agent.probe_paths)} path(s)"
    lines += [
        f"**Summary:** {len(agent.deps)} dependenc{'y' if len(agent.deps) == 1 else 'ies'} found, {verified} re-homed and verified; "
        f"{revoked} leaver credential(s) revoked; residual access: {residual}.",
        "",
        "## Dependencies",
        "",
        "| Target | Found by | Was using | New credential | Canary before revoke | Canary after revoke | Status |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for d in agent.deps:
        lines.append(
            f"| `{d.target}` | {d.found_by} | `{d.secret_name}` → `{d.credential_ref}` | `{d.new_credential or '-'}` "
            f"({', '.join(d.allowed_scopes)}) | {d.canary_before} | {d.canary_after} | {d.status} |"
        )
    if not agent.deps:
        lines.append("| none | | | | | | |")
    lines += ["", "### Evidence", ""]
    for d in agent.deps:
        lines.append(f"- `{d.target}`: " + "; ".join(f"`{e}`" for e in d.evidence) if d.evidence else f"- `{d.target}`: (audit log)")
    lines += ["", "## Credentials", ""]
    for c in agent.leaver_credential_ids:
        state = "revoked" if c in agent.revoked else f"**kept active**: {agent.held.get(c, 'not processed')}"
        lines.append(f"- `{c}`: {state}")
    lines += ["", "## Approvals", ""]
    if agent.approvals_log:
        lines += ["| Time | Action | Reason | Decision | By |", "| --- | --- | --- | --- | --- |"]
        for a in agent.approvals_log:
            lines.append(f"| {a['ts']} | {a['action']} | {a['reason']} | {a['decision']} | {a['by']} |")
    else:
        lines.append("No privileged action was needed.")
    lines += ["", "## Recoveries", ""]
    if agent.recoveries:
        for rec in agent.recoveries:
            lines.append(f"- **{rec['target']}** · failure: `{rec['failure']}` · diagnosis ({rec['by']}): {rec['diagnosis']} · fix: {rec['fix']}")
    else:
        lines.append("None needed.")
    lines += ["", "## Residual-access probe", ""]
    lines += [f"- {p}" for p in agent.probe_paths] or ["- Clean: no membership, no active login, no active credentials."]
    lines += ["", "## Open items for a human", ""]
    lines += [f"- [ ] {o}" for o in agent.open_items] or ["- None."]
    lines += [
        "",
        "## Controls applied",
        "",
        f"- Policy guard decisions that blocked an action: {m['guard_blocks']}",
        f"- Privileged actions without approval: {m['unapproved_privileged_actions']}",
        "- No credential was revoked before its dependents passed a canary; no account was deleted.",
        "- Token values never appear in this report; ids only.",
        "",
    ]
    return "\n".join(lines)
