"""Deterministic policy guard. Every tool call the agent proposes passes through `check`.

The LLM can propose anything; only this code decides whether it runs.

R1 Order          revoke a leaver credential only when every dependency on it is verified
                  and every observed use of it is explained
R2 Approval       write-scoped mints, role changes and member removal need a recorded approval
R3 Retries        at most `max_retries` recoveries per dependency
R4 Least privilege minted scopes must be justified (default read-only + scopes named in errors)
R5 Known tools    only the 12 declared tools
R6 Denial         an action a human denied is never retried another way
R7 Membership     never remove the leaver while one of their credentials is still held
                  (removal would break the automations still using it)
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from .contracts import PRIVILEGED_TOOLS, TOOL_NAMES, WRITE_SCOPES, Dependency

if TYPE_CHECKING:  # pragma: no cover
    from .agent import HandoffGuard


def approval_key(tool: str, args: dict) -> tuple:
    if tool == "mint_credential":
        return (tool, args.get("dep_id"), tuple(sorted(args.get("scopes", []))))
    if tool == "assign_role":
        return (tool, args.get("user"), args.get("role"))
    if tool == "remove_member":
        return (tool, args.get("user"))
    return (tool,)


class Guard:
    def __init__(self, agent: "HandoffGuard"):
        self.agent = agent
        self.blocks = 0

    def check(self, tool: str, args: dict, dep: Optional[Dependency]) -> tuple[bool, str]:
        a = self.agent
        if tool not in TOOL_NAMES:
            return self._no(f"R5: unknown tool '{tool}'")
        key = approval_key(tool, args)
        if key in a.denied:
            return self._no("R6: a human denied this action")
        if tool == "mint_credential":
            scopes = set(args.get("scopes", []))
            if dep is not None and not scopes <= set(dep.allowed_scopes):
                extra = sorted(scopes - set(dep.allowed_scopes))
                return self._no(f"R4: scopes {extra} are not justified by any observed error")
            if scopes & WRITE_SCOPES and key not in a.approved:
                return self._no("R2: write-scoped credential needs human approval")
        if tool in PRIVILEGED_TOOLS and key not in a.approved:
            return self._no(f"R2: {tool} needs human approval")
        if dep is not None and dep.attempts > a.max_retries:
            return self._no(f"R3: retry limit ({a.max_retries}) reached for {dep.target}")
        if tool == "revoke_credential":
            cred = args.get("credential_id")
            if cred in a.leaver_credential_ids:
                pending = [d.target for d in a.deps if d.credential_ref == cred and d.status != "verified"]
                if pending:
                    return self._no(f"R1: {cred} still backs unverified dependencies {pending}")
                if a.unexplained.get(cred):
                    return self._no(f"R1: {cred} has unexplained recent use by {a.unexplained[cred]}")
        if tool == "remove_member" and args.get("user") == a.employee:
            held = [c for c in a.leaver_credential_ids if c not in a.revoked]
            if held:
                return self._no(f"R7: removing {a.employee} would break automations still on {held}")
        return True, "ok"

    def _no(self, reason: str) -> tuple[bool, str]:
        self.blocks += 1
        return False, reason
