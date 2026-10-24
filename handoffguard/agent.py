"""HandoffGuard agent: ingest → discover → re-home → verify → revoke → remove → probe → report.

`HandoffGuard.run()` is a generator. It yields a LedgerEntry for every step
(so a UI can stream the timeline) and an ApprovalRequest whenever a human must
decide; send back "approved" or "denied". Its return value is the run summary.
Use `drive()` to run it to completion with an automatic approver.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Callable, Generator, Optional

from .contracts import (
    DEFAULT_SCOPES,
    PRIVILEGED_TOOLS,
    READ_TOOLS,
    WRITE_SCOPES,
    ApprovalRequest,
    Dependency,
    HRRequest,
    LedgerEntry,
    ToolResult,
)
from .guard import Guard, approval_key
from .planners import RulesPlanner, scopes_named_in

CANARY_ACTIONS = [
    {"tool": "mint_credential", "args": {"scopes": "list of scopes, e.g. ['repo:read','contents:write']"}, "use": "re-mint the replacement credential with different scopes"},
    {"tool": "retry_canary", "args": {}, "use": "run the canary again unchanged (transient failures)"},
    {"tool": "escalate", "args": {"reason": "text"}, "use": "stop and hand to a human"},
]
MEMBERSHIP_ACTIONS = [
    {"tool": "assign_role", "args": {"user": "username", "role": "owner|member"}, "use": "change someone's org role"},
    {"tool": "escalate", "args": {"reason": "text"}, "use": "stop and hand to a human"},
]

Event = LedgerEntry | ApprovalRequest


class HandoffGuard:
    def __init__(self, tools, planner, hr_path: str | Path, *, max_retries: int = 2, run_dir: Optional[Path] = None):
        self.tools = tools
        self.planner = planner
        self.fallback = RulesPlanner()
        self.hr_path = str(hr_path)
        self.max_retries = max_retries
        self.run_dir = Path(run_dir) if run_dir else None
        self.guard = Guard(self)
        self.ledger: list[LedgerEntry] = []
        self.deps: list[Dependency] = []
        self.approved: set[tuple] = set()
        self.denied: set[tuple] = set()
        self.approvals_log: list[dict] = []
        self.recoveries: list[dict] = []
        self.open_items: list[str] = []
        self.revoked: list[str] = []
        self.held: dict[str, str] = {}
        self.unexplained: dict[str, list[str]] = {}
        self.leaver_credential_ids: list[str] = []
        self.request: Optional[HRRequest] = None
        self.employee: str = ""
        self.org: str = ""
        self.probe_paths: list[str] = []
        self.status = "RUNNING"
        self.started = time.time()
        self.finished: Optional[float] = None
        self.discovery_summary = ""
        self.unprivileged_violations = 0

    # ------------------------------------------------------------ helpers
    def _log(self, phase: str, rationale: str, *, decided_by: str = "agent", tool=None, dep: Optional[Dependency] = None,
             input=None, output=None, level: str = "info") -> LedgerEntry:
        entry = LedgerEntry(
            step=len(self.ledger) + 1,
            phase=phase,
            rationale=rationale,
            decided_by=decided_by,
            tool=tool,
            dep_id=dep.dep_id if dep else None,
            input=input or {},
            output=output or {},
            level=level,
        )
        self.ledger.append(entry)
        return entry

    def _call(self, tool: str, args: dict, dep: Optional[Dependency] = None) -> Generator[Event, object, ToolResult]:
        allowed, reason = self.guard.check(tool, args, dep)
        if not allowed:
            yield self._log("block", f"Policy guard blocked {tool}: {reason}", decided_by="guard", tool=tool, dep=dep, input=args, level="block")
            return ToolResult(False, error=f"blocked by policy guard: {reason}", error_code="guard_blocked")
        res: ToolResult = getattr(self.tools, tool)(**{k: v for k, v in args.items() if k != "dep_id"})
        level = ("info" if tool in READ_TOOLS and tool != "run_canary" else "good") if res.ok else "bad"
        yield self._log(
            "observe" if tool in READ_TOOLS else "act",
            self._describe(tool, args, res),
            tool=tool,
            dep=dep,
            input=args,
            output=self._summarise(tool, res),
            level=level,
        )
        return res

    def _approve(self, tool: str, args: dict, reason: str, risk: str) -> Generator[Event, object, bool]:
        key = approval_key(tool, args)
        if key in self.approved:
            return True
        if key in self.denied:
            return False
        yield self._log("approval", f"Waiting for human approval: {reason}", tool=tool, input=args, level="wait")
        req = ApprovalRequest(approval_id=f"apr-{len(self.approvals_log) + 1}", action=tool, args=args, reason=reason, risk=risk)
        decision = yield req
        ok = decision == "approved"
        (self.approved if ok else self.denied).add(key)
        approver = self.request.approver if self.request else "approver"
        self.approvals_log.append({"id": req.approval_id, "action": tool, "args": {k: v for k, v in args.items() if k != "dep_id"}, "reason": reason, "decision": "approved" if ok else "denied", "by": approver, "ts": time.strftime("%H:%M:%S")})
        yield self._log("approval", f"{approver} {'approved' if ok else 'DENIED'}: {reason}", decided_by="human", tool=tool, input=args, level="good" if ok else "bad")
        return ok

    def _diagnose(self, ctx: dict, allowed: list[dict]) -> tuple[dict, str]:
        names = {a["tool"] for a in allowed}
        by = self.planner.name
        try:
            out = self.planner.diagnose(ctx, allowed)
            if out.get("action", {}).get("tool") not in names:
                raise ValueError(f"action not allowed: {out.get('action')}")
        except Exception as exc:  # LLM down, bad JSON, or invalid action → deterministic fallback
            out = self.fallback.diagnose(ctx, allowed)
            by = "rules" if self.planner.name == "rules" else f"rules (LLM fallback: {str(exc)[:80]})"
        out.setdefault("action", {}).setdefault("args", {})
        return out, by

    # --------------------------------------------------------------- run
    def run(self) -> Generator[Event, object, dict]:
        yield self._log("plan", "Goal: offboard the leaver with nothing broken and no residual access. Order: re-home → verify → revoke.")

        # 1. Ingest
        res = yield from self._call("read_hr_request", {"path": self.hr_path})
        if not res.ok:
            self.status = "FAILED"
            return self._finish()
        self.request = HRRequest.from_dict(res.data)
        self.employee = self.request.employee

        # 2. Inventory + usage evidence
        inv = yield from self._call("inventory_identity", {"user": self.employee})
        self.org = inv.data.get("org", "")
        creds = [t for t in inv.data.get("tokens", []) if t["status"] == "active"]
        self.leaver_credential_ids = [t["id"] for t in creds]
        uses: dict[str, list] = {}
        for t in creds:
            r = yield from self._call("read_audit_log", {"credential_id": t["id"], "days": 14})
            uses[t["id"]] = r.data.get("uses", [])

        # 3. Discover dependencies
        scan = yield from self._call("scan_artifacts", {})
        targets = {t["target"]: t for t in scan.data["targets"]}
        ctx = {"employee": self.employee, "credentials": creds, "uses": uses, "targets": list(targets.values()), "files": scan.data["files"]}
        yield from self._discover(ctx, targets)

        # Every observed use must be explained before its credential may be revoked
        for cred, cred_uses in uses.items():
            explained = {c for d in self.deps if d.credential_ref == cred for c in d.explains_clients}
            missing = [u["client"] for u in cred_uses if u["client"] not in explained]
            if missing:
                self.unexplained[cred] = missing
                yield self._log("plan", f"Unexplained recent use of {cred} by {missing}. It will not be revoked until this is explained.", level="wait", decided_by="agent")
        if not self.deps:
            yield self._log("plan", "No automation depends on the leaver's credentials.")

        # 4. Re-home and verify each dependency
        for dep in self.deps:
            yield from self._rehome(dep)

        # 5. Revoke leaver credentials (guard enforces R1)
        for cred in self.leaver_credential_ids:
            pending = [d for d in self.deps if d.credential_ref == cred and d.status != "verified"]
            if pending or self.unexplained.get(cred):
                why = f"dependencies not verified: {[d.target for d in pending]}" if pending else f"unexplained use by {self.unexplained[cred]}"
                self.held[cred] = why
                self.open_items.append(f"{cred} kept active ({why}); needs a human decision")
                yield self._log("escalate", f"Holding {cred}: {why}", level="wait")
                continue
            r = yield from self._call("revoke_credential", {"credential_id": cred})
            if not r.ok:
                self.held[cred] = r.error or "revoke failed"
                continue
            self.revoked.append(cred)
            for d in [d for d in self.deps if d.credential_ref == cred]:
                c = yield from self._call("run_canary", {"target": d.target}, d)
                ok, why = self._verdict(c, d)
                d.canary_after = "pass" if ok else "FAIL"
                if ok:
                    d.status = "revoked"
                    yield self._log("verify", f"Post-revoke canary passed for {d.target}: no hidden reliance on {cred}.", dep=d, level="good")
                else:
                    d.status = "escalated"
                    self.open_items.append(f"{d.target} failed after revoking {cred}: {why}")
                    yield self._log("escalate", f"Post-revoke canary FAILED for {d.target}: {why}", dep=d, level="bad")

        # 6. Remove from org (privileged, may hit last-owner)
        yield from self._remove_membership()

        # 7. Suspend login (never delete) and probe
        yield from self._call("suspend_login", {"user": self.employee})
        probe = yield from self._call("probe_access", {"user": self.employee})
        self.probe_paths = probe.data.get("paths", [])
        if not self.probe_paths:
            for d in self.deps:
                if d.status == "revoked":
                    d.status = "probe_clean"
        complete = not self.probe_paths and not self.open_items and all(d.status == "probe_clean" for d in self.deps)
        self.status = "COMPLETE" if complete else "PARTIAL"
        yield self._log(
            "report",
            "Offboarding COMPLETE: nothing broken, no residual access." if complete else f"Offboarding PARTIAL: {len(self.open_items)} open item(s) handed to a human.",
            level="good" if complete else "wait",
        )
        return self._finish()

    # ---------------------------------------------------------- discovery
    def _discover(self, ctx: dict, targets: dict) -> Generator[Event, object, None]:
        found: dict[str, dict] = {}
        sources: list[tuple[str, dict]] = []
        if self.planner.name != "rules":
            try:
                out = self.planner.discover(ctx)
                sources.append(("llm", out))
                yield self._log("plan", f"LLM discovery: {out.get('summary', '')}", decided_by="llm", output={"dependencies": len(out["dependencies"])})
            except Exception as exc:
                yield self._log("plan", f"LLM discovery unavailable ({str(exc)[:100]}); using rules.", decided_by="rules", level="bad")
        rules_out = self.fallback.discover(ctx)
        sources.append(("rules", rules_out))
        if self.planner.name == "rules":
            yield self._log("plan", f"Rules discovery: {rules_out['summary']}", decided_by="rules")
        self.discovery_summary = "; ".join(f"{s}: {len(o['dependencies'])}" for s, o in sources)

        valid_creds = set(self.leaver_credential_ids)
        for source, out in sources:
            for item in out.get("dependencies", []):
                t = item.get("target")
                problem = None
                if t not in targets:
                    problem = f"unknown target {t!r}"
                elif item.get("secret_name") not in targets[t]["secret_names"]:
                    problem = f"{t} has no secret {item.get('secret_name')!r}"
                elif item.get("credential_id") not in valid_creds:
                    problem = f"{item.get('credential_id')!r} is not a leaver credential"
                if problem:
                    yield self._log("block", f"Guard rejected a discovery item from {source}: {problem}", decided_by="guard", input=item, level="block")
                    continue
                if t in found:
                    prev = found[t]
                    if source not in prev["found_by"]:
                        prev["found_by"] = f"{prev['found_by']}+{source}"
                    prev["explains_audit_clients"] = sorted(set(prev["explains_audit_clients"]) | set(item.get("explains_audit_clients", [])))
                    continue
                found[t] = {**item, "found_by": source, "explains_audit_clients": list(item.get("explains_audit_clients", []))}

        for i, item in enumerate(found.values(), 1):
            spec = targets[item["target"]]
            explains = set(item["explains_audit_clients"])
            if spec["kind"] == "pipeline":
                explains.add(f"ci:{spec['defined_in']}")
            dep = Dependency(
                dep_id=f"dep-{i}",
                kind=item.get("kind") or spec["kind"],
                target=item["target"],
                secret_name=item["secret_name"],
                credential_ref=item["credential_id"],
                evidence=list(item.get("evidence", []))[:6],
                found_by=item["found_by"],
                confidence=item.get("confidence", "high"),
                explains_clients=sorted(explains),
            )
            self.deps.append(dep)
            yield self._log(
                "plan",
                f"Dependency {dep.target} uses {dep.credential_ref} via secret {dep.secret_name} (found by {dep.found_by}). Evidence: {' | '.join(dep.evidence[:3])}",
                decided_by="llm" if "llm" in dep.found_by else "rules",
                dep=dep,
            )

    # ------------------------------------------------------------ re-home
    def _rehome(self, dep: Dependency) -> Generator[Event, object, None]:
        scopes = list(DEFAULT_SCOPES)
        owner = f"svc-{dep.target.split(':', 1)[1]}"
        remint = True
        yield self._log("plan", f"Re-home {dep.target}: mint a least-privilege service credential ({', '.join(scopes)}), rebind {dep.secret_name}, run canary.", dep=dep)
        while True:
            if remint:
                args = {"owner": owner, "scopes": scopes, "repo": "club/website", "dep_id": dep.dep_id}
                if set(scopes) & WRITE_SCOPES:
                    ok = yield from self._approve(
                        "mint_credential",
                        args,
                        f"mint {owner} credential with {', '.join(scopes)} for {dep.target}",
                        "write access to the repository",
                    )
                    if not ok:
                        dep.status = "escalated"
                        self.open_items.append(f"{dep.target}: approver denied {', '.join(scopes)}; left on the leaver's credential")
                        yield self._log("escalate", f"Safe stop for {dep.target}: approval denied, keeping it working on the leaver's credential and escalating.", dep=dep, level="wait")
                        yield from self._rollback(dep)
                        return
                dep.status = "rehome_requested"
                m = yield from self._call("mint_credential", args, dep)
                if not m.ok:
                    dep.status = "escalated"
                    self.open_items.append(f"{dep.target}: could not mint credential ({m.error})")
                    return
                new = m.data["credential_id"]
                rb = yield from self._call("rebind_secret", {"target": dep.target, "secret_name": dep.secret_name, "credential_id": new}, dep)
                if not rb.ok:
                    dep.status = "escalated"
                    self.open_items.append(f"{dep.target}: rebind failed ({rb.error})")
                    return
                if dep.new_credential and dep.new_credential != new:
                    yield from self._call("revoke_credential", {"credential_id": dep.new_credential}, dep)
                dep.new_credential = new
                dep.status = "rehome_executed"
            c = yield from self._call("run_canary", {"target": dep.target}, dep)
            ok, why = self._verdict(c, dep)
            if ok:
                dep.status = "verified"
                dep.canary_before = "pass"
                yield self._log("verify", f"{dep.target} verified on {dep.new_credential}: canary passed and used only the new credential.", dep=dep, level="good")
                return
            dep.canary_before = "FAIL"
            dep.attempts += 1
            if dep.attempts > self.max_retries:
                dep.status = "escalated"
                self.open_items.append(f"{dep.target}: still failing after {self.max_retries} recoveries ({why})")
                yield self._log("escalate", f"R3: retry limit reached for {dep.target}; escalating to a human.", decided_by="guard", dep=dep, level="bad")
                yield from self._rollback(dep)
                return
            ctx = {
                "kind": "canary",
                "target": dep.target,
                "action_taken": f"rebound {dep.secret_name} to {dep.new_credential} with scopes {scopes}, ran canary",
                "error_code": c.error_code if not c.ok else "wrong_credential",
                "error": why,
                "current_scopes": scopes,
            }
            diag, by = self._diagnose(ctx, CANARY_ACTIONS)
            action = diag["action"]
            yield self._log("diagnose", f"Cause: {diag.get('cause', '?')} → next: {action['tool']} {action.get('args') or ''}", decided_by=by, dep=dep, output=diag, level="info")
            if action["tool"] == "mint_credential":
                justified = scopes_named_in(why)
                dep.allowed_scopes = sorted(set(dep.allowed_scopes) | justified)
                requested = sorted(set(action["args"].get("scopes") or []) | set(scopes))
                extra = set(requested) - set(dep.allowed_scopes)
                if extra:
                    yield self._log("block", f"Policy guard blocked over-broad request {sorted(extra)} (R4 least privilege); using only {dep.allowed_scopes}.", decided_by="guard", dep=dep, level="block")
                    requested = sorted(set(scopes) | justified)
                    self.guard.blocks += 1
                if set(requested) == set(scopes):
                    dep.status = "escalated"
                    self.open_items.append(f"{dep.target}: no justified fix for {c.error_code}")
                    yield self._log("escalate", f"No justified scope change fixes {dep.target}; escalating.", dep=dep, level="bad")
                    yield from self._rollback(dep)
                    return
                self.recoveries.append({"target": dep.target, "failure": why.splitlines()[-1] if why else "", "diagnosis": diag.get("cause", ""), "fix": f"re-mint with {', '.join(requested)}", "by": by})
                scopes = requested
                remint = True
            elif action["tool"] == "retry_canary":
                self.recoveries.append({"target": dep.target, "failure": why.splitlines()[-1] if why else "", "diagnosis": diag.get("cause", ""), "fix": "retry canary", "by": by})
                remint = False
            else:
                dep.status = "escalated"
                self.open_items.append(f"{dep.target}: {action['args'].get('reason') or diag.get('cause')}")
                yield self._log("escalate", f"Escalating {dep.target} to a human.", dep=dep, level="bad")
                yield from self._rollback(dep)
                return

    def _rollback(self, dep: Dependency) -> Generator[Event, object, None]:
        """Safe stop: put the automation back on the credential it worked with, retire our replacement."""
        if not dep.new_credential:
            return
        rb = yield from self._call("rebind_secret", {"target": dep.target, "secret_name": dep.secret_name, "credential_id": dep.credential_ref}, None)
        if rb.ok:
            yield from self._call("revoke_credential", {"credential_id": dep.new_credential}, None)
            yield self._log("escalate", f"Rolled {dep.target} back to {dep.credential_ref} so it keeps working until a human decides.", dep=dep, level="wait")
            dep.new_credential = None

    def _verdict(self, res: ToolResult, dep: Dependency) -> tuple[bool, str]:
        if not res.ok:
            return False, res.error or "canary failed"
        used = set(res.data.get("credentials_used", []))
        leftover = used & set(self.leaver_credential_ids)
        if leftover:
            return False, f"canary passed but still used the leaver credential {sorted(leftover)}"
        return True, "ok"

    # --------------------------------------------------------- membership
    def _remove_membership(self) -> Generator[Event, object, None]:
        user = self.employee
        args = {"org": self.org, "user": user}
        held = [c for c in self.leaver_credential_ids if c not in self.revoked]
        if held:
            self.open_items.append(f"{user} kept in {self.org}: removal would break automations still on {held}")
            yield self._log("escalate", f"Not removing {user} from {self.org}: credentials {held} are still in use (R7). Login will be suspended instead.", level="wait")
            return
        ok = yield from self._approve("remove_member", args, f"remove {user} from org {self.org}", "irreversible loss of org access")
        if not ok:
            self.open_items.append(f"Approver declined removing {user} from {self.org}")
            return
        r = yield from self._call("remove_member", args)
        attempts = 0
        while not r.ok and attempts < self.max_retries:
            attempts += 1
            ctx = {"kind": "membership", "action_taken": f"remove {user} from {self.org}", "error_code": r.error_code, "error": r.error, "successor": self.request.successor if self.request else None}
            diag, by = self._diagnose(ctx, MEMBERSHIP_ACTIONS)
            action = diag["action"]
            yield self._log("diagnose", f"Cause: {diag.get('cause', '?')} → next: {action['tool']} {action.get('args') or ''}", decided_by=by, output=diag)
            if action["tool"] != "assign_role":
                break
            a_args = {"org": self.org, "user": action["args"].get("user"), "role": action["args"].get("role", "owner")}
            if a_args["user"] != (self.request.successor if self.request else None):
                yield self._log("block", f"Policy guard: proposed user {a_args['user']!r} is not the HR-named successor.", decided_by="guard", level="block")
                break
            ok = yield from self._approve("assign_role", a_args, f"promote {a_args['user']} to {a_args['role']} of {self.org}", "grants org ownership")
            if not ok:
                break
            ar = yield from self._call("assign_role", a_args)
            if not ar.ok:
                break
            check = yield from self._call("inventory_identity", {"user": a_args["user"]})
            if check.data.get("org_role") != a_args["role"]:
                yield self._log("escalate", "Role change did not take effect.", level="bad")
                break
            yield self._log("verify", f"Verified {a_args['user']} is now {a_args['role']}; retrying removal.", level="good")
            self.recoveries.append({"target": f"org:{self.org}", "failure": r.error, "diagnosis": diag.get("cause", ""), "fix": f"promoted {a_args['user']} to owner", "by": by})
            r = yield from self._call("remove_member", args)
        if not r.ok:
            self.open_items.append(f"{user} still in {self.org}: {r.error}")
            yield self._log("escalate", f"Could not remove {user} from {self.org}; escalating.", level="bad")

    # ------------------------------------------------------------ outputs
    def _describe(self, tool: str, args: dict, res: ToolResult) -> str:
        d = res.data
        if not res.ok:
            msg = (res.error or "").splitlines()[-1] if res.error else res.error_code
            return f"{tool} failed: {msg}"
        if tool == "read_hr_request":
            return f"Ingested HR request {d.get('request_id')}: offboard {d.get('employee')} (last day {d.get('last_day')}, approver {d.get('approver')}, successor {d.get('successor')})"
        if tool == "inventory_identity":
            toks = ", ".join(f"{t['id']} [{t['status']}]" for t in d.get("tokens", []))
            return f"{d.get('user')}: org role {d.get('org_role')}, login {d.get('login')}, credentials: {toks or 'none'}"
        if tool == "read_audit_log":
            uses = d.get("uses", [])
            return f"{d.get('credential_id')}: {sum(u['count'] for u in uses)} uses in {d.get('days')} days by {[u['client'] for u in uses] or 'nobody'}"
        if tool == "scan_artifacts":
            return f"Scanned {len(d.get('files', []))} files; automation targets: {[t['target'] for t in d.get('targets', [])]}"
        if tool == "mint_credential":
            return f"Minted {d['credential_id']} for {d['owner']} with scopes {d['scopes']}"
        if tool == "rebind_secret":
            return f"{d['target']}: secret {d['secret_name']} now uses {d['credential_id']} (was {d['previous_credential_id']})"
        if tool == "run_canary":
            return f"Canary {args['target']} passed using {d.get('credentials_used')}"
        if tool == "revoke_credential":
            return f"Revoked {d['credential_id']}"
        if tool == "assign_role":
            return f"{d['user']} is now {d['role_now']} of {d['org']}"
        if tool == "remove_member":
            return f"Removed {d['user']} from {d['org']}"
        if tool == "suspend_login":
            return f"Suspended interactive login for {d['user']} (account kept, never deleted)"
        if tool == "probe_access":
            paths = d.get("paths", [])
            return "Residual-access probe: clean, 0 paths" if not paths else f"Residual-access probe: {len(paths)} path(s): {paths}"
        return tool

    @staticmethod
    def _summarise(tool: str, res: ToolResult) -> dict:
        if tool == "scan_artifacts":
            return {"files": [f["file"] for f in res.data.get("files", [])], "targets": [t["target"] for t in res.data.get("targets", [])]}
        out = dict(res.data)
        if res.error:
            out["error"] = res.error
        return out

    def metrics(self) -> dict:
        privileged_calls = [e for e in self.ledger if e.tool in PRIVILEGED_TOOLS and e.phase == "act"]
        unapproved = sum(1 for e in privileged_calls if approval_key(e.tool, e.input) not in self.approved)
        return {
            "status": self.status,
            "dependencies": len(self.deps),
            "verified": sum(1 for d in self.deps if d.status in ("verified", "revoked", "probe_clean")),
            "recoveries": len(self.recoveries),
            "guard_blocks": self.guard.blocks,
            "approvals": len(self.approvals_log),
            "unapproved_privileged_actions": unapproved,
            "residual_access_paths": len(self.probe_paths),
            "open_items": len(self.open_items),
            "duration_s": round((self.finished or time.time()) - self.started, 1),
        }

    def _finish(self) -> dict:
        from .report import build_report

        self.finished = time.time()
        summary = {"metrics": self.metrics(), "report": build_report(self)}
        if self.run_dir:
            self.run_dir.mkdir(parents=True, exist_ok=True)
            (self.run_dir / "ledger.jsonl").write_text("\n".join(json.dumps(e.to_dict()) for e in self.ledger) + "\n", encoding="utf-8")
            (self.run_dir / "report.md").write_text(summary["report"], encoding="utf-8")
            summary["run_dir"] = str(self.run_dir)
        return summary


def drive(agent: HandoffGuard, approver: Callable[[ApprovalRequest], str], on_event: Optional[Callable[[LedgerEntry], None]] = None) -> dict:
    """Run the agent to completion, answering approvals with `approver`."""
    gen = agent.run()
    value = None
    try:
        while True:
            event = gen.send(value)
            if isinstance(event, ApprovalRequest):
                value = approver(event)
            else:
                value = None
                if on_event:
                    on_event(event)
    except StopIteration as stop:
        return stop.value


def auto_approver(policy: str) -> Callable[[ApprovalRequest], str]:
    """approve_all | deny_write | deny_all"""

    def decide(req: ApprovalRequest) -> str:
        if policy == "deny_all":
            return "denied"
        if policy == "deny_write" and req.action == "mint_credential" and set(req.args.get("scopes", [])) & WRITE_SCOPES:
            return "denied"
        return "approved"

    return decide
