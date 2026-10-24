"""The 14 tools the agent can call. Each wraps the simulated org and returns a ToolResult.

Interfaces mirror real admin APIs (GitHub org/members/tokens/secrets, CI runs,
an identity provider's login suspension) so real connectors can replace the
world later without touching the agent. There is deliberately no delete tool.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from .contracts import ALL_SCOPES, ToolResult
from .world.ci_runner import run_target
from .world.state import World

TEXT_SUFFIXES = {".yml", ".yaml", ".py", ".md", ".sh", ".txt", ".env", ""}


class Tools:
    def __init__(self, world: World, base_url: str):
        self.world = world
        self.base_url = base_url

    # ---------------------------------------------------------------- read
    def read_hr_request(self, path: str) -> ToolResult:
        p = Path(path)
        if not p.exists():
            return ToolResult(False, error=f"HR request not found: {path}", error_code="not_found")
        return ToolResult(True, json.loads(p.read_text(encoding="utf-8")))

    def scan_artifacts(self) -> ToolResult:
        files = []
        for p in sorted(self.world.repo_dir.rglob("*")):
            if not p.is_file() or (p.suffix not in TEXT_SUFFIXES and p.name not in (".env", "crontab")):
                continue
            rel = p.relative_to(self.world.repo_dir).as_posix()
            numbered = "\n".join(f"{i:>3}: {line}" for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1))
            files.append({"file": rel, "text": numbered})
        targets = [
            {
                "target": t.name,
                "kind": t.kind,
                "defined_in": t.file,
                "runs_on": t.host,
                "repo": self.world.repo,
                "secret_names": sorted(t.secrets),  # names are listable, values are not
                "command": t.command or None,
            }
            for t in self.world.targets.values()
        ]
        return ToolResult(True, {"files": files, "targets": targets})

    def inventory_identity(self, user: str) -> ToolResult:
        w = self.world
        known = user in w.members or any(t.owner == user for t in w.tokens.values())
        if not known:
            return ToolResult(False, error=f"unknown user {user}", error_code="unknown_user")
        tokens = [
            {"id": t.id, "scopes": sorted(t.scopes), "status": t.status, "created": t.created, "note": t.note}
            for t in w.tokens.values()
            if t.owner == user
        ]
        return ToolResult(
            True,
            {"user": user, "org": w.org, "org_role": w.members.get(user, "none"), "login": w.logins.get(user, "none"), "tokens": tokens},
        )

    def read_audit_log(self, credential_id: str, days: int = 14) -> ToolResult:
        grouped: dict[str, dict] = defaultdict(lambda: {"count": 0, "last_seen": "", "actions": set()})
        with self.world.lock:
            for e in self.world.audit:
                if e["credential_id"] != credential_id:
                    continue
                g = grouped[e["client"]]
                g["count"] += 1
                g["last_seen"] = max(g["last_seen"], e["ts"])
                g["actions"].add(e["action"])
        uses = [
            {"client": c, "count": g["count"], "last_seen": g["last_seen"], "actions": sorted(g["actions"])}
            for c, g in sorted(grouped.items())
        ]
        return ToolResult(True, {"credential_id": credential_id, "days": days, "uses": uses})

    def run_canary(self, target: str) -> ToolResult:
        if target not in self.world.targets:
            return ToolResult(False, error=f"unknown target {target}", error_code="target_not_found")
        out = run_target(self.world, target, self.base_url)
        if out["passed"]:
            return ToolResult(True, out)
        return ToolResult(False, out, error=out["log_tail"], error_code=out["error_code"])

    def probe_access(self, user: str) -> ToolResult:
        w = self.world
        paths = []
        if user in w.members:
            paths.append(f"org membership: {w.org} ({w.members[user]})")
        if w.logins.get(user) == "active":
            paths.append("interactive login: active")
        for t in w.tokens.values():
            if t.owner == user and t.status == "active":
                where = [s.name for s in w.targets.values() if t.value in s.secrets.values()]
                paths.append(f"credential {t.id} active" + (f" (bound in {', '.join(where)})" if where else ""))
        return ToolResult(True, {"user": user, "paths": paths})

    # --------------------------------------------------------------- write
    def mint_credential(self, owner: str, scopes: list[str], repo: str) -> ToolResult:
        bad = set(scopes) - ALL_SCOPES
        if bad:
            return ToolResult(False, error=f"scopes not allowed: {sorted(bad)}", error_code="scope_not_allowed")
        tid = self.world.next_service_token_id(owner)
        self.world.add_token(tid, owner, "service", scopes, note=f"service credential for {repo}")
        return ToolResult(True, {"credential_id": tid, "owner": owner, "scopes": sorted(scopes)})

    def rebind_secret(self, target: str, secret_name: str, credential_id: str) -> ToolResult:
        w = self.world
        spec = w.targets.get(target)
        if spec is None:
            return ToolResult(False, error=f"unknown target {target}", error_code="target_not_found")
        if secret_name not in spec.secrets:
            return ToolResult(
                False,
                error=f"{target} has no secret {secret_name}; available: {sorted(spec.secrets)}",
                error_code="secret_not_found",
            )
        tok = w.tokens.get(credential_id)
        if tok is None or tok.status != "active":
            return ToolResult(False, error=f"credential {credential_id} not active", error_code="credential_not_active")
        with w.lock:
            previous = w.token_id_for_value(spec.secrets[secret_name])
            spec.secrets[secret_name] = tok.value
        return ToolResult(True, {"target": target, "secret_name": secret_name, "previous_credential_id": previous, "credential_id": credential_id})

    def revoke_credential(self, credential_id: str) -> ToolResult:
        tok = self.world.tokens.get(credential_id)
        if tok is None:
            return ToolResult(False, error=f"unknown credential {credential_id}", error_code="not_found")
        if tok.status == "revoked":
            return ToolResult(False, error=f"{credential_id} already revoked", error_code="already_revoked")
        tok.status = "revoked"
        return ToolResult(True, {"credential_id": credential_id, "status": "revoked"})

    def suspend_credential(self, credential_id: str) -> ToolResult:
        """Reversible: the credential stops authenticating but can be reactivated (disable-before-delete)."""
        tok = self.world.tokens.get(credential_id)
        if tok is None:
            return ToolResult(False, error=f"unknown credential {credential_id}", error_code="not_found")
        if tok.status != "active":
            return ToolResult(False, error=f"{credential_id} is {tok.status}", error_code="not_active")
        tok.status = "suspended"
        return ToolResult(True, {"credential_id": credential_id, "status": "suspended"})

    def reactivate_credential(self, credential_id: str) -> ToolResult:
        tok = self.world.tokens.get(credential_id)
        if tok is None:
            return ToolResult(False, error=f"unknown credential {credential_id}", error_code="not_found")
        if tok.status != "suspended":
            return ToolResult(False, error=f"{credential_id} is {tok.status}, not suspended", error_code="not_suspended")
        tok.status = "active"
        return ToolResult(True, {"credential_id": credential_id, "status": "active"})

    def assign_role(self, org: str, user: str, role: str) -> ToolResult:
        w = self.world
        if user not in w.members:
            return ToolResult(False, error=f"{user} is not a member of {org}", error_code="user_not_member")
        w.members[user] = role
        return ToolResult(True, {"org": org, "user": user, "role_now": role})

    def remove_member(self, org: str, user: str) -> ToolResult:
        w = self.world
        if user not in w.members:
            return ToolResult(False, error=f"{user} is not a member of {org}", error_code="not_member")
        owners = [u for u, r in w.members.items() if r == "owner"]
        if w.members[user] == "owner" and len(owners) == 1:
            return ToolResult(
                False,
                error="422: Organization must have at least one owner. Promote another member before removing this one.",
                error_code="last_owner",
            )
        del w.members[user]
        return ToolResult(True, {"org": org, "user": user, "removed": True})

    def suspend_login(self, user: str) -> ToolResult:
        if user not in self.world.logins:
            return ToolResult(False, error=f"unknown user {user}", error_code="unknown_user")
        self.world.logins[user] = "suspended"
        return ToolResult(True, {"user": user, "login": "suspended"})
