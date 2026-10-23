"""Shared data contracts for HandoffGuard.

Every module talks through these shapes: the HR request that starts a run,
the dependency items the agent works on, the ledger entries it writes, the
tool result envelope, and the approval requests it raises for a human.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

TOOL_NAMES = (
    "read_hr_request",
    "scan_artifacts",
    "inventory_identity",
    "read_audit_log",
    "mint_credential",
    "rebind_secret",
    "run_canary",
    "assign_role",
    "remove_member",
    "revoke_credential",
    "suspend_login",
    "probe_access",
)
READ_TOOLS = {
    "read_hr_request",
    "scan_artifacts",
    "inventory_identity",
    "read_audit_log",
    "run_canary",
    "probe_access",
}
# Tools that always need an explicit human approval before they run.
PRIVILEGED_TOOLS = {"assign_role", "remove_member"}
# Scopes that make a minted credential "write" and therefore approval-gated.
WRITE_SCOPES = {"contents:write", "admin:org"}
ALL_SCOPES = {"repo:read", "contents:write", "admin:org"}
DEFAULT_SCOPES = ["repo:read"]  # least privilege: start read-only, expand on evidence


def now_iso() -> str:
    return _dt.datetime.now().isoformat(timespec="seconds")


@dataclass
class HRRequest:
    """Offboarding request as it arrives from the HR system (data ingestion)."""

    request_id: str
    employee: str
    last_day: str
    reason: str
    approver: str
    successor: Optional[str] = None
    systems_hint: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HRRequest":
        known = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**known)


@dataclass
class ToolResult:
    """Envelope every tool returns. The LLM reads `error`; code reads `error_code`."""

    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    error_code: Optional[str] = None


@dataclass
class Dependency:
    """One automation that relies on the leaver's credentials."""

    dep_id: str
    kind: str  # pipeline | cron_job
    target: str  # e.g. pipeline:deploy, cron:backup
    secret_name: str
    credential_ref: str  # leaver credential id it currently uses
    evidence: list[str] = field(default_factory=list)
    found_by: str = "rules"  # llm | rules | llm+rules
    confidence: str = "high"
    explains_clients: list[str] = field(default_factory=list)
    status: str = "discovered"
    # discovered -> rehome_requested -> rehome_executed -> verified -> revoked -> probe_clean | escalated
    new_credential: Optional[str] = None
    attempts: int = 0
    allowed_scopes: list[str] = field(default_factory=lambda: list(DEFAULT_SCOPES))
    canary_before: str = "-"
    canary_after: str = "-"

    def row(self) -> dict[str, Any]:
        return {
            "dependency": self.target,
            "found by": self.found_by,
            "uses": f"{self.secret_name} → {self.credential_ref}",
            "new credential": self.new_credential or "-",
            "scopes": ", ".join(self.allowed_scopes),
            "canary before revoke": self.canary_before,
            "canary after revoke": self.canary_after,
            "status": self.status,
        }


@dataclass
class LedgerEntry:
    step: int
    phase: str  # plan | act | observe | diagnose | approval | verify | block | escalate | report
    rationale: str
    decided_by: str = "agent"  # agent | llm | rules | guard | human
    tool: Optional[str] = None
    dep_id: Optional[str] = None
    input: dict[str, Any] = field(default_factory=dict)
    output: dict[str, Any] = field(default_factory=dict)
    level: str = "info"  # info | good | bad | wait | block
    ts: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ApprovalRequest:
    """Yielded by the agent when a human must decide. Send back 'approved' or 'denied'."""

    approval_id: str
    action: str
    args: dict[str, Any]
    reason: str
    risk: str
