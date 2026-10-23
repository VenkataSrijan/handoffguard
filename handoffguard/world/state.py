"""In-memory state of the simulated organisation.

Holds org membership, logins, credentials, the secret stores of every
automation target, and the token-use audit log. The git service calls
`authorize`, so every 401/403 in the demo comes from this logic.
"""
from __future__ import annotations

import datetime as dt
import secrets as _secrets
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Token:
    id: str
    value: str
    owner: str
    owner_type: str  # user | service
    scopes: set[str]
    status: str = "active"  # active | revoked
    created: str = ""
    note: str = ""


@dataclass
class TargetSpec:
    """One automation target: a CI pipeline or a cron job on a host."""

    name: str  # pipeline:deploy | cron:backup
    kind: str  # pipeline | cron_job
    file: str  # file that defines it, relative to the repo
    client_id: str  # what the git service sees as User-Agent
    secrets: dict[str, str] = field(default_factory=dict)  # secret NAME -> token VALUE
    command: str = ""  # cron only
    host: str = "ci"


class World:
    def __init__(self, scenario: str, org: str, repo: str, repo_dir: Path, hr_path: Path, faults: dict):
        self.lock = threading.RLock()
        self.scenario = scenario
        self.org = org
        self.repo = repo
        self.repo_dir = Path(repo_dir)
        self.hr_path = Path(hr_path)
        self.faults = dict(faults)
        self.members: dict[str, str] = {}  # user -> owner | member
        self.logins: dict[str, str] = {}  # user -> active | suspended
        self.tokens: dict[str, Token] = {}
        self.targets: dict[str, TargetSpec] = {}
        self.audit: list[dict] = []
        self.flaky_spent: set[str] = set()
        self._svc_counter = 0

    # ----- credentials -------------------------------------------------
    def add_token(self, token_id: str, owner: str, owner_type: str, scopes, created: str = "", note: str = "") -> Token:
        value = f"ghp_{_secrets.token_hex(12)}"
        tok = Token(token_id, value, owner, owner_type, set(scopes), "active", created or dt.date.today().isoformat(), note)
        with self.lock:
            self.tokens[token_id] = tok
        return tok

    def next_service_token_id(self, owner: str) -> str:
        with self.lock:
            self._svc_counter += 1
            return f"tok-{owner}-{self._svc_counter}"

    def token_by_value(self, value: str) -> Optional[Token]:
        with self.lock:
            for tok in self.tokens.values():
                if tok.value == value:
                    return tok
        return None

    def token_id_for_value(self, value: str) -> Optional[str]:
        tok = self.token_by_value(value)
        return tok.id if tok else None

    # ----- auth, as enforced by the git service ------------------------
    def authorize(self, value: str, need: str, step: str, repo: str, client: str) -> tuple[int, str]:
        with self.lock:
            tok = self.token_by_value(value) if value else None
            if tok is None:
                code, msg = 401, "remote: Invalid username or token. 401: bad credentials"
            elif tok.status != "active":
                code, msg = 401, "remote: Invalid username or token. 401: credential revoked or expired"
            elif tok.owner_type == "user" and tok.owner not in self.members:
                code, msg = 403, (
                    f"remote: Permission to {repo}.git denied. 403: token owner '{tok.owner}' "
                    f"is no longer a member of organization '{self.org}' (step: {step})"
                )
            elif need not in tok.scopes:
                code, msg = 403, f"remote: Permission to {repo}.git denied. 403: token lacks scope {need} (step: {step})"
            else:
                code, msg = 200, f"{step}: ok"
            self.audit.append(
                {
                    "ts": dt.datetime.now().isoformat(timespec="seconds"),
                    "credential_id": tok.id if tok else None,
                    "client": client,
                    "action": step,
                    "status": code,
                }
            )
            return code, msg
