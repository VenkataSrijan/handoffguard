"""Runs an automation target for real: a CI workflow or a cron job.

Secrets are resolved from the target's secret store, `.env` alias chains are
expanded the way a shell would, and every step is executed as a subprocess
that calls the local git service. The audit log entries written during the
run tell us which credential the target actually used.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import yaml

from .state import World

_SECRET_REF = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")
_VAR_REF = re.compile(r"\$\{([A-Za-z0-9_]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
TIMEOUT_S = 10


def parse_dotenv(path: Path, base: dict[str, str]) -> dict[str, str]:
    """Expand KEY=VALUE lines in order; ${VAR} resolves from base, then earlier lines."""
    resolved: dict[str, str] = {}
    if not path.exists():
        return resolved
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.split(" #")[0].strip().strip('"').strip("'")

        def _sub(m: re.Match) -> str:
            name = m.group(1) or m.group(2)
            return resolved.get(name, base.get(name, ""))

        resolved[key.strip()] = _VAR_REF.sub(_sub, value)
    return resolved


def parse_crontab(path: Path) -> list[dict]:
    jobs = []
    if not path.exists():
        return jobs
    for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(None, 5)
        if len(fields) < 6:
            continue
        command = fields[5].split(" #")[0].strip()
        if "&&" in command:
            command = command.split("&&")[-1].strip()
        script = next((tok for tok in shlex.split(command) if tok.endswith(".py")), command)
        jobs.append({"line": lineno, "schedule": " ".join(fields[:5]), "command": command, "script": script})
    return jobs


def _workflow_steps(world: World, spec) -> tuple[dict[str, str], list[tuple[str, str]]]:
    data = yaml.safe_load((world.repo_dir / spec.file).read_text()) or {}
    job = next(iter((data.get("jobs") or {}).values()))
    env = {}
    for key, value in (job.get("env") or {}).items():
        env[key] = _SECRET_REF.sub(lambda m: spec.secrets.get(m.group(1), ""), str(value))
    steps = [(s.get("name", "step"), s["run"]) for s in job.get("steps", []) if "run" in s]
    return env, steps


def _cron_steps(world: World, spec) -> tuple[dict[str, str], list[tuple[str, str]]]:
    host_env = dict(spec.secrets)  # host-level secrets are exported as env vars
    env = {**host_env, **parse_dotenv(world.repo_dir / ".env", host_env)}
    return env, [("cron", spec.command)]


def _argv(command: str) -> list[str]:
    parts = shlex.split(command)
    if parts and parts[0] in ("python", "python3"):
        parts[0] = sys.executable
    return parts


def run_target(world: World, target: str, base_url: str) -> dict:
    spec = world.targets[target]
    if world.faults.get("flaky") and target not in world.flaky_spent:
        world.flaky_spent.add(target)
        return {
            "passed": False,
            "error_code": "timeout",
            "log_tail": f"canary timed out after {TIMEOUT_S}s (runner busy)",
            "credentials_used": [],
        }
    env_extra, steps = (_workflow_steps if spec.kind == "pipeline" else _cron_steps)(world, spec)
    env = {k: v for k, v in os.environ.items()}
    env.update(env_extra)
    env.update({"GIT_URL": base_url, "CLIENT_ID": spec.client_id, "REPO": env_extra.get("REPO", world.repo)})
    start = len(world.audit)
    log: list[str] = []
    passed, error_code = True, None
    for name, command in steps:
        try:
            proc = subprocess.run(
                _argv(command), cwd=world.repo_dir, env=env, capture_output=True, text=True, timeout=TIMEOUT_S
            )
        except subprocess.TimeoutExpired:
            passed, error_code = False, "timeout"
            log.append(f"[{name}] timed out after {TIMEOUT_S}s")
            break
        out = (proc.stdout + proc.stderr).strip()
        log.append(f"[{name}] {out}" if out else f"[{name}] exit {proc.returncode}")
        if proc.returncode != 0:
            passed = False
            error_code = "http_403" if "403" in out else "http_401" if "401" in out else "script_error"
            break
    with world.lock:
        used = sorted({e["credential_id"] for e in world.audit[start:] if e["client"] == spec.client_id and e["credential_id"]})
    return {
        "passed": passed,
        "error_code": error_code,
        "log_tail": "\n".join(log[-4:]),
        "credentials_used": used,
    }
