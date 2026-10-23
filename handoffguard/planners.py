"""Planners: the LLM does discovery and diagnosis; the rules planner is the offline fallback.

Both expose the same two methods:
  discover(context)          -> {"dependencies": [...], "unexplained_audit_clients": [...], "summary": str}
  diagnose(context, allowed) -> {"cause": str, "action": {"tool": str, "args": dict}}

The rules planner is deliberately checklist-grade: it only sees secrets that
are named directly in CI workflow files. It cannot follow alias chains, which
is exactly the gap the LLM closes.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Optional

SCOPE_IN_ERROR = re.compile(r"lacks scope ([a-z]+:[a-z]+)")


def scopes_named_in(text: str) -> set[str]:
    return set(SCOPE_IN_ERROR.findall(text or ""))


# ---------------------------------------------------------------------------
# Rules planner
# ---------------------------------------------------------------------------
class RulesPlanner:
    name = "rules"
    label = "Rules only (checklist-grade)"

    def discover(self, ctx: dict) -> dict:
        employee = ctx["employee"].upper()
        creds = ctx["credentials"]
        used = [c["id"] for c in creds if ctx["uses"].get(c["id"])]
        default_cred = used[0] if used else (creds[0]["id"] if creds else None)
        deps = []
        for f in ctx["files"]:
            if not f["file"].startswith(".github/workflows/"):
                continue
            stem = f["file"].rsplit("/", 1)[-1].rsplit(".", 1)[0]
            for line in f["text"].splitlines():
                for name in re.findall(r"secrets\.([A-Za-z0-9_]+)", line):
                    if employee in name.upper():
                        deps.append(
                            {
                                "target": f"pipeline:{stem}",
                                "kind": "pipeline",
                                "secret_name": name,
                                "credential_id": default_cred,
                                "evidence": [f"{f['file']}:{line.strip()}"],
                                "explains_audit_clients": [f"ci:{f['file']}"],
                                "confidence": "high",
                            }
                        )
        return {"dependencies": deps, "unexplained_audit_clients": [], "summary": f"{len(deps)} direct secret reference(s) in CI workflows"}

    def diagnose(self, ctx: dict, allowed: list[dict]) -> dict:
        code = ctx.get("error_code")
        error = ctx.get("error", "")
        if ctx.get("kind") == "membership":
            if code == "last_owner" and ctx.get("successor"):
                return {
                    "cause": "The leaver is the organisation's last owner, so the platform blocks removal.",
                    "action": {"tool": "assign_role", "args": {"user": ctx["successor"], "role": "owner"}},
                }
            return {"cause": f"Membership change failed ({code}).", "action": {"tool": "escalate", "args": {"reason": error}}}
        if code == "http_403" and scopes_named_in(error):
            needed = sorted(set(ctx.get("current_scopes", [])) | scopes_named_in(error))
            return {
                "cause": f"Replacement credential lacks {', '.join(sorted(scopes_named_in(error)))}; the old token only worked because it inherited the leaver's rights.",
                "action": {"tool": "mint_credential", "args": {"scopes": needed}},
            }
        if code == "timeout":
            return {"cause": "Runner timed out; likely transient.", "action": {"tool": "retry_canary", "args": {}}}
        return {"cause": f"Unrecognised failure ({code}).", "action": {"tool": "escalate", "args": {"reason": error[:200]}}}


# ---------------------------------------------------------------------------
# LLM planner (OpenAI-compatible: Groq or Gemini)
# ---------------------------------------------------------------------------
DISCOVERY_SYSTEM = """You are the dependency-discovery step of HandoffGuard, an IT infrastructure agent that offboards employees safely.
An employee is leaving. Find EVERY automation target that will break if the employee's credentials are revoked.

How credentials hide:
- directly, e.g. ${{ secrets.NAME }} in a CI workflow;
- indirectly, through alias chains: a variable set from another variable (e.g. A=${NAME}, B=${A}) in .env files, then read by a script that a cron job runs.
Follow every alias chain across files until you reach the script that uses it and the job that runs that script.

Use the audit log as ground truth: every client that used a leaver credential must be explained by one dependency (put that client string in explains_audit_clients). CI clients look like "ci:<workflow path>". If you cannot explain a client, list it in unexplained_audit_clients.

Hard rules:
- target MUST be one of the provided targets; secret_name MUST be one of that target's secret_names; credential_id MUST be one of the leaver's credentials.
- evidence items quote "file:line: text" exactly as shown. Never invent files, lines or targets.
- Return JSON only, no prose, in this shape:
{"dependencies":[{"target":"...","kind":"pipeline|cron_job","secret_name":"...","credential_id":"...","evidence":["..."],"explains_audit_clients":["..."],"confidence":"high|low"}],"unexplained_audit_clients":[],"summary":"one sentence"}"""

DIAGNOSIS_SYSTEM = """You are the diagnosis step of HandoffGuard, an IT infrastructure agent that offboards employees safely.
An action failed. Read the error, state the cause in one sentence, and choose exactly ONE next action from the allowed actions.

Rules:
- Prefer the smallest permission that fixes the problem. Only request scopes the error text justifies.
- If the failure looks transient (timeout), retry.
- If fixing it needs a decision only a human can make, or you are unsure, choose escalate.
- Return JSON only, no prose: {"cause":"...","action":{"tool":"...","args":{...}}}"""


def _extract_json(text: str) -> dict:
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?|```$", "", text).strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError(f"no JSON object in model output: {text[:120]!r}")
    return json.loads(text[start : end + 1])


PROVIDERS = {
    "groq": {"base_url": "https://api.groq.com/openai/v1", "key_env": "GROQ_API_KEY", "model_env": "HG_GROQ_MODEL", "model": "openai/gpt-oss-120b"},
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "key_env": "GEMINI_API_KEY",
        "model_env": "HG_GEMINI_MODEL",
        "model": "gemini-2.5-flash",
    },
}


class LLMPlanner:
    name = "llm"

    def __init__(self, provider: str, client: Any = None, model: Optional[str] = None):
        cfg = PROVIDERS[provider]
        self.provider = provider
        self.model = model or os.environ.get(cfg["model_env"]) or cfg["model"]
        if client is None:
            from openai import OpenAI

            client = OpenAI(api_key=os.environ[cfg["key_env"]], base_url=cfg["base_url"], timeout=45, max_retries=1)
        self.client = client
        self.low_effort = os.environ.get("HG_LOW_EFFORT", "1") == "1" and "gpt-oss" in self.model
        self.label = f"LLM · {provider} · {self.model}"

    def _ask(self, system: str, payload: dict) -> dict:
        kwargs = dict(
            model=self.model,
            temperature=0,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": json.dumps(payload, indent=1)}],
        )
        if self.low_effort:
            try:  # keeps reasoning models inside free-tier token-per-minute limits
                resp = self.client.chat.completions.create(reasoning_effort="low", **kwargs)
            except TypeError:
                self.low_effort = False
                resp = self.client.chat.completions.create(**kwargs)
            except Exception as exc:  # provider rejected the parameter
                if "reasoning" not in str(exc).lower():
                    raise
                self.low_effort = False
                resp = self.client.chat.completions.create(**kwargs)
        else:
            resp = self.client.chat.completions.create(**kwargs)
        return _extract_json(resp.choices[0].message.content)

    def discover(self, ctx: dict) -> dict:
        payload = {
            "employee": ctx["employee"],
            "leaver_credentials": ctx["credentials"],
            "audit_log_uses": ctx["uses"],
            "targets": ctx["targets"],
            "files": ctx["files"],
        }
        out = self._ask(DISCOVERY_SYSTEM, payload)
        out.setdefault("dependencies", [])
        out.setdefault("unexplained_audit_clients", [])
        return out

    def diagnose(self, ctx: dict, allowed: list[dict]) -> dict:
        return self._ask(DIAGNOSIS_SYSTEM, {"failure": ctx, "allowed_actions": allowed})


def load_dotenv(path) -> None:
    """Minimal .env loader (KEY=VALUE), so no extra dependency is needed."""
    from pathlib import Path

    p = Path(path)
    if not p.exists():
        return
    for raw in p.read_text().splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def available_providers() -> list[str]:
    return [p for p, cfg in PROVIDERS.items() if os.environ.get(cfg["key_env"])]


def make_planner(kind: str = "auto"):
    """kind: auto | llm | rules | groq | gemini. 'auto' uses an LLM if a key is set."""
    if kind == "rules":
        return RulesPlanner()
    if kind in PROVIDERS:
        return LLMPlanner(kind)
    preferred = os.environ.get("HG_LLM_PROVIDER")
    providers = available_providers()
    if preferred in providers:
        return LLMPlanner(preferred)
    if providers:
        return LLMPlanner(providers[0])
    if kind == "llm":
        raise RuntimeError("No LLM key found. Set GROQ_API_KEY or GEMINI_API_KEY in .env")
    return RulesPlanner()
