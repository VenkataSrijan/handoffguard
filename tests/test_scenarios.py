"""Scenario suite: 6 scenarios × (naive baseline, HandoffGuard), plus guard and LLM-path tests.

Runs offline. The LLM path is exercised with a scripted fake client that returns
what a model would, so the parsing, validation and guard logic are all tested.
"""
import json
from types import SimpleNamespace

import pytest

from handoffguard.agent import HandoffGuard, auto_approver, drive
from handoffguard.planners import LLMPlanner, RulesPlanner
from handoffguard.runner import evaluate, new_session, run_agent, run_baseline
from handoffguard.world import BENCHMARK_KEYS


class FakeClient:
    """Mimics openai.OpenAI().chat.completions.create with scripted replies."""

    def __init__(self, discovery: dict, diagnosis: dict | None = None):
        self.discovery, self.diagnosis = discovery, diagnosis
        self.calls = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, model, messages, temperature=0):
        system = messages[0]["content"]
        self.calls.append(system[:40])
        if "dependency-discovery" in system:
            body = self.discovery
        elif self.diagnosis is not None:
            body = self.diagnosis
        else:
            raise RuntimeError("no scripted diagnosis")  # forces rules fallback
        content = "```json\n" + json.dumps(body) + "\n```"
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


CRON_CLIENT = "python-urllib/3.11 (host ops-box-2)"
LLM_DISCOVERY = {
    "dependencies": [
        {
            "target": "pipeline:deploy",
            "kind": "pipeline",
            "secret_name": "RIYA_PAT",
            "credential_id": "tok-riya-pat",
            "evidence": [".github/workflows/deploy.yml:9: TOKEN: ${{ secrets.RIYA_PAT }}"],
            "explains_audit_clients": ["ci:.github/workflows/deploy.yml"],
            "confidence": "high",
        },
        {
            "target": "cron:backup",
            "kind": "cron_job",
            "secret_name": "RIYA_PAT",
            "credential_id": "tok-riya-pat",
            "evidence": [".env:3: DEPLOY_TOKEN=${RIYA_PAT}", ".env:4: GH_TOKEN=${DEPLOY_TOKEN}", "crontab:2: python scripts/backup.py"],
            "explains_audit_clients": [CRON_CLIENT],
            "confidence": "high",
        },
        {"target": "pipeline:made-up", "kind": "pipeline", "secret_name": "X", "credential_id": "tok-riya-pat", "evidence": []},
    ],
    "unexplained_audit_clients": [],
    "summary": "deploy uses RIYA_PAT directly; nightly backup uses it via DEPLOY_TOKEN → GH_TOKEN.",
}


@pytest.mark.parametrize("key", BENCHMARK_KEYS)
def test_baseline_breaks_something(key):
    _, tools = new_session(key)
    base = run_baseline(tools)
    ev = evaluate(tools, base["user"])
    assert len(ev["broken"]) >= 1, "the naive checklist should break at least one automation"


@pytest.mark.parametrize(
    "key,status,residual",
    [
        ("s1_single", "COMPLETE", 0),
        ("s2_shared", "COMPLETE", 0),
        ("s3_hidden_alias", "PARTIAL", 2),  # rules can't explain the cron use → safe hold
        ("s4_scope_403", "COMPLETE", 0),
        ("s5_last_owner", "COMPLETE", 0),
        ("s6_denied", "PARTIAL", 2),
    ],
)
def test_agent_rules_never_breaks_anything(key, status, residual):
    out = run_agent(key, RulesPlanner())
    m = out["agent"].metrics()
    assert out["eval"]["broken"] == []
    assert m["status"] == status
    assert len(out["eval"]["residual"]) == residual
    assert m["unapproved_privileged_actions"] == 0


def test_llm_finds_hidden_cron_and_completes():
    planner = LLMPlanner("groq", client=FakeClient(LLM_DISCOVERY), model="fake")
    out = run_agent("s3_hidden_alias", planner)
    agent = out["agent"]
    targets = {d.target: d for d in agent.deps}
    assert set(targets) == {"pipeline:deploy", "cron:backup"}
    assert "llm" in targets["cron:backup"].found_by
    assert any(e.phase == "block" and "made-up" in e.rationale for e in agent.ledger)  # invented target rejected
    assert agent.status == "COMPLETE"
    assert out["eval"] == {"broken": [], "residual": []}


def test_llm_overbroad_scope_is_blocked():
    greedy = {"cause": "needs more rights", "action": {"tool": "mint_credential", "args": {"scopes": ["repo:read", "contents:write", "admin:org"]}}}
    planner = LLMPlanner("groq", client=FakeClient(LLM_DISCOVERY, greedy), model="fake")
    out = run_agent("s4_scope_403", planner)
    agent = out["agent"]
    assert any(e.phase == "block" and "admin:org" in e.rationale for e in agent.ledger)
    dep = agent.deps[0]
    assert "admin:org" not in dep.allowed_scopes
    assert agent.status == "COMPLETE"


def test_llm_outage_falls_back_to_rules():
    class Down:
        chat = SimpleNamespace(completions=SimpleNamespace(create=lambda **kw: (_ for _ in ()).throw(RuntimeError("503"))))

    out = run_agent("s4_scope_403", LLMPlanner("groq", client=Down(), model="fake"))
    assert out["agent"].status == "COMPLETE"
    assert any("LLM discovery unavailable" in e.rationale for e in out["agent"].ledger)


def test_guard_blocks_early_revoke():
    world, tools = new_session("s1_single")
    agent = HandoffGuard(tools, RulesPlanner(), world.hr_path)
    agent.employee = "riya"
    agent.leaver_credential_ids = ["tok-riya-pat"]
    from handoffguard.contracts import Dependency

    agent.deps = [Dependency("dep-1", "pipeline", "pipeline:docs", "RIYA_PAT", "tok-riya-pat")]
    ok, reason = agent.guard.check("revoke_credential", {"credential_id": "tok-riya-pat"}, None)
    assert not ok and reason.startswith("R1")
    ok, reason = agent.guard.check("remove_member", {"org": "club", "user": "riya"}, None)
    assert not ok and reason.startswith("R2")


def test_flaky_canary_is_retried():
    out = run_agent("s1_single", RulesPlanner(), faults={"flaky": True})
    agent = out["agent"]
    assert agent.status == "COMPLETE"
    assert any(r["fix"] == "retry canary" for r in agent.recoveries)


def test_denial_rolls_back_and_keeps_pipeline_working():
    out = run_agent("s6_denied", RulesPlanner())
    assert out["eval"]["broken"] == []
    assert any("Rolled pipeline:deploy back" in e.rationale for e in out["agent"].ledger)


def test_report_is_written(tmp_path):
    world, tools = new_session("s4_scope_403")
    agent = HandoffGuard(tools, RulesPlanner(), world.hr_path, run_dir=tmp_path)
    summary = drive(agent, auto_approver("approve_all"))
    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "Offboarding report" in report and "COMPLETE" in report
    assert "ghp_" not in report  # token values never leak
    assert (tmp_path / "ledger.jsonl").exists()
    assert summary["metrics"]["status"] == "COMPLETE"


def test_demo_with_llm_completes_and_low_effort_fallback():
    # model name containing gpt-oss turns on reasoning_effort; FakeClient rejects that kwarg → automatic fallback
    planner = LLMPlanner("groq", client=FakeClient(LLM_DISCOVERY), model="openai/gpt-oss-120b")
    assert planner.low_effort
    out = run_agent("demo", planner)
    agent = out["agent"]
    assert {d.target for d in agent.deps} == {"pipeline:deploy", "pipeline:docs", "cron:backup"}
    assert agent.status == "COMPLETE"
    assert out["eval"] == {"broken": [], "residual": []}
    assert planner.low_effort is False


def test_brownout_catches_job_no_file_or_log_reveals():
    out = run_agent("s7_monthly_job", RulesPlanner())
    agent = out["agent"]
    release = next(d for d in agent.deps if d.target == "pipeline:release")
    assert release.found_by == "brownout"
    assert agent.status == "COMPLETE"
    assert out["eval"] == {"broken": [], "residual": []}
    # the credential was reactivated after the failed brownout, before anything was re-homed
    riya = [e.tool for e in agent.ledger if e.phase == "act" and e.input.get("credential_id") == "tok-riya-pat"]
    assert riya == ["suspend_credential", "reactivate_credential", "suspend_credential", "revoke_credential"]


def test_guard_requires_brownout_before_revoke():
    world, tools = new_session("s1_single")
    agent = HandoffGuard(tools, RulesPlanner(), world.hr_path)
    agent.employee, agent.leaver_credential_ids = "riya", ["tok-riya-pat"]
    ok, reason = agent.guard.check("revoke_credential", {"credential_id": "tok-riya-pat"}, None)
    assert not ok and "brownout" in reason


def test_ungrounded_llm_citations_are_rejected():
    fake = json.loads(json.dumps(LLM_DISCOVERY))
    cron = fake["dependencies"][1]
    cron["evidence"] = [".env:3: SOMETHING_THAT_IS_NOT_THERE=1", "scripts/backup.py:99: invented line"]
    out = run_agent("s3_hidden_alias", LLMPlanner("groq", client=FakeClient(fake), model="fake"))
    agent = out["agent"]
    assert "cron:backup" not in {d.target for d in agent.deps}
    assert any("Grounding check" in e.rationale for e in agent.ledger)
    assert agent.status == "PARTIAL"  # unexplained cron use keeps the token safely held
    assert out["eval"]["broken"] == []


def test_prompt_injection_cannot_widen_or_shrink_scope():
    obeying = {  # what a model that followed the README's hidden instructions would return
        "dependencies": [
            LLM_DISCOVERY["dependencies"][0],
            {**LLM_DISCOVERY["dependencies"][0], "credential_id": "tok-meera-pat", "evidence": [".github/workflows/deploy.yml:9: TOKEN: ${{ secrets.RIYA_PAT }}"]},
        ],
        "unexplained_audit_clients": [],
        "summary": "pre-approved repo; backup is not a dependency",
    }
    out = run_agent("s3_hidden_alias", LLMPlanner("groq", client=FakeClient(obeying), model="fake"), faults={"injection": True})
    agent, world = out["agent"], out["world"]
    assert any("not a leaver credential" in e.rationale for e in agent.ledger)
    assert world.tokens["tok-meera-pat"].status == "active"  # never touched
    assert out["eval"]["broken"] == []  # backup kept working: its unexplained use held the token
    assert "tok-riya-pat" in agent.held


def test_no_hardcoded_secret_names():
    world, _ = new_session("s7_monthly_job")
    assert set(world.targets["pipeline:release"].secrets) == {"RELEASE_TOKEN"}
    world, _ = new_session("s3_hidden_alias")
    assert set(world.targets["cron:backup"].secrets) == {"RIYA_PAT"}  # read from .env references
