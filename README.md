# HandoffGuard

**An IT Infrastructure agent for safe employee offboarding.**
When someone leaves, HandoffGuard finds the pipelines and jobs still running on their credentials, moves them to service-owned credentials, proves they still work, and only then revokes access.

> Never revoke what you haven't proven you can live without.

Team **Synaptix** (HX-VEEZ) · AgentOps'26, MIT Bengaluru × CGI · Domain: **IT Infrastructure**
Venkata Srijan (agent, planner, guard, UI) · Tushar Reddy (simulated org, services, tools, scenarios)

---

## The problem

Offboarding today is a checklist: revoke tokens, remove the person from the org, disable the account. But a person's identity is often still doing work. Deploy pipelines authenticate with their personal token, cron jobs read it through `.env` aliases, and they may be the org's last owner. Revoke first and production breaks; delay and a former member keeps live access.

Public examples: Jenkins builds stopped after the token owner left ([Liferay KB](https://learn.liferay.com/kb-article/how-to-resolve-jenkins-builds-no-longer-completing-after-github-user-contact-adjustments)); a CI token died with its creator and the error hid the cause ([SonarCloud community](https://community.sonarsource.com/t/sonarcloud-tokens-are-tied-to-the-user-that-added-the-project/74290)).

## What HandoffGuard does (CGI flow)

| Stage | What happens |
| --- | --- |
| **Data ingestion** | Reads the HR offboarding request (`OFF-2026-014.json`), the leaver's credentials and roles, 14 days of token-use audit log, and the repository's CI workflows, `.env`, crontab and scripts. |
| **Intelligent decision-making** | The LLM finds every dependency, including ones hidden behind alias chains (`RIYA_PAT → DEPLOY_TOKEN → GH_TOKEN → backup.py → cron`), and must explain every client seen in the audit log. When something fails it diagnoses the error text and picks the next action. |
| **Action execution** | Mints a least-privilege service credential, rebinds the secret, runs a real canary, re-mints with justified scopes after a 403, promotes a successor when the leaver is the last owner, revokes, removes, suspends login. |
| **Outcome reporting** | Writes a completion report (dependencies, evidence, canary results before and after revocation, approvals, recoveries, residual-access probe, open items) plus a JSONL audit ledger. |

## Responsible AI controls

The LLM proposes; a deterministic **policy guard** decides (`handoffguard/guard.py`).

- **R1 Order:** a leaver credential is revoked only after every dependency on it passes a canary *and* every observed use of it is explained.
- **R2 Approval:** write-scoped credentials, role changes and member removal need a human approval.
- **R3 Retries:** max 2 recoveries per dependency, then escalate.
- **R4 Least privilege:** new credentials start read-only; extra scopes only if an error names them. Over-broad LLM requests are blocked.
- **R5 Known tools:** 12 tools only, and none of them deletes anything (accounts are suspended).
- **R6 Denial:** a denied action is never retried another way. The agent rolls the automation back and escalates.
- **R7 Membership:** the leaver is never removed while one of their credentials still backs a running automation.
- Discovery output is validated: invented targets, secrets or credentials are rejected.
- A canary only counts if the audit log shows it used the *new* credential.
- Token values never appear in logs or reports.

## How it works

```
HR request ─► inventory + audit log ─► scan repo ─► LLM discovery (+ rules) ─► validate
   for each dependency: mint (read-only) ─► rebind ─► canary ─► pass? verified
                                            fail ─► LLM diagnosis ─► guard ─► approval? ─► retry
   revoke (guard R1) ─► post-revoke canary ─► remove member (approval; last-owner recovery)
   suspend login ─► residual-access probe ─► completion report
```

The simulated org is real code, not flags:
- `world/git_service.py`: a local HTTP git API that checks bearer tokens, org membership and scopes, returning real 401/403s.
- `world/ci_runner.py`: executes the workflow steps and cron command as subprocesses, resolving secrets and `.env` alias chains.
- Tool interfaces mirror GitHub/IdP admin APIs, so real connectors can replace the world later.

## Setup (5 minutes)

Requires Python 3.10+.

```bash
git clone <this repo> && cd handoffguard
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # Windows: copy .env.example .env
# put a free key in .env: GROQ_API_KEY=... (console.groq.com) or GEMINI_API_KEY=... (aistudio.google.com)
```

Without a key everything still runs with the rules planner (which can't follow alias chains, so the hidden-cron scenario ends PARTIAL by design).

## Run

```bash
streamlit run app.py                                 # the console
python -m handoffguard run --scenario demo           # CLI, auto approvals
python -m handoffguard run --scenario demo --approvals ask
python -m handoffguard run --scenario demo --baseline   # what the naive checklist breaks
python -m handoffguard bench                         # 6 scenarios, baseline vs agent
python -m pytest -q                                  # 20 tests, offline
```

### Demo script (90 seconds)

1. Scenario **Demo**, click **Run naive checklist**: three automations turn **Broken**.
2. Click **Run HandoffGuard**: the LLM finds three dependencies including the hidden cron job, re-homes them, hits a real 403, diagnoses it, asks for approval, re-mints, verifies, revokes, removes, probes clean.
3. Flip **Leaver is the org's last owner** in the judge's switchboard and run again: removal is blocked, the agent promotes the successor (approval), verifies, and finishes.
4. **Benchmark** tab: baseline vs HandoffGuard across six scenarios.
5. **Report** tab: the completion report an IT manager signs off.

## Scenarios and results

| # | Scenario | Naive checklist | HandoffGuard |
| --- | --- | --- | --- |
| S1 | Single pipeline on the leaver's token | 1 broken | COMPLETE, 0 broken |
| S2 | One token shared by two pipelines | 2 broken | COMPLETE, 0 broken |
| S3 | Hidden alias in `.env` + cron | 2 broken | LLM: COMPLETE, 0 broken · rules only: safe hold (PARTIAL) |
| S4 | Replacement token lacks write scope (403) | 1 broken | COMPLETE after diagnosis + approval |
| S5 | Leaver is the org's last owner | 1 broken, membership left | COMPLETE after promoting successor |
| S6 | Approver denies write access | 1 broken | Safe stop: rolled back, 0 broken, escalated |

Measured by `python -m handoffguard bench` / the Benchmark tab with the same yardstick for both: run every automation's canary after offboarding, then probe for residual access.

## Repository layout

```
app.py                      Streamlit console
handoffguard/
  contracts.py              HR request, dependency, ledger entry, tool result, approval
  agent.py                  the agent loop (generator: streams events, pauses for approvals)
  guard.py                  policy guard R1–R7
  planners.py               LLM planner (Groq/Gemini, OpenAI-compatible) + rules fallback
  tools.py                  12 tools over the simulated org
  report.py                 completion report
  runner.py                 baseline, evaluation, benchmark
  world/                    simulated org: state, git service, CI runner, scenarios
  fixtures/                 repo files and HR request used to build each scenario
tests/test_scenarios.py     scenario suite + guard + LLM-path tests
```

## Limitations

- The organisation is simulated for safety and repeatability; connectors for real GitHub and Google Workspace are the next step.
- Free-tier LLM limits apply; on any LLM error the agent falls back to rules and says so in the timeline.
- Discovery covers CI workflows, `.env` files, crontabs and scripts in one repository.
