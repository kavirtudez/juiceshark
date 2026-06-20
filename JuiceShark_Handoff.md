# JuiceShark Handoff Context

## What is JuiceShark?
JuiceShark is an autonomous, AI-powered penetration testing agent specifically designed to test the **OWASP Juice Shop** application. Its design follows the standard pentest workflow (recon → exploitation → validation) implemented as an orchestrator-worker multi-agent system:
- **Orchestrator**: The lead agent that follows a specific playbook/checklist of vulnerabilities, delegating tasks to sub-agents.
- **Recon**: Maps the application attack surface.
- **Attacker**: Executes specific exploit playbooks for given vulnerability categories.
- **Validator**: Independently verifies the findings to eliminate false positives and reports them to the state store.

## Current Status & Recent Fixes
We have recently made several critical improvements to ensure the agent can reliably exploit and validate all required vulnerability categories:

1. **Agent Loop Fix (Premature Termination)**:
   - *Bug*: The Orchestrator was terminating its entire scan loop as soon as the first vulnerability was reported because `report_finding` was configured as a global barrier tool.
   - *Fix*: Modified `agent/loop.py` to accept per-agent `barrier_tools`. The Orchestrator now only stops on `done`, while the Validator correctly stops on `report_finding` and `done`.

2. **Attack Playbooks & Token Context Injection**:
   - *Bug*: The Attacker was failing IDOR and Broken Auth tests because it was not attaching the captured admin JWT to its requests, despite being told to do so.
   - *Fix*: Updated `agent/attacker.py` to forcefully pre-load the captured admin and user JWTs directly into its `HTTPTool` instance. The prompts were also massively expanded to provide exact, Juice Shop-specific exploit techniques (e.g., null-byte bypass for path traversal, exact DOM XSS payloads).

3. **Validation & Headless Browser (`js_render`)**:
   - *Bug*: The Validator was missing DOM XSS and Admin panel misconfigurations because it relied solely on `http_request` which doesn't execute Angular SPA code.
   - *Fix*: Added the `js_render` (Playwright) tool to the Validator's registry and explicitly instructed it to use it for XSS validation.

4. **Analysis Tool Improvements**:
   - Upgraded `tools/analysis_tool.py` to detect JSON array directory listings (how Juice Shop handles `/ftp/`) and added specific markers for confidential files.

## Status: COMPLETE — 8/8 categories validated (2026-06-21)

A full OpenAI (`gpt-4o-mini`) run discovered and validated **all 8 categories**
(the original 7 plus `jwt_manipulation`) with no duplicates. Deliverables refreshed
in `logs/` (`findings_report.md`, `findings.json`, `session.jsonl`, `meta.json`);
the 8/8 run is preserved under `run-8/` (7/7 run under `run-final/`).

| Category | Result |
|----------|--------|
| sqli | ✅ | xss | ✅ | sensitive_data | ✅ | path_traversal | ✅ |
| idor | ✅ | broken_auth | ✅ | misconfig | ✅ | jwt_manipulation | ✅ |

### JWT manipulation (added 2026-06-21)
Two Juice Shop JWT challenges, both from `jwt.verify(token, publicKey)` having no
`algorithms` whitelist (lib/insecurity.ts), checked by global middleware
`verify.jwtChallenges()` on every request:
- **Unsigned JWT** — forge `alg:none` token for `jwtn3d@juice-sh.op`, empty signature.
- **Forged Signed JWT** — RS256→HS256 confusion: sign an `alg:HS256` token for
  `rsa_lord@juice-sh.op` using the public key (GET `/encryptionkeys/jwt.pub`, no auth)
  as the HMAC secret.
A tested, stdlib-only forging script lives at `tools/jwt_forge.py`
(`python3 tools/jwt_forge.py <target>` → prints forged tokens, CHALLENGE STATUS, and
"JWT MANIPULATION CONFIRMED"). The attacker/validator are handed the exact command
via their task message; orchestrator checklist item 8 drives it. Also: `http_tool`
now records every probed endpoint, so "Endpoints discovered" is populated (was 0).

### Root-cause fixes applied this session

1. **Dedup by `vuln_type`** (`state/store.py`): `add_finding` no longer keys on
   `endpoint`, so `/ftp/` vs `/ftp/acquisitions.md` etc. collapse to one finding.

2. **Centralized JWT capture** (`tools/http_tool.py`): the SQLi login is performed
   by the *attacker* sub-agent, but token capture previously only ran on the
   *orchestrator's* own requests — so the admin JWT was never stored and every
   authenticated test (IDOR / broken_auth / misconfig) got 401. `HTTPTool.execute`
   now captures JWTs for **every** agent and parses the role from Juice Shop's
   nested `data.role`/`data.email` (the old code read a non-existent top-level
   `email`). The redundant/buggy `_maybe_capture_token` was removed from
   `orchestrator.py`. Confirmed by `Auth roles captured: admin` in the report.

3. **Broken-auth technique** (attacker/validator/orchestrator prompts): the real
   Juice Shop bug requires **omitting** the `current` param — `current=WRONG`
   returns 401, and no token returns 500. Prompts now say to send only
   `?new=…&repeat=…` with `auth_token="admin"`.

4. **Path-traversal validation** (`agent/validator.py`): the null-byte bypass
   already returned `200`, but the validator ran `analyze_response` on the body —
   which is XOR-encrypted coupon gibberish — got "no indicators", and rejected it.
   The criteria now treat a `200` on `coupons_2013.md.bak%2500.md` as conclusive
   and forbid `analyze_response` for this check.

5. **Timeout / context bloat** (`agent/loop.py`, `tools/browser_tool.py`): the
   misconfig attacker looped on `js_render` of the ~185 KB `/#/administration`
   page until the 30 s OpenAI client timeout fired repeatedly. Raised the timeout
   to 120 s and `js_render` now strips `<style>/<script>`/tags and returns 2 KB of
   text instead of 5 KB of inlined font-awesome CSS.

6. **Accurate report label** (`reporter.py`): no longer hardcodes
   "Gemini-powered"; `generate_report` takes `model_name` and main.py passes it.

### How to re-run
```
python3 main.py http://localhost:3000 --provider openai --output ./run-final --verbose
```
Provider auto-detects from `.env`; pass `--provider gemini` to use Gemini (note the
free-tier Gemini key hits 429 RESOURCE_EXHAUSTED rate limits mid-scan).
