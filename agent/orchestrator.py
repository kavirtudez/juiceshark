"""
Orchestrator Agent — JuiceShark
The primary coordination agent (orchestrator-worker pattern): it owns the test
plan and delegates each phase to a focused sub-agent, mirroring how a human
red-team lead assigns recon/exploitation/verification to specialists.

Responsible for:
1. Directing recon, attack, and validation sub-agents
2. Keeping track of what's been tested
3. Deciding which vulnerabilities to pursue
4. Calling done when coverage is complete
"""

from __future__ import annotations

import logging
import json
import re
import base64
import uuid
import google.genai as genai

from agent.loop import perform_agent_chain
from agent.recon import run_recon
from agent.attacker import run_attacker
from agent.validator import run_validator
from tools.registry import (
    get_tool_declarations_for_agent,
    TOOL_HTTP_REQUEST, TOOL_RUN_COMMAND,
    TOOL_ANALYZE_RESPONSE, TOOL_JS_RENDER,
    TOOL_DELEGATE_RECON, TOOL_DELEGATE_ATTACK, TOOL_DELEGATE_VALIDATE,
    TOOL_REPORT_FINDING, TOOL_DONE,
)
from tools.http_tool import HTTPTool
from tools.terminal_tool import TerminalTool
from tools.browser_tool import BrowserTool
from tools.analysis_tool import AnalysisTool
from state.store import Finding

logger = logging.getLogger("juiceshark.orchestrator")

SYSTEM_PROMPT = """You are the Lead Penetration Tester (Orchestrator) for an authorized security assessment of OWASP Juice Shop.

OWASP Juice Shop is a deliberately vulnerable web application. Your mission is to autonomously discover and validate real vulnerabilities.

## Your Strategy

1. **Phase 1 - Recon**: Use delegate_recon to map the application's attack surface first.
   - Discover API endpoints, auth mechanisms, technology stack

2. **Phase 2 - Attack**: Use delegate_attack for each vulnerability category:
   - SQL Injection (login bypass: POST /rest/user/login with email `' OR 1=1--`)
   - XSS (DOM XSS in search: /#/search?q=<img src=x onerror=alert('XSS')>  — MUST use js_render)
   - IDOR (GET /api/Users with admin token — does it return ALL users? Try GET /rest/basket/2 with admin token)
   - JWT Manipulation (forge alg:none token for jwtn3d@juice-sh.op AND HS256 token signed with the public key from /encryptionkeys/jwt.pub for rsa_lord@juice-sh.op — the attacker has a ready-made script)
   - Sensitive Data Exposure (GET /ftp/ lists files, GET /ftp/acquisitions.md = confidential doc)
   - Path Traversal (GET /ftp/coupons_2013.md.bak%2500.md — null-byte bypasses the .md-only filter)
   - Security Misconfiguration (js_render /#/administration with admin auth shows admin panel)
   - Broken Auth (GET /rest/user/change-password?new=hacked&repeat=hacked with admin token, NO current param)

3. **Phase 3 - Validate**: For each potential finding, use delegate_validate to:
   - Independently reproduce the finding
   - Confirm it's real (not a false positive)
   - Record it with concrete evidence

4. **Phase 4 - Complete**: Call done() when you've tested all major categories.

## Juice Shop Quick Facts (critical — follow exactly)
- Login: POST /rest/user/login with {"email":"...","password":"..."}
- SQLi bypass: {"email":"' OR 1=1--","password":"anything"} → 200 with admin JWT
- Admin email: admin@juice-sh.op
- FTP: GET /ftp/ returns JSON list of filenames (NOT html); GET /ftp/acquisitions.md → confidential doc
- Path traversal bypass: append %2500.md to blocked extensions (e.g. /ftp/coupons_2013.md.bak%2500.md)
- IDOR basket: GET /rest/basket/{id} — try ID 1, 2, 3 with a DIFFERENT user's token
- Admin panel: GET /#/administration in browser (requires Angular + admin JWT in localStorage)
- Broken Auth: GET /rest/user/change-password?new=hacked&repeat=hacked with admin token and NO current param (check is skipped when current is absent!)
- Stored JWT via auth_token="admin" or auth_token="user" in http_request calls (reuses captured session)
- XSS search param: use `q=` not `query=` — e.g. /#/search?q=<img src=x onerror=alert('XSS')>
- JWT: public key is at GET /encryptionkeys/jwt.pub (no auth); jwt.verify has no algorithm whitelist, so alg:none and HS256-signed-with-public-key tokens are accepted (the attacker has a forging script)

## Available Tools
- delegate_recon: Spawn reconnaissance sub-agent
- delegate_attack: Spawn attack sub-agent for specific vuln type
- delegate_validate: Spawn validation sub-agent to confirm findings
- http_request: Make direct HTTP requests yourself
- run_command: Run CLI tools directly
- analyze_response: Analyze HTTP responses
- js_render: Load pages in headless browser (use for Angular SPA pages and XSS testing)
- report_finding: Record a validated finding directly
- done: BARRIER TOOL - call when penetration test is complete

## Rules
- Always validate before reporting: use delegate_validate
- Test ALL 8 vulnerability categories on the checklist (including jwt_manipulation)
- Provide concrete evidence for each finding
- When delegating attacks, always pass captured token info in the context field
- Call done() when you've completed your assessment"""


def run_orchestrator(
    *,
    client: genai.Client,
    model_name: str,
    target_url: str,
    state_store,
) -> str:
    """Run the orchestrator agent — this drives the entire pentest."""

    # Initialize tools
    http_tool     = HTTPTool(target_url)
    terminal_tool = TerminalTool()
    browser_tool  = BrowserTool()
    analysis_tool = AnalysisTool()

    tool_declarations = get_tool_declarations_for_agent("orchestrator")

    def execute_tool(name: str, args: dict) -> str:
        # ── Direct tool calls ──
        if name == TOOL_HTTP_REQUEST:
            # Token capture is handled centrally inside HTTPTool.execute so that
            # every agent (not just the orchestrator) captures JWTs.
            return http_tool.execute(args, state_store)

        elif name == TOOL_RUN_COMMAND:
            return terminal_tool.execute(args)

        elif name == TOOL_ANALYZE_RESPONSE:
            return analysis_tool.execute(args)

        elif name == TOOL_JS_RENDER:
            return browser_tool.execute(args)

        # ── Sub-agent delegation ──
        elif name == TOOL_DELEGATE_RECON:
            task   = args.get("task", "Map the application")
            target = args.get("target_url", target_url)
            logger.info(f"[orchestrator] Delegating recon: {task[:100]}")
            result = run_recon(
                client=client,
                model_name=model_name,
                target_url=target,
                task=task,
                state_store=state_store,
                http_tool=HTTPTool(target_url),
                terminal_tool=terminal_tool,
                browser_tool=browser_tool,
                analysis_tool=analysis_tool,
            )
            return f"RECON RESULT:\n{result}"

        elif name == TOOL_DELEGATE_ATTACK:
            task      = args.get("task", "")
            vuln_type = args.get("vulnerability_type", "other")
            endpoint  = args.get("endpoint", "/")
            context   = args.get("context", "")
            logger.info(f"[orchestrator] Delegating attack: {vuln_type} on {endpoint}")
            result = run_attacker(
                client=client,
                model_name=model_name,
                target_url=target_url,
                task=task,
                vulnerability_type=vuln_type,
                endpoint=endpoint,
                context=context,
                state_store=state_store,
                http_tool=HTTPTool(target_url),
                terminal_tool=terminal_tool,
                browser_tool=browser_tool,
                analysis_tool=analysis_tool,
            )
            return f"ATTACK RESULT:\n{result}"

        elif name == TOOL_DELEGATE_VALIDATE:
            task            = args.get("task", "")
            finding_details = args.get("finding_details", {})
            logger.info(f"[orchestrator] Delegating validation: {task[:100]}")
            result = run_validator(
                client=client,
                model_name=model_name,
                target_url=target_url,
                task=task,
                finding_details=finding_details,
                state_store=state_store,
                http_tool=HTTPTool(target_url),
                terminal_tool=terminal_tool,
                browser_tool=browser_tool,
                analysis_tool=analysis_tool,
            )
            return f"VALIDATION RESULT:\n{result}"

        elif name == TOOL_REPORT_FINDING:
            finding = Finding(
                id=str(uuid.uuid4())[:8],
                title=args.get("title", ""),
                severity=args.get("severity", "medium"),
                vuln_type=args.get("vuln_type", "other"),
                endpoint=args.get("endpoint", ""),
                method=args.get("method", "GET"),
                payload=args.get("payload", ""),
                evidence=args.get("evidence", ""),
                validation_proof=args.get("validation_proof", ""),
                curl_repro=args.get("curl_repro", ""),
                agent="orchestrator",
            )
            state_store.add_finding(finding)
            return (
                f"FINDING RECORDED: {finding.title} ({finding.severity})\n"
                f"Total findings so far: {state_store.finding_count()}\n"
                f"Continue testing the remaining vulnerability categories on your checklist."
            )

        elif name == TOOL_DONE:
            summary        = args.get("summary", "Pentest complete")
            findings_count = args.get("findings_count", state_store.finding_count())
            logger.info(f"[orchestrator] Pentest complete. Findings: {findings_count}")
            return f"PENTEST COMPLETE\nFindings: {findings_count}\nSummary: {summary}"

        else:
            return f"Unknown tool: {name}"

    initial_message = f"""Target: {target_url}

You are conducting an authorized penetration test of OWASP Juice Shop at the above URL.

Your REQUIRED checklist — test ALL of these in order:
1. [ ] SQLi: POST /rest/user/login with email=' OR 1=1-- → get admin JWT
2. [ ] XSS: js_render /#/search?q=<img src=x onerror=alert('XSS')> → alert triggers
3. [ ] Sensitive Data: GET /ftp/ → JSON file list; GET /ftp/acquisitions.md → confidential
4. [ ] Path Traversal: GET /ftp/coupons_2013.md.bak%2500.md → bypass .md-only filter
5. [ ] IDOR: GET /rest/basket/2 with admin token → another user's basket data
6. [ ] Broken Auth: GET /rest/user/change-password?new=h@cked&repeat=h@cked with admin token, NO current param (no old-pw check)
7. [ ] Misconfig: GET /api/Users/ with admin token → returns all user accounts
8. [ ] JWT Manipulation: delegate_attack with vulnerability_type="jwt_manipulation" → the
       attacker runs the provided forging script (alg:none + HS256 public-key confusion)

For EACH item:
  a) Delegate attack
  b) If attack finds something, delegate validate
  c) If validated, record the finding

Start with item 1 (SQLi) to capture the admin JWT first — all other tests benefit from having the token."""

    return perform_agent_chain(
        client=client,
        model_name=model_name,
        system_prompt=SYSTEM_PROMPT,
        initial_message=initial_message,
        tool_declarations=tool_declarations,
        tool_executor=execute_tool,
        agent_name="orchestrator",
        state_store=state_store,
        barrier_tools={"done"},  # Only done() stops orchestrator — report_finding is non-blocking
    )
