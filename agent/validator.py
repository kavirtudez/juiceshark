"""
Validator Agent — JuiceShark
Validation sub-agent. Given a potential finding, independently reproduces
and confirms it is a real vulnerability (not a false positive).
Spawned by the orchestrator via delegate_validate.
"""

from __future__ import annotations

import logging
import json
import os
import uuid
import google.genai as genai

from agent.loop import perform_agent_chain
from tools.registry import (
    get_tool_declarations_for_agent,
    TOOL_HTTP_REQUEST, TOOL_RUN_COMMAND,
    TOOL_ANALYZE_RESPONSE, TOOL_JS_RENDER, TOOL_REPORT_FINDING, TOOL_DONE,
)
from tools.http_tool import HTTPTool
from tools.terminal_tool import TerminalTool
from tools.browser_tool import BrowserTool
from tools.analysis_tool import AnalysisTool
from state.store import Finding

logger = logging.getLogger("juiceshark.validator")

SYSTEM_PROMPT = """You are the Validation Agent for a penetration test against OWASP Juice Shop.

Your job is CRITICAL: you eliminate false positives by independently reproducing findings.

You receive details of a potential vulnerability. Your mission:
1. Reproduce the finding independently from scratch using the exact payload
2. Confirm the vulnerability is real (not a coincidence or error message)
3. Gather concrete proof (HTTP response body, status code, token content)
4. Call report_finding with validated evidence

VALIDATION CRITERIA:

## SQL Injection
- CONFIRMED if: response contains auth token with real user data, OR SQL error message
- NOT CONFIRMED if: just a different error message
- Use http_request to replay the exact payload

## XSS (IMPORTANT: must use js_render for DOM XSS!)
- CONFIRMED if: js_render shows "ALERTS TRIGGERED" in result containing "XSS DETECTED"
- For Juice Shop search XSS: use js_render to load /#/search?q=<img src=x onerror=alert('XSS')>
  - The js_render tool returns "ALERTS TRIGGERED: [\"XSS\"]" if an alert fires
  - This IS confirmed even though http_request doesn't reflect it (Angular SPA parses the fragment!)
- NEVER use http_request alone to validate XSS in /#/search — the # fragment is not sent to server
- NOT CONFIRMED if: js_render shows no alert and response is safe-escaped

## IDOR / Broken Access Control
- CONFIRMED if: you can access another user's private data using the captured admin/user token
- Try GET /api/Users with admin token — if it returns ALL user records = IDOR (no owner restriction)
- Try GET /rest/basket/2 with the ADMIN token (basket belongs to a different user) — if 200 = IDOR
- NOT CONFIRMED if: server returns 401/403 for all cross-user requests
- Use auth_token="admin" or auth_token="user" in http_request to use captured tokens

## JWT Manipulation
- CONFIRMED if: a forged token is accepted by the server. The exact run_command to
  reproduce is provided in your task message under "JWT FORGING SCRIPT" — run it.
- It forges an alg:none token (jwtn3d@juice-sh.op) and an HS256 token signed with
  the public key from /encryptionkeys/jwt.pub (rsa_lord@juice-sh.op), sends them,
  and prints CHALLENGE STATUS. CONFIRMED if it prints "JWT MANIPULATION CONFIRMED"
  or CHALLENGE STATUS shows jwtUnsignedChallenge=true or jwtForgedChallenge=true.
- NOT CONFIRMED if: the script prints "NOT CONFIRMED" / both challenges stay false.

## Sensitive Data Exposure (FTP files)
- CONFIRMED if: /ftp/acquisitions.md is accessible WITHOUT authentication and content says "confidential"
  OR /ftp/ returns a JSON list of filenames (directory enumeration = misconfig)
  OR any .bak/.kdbx file is accessible
- Evidence: the response body containing confidential text or listing private files
- This IS a real finding even without a "traditional" directory listing HTML page

## Path Traversal
- CONFIRMED if: GET /ftp/coupons_2013.md.bak%2500.md returns HTTP 200 (null-byte bypass).
  The 200 status ALONE is conclusive proof — the server delivered a .bak file whose
  extension the ".md and .pdf only" filter should have blocked. As soon as you see
  STATUS: 200 on this URL, call report_finding immediately.
- Do NOT run analyze_response for this finding and do NOT wait for "path traversal
  indicators". The body of coupons_2013.md.bak is intentionally XOR-encrypted coupon
  data and looks like random gibberish (e.g. "n<MibgC7sn..."). That gibberish IS the
  protected .bak file content — seeing it returned with a 200 confirms the bypass.
  analyze_response will say "No path traversal indicators" for this binary body; that
  is EXPECTED and is NOT a reason to reject the finding.
- NOT CONFIRMED only if: status is 403/404 or body is "Only .md and .pdf files are allowed!"

## Security Misconfiguration / Admin Panel
- CONFIRMED if: GET /#/administration with admin token via js_render shows admin dashboard content
  OR /api/Users with admin auth token returns complete user list (should be admin-only but may be open)
- Use auth_token="admin" header in http_request for /api/Users endpoint

## Broken Auth (password change without verification)
- CONFIRMED if: GET /rest/user/change-password?new=hacked&repeat=hacked
  (with auth_token="admin" and NO `current` parameter) returns 200
- The current-password check only runs when `current` is present, so OMIT it entirely.
- Pitfalls: current=WRONG returns 401; no auth token returns 500. You MUST attach the
  token AND leave out `current` to get the 200 that proves the vulnerability.

RULES:
- Be skeptical. Do not report unless you can independently reproduce the finding.
- Use js_render (not http_request) for ANY finding involving Angular SPA rendering or DOM XSS
- Use auth_token="admin" or auth_token="user" in http_request to reuse captured session tokens
- Use analyze_response to verify what the response contains
- Call report_finding ONLY when you are 100% certain it's real
- Call done if you cannot reproduce the finding (it's a false positive)
- Include a curl command in your report_finding call that EXACTLY reproduces the finding"""


def run_validator(
    *,
    client: genai.Client,
    model_name: str,
    target_url: str,
    task: str,
    finding_details: dict,
    state_store,
    http_tool: HTTPTool,
    terminal_tool: TerminalTool,
    browser_tool: BrowserTool,
    analysis_tool: AnalysisTool,
) -> str:
    """Run the validator sub-agent and return validation result."""

    tool_declarations = get_tool_declarations_for_agent("validator")

    def execute_tool(name: str, args: dict) -> str:
        if name == TOOL_HTTP_REQUEST:
            return http_tool.execute(args, state_store)
        elif name == TOOL_RUN_COMMAND:
            return terminal_tool.execute(args)
        elif name == TOOL_ANALYZE_RESPONSE:
            return analysis_tool.execute(args)
        elif name == TOOL_JS_RENDER:
            return browser_tool.execute(args)
        elif name == TOOL_REPORT_FINDING:
            # Record the validated finding in state store
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
                agent="validator",
            )
            state_store.add_finding(finding)
            logger.info(f"[validator] Finding recorded: {finding.title} ({finding.severity})")
            return (
                f"FINDING RECORDED: {finding.title}\n"
                f"Severity: {finding.severity}\n"
                f"ID: {finding.id}\n"
                f"Total findings so far: {state_store.finding_count()}"
            )
        elif name == TOOL_DONE:
            summary = args.get("summary", "Validation complete")
            logger.info(f"[validator] Done: {summary[:200]}")
            return f"VALIDATION COMPLETE: {summary}"
        else:
            return f"Unknown tool: {name}"

    # Provide the JWT forging command when validating a JWT-manipulation finding.
    jwt_context = ""
    if "jwt" in (task or "").lower() or "jwt" in json.dumps(finding_details).lower():
        script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "jwt_forge.py")
        jwt_context = (
            f"\n\n=== JWT FORGING SCRIPT ===\n"
            f"To independently reproduce, run with run_command:\n"
            f'  python3 "{script_path}" {target_url}\n'
            f'Confirm if it prints "RESULT: JWT MANIPULATION CONFIRMED".'
        )

    initial_message = f"""Target URL: {target_url}

Validation Task: {task}

Potential Finding Details:
{json.dumps(finding_details, indent=2)}{jwt_context}

Reproduce this finding independently and confirm whether it is a real vulnerability.
If confirmed, call report_finding with full evidence.
If you cannot reproduce it, call done with explanation."""

    return perform_agent_chain(
        client=client,
        model_name=model_name,
        system_prompt=SYSTEM_PROMPT,
        initial_message=initial_message,
        tool_declarations=tool_declarations,
        tool_executor=execute_tool,
        agent_name="validator",
        state_store=state_store,
    )
