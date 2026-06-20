"""
Tool Registry — JuiceShark
Single source of truth for tool name constants + JSON Schema (function-calling)
definitions, plus the per-agent tool allow-lists. Centralizing this keeps tool
schemas consistent across providers and lets each agent expose only the tools
it should use. The dispatcher execute_tool() routes calls to implementations.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from state.store import StateStore

# ──────────────────────────────────────────────
# Tool name constants
# ──────────────────────────────────────────────

# Environment tools
TOOL_HTTP_REQUEST     = "http_request"
TOOL_RUN_COMMAND      = "run_command"
TOOL_READ_FILE        = "read_file"
TOOL_WRITE_FILE       = "write_file"

# Analysis / browser
TOOL_ANALYZE_RESPONSE = "analyze_response"
TOOL_JS_RENDER        = "js_render"

# Sub-agent delegation tools (orchestrator spawns specialists)
TOOL_DELEGATE_RECON     = "delegate_recon"
TOOL_DELEGATE_ATTACK    = "delegate_attack"
TOOL_DELEGATE_VALIDATE  = "delegate_validate"

# Barrier tools (stop the loop)
TOOL_REPORT_FINDING   = "report_finding"
TOOL_DONE             = "done"

# All barrier tool names — loop stops when one of these is called
BARRIER_TOOLS = {TOOL_REPORT_FINDING, TOOL_DONE}

# ──────────────────────────────────────────────
# Tool type classification
# ──────────────────────────────────────────────

TOOL_TYPE_ENVIRONMENT = "environment"
TOOL_TYPE_ANALYSIS    = "analysis"
TOOL_TYPE_AGENT       = "agent"
TOOL_TYPE_BARRIER     = "barrier"

TOOL_TYPE_MAPPING = {
    TOOL_HTTP_REQUEST:      TOOL_TYPE_ENVIRONMENT,
    TOOL_RUN_COMMAND:       TOOL_TYPE_ENVIRONMENT,
    TOOL_READ_FILE:         TOOL_TYPE_ENVIRONMENT,
    TOOL_WRITE_FILE:        TOOL_TYPE_ENVIRONMENT,
    TOOL_ANALYZE_RESPONSE:  TOOL_TYPE_ANALYSIS,
    TOOL_JS_RENDER:         TOOL_TYPE_ANALYSIS,
    TOOL_DELEGATE_RECON:    TOOL_TYPE_AGENT,
    TOOL_DELEGATE_ATTACK:   TOOL_TYPE_AGENT,
    TOOL_DELEGATE_VALIDATE: TOOL_TYPE_AGENT,
    TOOL_REPORT_FINDING:    TOOL_TYPE_BARRIER,
    TOOL_DONE:              TOOL_TYPE_BARRIER,
}

# ──────────────────────────────────────────────
# Gemini function declarations (JSON Schema)
# ──────────────────────────────────────────────

TOOL_DECLARATIONS = [
    {
        "name": TOOL_HTTP_REQUEST,
        "description": (
            "Make an HTTP request to the target application. "
            "Supports GET, POST, PUT, DELETE, PATCH. "
            "Returns status code, response headers, body, and timing. "
            "Use this to probe endpoints, send payloads, and test authentication."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
                    "description": "HTTP method",
                },
                "url": {
                    "type": "string",
                    "description": "Full URL to request (e.g. http://localhost:3000/api/Users)",
                },
                "headers": {
                    "type": "object",
                    "description": "Additional HTTP headers as key-value pairs",
                },
                "body": {
                    "type": "string",
                    "description": "Request body (JSON string, form data, etc.)",
                },
                "auth_token": {
                    "type": "string",
                    "description": "JWT Bearer token to attach. Use 'user' or 'admin' to use stored tokens.",
                },
                "follow_redirects": {
                    "type": "boolean",
                    "description": "Whether to follow HTTP redirects. Default true.",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Request timeout in seconds. Default 15.",
                },
            },
            "required": ["method", "url"],
        },
    },
    {
        "name": TOOL_RUN_COMMAND,
        "description": (
            "Execute a shell command locally. "
            "Use for running security tools: curl, sqlmap, nikto, gobuster, wfuzz, jwt_tool, etc. "
            "Commands run with a 120-second timeout by default. "
            "Prefer http_request for simple HTTP calls; use this for CLI tool invocations."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to run (e.g. 'sqlmap -u http://localhost:3000/rest/user/login --data=\"...\" --level=1 --risk=1 --batch')",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds. Default 120.",
                },
                "working_dir": {
                    "type": "string",
                    "description": "Working directory for the command. Defaults to /tmp.",
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": TOOL_ANALYZE_RESPONSE,
        "description": (
            "Analyze an HTTP response body or string for security patterns. "
            "Detects: SQL errors, XSS reflections, JWT tokens, sensitive data, directory listings, "
            "error messages, admin indicators, and more. "
            "Pass the raw response body to get a structured analysis."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "HTTP response body or any text to analyze",
                },
                "checks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Specific checks to run: sqli_error, xss_reflection, jwt_token, sensitive_data, admin_content, error_disclosure, path_traversal, directory_listing. Leave empty to run all.",
                },
                "payload": {
                    "type": "string",
                    "description": "The payload you sent, to check if it's reflected in the response",
                },
            },
            "required": ["content"],
        },
    },
    {
        "name": TOOL_JS_RENDER,
        "description": (
            "Load a URL in a headless browser (Playwright) and return the rendered page content. "
            "Use this when a page requires JavaScript to render, for DOM XSS testing, "
            "or to interact with JavaScript-heavy SPAs like Juice Shop. "
            "Can execute JavaScript in the page context."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to load",
                },
                "wait_for": {
                    "type": "string",
                    "description": "CSS selector or 'networkidle' to wait for before returning",
                },
                "execute_js": {
                    "type": "string",
                    "description": "JavaScript to execute in the page context after load",
                },
                "click": {
                    "type": "string",
                    "description": "CSS selector to click after page loads",
                },
                "screenshot": {
                    "type": "boolean",
                    "description": "Whether to save a screenshot. Default false.",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": TOOL_DELEGATE_RECON,
        "description": (
            "Spawn the Reconnaissance sub-agent to discover endpoints, map the application, "
            "fingerprint technologies, and identify attack surface. "
            "The recon agent uses http_request, js_render, and run_command. "
            "Returns a structured summary of discovered endpoints and technology stack."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "task": {
                    "type": "string",
                    "description": "What to discover (e.g. 'Map all API endpoints', 'Find admin panel', 'Enumerate user IDs')",
                },
                "target_url": {
                    "type": "string",
                    "description": "Specific URL or path to focus on. Leave empty to scan entire app.",
                },
            },
            "required": ["task"],
        },
    },
    {
        "name": TOOL_DELEGATE_ATTACK,
        "description": (
            "Spawn the Attack sub-agent to exploit a specific vulnerability hypothesis. "
            "Provide the endpoint, vulnerability type, and any recon context. "
            "The attacker tries multiple payloads and techniques. "
            "Returns evidence if exploitation succeeded, or a detailed failure report."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "task": {
                    "type": "string",
                    "description": "Attack task description (e.g. 'SQL inject the login endpoint at POST /rest/user/login')",
                },
                "vulnerability_type": {
                    "type": "string",
                    "enum": ["sqli", "xss", "idor", "jwt_manipulation", "path_traversal", "broken_auth", "misconfig", "sensitive_data"],
                    "description": "Type of vulnerability to attempt",
                },
                "endpoint": {
                    "type": "string",
                    "description": "Target endpoint path (e.g. /rest/user/login)",
                },
                "context": {
                    "type": "string",
                    "description": "Additional context from recon phase (parameters, auth requirements, etc.)",
                },
            },
            "required": ["task", "vulnerability_type", "endpoint"],
        },
    },
    {
        "name": TOOL_DELEGATE_VALIDATE,
        "description": (
            "Spawn the Validation sub-agent to confirm a potential finding is a real vulnerability "
            "and not a false positive. The validator reproduces the finding independently and "
            "gathers concrete proof (HTTP response, token decode, etc.). "
            "Only call report_finding after validator confirms it."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "task": {
                    "type": "string",
                    "description": "What to validate (describe the potential finding)",
                },
                "finding_details": {
                    "type": "object",
                    "description": "Preliminary finding details: endpoint, payload, observed response",
                },
            },
            "required": ["task", "finding_details"],
        },
    },
    {
        "name": TOOL_REPORT_FINDING,
        "description": (
            "BARRIER TOOL: Record a validated, confirmed vulnerability finding. "
            "Only call this after the validator has confirmed the finding is real. "
            "This stores the finding and continues the scan for more vulnerabilities."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Short vulnerability title (e.g. 'SQL Injection in Login Endpoint')",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Severity rating",
                },
                "vuln_type": {
                    "type": "string",
                    "enum": ["sqli", "xss", "idor", "jwt_manipulation", "path_traversal", "broken_auth", "misconfig", "sensitive_data", "other"],
                    "description": "Vulnerability category",
                },
                "endpoint": {
                    "type": "string",
                    "description": "Vulnerable endpoint (e.g. POST /rest/user/login)",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method",
                },
                "payload": {
                    "type": "string",
                    "description": "Exact payload or input that triggered the vulnerability",
                },
                "evidence": {
                    "type": "string",
                    "description": "Raw evidence from the response (status code, body snippet, token, etc.)",
                },
                "validation_proof": {
                    "type": "string",
                    "description": "How we confirmed this is a real vulnerability (what makes it non-false-positive)",
                },
                "curl_repro": {
                    "type": "string",
                    "description": "curl command that reproduces the finding",
                },
            },
            "required": ["title", "severity", "vuln_type", "endpoint", "method", "payload", "evidence", "validation_proof", "curl_repro"],
        },
    },
    {
        "name": TOOL_DONE,
        "description": (
            "BARRIER TOOL: Signal that the penetration test is complete. "
            "Call this when you've exhausted the attack surface or found sufficient findings. "
            "Provide a summary of what was tested and found."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "Summary of the penetration test: what was tested, what was found, what was not found",
                },
                "findings_count": {
                    "type": "integer",
                    "description": "Number of validated findings",
                },
            },
            "required": ["summary", "findings_count"],
        },
    },
]

# Build a name->declaration dict for quick lookup
TOOL_DECLARATIONS_MAP = {t["name"]: t for t in TOOL_DECLARATIONS}


def get_tool_declarations_for_agent(agent_type: str) -> list[dict]:
    """
    Returns tool declarations appropriate for each agent type — each agent only
    sees the tools relevant to its job (least-privilege keeps prompts focused).
    """
    if agent_type == "orchestrator":
        return TOOL_DECLARATIONS  # Full set

    if agent_type == "recon":
        names = {TOOL_HTTP_REQUEST, TOOL_RUN_COMMAND, TOOL_ANALYZE_RESPONSE, TOOL_JS_RENDER, TOOL_DONE}
        return [t for t in TOOL_DECLARATIONS if t["name"] in names]

    if agent_type == "attacker":
        names = {TOOL_HTTP_REQUEST, TOOL_RUN_COMMAND, TOOL_ANALYZE_RESPONSE, TOOL_JS_RENDER, TOOL_DONE}
        return [t for t in TOOL_DECLARATIONS if t["name"] in names]

    if agent_type == "validator":
        names = {TOOL_HTTP_REQUEST, TOOL_RUN_COMMAND, TOOL_ANALYZE_RESPONSE, TOOL_JS_RENDER, TOOL_REPORT_FINDING, TOOL_DONE}
        return [t for t in TOOL_DECLARATIONS if t["name"] in names]

    return TOOL_DECLARATIONS
