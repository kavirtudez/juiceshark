"""
Recon Agent — JuiceShark
Reconnaissance sub-agent: discovers endpoints, maps the attack surface,
fingerprints technologies. Spawned by the orchestrator via delegate_recon.
"""

from __future__ import annotations

import logging
import json
import google.genai as genai

from agent.loop import perform_agent_chain
from tools.registry import (
    get_tool_declarations_for_agent,
    TOOL_HTTP_REQUEST, TOOL_RUN_COMMAND, TOOL_ANALYZE_RESPONSE,
    TOOL_JS_RENDER, TOOL_DONE,
)
from tools.http_tool import HTTPTool
from tools.terminal_tool import TerminalTool
from tools.browser_tool import BrowserTool
from tools.analysis_tool import AnalysisTool

logger = logging.getLogger("juiceshark.recon")

SYSTEM_PROMPT = """You are the Reconnaissance Agent for a penetration test against OWASP Juice Shop.

Your mission is to map the attack surface of the target application:
1. Discover all API endpoints (especially /api/*, /rest/*)
2. Identify authentication mechanisms (login, registration, JWT)
3. Find admin interfaces or special routes
4. Map all parameters accepted by each endpoint
5. Identify technologies: frameworks, libraries, versions
6. Note any interesting headers, cookies, or configuration details

You have access to:
- http_request: Make HTTP requests to probe endpoints
- run_command: Run CLI tools (curl, gobuster, nikto)
- analyze_response: Analyze responses for interesting patterns
- js_render: Load pages in a real browser to see JS-rendered content
- done: When you have sufficient recon, call done with your findings summary

IMPORTANT:
- Focus on breadth first: find as many endpoints as possible
- Note any error messages that reveal technology details
- Check robots.txt, sitemap.xml, .well-known/, and common paths
- Look for API documentation at /api-docs, /swagger.json, /swagger-ui
- Check for exposed .git, .env, backup files
- Always call 'done' when your task is complete

Start with a GET request to the root URL to understand the application."""


def run_recon(
    *,
    client: genai.Client,
    model_name: str,
    target_url: str,
    task: str,
    state_store,
    http_tool: HTTPTool,
    terminal_tool: TerminalTool,
    browser_tool: BrowserTool,
    analysis_tool: AnalysisTool,
) -> str:
    """Run the recon sub-agent and return its findings summary."""

    tool_declarations = get_tool_declarations_for_agent("recon")

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
            summary = args.get("summary", "Recon complete")
            logger.info(f"[recon] Done: {summary[:200]}")
            return f"RECON COMPLETE: {summary}"
        else:
            return f"Unknown tool: {name}"

    initial_message = f"""Target URL: {target_url}

Your recon task: {task}

Start by probing the root URL and then systematically explore the application's endpoints."""

    return perform_agent_chain(
        client=client,
        model_name=model_name,
        system_prompt=SYSTEM_PROMPT,
        initial_message=initial_message,
        tool_declarations=tool_declarations,
        tool_executor=execute_tool,
        agent_name="recon",
        state_store=state_store,
    )
