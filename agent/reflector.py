"""
Reflector — JuiceShark

When the LLM returns plain text instead of a tool call, this generates a
corrective message that nudges it back to tool use. Without it, a chatty model
stalls the chain; with it, the loop self-corrects instead of dead-ending.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("juiceshark.reflector")

MAX_REFLECTOR_CALLS = 3


def perform_reflector(
    *,
    agent_name: str,
    content: str,
    barrier_tool_names: list,
    tool_declarations: list,
    iteration: int = 1,
) -> str:
    """
    Returns a corrective human message to inject into the agent chain
    when the LLM returned text without a tool call.
    """
    if iteration > MAX_REFLECTOR_CALLS:
        logger.warning(f"[{agent_name}] Reflector maxed out at {MAX_REFLECTOR_CALLS} calls, forcing done")
        return (
            "SYSTEM OVERRIDE: You have been asked multiple times to call a tool but keep responding with text. "
            "This is your final instruction: call the 'done' tool RIGHT NOW with a summary of what you've found. "
            f"Available barrier tools: {', '.join(str(b) for b in barrier_tool_names)}. "
            "You MUST call a tool. Do NOT respond with text."
        )

    logger.info(f"[{agent_name}] Reflector iteration {iteration}: nudging back to tool use")

    # Build barrier tools description
    barrier_details = []
    for decl in tool_declarations:
        if decl.get("name") in barrier_tool_names:
            barrier_details.append(f"  - {decl['name']}: {decl.get('description', '')[:100]}")
    barrier_text = "\n".join(barrier_details) if barrier_details else f"  {barrier_tool_names}"

    return f"""SYSTEM: You responded with plain text instead of calling a tool. In this agentic framework, you must ALWAYS respond with a tool call.

Your last text response was:
---
{content[:400]}
---

You must call a tool now to continue. Options:
1. If you've completed your objective, call one of these barrier tools:
{barrier_text}

2. If you need to continue working, call any appropriate tool (http_request, run_command, etc.)

DO NOT respond with text. Call a tool immediately."""
