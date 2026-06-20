"""
Agentic Loop — JuiceShark
A ReAct-style reason/act loop: the model picks a tool, we execute it, feed the
result back, and repeat until a terminal ("barrier") tool fires. Works against
both Gemini (google-genai) and OpenAI chat-completions.

Design goals (what an autonomous pentest loop needs to be robust):
  - A hard iteration ceiling so a confused chain can't run forever
  - A graceful-shutdown window that tells the model to wrap up near the limit
  - Barrier tools that cleanly terminate a chain
  - Repeating-tool-call detection to break out of "stuck" loops
  - Bounded retries with back-off for transient API errors (rate limit / timeout)
  - A reflector that nudges the model when it returns prose instead of a tool call
"""

from __future__ import annotations

import json
import time
import logging
from dataclasses import dataclass, field
from typing import Any, Callable

import google.genai as genai
from google.genai import types
import openai

from tools.registry import BARRIER_TOOLS

logger = logging.getLogger("juiceshark.loop")

# ──────────────────────────────────────────────
# Loop safety/tuning constants
# ──────────────────────────────────────────────

MAX_GENERAL_AGENT_CHAIN_ITERATIONS = 80   # slightly lower to save tokens
MAX_AGENT_SHUTDOWN_ITERATIONS      = 3
MAX_RETRIES_TO_CALL_AGENT          = 3
MAX_REFLECTOR_CALLS_PER_CHAIN      = 3
DELAY_BETWEEN_RETRIES              = 3.0  # seconds

REPEATING_TOOL_CALL_THRESHOLD      = 3
MAX_SOFT_DETECTIONS_BEFORE_ABORT   = 4


# ──────────────────────────────────────────────
# Repeating Tool Call Detector — breaks "stuck" loops where the model
# keeps issuing the same call expecting a different result.
# ──────────────────────────────────────────────

@dataclass
class RepeatingDetector:
    history: list[tuple[str, str]] = field(default_factory=list)
    soft_warning_count: int = 0
    _reflector_count: int = 0
    count: int = 0

    def detect(self, tool_name: str, args_str: str) -> bool:
        # Ignore done/barrier tools from repetition warnings
        from tools.registry import BARRIER_TOOLS
        if tool_name in BARRIER_TOOLS:
            return False

        call = (tool_name, args_str)
        self.history.append(call)
        if len(self.history) > 10:
            self.history.pop(0)

        # Count occurrences in sliding window
        appearances = self.history.count(call)
        self.count = appearances
        if appearances >= REPEATING_TOOL_CALL_THRESHOLD:
            self.soft_warning_count += 1
            return True
        return False

    def is_abort_threshold(self) -> bool:
        return self.soft_warning_count >= REPEATING_TOOL_CALL_THRESHOLD + MAX_SOFT_DETECTIONS_BEFORE_ABORT


# ──────────────────────────────────────────────
# Build tool declarations for Gemini SDK
# ──────────────────────────────────────────────

def _build_tools(tool_declarations: list[dict]) -> list[types.Tool]:
    """Convert our JSON schema tool dicts into google-genai Tool objects."""
    fn_decls = []
    for decl in tool_declarations:
        params = decl.get("parameters", {})
        fn_decls.append(
            types.FunctionDeclaration(
                name=decl["name"],
                description=decl.get("description", ""),
                parameters=_schema_dict_to_genai(params),
            )
        )
    return [types.Tool(function_declarations=fn_decls)]


def _schema_dict_to_genai(schema: dict) -> types.Schema:
    """Recursively convert a JSON Schema dict to genai Schema."""
    if not schema:
        return types.Schema(type=types.Type.OBJECT)

    type_str = schema.get("type", "object").upper()
    type_map = {
        "OBJECT":  types.Type.OBJECT,
        "STRING":  types.Type.STRING,
        "INTEGER": types.Type.INTEGER,
        "NUMBER":  types.Type.NUMBER,
        "BOOLEAN": types.Type.BOOLEAN,
        "ARRAY":   types.Type.ARRAY,
    }
    schema_type = type_map.get(type_str, types.Type.OBJECT)

    kwargs: dict[str, Any] = {"type": schema_type}

    if "description" in schema:
        kwargs["description"] = schema["description"]

    if "enum" in schema:
        kwargs["enum"] = schema["enum"]

    if "properties" in schema:
        kwargs["properties"] = {
            k: _schema_dict_to_genai(v)
            for k, v in schema["properties"].items()
        }

    if "required" in schema:
        kwargs["required"] = schema["required"]

    if "items" in schema:
        kwargs["items"] = _schema_dict_to_genai(schema["items"])

    return types.Schema(**kwargs)


def _fc_args_to_dict(args: Any) -> dict:
    """Convert Gemini function call args (MapComposite or dict) to plain dict."""
    if args is None:
        return {}
    if isinstance(args, dict):
        return args
    # MapComposite from proto
    try:
        return {k: _fc_args_to_dict(v) for k, v in args.items()}
    except Exception:
        return {}


# ──────────────────────────────────────────────
# Core Agentic Loop
# ──────────────────────────────────────────────

def perform_agent_chain(
    *,
    client: Any,
    model_name: str,
    system_prompt: str,
    initial_message: str,
    tool_declarations: list[dict],
    tool_executor: Callable[[str, dict], str],
    agent_name: str = "agent",
    state_store: Any = None,
    barrier_tools: set[str] | None = None,  # None = use global BARRIER_TOOLS
) -> str:
    """
    The main agentic loop: call the model, execute the tool it asks for, feed
    the result back, repeat until a barrier tool fires or limits are hit.

    Supports both OpenAI and Google Gemini backends.

    Returns:
        Final result string from the agent (barrier tool output or timeout message)
    """
    # Use per-agent barrier set or fall back to global
    active_barriers = barrier_tools if barrier_tools is not None else BARRIER_TOOLS

    is_openai = hasattr(client, "chat")

    if is_openai:
        openai_tools = [
            {
                "type": "function",
                "function": {
                    "name": decl["name"],
                    "description": decl.get("description", ""),
                    "parameters": decl.get("parameters", {}),
                }
            }
            for decl in tool_declarations
        ]
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": initial_message}
        ]
        gemini_tools = []
        config = None
        contents = []
    else:
        gemini_tools = _build_tools(tool_declarations)
        config = types.GenerateContentConfig(
            system_instruction=system_prompt,
            temperature=0.3,
            max_output_tokens=8192,
            tools=gemini_tools,
            tool_config=types.ToolConfig(
                function_calling_config=types.FunctionCallingConfig(mode="AUTO")
            ),
        )
        contents = [
            types.Content(role="user", parts=[types.Part(text=initial_message)])
        ]
        openai_tools = []
        messages = []

    detector = RepeatingDetector()

    def _log(action: str, tool: str = "", args: dict | None = None, result: str = ""):
        if state_store:
            state_store.log_step(agent_name, action, tool=tool, args=args or {}, result=result)

    _log("start", result=initial_message[:500])

    for iteration in range(MAX_GENERAL_AGENT_CHAIN_ITERATIONS):

        # ── Approaching limit: inject shutdown guidance ──
        if iteration >= MAX_GENERAL_AGENT_CHAIN_ITERATIONS - MAX_AGENT_SHUTDOWN_ITERATIONS:
            logger.warning(f"[{agent_name}] Approaching iteration limit ({iteration}/{MAX_GENERAL_AGENT_CHAIN_ITERATIONS})")
            shutdown_msg = (
                f"SYSTEM: You are approaching the maximum iteration limit "
                f"({MAX_GENERAL_AGENT_CHAIN_ITERATIONS}). You MUST call 'done' immediately "
                f"to conclude your work gracefully."
            )
            if is_openai:
                messages.append({"role": "user", "content": shutdown_msg})
            else:
                contents.append(types.Content(role="user", parts=[types.Part(text=shutdown_msg)]))

        # ── Call LLM with retries ──
        if is_openai:
            response = _call_openai_with_retries(
                client=client,
                model_name=model_name,
                messages=messages,
                tools=openai_tools,
                agent_name=agent_name,
            )
        else:
            response = _call_with_retries(
                client=client,
                model_name=model_name,
                contents=contents,
                config=config,
                agent_name=agent_name,
            )

        # ── Parse response parts ──
        text_content = ""
        tool_calls: list[tuple[str, dict]] = []  # (name, args)

        if is_openai:
            if response and response.choices:
                msg = response.choices[0].message
                if msg.content:
                    text_content = msg.content
                if msg.tool_calls:
                    for tc in msg.tool_calls:
                        try:
                            tc_args = json.loads(tc.function.arguments)
                        except Exception:
                            tc_args = {}
                        tool_calls.append((tc.function.name, tc_args))
        else:
            if response and response.candidates:
                candidate = response.candidates[0]
                if candidate.content and candidate.content.parts:
                    for part in candidate.content.parts:
                        if part.text:
                            text_content += part.text
                        if part.function_call:
                            fc = part.function_call
                            args = _fc_args_to_dict(fc.args)
                            tool_calls.append((fc.name, args))

        # ── Handle text-only response (no tool calls) — invoke reflector ──
        if not tool_calls:
            logger.info(f"[{agent_name}] No tool call (iter {iteration}), invoking reflector")
            _log("thinking", result=text_content[:500])

            # Add model response to history
            if is_openai:
                messages.append({"role": "assistant", "content": text_content})
            else:
                if text_content:
                    contents.append(types.Content(
                        role="model",
                        parts=[types.Part(text=text_content)]
                    ))

            # Reflector prompt
            from agent.reflector import perform_reflector
            reflector_advice = perform_reflector(
                agent_name=agent_name,
                content=text_content,
                barrier_tool_names=list(BARRIER_TOOLS),
                tool_declarations=tool_declarations,
                iteration=getattr(detector, "_reflector_count", 0) + 1,
            )
            detector._reflector_count = getattr(detector, "_reflector_count", 0) + 1

            if is_openai:
                messages.append({"role": "user", "content": reflector_advice})
            else:
                contents.append(types.Content(role="user", parts=[types.Part(text=reflector_advice)]))
            continue

        # Reset reflector count on successful tool call
        detector._reflector_count = 0

        # ── Add model response with tool calls to history ──
        if is_openai:
            messages.append(response.choices[0].message)
        else:
            model_parts = []
            if text_content:
                model_parts.append(types.Part(text=text_content))
            for tc_name, tc_args in tool_calls:
                model_parts.append(types.Part(
                    function_call=types.FunctionCall(name=tc_name, args=tc_args)
                ))
            contents.append(types.Content(role="model", parts=model_parts))

        # ── Execute each tool call ──
        hit_barrier = False
        tool_response_parts = []
        final_result = ""

        if is_openai:
            openai_tool_calls = response.choices[0].message.tool_calls or []
            for tc in openai_tool_calls:
                tc_name = tc.function.name
                try:
                    tc_args = json.loads(tc.function.arguments)
                except Exception:
                    tc_args = {}

                args_str = json.dumps(tc_args, sort_keys=True)
                _log("tool_call", tool=tc_name, args=tc_args)

                # Repeating call detection
                if detector.detect(tc_name, args_str):
                    if detector.is_abort_threshold():
                        msg = f"Tool '{tc_name}' repeated {detector.count} times. Aborting."
                        logger.error(f"[{agent_name}] {msg}")
                        return f"AGENT ABORTED: {msg}"
                    tool_result = f"WARNING: You are calling '{tc_name}' with the same arguments repeatedly ({detector.count} times). Try a different approach."
                    logger.warning(f"[{agent_name}] Repeating tool call: {tc_name}")
                else:
                    try:
                        tool_result = tool_executor(tc_name, tc_args)
                    except Exception as e:
                        tool_result = f"ERROR executing {tc_name}: {e}"
                        logger.exception(f"[{agent_name}] Tool error: {tc_name}")

                _log("tool_result", tool=tc_name, args=tc_args, result=str(tool_result)[:1000])

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": tc_name,
                    "content": str(tool_result),
                })

                if tc_name in active_barriers:
                    hit_barrier = True
                    final_result = str(tool_result)
                    logger.info(f"[{agent_name}] Barrier tool '{tc_name}' hit — stopping loop")
        else:
            for tc_name, tc_args in tool_calls:
                args_str = json.dumps(tc_args, sort_keys=True)
                _log("tool_call", tool=tc_name, args=tc_args)

                # Repeating call detection
                if detector.detect(tc_name, args_str):
                    if detector.is_abort_threshold():
                        msg = f"Tool '{tc_name}' repeated {detector.count} times. Aborting."
                        logger.error(f"[{agent_name}] {msg}")
                        return f"AGENT ABORTED: {msg}"
                    tool_result = f"WARNING: You are calling '{tc_name}' with the same arguments repeatedly ({detector.count} times). Try a different approach."
                    logger.warning(f"[{agent_name}] Repeating tool call: {tc_name}")
                else:
                    try:
                        tool_result = tool_executor(tc_name, tc_args)
                    except Exception as e:
                        tool_result = f"ERROR executing {tc_name}: {e}"
                        logger.exception(f"[{agent_name}] Tool error: {tc_name}")

                _log("tool_result", tool=tc_name, args=tc_args, result=str(tool_result)[:1000])

                tool_response_parts.append(types.Part(
                    function_response=types.FunctionResponse(
                        name=tc_name,
                        response={"result": str(tool_result)},
                    )
                ))

                if tc_name in active_barriers:
                    hit_barrier = True
                    final_result = str(tool_result)
                    logger.info(f"[{agent_name}] Barrier tool '{tc_name}' hit — stopping loop")

            # Append tool responses
            contents.append(types.Content(role="user", parts=tool_response_parts))

        if hit_barrier:
            _log("done", result=final_result)
            return final_result

    logger.error(f"[{agent_name}] Exceeded max iterations ({MAX_GENERAL_AGENT_CHAIN_ITERATIONS})")
    return f"AGENT TIMEOUT: exceeded {MAX_GENERAL_AGENT_CHAIN_ITERATIONS} iterations"



# ──────────────────────────────────────────────
# OpenAI API Call with Retries
# ──────────────────────────────────────────────

def _call_openai_with_retries(
    *,
    client: Any,
    model_name: str,
    messages: list,
    tools: list,
    agent_name: str,
) -> Any:
    last_error = None
    attempts = 0
    
    while attempts < MAX_RETRIES_TO_CALL_AGENT + 5:  # allow extra retries for rate limits
        attempts += 1
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=messages,
                tools=tools,
                tool_choice="auto",
                temperature=0.3,
                timeout=120.0,
            )
            return response
        except Exception as e:
            last_error = e
            error_str = str(e)
            logger.warning(f"[{agent_name}] OpenAI API error attempt {attempts}: {error_str[:200]}")
            
            # Check for Rate Limit or Quota issues (HTTP 429)
            if "429" in error_str or "rate_limit" in error_str.lower() or "insufficient_quota" in error_str.lower():
                wait_time = 15.0
                if "insufficient_quota" in error_str.lower() or "billing" in error_str.lower():
                    logger.error(f"[{agent_name}] OpenAI Quota Exceeded / Billing issue. Cannot proceed.")
                    raise e
                
                logger.info(f"[{agent_name}] OpenAI Rate limited. Waiting {wait_time:.1f}s before retry...")
                time.sleep(wait_time)
                continue
                
            if attempts < MAX_RETRIES_TO_CALL_AGENT:
                time.sleep(DELAY_BETWEEN_RETRIES * attempts)
            else:
                break
                
    raise RuntimeError(f"All OpenAI API retries failed for [{agent_name}]: {last_error}")


# ──────────────────────────────────────────────
# Gemini API Call with Retries
# ──────────────────────────────────────────────

def _call_with_retries(
    *,
    client: genai.Client,
    model_name: str,
    contents: list,
    config: types.GenerateContentConfig,
    agent_name: str,
) -> Any:
    last_error = None
    import re
    
    # We may hit 429 quota errors which tell us exactly how long to wait
    # e.g., "Please retry in 5.8s."
    MAX_429_RETRIES = 5
    attempts = 0
    
    while attempts < MAX_RETRIES_TO_CALL_AGENT + MAX_429_RETRIES:
        attempts += 1
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=contents,
                config=config,
            )
            return response
        except Exception as e:
            last_error = e
            error_str = str(e)
            logger.warning(f"[{agent_name}] API error attempt {attempts}: {error_str[:200]}")
            
            # Handle 429 Quota Exceeded (specifically the Free Tier RPM limit)
            if "429" in error_str or "RESOURCE_EXHAUSTED" in error_str:
                wait_time = 15.0 # Default fallback wait
                match = re.search(r"Please retry in ([\d\.]+)s", error_str)
                if match:
                    try:
                        wait_time = float(match.group(1)) + 1.0 # Add 1s buffer
                    except ValueError:
                        pass
                
                logger.info(f"[{agent_name}] Rate limited. Waiting {wait_time:.1f}s before retry...")
                time.sleep(wait_time)
                continue # 429s don't count towards the normal MAX_RETRIES_TO_CALL_AGENT as strictly
                
            # Normal error backoff
            if attempts < MAX_RETRIES_TO_CALL_AGENT:
                time.sleep(DELAY_BETWEEN_RETRIES * attempts)
            else:
                break # Reached normal max retries

    raise RuntimeError(f"All API retries failed for [{agent_name}]: {last_error}")
