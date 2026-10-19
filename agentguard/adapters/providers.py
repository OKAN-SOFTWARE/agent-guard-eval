"""OpenAI and Anthropic message trace parsers for direct SDK trace evaluation."""

from __future__ import annotations

import json
from typing import Any

from agentguard.models import AgentTrace, ToolCall


def _get_val(obj: Any, key: str, default: Any = None) -> Any:
    """Safely get an attribute or dictionary key."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def parse_openai_messages(
    messages: list[Any],
    session_id: str = "openai-session",
    agent_name: str = "openai_agent",
) -> AgentTrace:
    """
    Parse a conversation history from OpenAI Chat Completions into an AgentTrace.

    Supports both raw dictionaries and OpenAI SDK model objects.
    """
    user_prompt = ""
    final_response: str | None = None
    tool_calls: list[ToolCall] = []

    # Map tool_call_id to ToolCall for output correlation
    call_id_to_tool: dict[str, ToolCall] = {}
    step_id = 0

    for msg in messages:
        role = _get_val(msg, "role", "")
        content = _get_val(msg, "content", "")

        if role == "user" and not user_prompt:
            if isinstance(content, str):
                user_prompt = content
            elif isinstance(content, list):
                # Multimodal or text block list
                for part in content:
                    if _get_val(part, "type") == "text":
                        user_prompt = _get_val(part, "text", "")
                        break

        elif role == "assistant":
            raw_tool_calls = _get_val(msg, "tool_calls")
            if raw_tool_calls:
                for tc in raw_tool_calls:
                    step_id += 1
                    call_id = _get_val(tc, "id") or f"call_{step_id}"
                    fn = _get_val(tc, "function") or {}
                    tool_name = _get_val(fn, "name") or "unknown_tool"
                    raw_args = _get_val(fn, "arguments") or {}

                    if isinstance(raw_args, str):
                        try:
                            arguments = json.loads(raw_args)
                        except (json.JSONDecodeError, TypeError):
                            arguments = {"raw": raw_args}
                    elif isinstance(raw_args, dict):
                        arguments = raw_args
                    else:
                        arguments = {}

                    tool_obj = ToolCall(
                        step_id=step_id,
                        tool_name=tool_name,
                        arguments=arguments,
                    )
                    tool_calls.append(tool_obj)
                    call_id_to_tool[call_id] = tool_obj

            if content and isinstance(content, str):
                final_response = content

        elif role == "tool":
            call_id = _get_val(msg, "tool_call_id")
            if call_id and call_id in call_id_to_tool:
                target_tool = call_id_to_tool[call_id]
                if isinstance(content, str):
                    try:
                        target_tool.output = json.loads(content)
                    except (json.JSONDecodeError, TypeError):
                        target_tool.output = content
                else:
                    target_tool.output = content

    return AgentTrace(
        session_id=session_id,
        agent_name=agent_name,
        user_prompt=user_prompt,
        tool_calls=tool_calls,
        final_response=final_response,
    )


def parse_anthropic_messages(
    messages: list[Any],
    session_id: str = "anthropic-session",
    agent_name: str = "claude_agent",
) -> AgentTrace:
    """
    Parse a conversation history from Anthropic Claude Messages API into an AgentTrace.

    Supports both raw dictionaries and Anthropic SDK message objects.
    """
    user_prompt = ""
    final_response: str | None = None
    tool_calls: list[ToolCall] = []

    tool_use_id_to_tool: dict[str, ToolCall] = {}
    step_id = 0

    for msg in messages:
        role = _get_val(msg, "role", "")
        content = _get_val(msg, "content", "")

        if role == "user":
            if isinstance(content, str) and not user_prompt:
                user_prompt = content
            elif isinstance(content, list):
                for block in content:
                    b_type = _get_val(block, "type")
                    if b_type == "text" and not user_prompt:
                        user_prompt = _get_val(block, "text", "")
                    elif b_type == "tool_result":
                        tool_use_id = _get_val(block, "tool_use_id")
                        if tool_use_id and tool_use_id in tool_use_id_to_tool:
                            result_content = _get_val(block, "content")
                            tool_use_id_to_tool[tool_use_id].output = result_content
                            if _get_val(block, "is_error", False):
                                tool_use_id_to_tool[tool_use_id].error = str(
                                    result_content
                                )

        elif role == "assistant":
            if isinstance(content, str):
                final_response = content
            elif isinstance(content, list):
                for block in content:
                    b_type = _get_val(block, "type")
                    if b_type == "text":
                        final_response = _get_val(block, "text", "")
                    elif b_type == "tool_use":
                        step_id += 1
                        use_id = _get_val(block, "id") or f"toolu_{step_id}"
                        tool_name = _get_val(block, "name") or "unknown_tool"
                        tool_input = _get_val(block, "input") or {}
                        if not isinstance(tool_input, dict):
                            tool_input = {"raw": tool_input}

                        tool_obj = ToolCall(
                            step_id=step_id,
                            tool_name=tool_name,
                            arguments=tool_input,
                        )
                        tool_calls.append(tool_obj)
                        tool_use_id_to_tool[use_id] = tool_obj

    return AgentTrace(
        session_id=session_id,
        agent_name=agent_name,
        user_prompt=user_prompt,
        tool_calls=tool_calls,
        final_response=final_response,
    )
