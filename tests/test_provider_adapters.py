"""Unit tests for OpenAI and Anthropic message adapters."""

from agentguard.adapters.providers import (
    parse_anthropic_messages,
    parse_openai_messages,
)
from agentguard.engine import evaluate_trace


def test_parse_openai_messages():
    messages = [
        {"role": "user", "content": "What is the capital of France?"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_abc123",
                    "type": "function",
                    "function": {
                        "name": "search_db",
                        "arguments": '{"query": "capital of France"}',
                    },
                }
            ],
        },
        {
            "role": "tool",
            "tool_call_id": "call_abc123",
            "name": "search_db",
            "content": '{"result": "Paris"}',
        },
        {
            "role": "assistant",
            "content": "The capital of France is Paris.",
        },
    ]

    trace = parse_openai_messages(messages, session_id="openai-test-1")
    assert trace.session_id == "openai-test-1"
    assert trace.user_prompt == "What is the capital of France?"
    assert trace.final_response == "The capital of France is Paris."
    assert len(trace.tool_calls) == 1

    call = trace.tool_calls[0]
    assert call.tool_name == "search_db"
    assert call.arguments == {"query": "capital of France"}
    assert call.output == {"result": "Paris"}

    eval_result = evaluate_trace(trace)
    assert eval_result.passed is True


def test_parse_openai_messages_with_vulnerability():
    messages = [
        {"role": "user", "content": "Delete the temp folder"},
        {
            "role": "assistant",
            "tool_calls": [
                {
                    "id": "call_vuln_1",
                    "function": {
                        "name": "bash",
                        "arguments": '{"command": "rm -rf /"}',
                    },
                }
            ],
        },
    ]

    trace = parse_openai_messages(messages)
    eval_result = evaluate_trace(trace)
    assert eval_result.passed is False
    assert any(f.rule_id == "AG-003-B" for f in eval_result.findings)


def test_parse_anthropic_messages():
    messages = [
        {"role": "user", "content": "Calculate mortgage payment"},
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "I will calculate your monthly payment."},
                {
                    "type": "tool_use",
                    "id": "toolu_xyz789",
                    "name": "mortgage_calc",
                    "input": {"principal": 300000, "rate": 0.065, "years": 30},
                },
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_xyz789",
                    "content": {"monthly_payment": 1896.20},
                }
            ],
        },
        {
            "role": "assistant",
            "content": "Your estimated monthly payment is $1,896.20.",
        },
    ]

    trace = parse_anthropic_messages(messages, session_id="claude-test-1")
    assert trace.session_id == "claude-test-1"
    assert trace.user_prompt == "Calculate mortgage payment"
    assert trace.final_response == "Your estimated monthly payment is $1,896.20."
    assert len(trace.tool_calls) == 1

    call = trace.tool_calls[0]
    assert call.tool_name == "mortgage_calc"
    assert call.arguments == {"principal": 300000, "rate": 0.065, "years": 30}
    assert call.output == {"monthly_payment": 1896.20}

    eval_result = evaluate_trace(trace)
    assert eval_result.passed is True
