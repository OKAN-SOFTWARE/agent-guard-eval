"""Tests for AgentTraceSanitizer and secret redaction."""

from agentguard.models import AgentTrace, ToolCall
from agentguard.sanitizer import AgentTraceSanitizer


def test_sanitizer_masks_credentials():
    sanitizer = AgentTraceSanitizer()
    trace = AgentTrace(
        session_id="test-clean-1",
        user_prompt="Run with key AKIA1234567890ABCDEF",
        tool_calls=[
            ToolCall(
                step_id=1,
                tool_name="api_call",
                arguments={
                    "token": "sk-proj-test1234567890abcdef1234567890abcdef",
                    "auth": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz",
                },
            )
        ],
        final_response="Key was sk-proj-test1234567890abcdef1234567890abcdef",
    )

    clean_trace, count = sanitizer.sanitize(trace)
    assert count >= 4
    assert "AKIA" not in clean_trace.user_prompt
    assert "[REDACTED:AWS_ACCESS_KEY]" in clean_trace.user_prompt
    assert "sk-proj" not in str(clean_trace.tool_calls[0].arguments)
    assert "[REDACTED:OPENAI_KEY]" in str(clean_trace.tool_calls[0].arguments)
    assert "[REDACTED:BEARER_TOKEN]" in str(clean_trace.tool_calls[0].arguments)
    assert clean_trace.metadata.get("sanitized") is True


def test_sanitizer_prunes_payload_and_defangs_path():
    sanitizer = AgentTraceSanitizer(max_string_length=100)
    trace = AgentTrace(
        session_id="test-clean-2",
        tool_calls=[
            ToolCall(
                step_id=1,
                tool_name="read_file",
                arguments={"path": "../../../etc/passwd", "huge_data": "A" * 500},
            )
        ],
    )

    clean_trace, count = sanitizer.sanitize(trace)
    assert count >= 2
    path_val = clean_trace.tool_calls[0].arguments["path"]
    assert "../" not in path_val
    assert "[DEFANGED_PATH]" in path_val
    huge_val = clean_trace.tool_calls[0].arguments["huge_data"]
    assert len(huge_val) < 200
    assert "[TRUNCATED:" in huge_val
