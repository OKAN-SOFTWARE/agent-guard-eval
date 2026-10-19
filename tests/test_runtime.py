"""Tests for AgentGuard runtime guardrail middleware and decorators."""

import pytest

from agentguard.models import Severity
from agentguard.runtime import (
    AgentGuardBlockedException,
    AgentGuardRuntime,
    RuntimeMode,
)


def test_runtime_allows_benign_tool_call():
    runtime = AgentGuardRuntime(mode=RuntimeMode.BLOCK)
    decision = runtime.intercept("calculator", {"expression": "2 + 2"})

    assert decision.allowed is True
    assert decision.step_id == 1
    assert decision.finding is None
    assert len(runtime.tool_calls) == 1
    assert runtime.tool_calls[0].tool_name == "calculator"


def test_runtime_blocks_command_injection():
    runtime = AgentGuardRuntime(mode=RuntimeMode.BLOCK, fail_on=Severity.HIGH)

    with pytest.raises(AgentGuardBlockedException) as exc_info:
        runtime.intercept("bash_execute", {"cmd": "cat report.txt; rm -rf /"})

    assert "AG-003-B" in str(exc_info.value)
    assert exc_info.value.tool_name == "bash_execute"


def test_runtime_synthetic_error_mode():
    runtime = AgentGuardRuntime(mode=RuntimeMode.SYNTHETIC_ERROR, fail_on=Severity.HIGH)
    decision = runtime.intercept(
        "web_fetch", {"url": "http://169.254.169.254/latest/meta-data/"}
    )

    assert decision.allowed is False
    assert decision.synthetic_error is not None
    assert decision.synthetic_error["agentguard_blocked"] is True
    assert "AG-004-B" in decision.synthetic_error["error"]


def test_runtime_monitor_mode():
    runtime = AgentGuardRuntime(mode=RuntimeMode.MONITOR, fail_on=Severity.HIGH)
    decision = runtime.intercept(
        "sql_query", {"query": "SELECT * FROM users WHERE id = 1 OR 1=1"}
    )

    assert decision.allowed is True
    assert len(runtime.findings) > 0
    assert any(f.rule_id == "AG-003-D" for f in runtime.findings)


def test_runtime_decorator_sync():
    runtime = AgentGuardRuntime(mode=RuntimeMode.SYNTHETIC_ERROR)

    @runtime.protect(tool_name="bash_exec")
    def execute_command(cmd: str) -> str:
        return f"Executed: {cmd}"

    # Safe call
    res = execute_command("ls -la")
    assert res == "Executed: ls -la"

    # Malicious call
    blocked_res = execute_command("cat file.txt | bash")
    assert isinstance(blocked_res, dict)
    assert blocked_res["agentguard_blocked"] is True

    # Check trace export
    trace = runtime.to_trace()
    assert len(trace.tool_calls) == 2
    assert trace.tool_calls[0].duration_ms is not None
    assert trace.tool_calls[0].output == "Executed: ls -la"


def test_runtime_decorator_async():
    import asyncio

    runtime = AgentGuardRuntime(mode=RuntimeMode.BLOCK)

    @runtime.protect_async(tool_name="async_fetch")
    async def fetch_url(url: str) -> str:
        return f"Content of {url}"

    async def runner():
        res = await fetch_url("https://api.github.com/repos")
        assert res == "Content of https://api.github.com/repos"

        with pytest.raises(AgentGuardBlockedException):
            await fetch_url("file:///etc/passwd")

    asyncio.run(runner())
