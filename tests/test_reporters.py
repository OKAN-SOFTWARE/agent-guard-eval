"""Tests for reporters (console, junit, sarif)."""

import json

from agentguard.engine import evaluate_trace
from agentguard.models import AgentTrace, ToolCall
from agentguard.reporters.console import render_console_report
from agentguard.reporters.html import render_html_report
from agentguard.reporters.junit import render_junit_report
from agentguard.reporters.sarif import render_sarif_report


def test_console_and_junit_sarif_reporters():
    trace = AgentTrace(
        session_id="test-session-report",
        tool_calls=[
            ToolCall(
                step_id=1,
                tool_name="bash_execute",
                arguments={"command": "rm -rf /"},
            )
        ],
    )
    result = evaluate_trace(trace)
    assert not result.passed
    assert len(result.findings) >= 1

    # Test Console Reporter
    console_out = render_console_report(result)
    assert "AgentGuard Evaluation Summary" in console_out
    assert "AG-003-B" in console_out or "command injection" in console_out

    # Test JUnit Reporter
    junit_out = render_junit_report(result)
    assert '<?xml version="1.0" encoding="UTF-8"?>' in junit_out
    assert "<testsuite" in junit_out
    assert "failures=" in junit_out
    assert "<failure" in junit_out

    # Test SARIF Reporter
    sarif_out = render_sarif_report(result)
    sarif_json = json.loads(sarif_out)
    assert sarif_json["version"] == "2.1.0"
    assert len(sarif_json["runs"][0]["results"]) >= 1
    assert sarif_json["runs"][0]["results"][0]["level"] == "error"

    # Test HTML Reporter
    html_out = render_html_report(result, trace=trace)
    assert "<!DOCTYPE html>" in html_out
    assert "AgentGuard Evaluation Report" in html_out
    assert "test-session-report" in html_out
    assert "FAILED" in html_out
    assert "bash_execute" in html_out
