"""Tests for LatencyAndSLAGuard (AG-006)."""

from agentguard.evaluators.latency_guard import LatencyAndSLAGuard
from agentguard.models import AgentTrace, Severity, ToolCall


def test_latency_guard_step_spike():
    guard = LatencyAndSLAGuard(max_step_duration_ms=2000.0)
    trace = AgentTrace(
        session_id="test-lat-1",
        tool_calls=[
            ToolCall(step_id=1, tool_name="fetch_slow", duration_ms=2500.0),
            ToolCall(step_id=2, tool_name="cache_hit", duration_ms=50.0),
        ],
    )
    findings = guard.evaluate(trace)
    assert len(findings) == 1
    assert findings[0].rule_id == "AG-006-A"
    assert findings[0].severity == Severity.HIGH
    assert "2500.0ms" in findings[0].message


def test_latency_guard_session_sla_breach():
    guard = LatencyAndSLAGuard(
        max_step_duration_ms=5000.0, max_session_duration_ms=4000.0
    )
    trace = AgentTrace(
        session_id="test-lat-2",
        tool_calls=[
            ToolCall(step_id=1, tool_name="db1", duration_ms=2200.0),
            ToolCall(step_id=2, tool_name="db2", duration_ms=2300.0),
        ],
    )
    findings = guard.evaluate(trace)
    assert any(f.rule_id == "AG-006-B" for f in findings)


def test_latency_guard_progressive_degradation():
    guard = LatencyAndSLAGuard(
        max_step_duration_ms=10000.0,
        max_session_duration_ms=50000.0,
        degradation_threshold_ratio=1.5,
    )
    trace = AgentTrace(
        session_id="test-lat-3",
        tool_calls=[
            ToolCall(step_id=1, tool_name="query", duration_ms=100.0),
            ToolCall(step_id=2, tool_name="query", duration_ms=200.0),
            ToolCall(step_id=3, tool_name="query", duration_ms=450.0),
        ],
    )
    findings = guard.evaluate(trace)
    assert any(f.rule_id == "AG-006-C" for f in findings)
    assert any(f.severity == Severity.MEDIUM for f in findings)


def test_latency_guard_normal():
    guard = LatencyAndSLAGuard()
    trace = AgentTrace(
        session_id="test-lat-4",
        tool_calls=[
            ToolCall(step_id=1, tool_name="query", duration_ms=120.0),
            ToolCall(step_id=2, tool_name="query", duration_ms=115.0),
        ],
    )
    findings = guard.evaluate(trace)
    assert len(findings) == 0
