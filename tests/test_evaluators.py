"""Tests for AgentGuard trace evaluators."""

from agentguard.evaluators.loop_detector import LoopDetector
from agentguard.evaluators.schema_validator import SchemaValidator
from agentguard.evaluators.security_guard import SecurityGuard
from agentguard.models import AgentTrace, Severity, ToolCall


def test_schema_validator_undeclared_tool():
    validator = SchemaValidator(
        tool_schemas={
            "search": {
                "type": "object",
                "required": ["q"],
                "properties": {"q": {"type": "string"}},
            }
        }
    )
    trace = AgentTrace(
        session_id="test-1",
        tool_calls=[
            ToolCall(step_id=1, tool_name="bash_eval", arguments={"cmd": "whoami"})
        ],
    )
    findings = validator.evaluate(trace)
    assert len(findings) == 1
    assert findings[0].rule_id == "AG-001-A"
    assert "Undeclared" in findings[0].rule_name


def test_schema_validator_argument_drift():
    validator = SchemaValidator(
        tool_schemas={
            "search": {
                "type": "object",
                "required": ["q"],
                "properties": {"q": {"type": "string"}},
            }
        }
    )
    trace = AgentTrace(
        session_id="test-2",
        tool_calls=[
            ToolCall(step_id=1, tool_name="search", arguments={"invalid_arg": 123})
        ],
    )
    findings = validator.evaluate(trace)
    assert len(findings) == 1
    assert findings[0].rule_id == "AG-001-B"


def test_loop_detector_identical_invocations():
    detector = LoopDetector(max_identical_calls=3)
    trace = AgentTrace(
        session_id="test-3",
        tool_calls=[
            ToolCall(step_id=1, tool_name="ping", arguments={"host": "1.1.1.1"}),
            ToolCall(step_id=2, tool_name="ping", arguments={"host": "1.1.1.1"}),
            ToolCall(step_id=3, tool_name="ping", arguments={"host": "1.1.1.1"}),
        ],
    )
    findings = detector.evaluate(trace)
    assert any(f.rule_id == "AG-002-B" for f in findings)


def test_loop_detector_cycle():
    detector = LoopDetector(cycle_threshold=3, max_cycle_length=2)
    trace = AgentTrace(
        session_id="test-4",
        tool_calls=[
            ToolCall(step_id=1, tool_name="tool_a"),
            ToolCall(step_id=2, tool_name="tool_b"),
            ToolCall(step_id=3, tool_name="tool_a"),
            ToolCall(step_id=4, tool_name="tool_b"),
            ToolCall(step_id=5, tool_name="tool_a"),
            ToolCall(step_id=6, tool_name="tool_b"),
        ],
    )
    findings = detector.evaluate(trace)
    assert any(f.rule_id == "AG-002-C" for f in findings)


def test_security_guard_path_traversal():
    guard = SecurityGuard()
    trace = AgentTrace(
        session_id="test-5",
        tool_calls=[
            ToolCall(
                step_id=1, tool_name="read", arguments={"file": "../../../etc/passwd"}
            ),
        ],
    )
    findings = guard.evaluate(trace)
    assert len(findings) == 1
    assert findings[0].rule_id == "AG-003-A"
    assert findings[0].severity == Severity.HIGH


def test_security_guard_command_injection():
    guard = SecurityGuard()
    trace = AgentTrace(
        session_id="test-6",
        tool_calls=[
            ToolCall(
                step_id=1,
                tool_name="exec",
                arguments={"cmd": "rm -rf / --no-preserve-root"},
            ),
        ],
    )
    findings = guard.evaluate(trace)
    assert any(f.rule_id == "AG-003-B" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_security_guard_secret_leak():
    guard = SecurityGuard()
    trace = AgentTrace(
        session_id="test-7",
        tool_calls=[
            ToolCall(
                step_id=1,
                tool_name="request",
                arguments={"header": "Bearer sk-proj-1234567890abcdef1234567890abcdef"},
            ),
        ],
    )
    findings = guard.evaluate(trace)
    assert any(f.rule_id == "AG-003-C" for f in findings)


def test_security_guard_sql_injection():
    guard = SecurityGuard()
    trace = AgentTrace(
        session_id="test-8",
        tool_calls=[
            ToolCall(
                step_id=1,
                tool_name="db",
                arguments={"query": "SELECT * FROM users WHERE 1=1 OR 2=2"},
            ),
        ],
    )
    findings = guard.evaluate(trace)
    assert any(f.rule_id == "AG-003-D" for f in findings)


def test_ssrf_guard_imds_probe():
    from agentguard.evaluators.ssrf_guard import SSRFAndExfiltrationGuard

    guard = SSRFAndExfiltrationGuard()
    trace = AgentTrace(
        session_id="test-ssrf-1",
        tool_calls=[
            ToolCall(
                step_id=1,
                tool_name="http_get",
                arguments={
                    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                },
            )
        ],
    )
    findings = guard.evaluate(trace)
    assert len(findings) == 1
    assert findings[0].rule_id == "AG-004-B"
    assert findings[0].severity == Severity.CRITICAL


def test_ssrf_guard_private_ip_and_file():
    from agentguard.evaluators.ssrf_guard import SSRFAndExfiltrationGuard

    guard = SSRFAndExfiltrationGuard()
    trace = AgentTrace(
        session_id="test-ssrf-2",
        tool_calls=[
            ToolCall(
                step_id=1,
                tool_name="fetch",
                arguments={"url": "http://192.168.1.100/admin"},
            ),
            ToolCall(
                step_id=2, tool_name="fetch", arguments={"url": "file:///etc/shadow"}
            ),
        ],
    )
    findings = guard.evaluate(trace)
    assert any(f.rule_id == "AG-004-C" for f in findings)
    assert any(f.rule_id == "AG-004-A" for f in findings)


def test_budget_guard_payload_bloat_and_token_ceiling():
    from agentguard.evaluators.budget_guard import TokenAndCostBudgetGuard

    guard = TokenAndCostBudgetGuard(
        max_step_payload_bytes=1000, max_session_estimated_tokens=500
    )
    trace = AgentTrace(
        session_id="test-budget-1",
        tool_calls=[
            ToolCall(step_id=1, tool_name="query", arguments={"data": "x" * 2000}),
        ],
    )
    findings = guard.evaluate(trace)
    assert any(f.rule_id == "AG-005-A" for f in findings)
    assert any(f.rule_id == "AG-005-B" for f in findings)


def test_budget_guard_cascading_failures():
    from agentguard.evaluators.budget_guard import TokenAndCostBudgetGuard

    guard = TokenAndCostBudgetGuard(max_failure_rate_threshold=0.5)
    trace = AgentTrace(
        session_id="test-budget-2",
        tool_calls=[
            ToolCall(step_id=1, tool_name="t1", error="Network error"),
            ToolCall(step_id=2, tool_name="t2", error="Timeout"),
            ToolCall(step_id=3, tool_name="t3", error="Bad gateway"),
            ToolCall(step_id=4, tool_name="t4", output="ok"),
        ],
    )
    findings = guard.evaluate(trace)
    assert any(f.rule_id == "AG-005-C" for f in findings)
