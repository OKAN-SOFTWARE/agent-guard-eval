"""JUnit XML reporter for CI test runner integration."""

import html
from typing import List
from agentguard.models import EvaluationResult, Finding


def render_junit_report(result: EvaluationResult) -> str:
    """Generates standard JUnit XML string from EvaluationResult."""
    testsuite_name = f"agentguard.{result.session_id}"
    tests_count = result.total_checks
    failures_count = result.failed_checks
    time_sec = result.duration_ms / 1000.0

    lines: List[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuite name="{html.escape(testsuite_name)}" tests="{tests_count}" failures="{failures_count}" errors="0" time="{time_sec:.3f}">',
    ]

    # Map findings by rule prefix
    findings_by_rule = {}
    for f in result.findings:
        prefix = f.rule_id.split("-")[0] + "-" + f.rule_id.split("-")[1]
        findings_by_rule.setdefault(prefix, []).append(f)

    # Standard checks
    standard_rules = [
        ("AG-001", "ToolSchemaAdherence"),
        ("AG-002", "RunawayLoopAndStateThrashing"),
        ("AG-003", "SecurityAndVulnerabilityGuard"),
    ]

    for rule_id, rule_name in standard_rules:
        rule_findings: List[Finding] = findings_by_rule.get(rule_id, [])
        lines.append(f'  <testcase classname="AgentGuard" name="{rule_name}" time="0.001">')
        if rule_findings:
            for rf in rule_findings:
                msg = html.escape(rf.message)
                details = html.escape(str(rf.details))
                lines.append(
                    f'    <failure message="{msg}" type="{rf.severity.value}">'
                    f"{msg}\nDetails: {details}\nStep: {rf.step_id}\nTool: {rf.tool_name}"
                    f"</failure>"
                )
        lines.append("  </testcase>")

    lines.append("</testsuite>")
    return "\n".join(lines)
