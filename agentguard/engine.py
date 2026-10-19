"""Evaluation engine orchestrator for AgentGuard."""

import time

from agentguard.evaluators.base import BaseEvaluator
from agentguard.evaluators.budget_guard import TokenAndCostBudgetGuard
from agentguard.evaluators.latency_guard import LatencyAndSLAGuard
from agentguard.evaluators.loop_detector import LoopDetector
from agentguard.evaluators.schema_validator import SchemaValidator
from agentguard.evaluators.security_guard import SecurityGuard
from agentguard.evaluators.ssrf_guard import SSRFAndExfiltrationGuard
from agentguard.evaluators.taint_guard import TaintFlowGuard
from agentguard.models import AgentTrace, EvaluationResult, Finding


def get_default_evaluators() -> list[BaseEvaluator]:
    """Returns the standard production suite of deterministic trace evaluators."""
    return [
        SchemaValidator(),
        LoopDetector(),
        SecurityGuard(),
        SSRFAndExfiltrationGuard(),
        TokenAndCostBudgetGuard(),
        LatencyAndSLAGuard(),
        TaintFlowGuard(),
    ]


def evaluate_trace(
    trace: AgentTrace,
    evaluators: list[BaseEvaluator] | None = None,
) -> EvaluationResult:
    """
    Evaluates an agent execution trace against all registered evaluators.

    Args:
        trace: The structured trace of agent tool calls and interactions.
        evaluators: Optional list of evaluators. Defaults to standard suite.

    Returns:
        EvaluationResult containing overall pass/fail status, statistics, and findings.
    """
    if evaluators is None:
        evaluators = get_default_evaluators()

    start_time = time.perf_counter()
    all_findings: list[Finding] = []

    for evaluator in evaluators:
        findings = evaluator.evaluate(trace)
        all_findings.extend(findings)

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    total_checks = len(evaluators)
    # A check passes if no finding with its rule ID prefix was emitted
    failed_rule_ids = {
        f.rule_id.split("-")[0] + "-" + f.rule_id.split("-")[1] for f in all_findings
    }
    failed_checks = len(failed_rule_ids)
    passed_checks = max(0, total_checks - failed_checks)

    # Trace is considered passed if no findings exist
    passed = len(all_findings) == 0

    return EvaluationResult(
        session_id=trace.session_id,
        passed=passed,
        total_checks=total_checks,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        findings=all_findings,
        duration_ms=round(elapsed_ms, 2),
    )
