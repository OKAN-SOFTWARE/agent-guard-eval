"""AgentGuard: Deterministic Security & Reliability Evaluation Framework for AI Agents."""

from agentguard.diff import (
    DiffSummary,
    TraceDiffEngine,
    render_diff_console,
    render_diff_markdown,
)
from agentguard.engine import evaluate_trace, get_default_evaluators
from agentguard.evaluators.base import BaseEvaluator
from agentguard.evaluators.budget_guard import TokenAndCostBudgetGuard
from agentguard.evaluators.latency_guard import LatencyAndSLAGuard
from agentguard.evaluators.loop_detector import LoopDetector
from agentguard.evaluators.schema_validator import SchemaValidator
from agentguard.evaluators.security_guard import SecurityGuard
from agentguard.evaluators.ssrf_guard import SSRFAndExfiltrationGuard
from agentguard.evaluators.taint_guard import TaintFlowGuard
from agentguard.models import (
    AgentTrace,
    EvaluationResult,
    Finding,
    Severity,
    ToolCall,
)
from agentguard.redteam.fuzzer import AgentRedTeamFuzzer, RedTeamTestCase
from agentguard.reporters.console import render_console_report
from agentguard.reporters.html import render_html_report
from agentguard.reporters.junit import render_junit_report
from agentguard.reporters.sarif import render_sarif_report
from agentguard.runtime import (
    AgentGuardBlockedException,
    AgentGuardRuntime,
    InterceptDecision,
    RuntimeMode,
)

__version__ = "0.2.0"

__all__ = [
    "AgentGuardBlockedException",
    "AgentGuardRuntime",
    "AgentRedTeamFuzzer",
    "AgentTrace",
    "BaseEvaluator",
    "DiffSummary",
    "EvaluationResult",
    "Finding",
    "InterceptDecision",
    "LatencyAndSLAGuard",
    "LoopDetector",
    "RedTeamTestCase",
    "RuntimeMode",
    "SSRFAndExfiltrationGuard",
    "SchemaValidator",
    "SecurityGuard",
    "Severity",
    "TaintFlowGuard",
    "TokenAndCostBudgetGuard",
    "ToolCall",
    "TraceDiffEngine",
    "evaluate_trace",
    "get_default_evaluators",
    "render_console_report",
    "render_diff_console",
    "render_diff_markdown",
    "render_html_report",
    "render_junit_report",
    "render_sarif_report",
]
