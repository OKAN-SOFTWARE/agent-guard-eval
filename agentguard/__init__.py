"""AgentGuard: Deterministic Security & Reliability Evaluation Framework for AI Agents."""

from agentguard.engine import evaluate_trace, get_default_evaluators
from agentguard.evaluators.base import BaseEvaluator
from agentguard.evaluators.budget_guard import TokenAndCostBudgetGuard
from agentguard.evaluators.loop_detector import LoopDetector
from agentguard.evaluators.schema_validator import SchemaValidator
from agentguard.evaluators.security_guard import SecurityGuard
from agentguard.evaluators.ssrf_guard import SSRFAndExfiltrationGuard
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

__version__ = "0.2.0"

__all__ = [
    "AgentRedTeamFuzzer",
    "AgentTrace",
    "BaseEvaluator",
    "EvaluationResult",
    "Finding",
    "LoopDetector",
    "RedTeamTestCase",
    "SSRFAndExfiltrationGuard",
    "SchemaValidator",
    "SecurityGuard",
    "Severity",
    "TokenAndCostBudgetGuard",
    "ToolCall",
    "evaluate_trace",
    "get_default_evaluators",
    "render_console_report",
    "render_html_report",
    "render_junit_report",
    "render_sarif_report",
]
