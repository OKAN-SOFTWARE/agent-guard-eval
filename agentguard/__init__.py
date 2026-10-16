"""AgentGuard: Deterministic Security & Reliability Evaluation Framework for AI Agents."""

from agentguard.engine import evaluate_trace, get_default_evaluators
from agentguard.evaluators.base import BaseEvaluator
from agentguard.evaluators.loop_detector import LoopDetector
from agentguard.evaluators.schema_validator import SchemaValidator
from agentguard.evaluators.security_guard import SecurityGuard
from agentguard.models import (
    AgentTrace,
    EvaluationResult,
    Finding,
    Severity,
    ToolCall,
)
from agentguard.redteam.fuzzer import AgentRedTeamFuzzer, RedTeamTestCase
from agentguard.reporters.console import render_console_report
from agentguard.reporters.junit import render_junit_report
from agentguard.reporters.sarif import render_sarif_report

__version__ = "0.1.0"

__all__ = [
    "AgentTrace",
    "ToolCall",
    "Finding",
    "Severity",
    "EvaluationResult",
    "BaseEvaluator",
    "SchemaValidator",
    "LoopDetector",
    "SecurityGuard",
    "AgentRedTeamFuzzer",
    "RedTeamTestCase",
    "evaluate_trace",
    "get_default_evaluators",
    "render_console_report",
    "render_junit_report",
    "render_sarif_report",
]
