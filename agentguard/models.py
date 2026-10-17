"""Data models for AgentGuard Evaluation Framework."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ToolCall(BaseModel):
    step_id: int
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    output: Any | None = None
    error: str | None = None
    duration_ms: float | None = None


class AgentTrace(BaseModel):
    session_id: str
    agent_name: str = "default_agent"
    user_prompt: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    final_response: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    rule_id: str
    rule_name: str
    severity: Severity
    message: str
    step_id: int | None = None
    tool_name: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class EvaluationResult(BaseModel):
    session_id: str
    passed: bool
    total_checks: int
    passed_checks: int
    failed_checks: int
    findings: list[Finding] = Field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def has_critical_or_high(self) -> bool:
        return any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings
        )
