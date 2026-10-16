"""Data models for AgentGuard Evaluation Framework."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ToolCall(BaseModel):
    step_id: int
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    output: Optional[Any] = None
    error: Optional[str] = None
    duration_ms: Optional[float] = None


class AgentTrace(BaseModel):
    session_id: str
    agent_name: str = "default_agent"
    user_prompt: str = ""
    tool_calls: List[ToolCall] = Field(default_factory=list)
    final_response: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    rule_id: str
    rule_name: str
    severity: Severity
    message: str
    step_id: Optional[int] = None
    tool_name: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class EvaluationResult(BaseModel):
    session_id: str
    passed: bool
    total_checks: int
    passed_checks: int
    failed_checks: int
    findings: List[Finding] = Field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def has_critical_or_high(self) -> bool:
        return any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)
