"""Real-time in-line runtime guardrail middleware and decorator for autonomous agents."""

from __future__ import annotations

import asyncio
import functools
import inspect
import time
from collections.abc import Callable
from enum import Enum
from typing import Any, ClassVar, TypeVar

from agentguard.engine import get_default_evaluators
from agentguard.evaluators.base import BaseEvaluator
from agentguard.models import AgentTrace, Finding, Severity, ToolCall

F = TypeVar("F", bound=Callable[..., Any])


class RuntimeMode(str, Enum):
    """Behavior when a runtime guardrail violation is detected."""

    BLOCK = "BLOCK"  # Raise AgentGuardBlockedException immediately
    SYNTHETIC_ERROR = "SYNTHETIC_ERROR"  # Return a synthetic error dict to the agent
    MONITOR = "MONITOR"  # Record finding and permit tool execution


class AgentGuardBlockedException(Exception):
    """Exception raised when an agent tool call is blocked by AgentGuard at runtime."""

    def __init__(self, finding: Finding, tool_name: str, arguments: dict[str, Any]):
        self.finding = finding
        self.tool_name = tool_name
        self.arguments = arguments
        super().__init__(
            f"AgentGuard blocked invocation of tool '{tool_name}' "
            f"under rule [{finding.rule_id}] ({finding.severity}): {finding.message}"
        )


class InterceptDecision:
    """Decision outcome returned by AgentGuardRuntime.intercept."""

    def __init__(
        self,
        allowed: bool,
        step_id: int,
        finding: Finding | None = None,
        synthetic_error: dict[str, Any] | None = None,
    ):
        self.allowed = allowed
        self.step_id = step_id
        self.finding = finding
        self.synthetic_error = synthetic_error


class AgentGuardRuntime:
    """
    In-line runtime guardrail engine for live autonomous agents.

    Provides pre-execution tool parameter validation, attack interception (SSRF,
    command injection, loop thrashing), and session trace capture.
    """

    SEVERITY_ORDER: ClassVar[dict[Severity, int]] = {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }

    def __init__(
        self,
        session_id: str | None = None,
        agent_name: str = "runtime_agent",
        mode: RuntimeMode = RuntimeMode.BLOCK,
        fail_on: Severity = Severity.HIGH,
        evaluators: list[BaseEvaluator] | None = None,
    ):
        self.session_id = session_id or f"rt-{int(time.time() * 1000)}"
        self.agent_name = agent_name
        self.mode = mode
        self.fail_on = fail_on
        self.evaluators = (
            evaluators if evaluators is not None else get_default_evaluators()
        )

        self._tool_calls: list[ToolCall] = []
        self._findings: list[Finding] = []
        self._step_counter: int = 0

    @property
    def tool_calls(self) -> list[ToolCall]:
        return list(self._tool_calls)

    @property
    def findings(self) -> list[Finding]:
        return list(self._findings)

    def _should_block(self, finding: Finding) -> bool:
        threshold = self.SEVERITY_ORDER.get(self.fail_on, 3)
        finding_level = self.SEVERITY_ORDER.get(finding.severity, 1)
        return finding_level >= threshold

    def intercept(self, tool_name: str, arguments: dict[str, Any]) -> InterceptDecision:
        """
        Intercept a candidate tool invocation before execution.

        Evaluates the proposed tool call against active guardrails.
        """
        self._step_counter += 1
        step_id = self._step_counter

        candidate_call = ToolCall(
            step_id=step_id,
            tool_name=tool_name,
            arguments=arguments,
        )

        speculative_trace = AgentTrace(
            session_id=self.session_id,
            agent_name=self.agent_name,
            tool_calls=[*self._tool_calls, candidate_call],
        )

        blocking_finding: Finding | None = None
        for evaluator in self.evaluators:
            findings = evaluator.evaluate(speculative_trace)
            for f in findings:
                # Associate step ID if omitted
                if f.step_id is None:
                    f.step_id = step_id
                if f.tool_name is None:
                    f.tool_name = tool_name
                self._findings.append(f)
                if self._should_block(f) and blocking_finding is None:
                    blocking_finding = f

        if blocking_finding is not None:
            if self.mode == RuntimeMode.BLOCK:
                raise AgentGuardBlockedException(
                    finding=blocking_finding,
                    tool_name=tool_name,
                    arguments=arguments,
                )
            elif self.mode == RuntimeMode.SYNTHETIC_ERROR:
                error_dict = {
                    "agentguard_blocked": True,
                    "error": f"Invocation blocked by security policy [{blocking_finding.rule_id}]: {blocking_finding.message}",
                    "rule_id": blocking_finding.rule_id,
                    "severity": blocking_finding.severity.value,
                }
                # Record blocked step
                candidate_call.error = error_dict["error"]
                self._tool_calls.append(candidate_call)
                return InterceptDecision(
                    allowed=False,
                    step_id=step_id,
                    finding=blocking_finding,
                    synthetic_error=error_dict,
                )

        # Allowed (either clean or MONITOR mode)
        self._tool_calls.append(candidate_call)
        return InterceptDecision(
            allowed=True,
            step_id=step_id,
            finding=blocking_finding,
        )

    def record_output(
        self,
        step_id: int,
        output: Any | None = None,
        duration_ms: float | None = None,
        error: str | None = None,
    ) -> None:
        """Record the post-execution outcome for a completed tool call."""
        for call in self._tool_calls:
            if call.step_id == step_id:
                call.output = output
                call.duration_ms = duration_ms
                if error:
                    call.error = error
                break

    def to_trace(self, final_response: str | None = None) -> AgentTrace:
        """Export the full execution session as an AgentTrace."""
        return AgentTrace(
            session_id=self.session_id,
            agent_name=self.agent_name,
            tool_calls=list(self._tool_calls),
            final_response=final_response,
        )

    def protect(self, tool_name: str | None = None) -> Callable[[F], F]:
        """Decorator to wrap synchronous functions with AgentGuard runtime protection."""

        def decorator(func: F) -> F:
            name = tool_name or func.__name__

            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                sig = inspect.signature(func)
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
                arguments = dict(bound_args.arguments)

                decision = self.intercept(name, arguments)
                if not decision.allowed and decision.synthetic_error is not None:
                    return decision.synthetic_error

                start = time.perf_counter()
                error_msg = None
                result = None
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as exc:
                    error_msg = str(exc)
                    raise
                finally:
                    duration = (time.perf_counter() - start) * 1000.0
                    self.record_output(
                        step_id=decision.step_id,
                        output=result,
                        duration_ms=round(duration, 2),
                        error=error_msg,
                    )

            return wrapper  # type: ignore[return-value]

        return decorator

    def protect_async(self, tool_name: str | None = None) -> Callable[[F], F]:
        """Decorator to wrap asynchronous functions with AgentGuard runtime protection."""

        def decorator(func: F) -> F:
            name = tool_name or func.__name__

            @functools.wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                sig = inspect.signature(func)
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
                arguments = dict(bound_args.arguments)

                decision = self.intercept(name, arguments)
                if not decision.allowed and decision.synthetic_error is not None:
                    return decision.synthetic_error

                start = time.perf_counter()
                error_msg = None
                result = None
                try:
                    if asyncio.iscoroutinefunction(func):
                        result = await func(*args, **kwargs)
                    else:
                        result = func(*args, **kwargs)
                    return result
                except Exception as exc:
                    error_msg = str(exc)
                    raise
                finally:
                    duration = (time.perf_counter() - start) * 1000.0
                    self.record_output(
                        step_id=decision.step_id,
                        output=result,
                        duration_ms=round(duration, 2),
                        error=error_msg,
                    )

            return wrapper  # type: ignore[return-value]

        return decorator
