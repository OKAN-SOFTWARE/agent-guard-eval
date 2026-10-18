"""LangChain and LangGraph callback adapter for automated trace collection."""

import time
from typing import Any

from agentguard.engine import evaluate_trace
from agentguard.evaluators.base import BaseEvaluator
from agentguard.models import AgentTrace, EvaluationResult, ToolCall


class AgentGuardCallbackHandler:
    """Drop-in callback handler for LangChain and LangGraph agent runs.

    Usage:
        handler = AgentGuardCallbackHandler(session_id="agent-run-1")
        agent_executor.invoke({"input": "..."}, config={"callbacks": [handler]})
        result = handler.evaluate()
    """

    def __init__(
        self, session_id: str = "langchain-session", agent_name: str = "langchain_agent"
    ):
        self.session_id = session_id
        self.agent_name = agent_name
        self.user_prompt = ""
        self.final_response: str | None = None
        self.tool_calls: list[ToolCall] = []
        self._active_step_starts: dict[int, float] = {}
        self._step_counter = 0

    def on_chain_start(
        self, serialized: dict[str, Any] | None, inputs: dict[str, Any], **kwargs: Any
    ) -> None:
        """Capture the initial user prompt."""
        if not self.user_prompt and isinstance(inputs, dict):
            # Typical LangChain inputs are under 'input', 'question', or 'prompt'
            self.user_prompt = str(
                inputs.get("input")
                or inputs.get("question")
                or inputs.get("prompt")
                or ""
            )

    def on_chain_end(self, outputs: dict[str, Any], **kwargs: Any) -> None:
        """Capture the agent's final response."""
        if isinstance(outputs, dict):
            self.final_response = str(
                outputs.get("output") or outputs.get("response") or ""
            )

    def on_tool_start(
        self, serialized: dict[str, Any] | None, input_str: str, **kwargs: Any
    ) -> None:
        """Record the start of a tool invocation."""
        self._step_counter += 1
        step_id = self._step_counter
        self._active_step_starts[step_id] = time.perf_counter()

        tool_name = (
            (serialized or {}).get("name") or kwargs.get("name") or "unknown_tool"
        )

        # Attempt to parse input_str into structured dict if it's JSON-like or key-value
        args = {"input": input_str}
        if isinstance(input_str, dict):
            args = input_str

        call = ToolCall(
            step_id=step_id,
            tool_name=tool_name,
            arguments=args,
        )
        self.tool_calls.append(call)

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        """Record the completion of a tool invocation and calculate duration."""
        step_id = self._step_counter
        start_time = self._active_step_starts.pop(step_id, None)
        duration_ms = (
            (time.perf_counter() - start_time) * 1000.0 if start_time else None
        )

        if self.tool_calls and self.tool_calls[-1].step_id == step_id:
            self.tool_calls[-1].output = output
            self.tool_calls[-1].duration_ms = (
                round(duration_ms, 2) if duration_ms is not None else None
            )

    def on_tool_error(self, error: BaseException | str, **kwargs: Any) -> None:
        """Record a tool failure."""
        step_id = self._step_counter
        start_time = self._active_step_starts.pop(step_id, None)
        duration_ms = (
            (time.perf_counter() - start_time) * 1000.0 if start_time else None
        )

        if self.tool_calls and self.tool_calls[-1].step_id == step_id:
            self.tool_calls[-1].error = str(error)
            self.tool_calls[-1].duration_ms = (
                round(duration_ms, 2) if duration_ms is not None else None
            )

    def get_trace(self) -> AgentTrace:
        """Builds and returns the structured AgentTrace."""
        return AgentTrace(
            session_id=self.session_id,
            agent_name=self.agent_name,
            user_prompt=self.user_prompt,
            tool_calls=self.tool_calls,
            final_response=self.final_response,
            metadata={"framework": "langchain"},
        )

    def evaluate(
        self, evaluators: list[BaseEvaluator] | None = None
    ) -> EvaluationResult:
        """Evaluates the recorded trace using AgentGuard."""
        trace = self.get_trace()
        return evaluate_trace(trace, evaluators=evaluators)


def parse_langsmith_run(run: dict[str, Any]) -> AgentTrace:
    """Converts a LangSmith or OpenInference JSON run dictionary into an AgentTrace."""
    session_id = str(run.get("id") or run.get("session_id") or "langsmith-session")
    agent_name = str(run.get("name") or "langsmith-agent")
    inputs = run.get("inputs") or {}
    user_prompt = str(inputs.get("input") or inputs.get("question") or "")
    outputs = run.get("outputs") or {}
    final_response = str(outputs.get("output") or "")

    tool_calls: list[ToolCall] = []
    child_runs = run.get("child_runs") or run.get("runs") or []

    step = 1
    for child in child_runs:
        if child.get("run_type") == "tool" or "tool" in child.get("name", "").lower():
            child_inputs = child.get("inputs") or {}
            child_outputs = child.get("outputs") or {}
            duration_ms = None
            if child.get("end_time") and child.get("start_time"):
                try:
                    duration_ms = float(child["end_time"]) - float(child["start_time"])
                except (ValueError, TypeError):
                    pass

            tool_calls.append(
                ToolCall(
                    step_id=step,
                    tool_name=child.get("name") or "tool",
                    arguments=child_inputs
                    if isinstance(child_inputs, dict)
                    else {"input": child_inputs},
                    output=child_outputs.get("output")
                    if isinstance(child_outputs, dict)
                    else child_outputs,
                    error=child.get("error"),
                    duration_ms=duration_ms,
                )
            )
            step += 1

    return AgentTrace(
        session_id=session_id,
        agent_name=agent_name,
        user_prompt=user_prompt,
        tool_calls=tool_calls,
        final_response=final_response,
        metadata={"source": "langsmith"},
    )
