"""Token budget, context bloat, and cascading failure evaluator."""

import json

from agentguard.evaluators.base import BaseEvaluator
from agentguard.models import AgentTrace, Finding, Severity


class TokenAndCostBudgetGuard(BaseEvaluator):
    """Detects context window bloat, cascading tool failures, and token budget overruns."""

    rule_id = "AG-005"
    rule_name = "Token Budget & Context Bloat Guard"

    def __init__(
        self,
        max_step_payload_bytes: int = 100_000,
        max_session_estimated_tokens: int = 50_000,
        max_failure_rate_threshold: float = 0.5,
    ):
        """
        Args:
            max_step_payload_bytes: Max payload size in bytes for a single tool call argument or output (default 100KB).
            max_session_estimated_tokens: Maximum estimated cumulative tokens across trace (default 50k).
            max_failure_rate_threshold: Max ratio of failed tool calls before flagging cascading errors.
        """
        self.max_step_payload_bytes = max_step_payload_bytes
        self.max_session_estimated_tokens = max_session_estimated_tokens
        self.max_failure_rate_threshold = max_failure_rate_threshold

    def evaluate(self, trace: AgentTrace) -> list[Finding]:
        findings: list[Finding] = []
        total_chars = len(trace.user_prompt) + len(trace.final_response or "")
        failed_calls = 0

        for call in trace.tool_calls:
            # Measure argument size
            arg_str = json.dumps(call.arguments, default=str)
            total_chars += len(arg_str)

            if len(arg_str.encode("utf-8")) > self.max_step_payload_bytes:
                findings.append(
                    Finding(
                        rule_id="AG-005-A",
                        rule_name=f"{self.rule_name}: Massive Argument Payload",
                        severity=Severity.HIGH,
                        message=f"Tool '{call.tool_name}' argument exceeds payload limit ({len(arg_str.encode('utf-8'))} > {self.max_step_payload_bytes} bytes)",
                        step_id=call.step_id,
                        tool_name=call.tool_name,
                        details={
                            "bytes": len(arg_str.encode("utf-8")),
                            "limit": self.max_step_payload_bytes,
                        },
                    )
                )

            # Measure output size if present
            if call.output is not None:
                out_str = json.dumps(call.output, default=str)
                total_chars += len(out_str)
                if len(out_str.encode("utf-8")) > self.max_step_payload_bytes:
                    findings.append(
                        Finding(
                            rule_id="AG-005-A",
                            rule_name=f"{self.rule_name}: Massive Output Payload",
                            severity=Severity.HIGH,
                            message=f"Tool '{call.tool_name}' output exceeds payload limit ({len(out_str.encode('utf-8'))} > {self.max_step_payload_bytes} bytes)",
                            step_id=call.step_id,
                            tool_name=call.tool_name,
                            details={
                                "bytes": len(out_str.encode("utf-8")),
                                "limit": self.max_step_payload_bytes,
                            },
                        )
                    )

            if call.error:
                failed_calls += 1

        # Check total estimated tokens (~4 characters per token heuristic)
        estimated_tokens = total_chars // 4
        if estimated_tokens > self.max_session_estimated_tokens:
            findings.append(
                Finding(
                    rule_id="AG-005-B",
                    rule_name=f"{self.rule_name}: Token Budget Overrun",
                    severity=Severity.HIGH,
                    message=f"Trace estimated tokens ({estimated_tokens:,}) exceeds safety ceiling ({self.max_session_estimated_tokens:,})",
                    details={
                        "estimated_tokens": estimated_tokens,
                        "limit": self.max_session_estimated_tokens,
                    },
                )
            )

        # Check cascading tool failure rate
        if len(trace.tool_calls) >= 4:
            failure_rate = failed_calls / len(trace.tool_calls)
            if failure_rate >= self.max_failure_rate_threshold:
                findings.append(
                    Finding(
                        rule_id="AG-005-C",
                        rule_name=f"{self.rule_name}: Cascading Tool Failures",
                        severity=Severity.MEDIUM,
                        message=f"Agent experienced high failure rate ({failed_calls}/{len(trace.tool_calls)} calls failed, {failure_rate:.0%})",
                        details={
                            "failed_calls": failed_calls,
                            "total_calls": len(trace.tool_calls),
                            "rate": failure_rate,
                        },
                    )
                )

        return findings
