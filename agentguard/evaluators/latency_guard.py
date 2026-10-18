"""Latency and SLA degradation evaluator for AI agent tool executions."""

from agentguard.evaluators.base import BaseEvaluator
from agentguard.models import AgentTrace, Finding, Severity


class LatencyAndSLAGuard(BaseEvaluator):
    """Detects step-level latency spikes, session SLA breaches, and monotonic latency degradation."""

    rule_id = "AG-006"
    rule_name = "Latency & SLA Degradation Guard"

    def __init__(
        self,
        max_step_duration_ms: float = 5000.0,
        max_session_duration_ms: float = 30000.0,
        degradation_threshold_ratio: float = 1.5,
    ):
        """
        Args:
            max_step_duration_ms: Maximum allowed duration in ms for an individual tool step (default 5000ms).
            max_session_duration_ms: Maximum allowed cumulative tool duration for the entire session (default 30000ms).
            degradation_threshold_ratio: Factor by which consecutive steps must increase to flag latency degradation.
        """
        self.max_step_duration_ms = max_step_duration_ms
        self.max_session_duration_ms = max_session_duration_ms
        self.degradation_threshold_ratio = degradation_threshold_ratio

    def evaluate(self, trace: AgentTrace) -> list[Finding]:
        findings: list[Finding] = []
        total_duration_ms = 0.0
        durations: list[float] = []

        for call in trace.tool_calls:
            if call.duration_ms is not None:
                total_duration_ms += call.duration_ms
                durations.append(call.duration_ms)

                # 1. Step-level latency spike
                if call.duration_ms > self.max_step_duration_ms:
                    findings.append(
                        Finding(
                            rule_id="AG-006-A",
                            rule_name=f"{self.rule_name}: Step Latency Spike",
                            severity=Severity.HIGH,
                            message=(
                                f"Tool '{call.tool_name}' exceeded latency threshold "
                                f"({call.duration_ms:.1f}ms > {self.max_step_duration_ms:.1f}ms)"
                            ),
                            step_id=call.step_id,
                            tool_name=call.tool_name,
                            details={
                                "duration_ms": call.duration_ms,
                                "threshold_ms": self.max_step_duration_ms,
                            },
                        )
                    )

        # 2. Cumulative session SLA breach
        if total_duration_ms > self.max_session_duration_ms:
            findings.append(
                Finding(
                    rule_id="AG-006-B",
                    rule_name=f"{self.rule_name}: Session SLA Breach",
                    severity=Severity.HIGH,
                    message=(
                        f"Cumulative trace execution latency ({total_duration_ms:.1f}ms) "
                        f"exceeded session SLA budget ({self.max_session_duration_ms:.1f}ms)"
                    ),
                    details={
                        "total_duration_ms": total_duration_ms,
                        "sla_threshold_ms": self.max_session_duration_ms,
                    },
                )
            )

        # 3. Progressive latency degradation (e.g. step n+1 > 1.5 * step n for 3+ consecutive steps)
        if len(durations) >= 3:
            consecutive_increases = 0
            for i in range(len(durations) - 1):
                if (
                    durations[i] > 50.0  # Ignore negligible baselines
                    and durations[i + 1]
                    >= durations[i] * self.degradation_threshold_ratio
                ):
                    consecutive_increases += 1
                else:
                    consecutive_increases = 0

                if consecutive_increases >= 2:
                    findings.append(
                        Finding(
                            rule_id="AG-006-C",
                            rule_name=f"{self.rule_name}: Progressive Latency Degradation",
                            severity=Severity.MEDIUM,
                            message=(
                                f"Detected monotonic latency degradation over {consecutive_increases + 1} steps "
                                f"(potential resource leak or connection pooling starvation)"
                            ),
                            details={"durations_ms": durations},
                        )
                    )
                    break

        return findings
