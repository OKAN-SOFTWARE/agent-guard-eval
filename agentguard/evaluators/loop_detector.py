"""Runaway execution and cyclical loop detector for agent traces."""

from collections import Counter
import json
from typing import List, Tuple
from agentguard.evaluators.base import BaseEvaluator
from agentguard.models import AgentTrace, Finding, Severity


class LoopDetector(BaseEvaluator):
    """Detects infinite loops, identical repeated invocations, and oscillatory state thrashing."""

    rule_id = "AG-002"
    rule_name = "Runaway Loop & State Thrashing"

    def __init__(
        self,
        max_identical_calls: int = 3,
        max_cycle_length: int = 3,
        cycle_threshold: int = 3,
        max_total_steps: int = 25,
    ):
        """
        Args:
            max_identical_calls: Max number of times the exact same (tool, args) can repeat.
            max_cycle_length: Max cycle window size (e.g., A-B-A-B is cycle length 2).
            cycle_threshold: How many times a cycle must repeat before flagging.
            max_total_steps: Hard limit on tool calling depth.
        """
        self.max_identical_calls = max_identical_calls
        self.max_cycle_length = max_cycle_length
        self.cycle_threshold = cycle_threshold
        self.max_total_steps = max_total_steps

    def evaluate(self, trace: AgentTrace) -> List[Finding]:
        findings: List[Finding] = []
        calls = trace.tool_calls

        # 1. Total step threshold check
        if len(calls) > self.max_total_steps:
            findings.append(
                Finding(
                    rule_id="AG-002-A",
                    rule_name=f"{self.rule_name}: Step Budget Exceeded",
                    severity=Severity.HIGH,
                    message=f"Agent exceeded maximum step limit ({len(calls)} > {self.max_total_steps})",
                    step_id=calls[-1].step_id if calls else None,
                    details={"total_steps": len(calls), "max_allowed": self.max_total_steps},
                )
            )

        if not calls:
            return findings

        # Canonical signature for each call: (tool_name, serialized_sorted_args)
        signatures: List[str] = []
        for c in calls:
            try:
                serialized_args = json.dumps(c.arguments, sort_keys=True)
            except (TypeError, ValueError):
                serialized_args = str(c.arguments)
            signatures.append(f"{c.tool_name}:{serialized_args}")

        # 2. Identical call repetitions
        sig_counts = Counter(signatures)
        for sig, count in sig_counts.items():
            if count >= self.max_identical_calls:
                tool_name = sig.split(":", 1)[0]
                findings.append(
                    Finding(
                        rule_id="AG-002-B",
                        rule_name=f"{self.rule_name}: Repeated Invocations",
                        severity=Severity.HIGH,
                        message=f"Tool '{tool_name}' invoked {count} times with identical parameters without state change",
                        tool_name=tool_name,
                        details={"tool_name": tool_name, "repetition_count": count},
                    )
                )

        # 3. Oscillatory / Cyclical Loop Detection (e.g. A -> B -> A -> B -> A -> B)
        # Check cycle lengths 2 to max_cycle_length
        tool_names = [c.tool_name for c in calls]
        n = len(tool_names)
        for k in range(2, min(self.max_cycle_length + 1, n // 2 + 1)):
            for i in range(n - k * self.cycle_threshold + 1):
                pattern: Tuple[str, ...] = tuple(tool_names[i : i + k])
                is_cycle = True
                for repeat in range(1, self.cycle_threshold):
                    next_chunk = tuple(tool_names[i + repeat * k : i + (repeat + 1) * k])
                    if next_chunk != pattern:
                        is_cycle = False
                        break
                if is_cycle:
                    pattern_str = " -> ".join(pattern)
                    findings.append(
                        Finding(
                            rule_id="AG-002-C",
                            rule_name=f"{self.rule_name}: Oscillatory Cycle",
                            severity=Severity.CRITICAL,
                            message=f"Detected cyclical tool pattern [{pattern_str}] repeating {self.cycle_threshold}+ times",
                            step_id=calls[i].step_id,
                            details={"pattern": list(pattern), "cycle_length": k},
                        )
                    )
                    break

        return findings
