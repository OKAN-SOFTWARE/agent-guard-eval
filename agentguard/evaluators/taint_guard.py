"""Indirect prompt injection and taint-flow evaluator for autonomous agents."""

from __future__ import annotations

import re
from re import Pattern
from typing import Any, ClassVar

from agentguard.evaluators.base import BaseEvaluator
from agentguard.models import AgentTrace, Finding, Severity


class TaintFlowGuard(BaseEvaluator):
    """
    Detects indirect prompt injection payloads in tool outputs and audits

    tainted data propagation into high-privilege execution sinks.
    """

    rule_id = "AG-007"
    rule_name = "Indirect Prompt Injection & Taint-Flow Guard"

    PROMPT_INJECTION_PATTERN: ClassVar[Pattern] = re.compile(
        r"(ignore\s+(?:all\s+)?previous\s+instructions|"
        r"disregard\s+(?:all\s+)?prior\s+(?:prompts|instructions)|"
        r"system\s+(?:override|directive):|"
        r"<\|im_start\|>system|"
        r"\[INST\]|"
        r"\[ADMIN\s+OVERRIDE\]|"
        r"NEW\s+INSTRUCTION:)",
        re.IGNORECASE,
    )

    MARKDOWN_EXFILTRATION_PATTERN: ClassVar[Pattern] = re.compile(
        r"!\[.*?\]\((https?://[^\s\)]+)\)",
        re.IGNORECASE,
    )

    PRIVILEGED_SINK_PATTERNS: ClassVar[tuple[str, ...]] = (
        "bash",
        "shell",
        "terminal",
        "exec",
        "sql",
        "query",
        "database",
        "http_post",
        "send_email",
        "webhook",
    )

    def evaluate(self, trace: AgentTrace) -> list[Finding]:
        findings: list[Finding] = []
        tainted_snippets: list[
            tuple[int, str, str]
        ] = []  # (step_id, tool_name, snippet)

        for call in trace.tool_calls:
            # 1. Inspect tool outputs for Indirect Prompt Injection
            if call.output is not None:
                output_str = self._stringify(call.output)
                if output_str:
                    # Check for prompt injection markers
                    match = self.PROMPT_INJECTION_PATTERN.search(output_str)
                    if match:
                        findings.append(
                            Finding(
                                rule_id="AG-007-A",
                                rule_name=f"{self.rule_name}: Indirect Prompt Injection",
                                severity=Severity.CRITICAL,
                                message=(
                                    f"Tool '{call.tool_name}' output contained indirect prompt injection marker: "
                                    f"'{match.group(0)}'"
                                ),
                                step_id=call.step_id,
                                tool_name=call.tool_name,
                                details={
                                    "matched_pattern": match.group(0),
                                    "output_sample": output_str[:200],
                                },
                            )
                        )
                        tainted_snippets.append(
                            (call.step_id, call.tool_name, match.group(0))
                        )

                    # Check for Markdown Image Exfiltration payloads
                    exfil_match = self.MARKDOWN_EXFILTRATION_PATTERN.search(output_str)
                    if exfil_match:
                        findings.append(
                            Finding(
                                rule_id="AG-007-C",
                                rule_name=f"{self.rule_name}: Markdown Data Exfiltration Vector",
                                severity=Severity.HIGH,
                                message=(
                                    f"Tool '{call.tool_name}' output contained markdown exfiltration link: "
                                    f"'{exfil_match.group(0)}'"
                                ),
                                step_id=call.step_id,
                                tool_name=call.tool_name,
                                details={
                                    "matched_url": exfil_match.group(1),
                                },
                            )
                        )
                        tainted_snippets.append(
                            (call.step_id, call.tool_name, exfil_match.group(1))
                        )

            # 2. Check if this call is a high-privilege sink receiving tainted data from earlier steps
            if self._is_privileged_sink(call.tool_name) and tainted_snippets:
                args_str = self._stringify(call.arguments)
                for source_step, source_tool, snippet in tainted_snippets:
                    if (
                        source_step < call.step_id
                        and snippet.lower() in args_str.lower()
                    ):
                        findings.append(
                            Finding(
                                rule_id="AG-007-B",
                                rule_name=f"{self.rule_name}: Tainted Data Propagation to Privilege Sink",
                                severity=Severity.CRITICAL,
                                message=(
                                    f"Privileged sink tool '{call.tool_name}' received tainted payload "
                                    f"propagated from step {source_step} ('{source_tool}'): '{snippet}'"
                                ),
                                step_id=call.step_id,
                                tool_name=call.tool_name,
                                details={
                                    "source_step": source_step,
                                    "source_tool": source_tool,
                                    "tainted_payload": snippet,
                                },
                            )
                        )

        return findings

    def _is_privileged_sink(self, tool_name: str) -> bool:
        lowered = tool_name.lower()
        return any(sink in lowered for sink in self.PRIVILEGED_SINK_PATTERNS)

    def _stringify(self, obj: Any) -> str:
        if isinstance(obj, str):
            return obj
        try:
            import json

            return json.dumps(obj)
        except (TypeError, ValueError):
            return str(obj)
