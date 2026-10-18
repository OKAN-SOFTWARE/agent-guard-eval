"""Automated trace remediation, secret redaction, and payload pruning engine."""

import copy
import re
from typing import Any, ClassVar

from agentguard.models import AgentTrace, ToolCall


class AgentTraceSanitizer:
    """Remediates agent execution traces by masking credentials and pruning bloated payloads."""

    SECRET_REPLACEMENTS: ClassVar[list[tuple[re.Pattern, str]]] = [
        (re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE), "[REDACTED:AWS_ACCESS_KEY]"),
        (
            re.compile(r"sk-(?:proj-)?[a-zA-Z0-9_\-]{20,}", re.IGNORECASE),
            "[REDACTED:OPENAI_KEY]",
        ),
        (re.compile(r"ghp_[a-zA-Z0-9]{36}", re.IGNORECASE), "[REDACTED:GITHUB_TOKEN]"),
        (
            re.compile(
                r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
                re.IGNORECASE,
            ),
            "[REDACTED:PRIVATE_KEY]",
        ),
        (
            re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}", re.IGNORECASE),
            "Bearer [REDACTED:BEARER_TOKEN]",
        ),
    ]

    def __init__(
        self, max_string_length: int = 10_000, sanitize_path_traversal: bool = True
    ):
        self.max_string_length = max_string_length
        self.sanitize_path_traversal = sanitize_path_traversal

    def sanitize(self, trace: AgentTrace) -> tuple[AgentTrace, int]:
        """Returns a sanitized deep copy of AgentTrace and the total count of redactions performed."""
        clean_trace = copy.deepcopy(trace)
        redaction_count = 0

        # Sanitize prompt
        clean_prompt, count = self._clean_string(clean_trace.user_prompt)
        clean_trace.user_prompt = clean_prompt
        redaction_count += count

        # Sanitize response
        if clean_trace.final_response:
            clean_resp, count = self._clean_string(clean_trace.final_response)
            clean_trace.final_response = clean_resp
            redaction_count += count

        # Sanitize tool calls
        clean_tool_calls: list[ToolCall] = []
        for call in clean_trace.tool_calls:
            clean_args, arg_count = self._clean_object(call.arguments)
            redaction_count += arg_count

            clean_out = call.output
            if call.output is not None:
                clean_out, out_count = self._clean_object(call.output)
                redaction_count += out_count

            call.arguments = (
                clean_args if isinstance(clean_args, dict) else {"data": clean_args}
            )
            call.output = clean_out
            clean_tool_calls.append(call)

        clean_trace.tool_calls = clean_tool_calls
        clean_trace.metadata["sanitized"] = True
        clean_trace.metadata["redaction_count"] = redaction_count

        return clean_trace, redaction_count

    def _clean_object(self, obj: Any) -> tuple[Any, int]:
        if isinstance(obj, dict):
            new_dict = {}
            total = 0
            for k, v in obj.items():
                clean_v, count = self._clean_object(v)
                new_dict[k] = clean_v
                total += count
            return new_dict, total
        elif isinstance(obj, list):
            new_list = []
            total = 0
            for item in obj:
                clean_item, count = self._clean_object(item)
                new_list.append(clean_item)
                total += count
            return new_list, total
        elif isinstance(obj, str):
            return self._clean_string(obj)
        return obj, 0

    def _clean_string(self, text: str) -> tuple[str, int]:
        count = 0
        cleaned = text

        # 1. Mask secrets
        for pattern, mask in self.SECRET_REPLACEMENTS:
            matches = list(pattern.finditer(cleaned))
            if matches:
                count += len(matches)
                cleaned = pattern.sub(mask, cleaned)

        # 2. Defang path traversal
        if self.sanitize_path_traversal and ("../" in cleaned or "..\\" in cleaned):
            count += 1
            cleaned = cleaned.replace("../", "[DEFANGED_PATH]/").replace(
                "..\\", "[DEFANGED_PATH]\\"
            )

        # 3. Payload length pruning
        if len(cleaned) > self.max_string_length:
            count += 1
            cleaned = (
                cleaned[: self.max_string_length]
                + f" ... [TRUNCATED: {len(text):,} bytes -> {self.max_string_length:,} bytes]"
            )

        return cleaned, count
