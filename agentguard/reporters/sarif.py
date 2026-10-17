"""SARIF v2.1.0 reporter for GitHub Security & Code Scanning integration."""

import json
from typing import Any

from agentguard.models import EvaluationResult, Severity


def render_sarif_report(result: EvaluationResult) -> str:
    """Generates standard SARIF v2.1.0 JSON string from EvaluationResult."""
    level_map = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
    }

    results: list[dict[str, Any]] = []

    for finding in result.findings:
        level = level_map.get(finding.severity, "warning")
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": level,
                "message": {
                    "text": finding.message,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"traces/{result.session_id}.json",
                            },
                            "region": {
                                "startLine": finding.step_id or 1,
                                "startColumn": 1,
                            },
                        }
                    }
                ],
                "properties": {
                    "tool": finding.tool_name,
                    "severity": finding.severity.value,
                    "details": finding.details,
                },
            }
        )

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentGuard",
                        "informationUri": "https://github.com/veerjain-1/agent-guard-eval",
                        "version": "0.1.0",
                        "rules": [
                            {
                                "id": "AG-001",
                                "name": "ToolSchemaAdherence",
                                "shortDescription": {
                                    "text": "Tool Schema Adherence & Drift Validator"
                                },
                            },
                            {
                                "id": "AG-002",
                                "name": "RunawayLoopAndStateThrashing",
                                "shortDescription": {
                                    "text": "Agent Runaway Execution & Infinite Loop Detector"
                                },
                            },
                            {
                                "id": "AG-003",
                                "name": "SecurityAndVulnerabilityGuard",
                                "shortDescription": {
                                    "text": "Agent Tool Payload Security & Injection Guard"
                                },
                            },
                            {
                                "id": "AG-004",
                                "name": "SSRFAndCloudMetadataGuard",
                                "shortDescription": {
                                    "text": "SSRF & Cloud Metadata Exfiltration Guard"
                                },
                            },
                            {
                                "id": "AG-005",
                                "name": "TokenBudgetAndContextBloatGuard",
                                "shortDescription": {
                                    "text": "Token Budget & Context Bloat Guard"
                                },
                            },
                        ],
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif_data, indent=2)
