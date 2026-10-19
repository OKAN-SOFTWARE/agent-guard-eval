"""Unit tests for TraceDiffEngine and CLI diff command."""

from pathlib import Path

from click.testing import CliRunner

from agentguard.cli import cli
from agentguard.diff import (
    TraceDiffEngine,
    render_diff_markdown,
)
from agentguard.models import AgentTrace, ToolCall


def test_diff_engine_regressed():
    base = AgentTrace(
        session_id="base-1",
        tool_calls=[
            ToolCall(
                step_id=1,
                tool_name="calculator",
                arguments={"expr": "1 + 1"},
                duration_ms=10.0,
            )
        ],
    )
    cand = AgentTrace(
        session_id="cand-1",
        tool_calls=[
            ToolCall(
                step_id=1,
                tool_name="calculator",
                arguments={"expr": "1 + 1"},
                duration_ms=12.0,
            ),
            ToolCall(
                step_id=2,
                tool_name="bash_execute",
                arguments={"cmd": "rm -rf /"},
                duration_ms=50.0,
            ),
        ],
    )

    engine = TraceDiffEngine()
    diff = engine.compare(base, cand)

    assert diff.verdict == "REGRESSED"
    assert diff.steps_delta == 1
    assert len(diff.new_findings) >= 1
    assert any(f.rule_id == "AG-003-B" for f in diff.new_findings)

    md = render_diff_markdown(diff)
    assert "REGRESSED" in md
    assert "rm -rf" in md or "Command Injection" in md or "AG-003-B" in md


def test_diff_engine_improved():
    base = AgentTrace(
        session_id="base-vuln",
        tool_calls=[
            ToolCall(
                step_id=1,
                tool_name="bash",
                arguments={"command": "cat /etc/passwd"},
            )
        ],
    )
    cand = AgentTrace(
        session_id="cand-fixed",
        tool_calls=[
            ToolCall(
                step_id=1,
                tool_name="file_read",
                arguments={"path": "safe_file.txt"},
            )
        ],
    )

    engine = TraceDiffEngine()
    diff = engine.compare(base, cand)

    assert diff.verdict == "IMPROVED"
    assert len(diff.resolved_findings) >= 1
    assert len(diff.new_findings) == 0


def test_diff_engine_unchanged():
    base = AgentTrace(
        session_id="base-clean",
        tool_calls=[
            ToolCall(
                step_id=1,
                tool_name="status_check",
                arguments={},
                duration_ms=5.0,
            )
        ],
    )
    cand = AgentTrace(
        session_id="cand-clean",
        tool_calls=[
            ToolCall(
                step_id=1,
                tool_name="status_check",
                arguments={},
                duration_ms=6.0,
            )
        ],
    )

    engine = TraceDiffEngine()
    diff = engine.compare(base, cand)

    assert diff.verdict == "UNCHANGED"
    assert len(diff.new_findings) == 0
    assert len(diff.resolved_findings) == 0


def test_cli_diff_command(tmp_path: Path):
    runner = CliRunner()

    base_path = tmp_path / "base.json"
    cand_path = tmp_path / "cand.json"

    base_trace = AgentTrace(
        session_id="run-v1",
        tool_calls=[ToolCall(step_id=1, tool_name="ping", arguments={})],
    )
    cand_trace = AgentTrace(
        session_id="run-v2",
        tool_calls=[
            ToolCall(step_id=1, tool_name="ping", arguments={}),
            ToolCall(step_id=2, tool_name="bash", arguments={"command": "rm -rf /"}),
        ],
    )

    base_path.write_text(base_trace.model_dump_json(), encoding="utf-8")
    cand_path.write_text(cand_trace.model_dump_json(), encoding="utf-8")

    # Should exit with code 1 because verdict is REGRESSED
    res = runner.invoke(
        cli,
        [
            "diff",
            str(base_path),
            str(cand_path),
            "--format",
            "markdown",
        ],
    )
    assert res.exit_code == 1
    assert "REGRESSED" in res.output
    assert "AG-003-B" in res.output
