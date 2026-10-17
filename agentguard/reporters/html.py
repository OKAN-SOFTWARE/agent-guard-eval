"""Standalone interactive HTML dashboard reporter for AgentGuard."""

import html
import json

from agentguard.models import AgentTrace, EvaluationResult, Severity


def render_html_report(
    result: EvaluationResult, trace: AgentTrace | None = None
) -> str:
    """Renders a self-contained, interactive HTML dashboard report from EvaluationResult."""
    status_label = "PASSED" if result.passed else "FAILED"
    status_badge_bg = "#10b981" if result.passed else "#ef4444"

    crit_count = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in result.findings if f.severity == Severity.HIGH)

    rows_html = []
    for idx, f in enumerate(result.findings, 1):
        sev_color = {
            Severity.CRITICAL: "#ef4444",
            Severity.HIGH: "#f97316",
            Severity.MEDIUM: "#eab308",
            Severity.LOW: "#3b82f6",
        }.get(f.severity, "#94a3b8")

        step_badge = (
            f'<span class="badge step">Step {f.step_id}</span>'
            if f.step_id is not None
            else '<span class="badge step">Session</span>'
        )
        tool_badge = (
            f'<span class="badge tool">{html.escape(f.tool_name)}</span>'
            if f.tool_name
            else '<span class="badge tool">-</span>'
        )
        details_json = html.escape(json.dumps(f.details, indent=2))

        rows_html.append(f"""
        <tr class="finding-row sev-{f.severity.value.lower()}">
            <td><span class="sev-pill" style="background:{sev_color}">{f.severity.value}</span></td>
            <td><code>{html.escape(f.rule_id)}</code></td>
            <td>{step_badge}</td>
            <td>{tool_badge}</td>
            <td class="msg-col">
                <strong>{html.escape(f.rule_name)}</strong>
                <p>{html.escape(f.message)}</p>
                <details>
                    <summary>View Details</summary>
                    <pre><code>{details_json}</code></pre>
                </details>
            </td>
        </tr>
        """)

    tbody_content = (
        "\n".join(rows_html)
        if rows_html
        else """
        <tr>
            <td colspan="5" style="text-align:center; padding: 40px; color: #10b981; font-weight: 600;">
                ✔ No security vulnerabilities, schema violations, or loop anomalies detected.
            </td>
        </tr>
    """
    )

    trace_section_html = ""
    if trace and trace.tool_calls:
        steps_html = []
        for call in trace.tool_calls:
            args_formatted = html.escape(json.dumps(call.arguments, indent=2))
            out_formatted = (
                html.escape(json.dumps(call.output, indent=2))
                if call.output is not None
                else "<em>None</em>"
            )
            dur = f"{call.duration_ms:.1f}ms" if call.duration_ms else "-"
            steps_html.append(f"""
            <div class="trace-step">
                <div class="trace-header">
                    <span class="step-num">Step {call.step_id}</span>
                    <span class="step-tool">{html.escape(call.tool_name)}</span>
                    <span class="step-dur">{dur}</span>
                </div>
                <div class="trace-body">
                    <div class="pane"><strong>Arguments:</strong><pre><code>{args_formatted}</code></pre></div>
                    <div class="pane"><strong>Output:</strong><pre><code>{out_formatted}</code></pre></div>
                </div>
            </div>
            """)
        trace_section_html = f"""
        <div class="card trace-card">
            <h2>Tool Execution Trace ({len(trace.tool_calls)} steps)</h2>
            <div class="trace-list">
                {"".join(steps_html)}
            </div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AgentGuard Report - {html.escape(result.session_id)}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --border: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #38bdf8;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            padding: 32px 20px;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 32px;
        }}
        .brand {{ display: flex; align-items: center; gap: 12px; }}
        .brand h1 {{ font-size: 24px; font-weight: 700; }}
        .badge-status {{
            background: {status_badge_bg};
            color: #fff;
            font-weight: 700;
            padding: 6px 16px;
            border-radius: 9999px;
            font-size: 14px;
            letter-spacing: 0.05em;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .metric-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
        }}
        .metric-card .title {{ font-size: 13px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }}
        .metric-card .value {{ font-size: 28px; font-weight: 700; margin-top: 6px; }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 32px;
        }}
        .card h2 {{ font-size: 18px; margin-bottom: 16px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}
        th {{
            text-align: left;
            padding: 12px;
            border-bottom: 2px solid var(--border);
            color: var(--text-muted);
            font-size: 12px;
            text-transform: uppercase;
        }}
        td {{ padding: 14px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
        .sev-pill {{
            display: inline-block;
            font-size: 11px;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 6px;
            color: #fff;
        }}
        .badge.step {{ background: #0284c7; color: #fff; font-size: 11px; padding: 2px 8px; border-radius: 4px; }}
        .badge.tool {{ background: #475569; color: #fff; font-size: 11px; padding: 2px 8px; border-radius: 4px; font-family: monospace; }}
        .msg-col strong {{ color: #e2e8f0; font-size: 14px; }}
        .msg-col p {{ color: var(--text-muted); margin-top: 4px; font-size: 13px; }}
        details {{ margin-top: 8px; font-size: 12px; }}
        details summary {{ cursor: pointer; color: var(--primary); }}
        pre {{
            background: #090d16;
            padding: 12px;
            border-radius: 8px;
            overflow-x: auto;
            margin-top: 6px;
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            font-size: 12px;
        }}
        .trace-step {{
            background: #0f172a;
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 12px;
            overflow: hidden;
        }}
        .trace-header {{
            background: #1e293b;
            padding: 10px 16px;
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 13px;
        }}
        .step-num {{ font-weight: 700; color: var(--primary); }}
        .step-tool {{ font-family: monospace; font-weight: 600; color: #cbd5e1; }}
        .step-dur {{ margin-left: auto; color: var(--text-muted); font-size: 12px; }}
        .trace-body {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; padding: 12px; }}
        .pane strong {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; }}
        footer {{ text-align: center; color: var(--text-muted); font-size: 12px; margin-top: 40px; }}
        footer a {{ color: var(--primary); text-decoration: none; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <span style="font-size: 28px;">🛡️</span>
                <div>
                    <h1>AgentGuard Evaluation Report</h1>
                    <p style="color: var(--text-muted); font-size: 13px;">Session: {html.escape(result.session_id)} • Latency: {result.duration_ms}ms</p>
                </div>
            </div>
            <div>
                <span class="badge-status">{status_label}</span>
            </div>
        </header>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="title">Total Checks</div>
                <div class="value">{result.total_checks}</div>
            </div>
            <div class="metric-card">
                <div class="title">Checks Passed</div>
                <div class="value" style="color: #10b981;">{result.passed_checks}</div>
            </div>
            <div class="metric-card">
                <div class="title">Critical / High Issues</div>
                <div class="value" style="color: {"#ef4444" if (crit_count + high_count) > 0 else "#10b981"};">{crit_count + high_count}</div>
            </div>
            <div class="metric-card">
                <div class="title">Total Findings</div>
                <div class="value" style="color: {"#ef4444" if result.findings else "#10b981"};">{len(result.findings)}</div>
            </div>
        </div>

        <div class="card">
            <h2>Evaluation Findings ({len(result.findings)})</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 110px;">Severity</th>
                        <th style="width: 100px;">Rule</th>
                        <th style="width: 90px;">Target</th>
                        <th style="width: 140px;">Tool</th>
                        <th>Details & Findings</th>
                    </tr>
                </thead>
                <tbody>
                    {tbody_content}
                </tbody>
            </table>
        </div>

        {trace_section_html}

        <footer>
            Generated by <a href="https://github.com/veerjain-1/agent-guard-eval">AgentGuard</a> • Deterministic AI Agent Security & Reliability
        </footer>
    </div>
</body>
</html>
"""
