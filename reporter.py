"""
Report Generator — JuiceShark
Generates a structured findings report in Markdown format.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from state.store import Finding, StateStore


SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def generate_report(
    state_store: StateStore,
    target_url: str,
    output_path: Path,
    model_name: str = "",
) -> str:
    """Generate a findings report and write it to output_path. Returns the report text."""

    findings = sorted(
        state_store.get_findings(),
        key=lambda f: SEVERITY_ORDER.get(f.severity, 5),
    )
    summary = state_store.summary()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# JuiceShark Penetration Test Findings Report",
        "",
        f"**Target:** {target_url}  ",
        f"**Date:** {now}  ",
        f"**Agent:** JuiceShark{f' ({model_name})' if model_name else ''}  ",
        f"**Total Findings:** {len(findings)}  ",
        f"**Steps Executed:** {summary['steps']}  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    if not findings:
        lines.append("No validated findings were recorded in this scan run.")
    else:
        # Severity breakdown
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_sev:
                emoji = SEVERITY_EMOJI.get(sev, "")
                lines.append(f"| {emoji} {sev.capitalize()} | {by_sev[sev]} |")
        lines.append("")

    lines += [
        "---",
        "",
        "## Findings",
        "",
    ]

    for idx, finding in enumerate(findings, 1):
        emoji = SEVERITY_EMOJI.get(finding.severity, "")
        lines += [
            f"### {idx}. {emoji} {finding.title}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **ID** | `{finding.id}` |",
            f"| **Severity** | {finding.severity.upper()} |",
            f"| **Type** | {finding.vuln_type} |",
            f"| **Endpoint** | `{finding.method} {finding.endpoint}` |",
            f"| **Found by** | {finding.agent} agent |",
            f"| **Timestamp** | {finding.timestamp} |",
            "",
            "#### Payload",
            "",
            f"```",
            finding.payload,
            f"```",
            "",
            "#### Evidence",
            "",
            f"```",
            finding.evidence[:2000],
            f"```",
            "",
            "#### Validation Proof",
            "",
            finding.validation_proof,
            "",
            "#### Reproduction (curl)",
            "",
            f"```bash",
            finding.curl_repro,
            f"```",
            "",
            "---",
            "",
        ]

    # Append test coverage section
    lines += [
        "## Test Coverage",
        "",
        f"- Endpoints discovered: {summary['endpoints_discovered']}",
        f"- Auth roles captured: {', '.join(summary['auth_roles']) if summary['auth_roles'] else 'none'}",
        f"- Total agent steps: {summary['steps']}",
        "",
        "### Vulnerability Categories Tested",
        "",
        "| Category | Result |",
        "|----------|--------|",
    ]

    tested_types = {f.vuln_type for f in findings}
    all_types = ["sqli", "xss", "idor", "jwt_manipulation", "path_traversal", "broken_auth", "misconfig", "sensitive_data"]
    for vtype in all_types:
        status = "✅ Found" if vtype in tested_types else "🔍 Tested / Not found"
        lines.append(f"| {vtype} | {status} |")

    report_text = "\n".join(lines)
    output_path.write_text(report_text)
    return report_text
