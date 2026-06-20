#!/usr/bin/env python3
"""
JuiceShark — AI-Powered Penetration Testing Agent
Targets OWASP Juice Shop with a multi-agent (orchestrator + recon/attack/validate)
architecture modeled on the standard pentest workflow. Runs on OpenAI or Gemini.

Usage:
    python main.py http://localhost:3000
    python main.py http://localhost:3000 --output ./my-run
    python main.py http://localhost:3000 --no-browser
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

# Load .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import google.genai as genai
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import print as rprint

console = Console()

# ──────────────────────────────────────────────
# Logging Setup
# ──────────────────────────────────────────────

def setup_logging(log_dir: Path, verbose: bool = False) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"agent_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.log"

    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout) if verbose else logging.NullHandler(),
        ],
    )
    return log_file


# ──────────────────────────────────────────────
# Target Connectivity Check
# ──────────────────────────────────────────────

def check_target(url: str) -> bool:
    """Verify the target is reachable before starting."""
    import requests
    try:
        resp = requests.get(url, timeout=10)
        return resp.status_code < 500
    except Exception as e:
        console.print(f"[red]Cannot reach target {url}: {e}[/red]")
        return False


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="JuiceShark — AI-powered pentest agent for OWASP Juice Shop",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Target URL (e.g. http://localhost:3000)")
    parser.add_argument("--output", "-o", default="./logs", help="Output directory for logs and findings (default: ./logs)")
    parser.add_argument("--no-browser", action="store_true", help="Disable Playwright browser tool")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging to stdout")
    parser.add_argument("--model", default=None, help="Model to use (default: gemini-2.5-flash or gpt-4o-mini)")
    parser.add_argument("--provider", choices=["gemini", "openai"], default=None, help="LLM provider (default: auto-detected)")
    args = parser.parse_args()

    target_url = args.target.rstrip("/")

    # ── Detect provider ──
    openai_key = os.environ.get("OPENAI_API_KEY")
    gemini_key = os.environ.get("GEMINI_API_KEY")

    provider = args.provider
    if not provider:
        if openai_key:
            provider = "openai"
        elif gemini_key:
            provider = "gemini"
        else:
            console.print("[red]ERROR: Neither OPENAI_API_KEY nor GEMINI_API_KEY environment variable is set.[/red]")
            console.print("[dim]Create a .env file with: OPENAI_API_KEY=your_key or GEMINI_API_KEY=your_key[/dim]")
            return 1

    # ── Model Selection ──
    model_name = args.model
    if not model_name:
        model_name = "gpt-4o-mini" if provider == "openai" else "gemini-2.5-flash"

    # ── Banner ──
    console.print(Panel.fit(
        "[bold cyan]🦈 JuiceShark[/bold cyan]\n"
        "[dim]AI-Powered Penetration Testing Agent[/dim]\n"
        f"[yellow]Target:[/yellow] {target_url}\n"
        f"[yellow]Provider:[/yellow] {provider}\n"
        f"[yellow]Model:[/yellow] {model_name}",
        border_style="cyan",
    ))

    # ── Output directory ──
    output_dir = Path(args.output)
    log_dir    = output_dir / "logs"
    log_file   = setup_logging(log_dir, args.verbose)
    console.print(f"[dim]Logs: {log_file}[/dim]")

    # ── Target check ──
    console.print(f"\n[bold]Checking target connectivity...[/bold]")
    if not check_target(target_url):
        console.print(f"[red]Target {target_url} is not reachable. Is Juice Shop running?[/red]")
        console.print("[dim]Start it with: docker run -d -p 3000:3000 bkimminich/juice-shop[/dim]")
        return 1
    console.print(f"[green]✓ Target is reachable[/green]")

    # ── State store ──
    from state.store import StateStore
    state_store = StateStore(output_dir)

    # ── Configure LLM Client ──
    if provider == "openai":
        from openai import OpenAI
        client = OpenAI(api_key=openai_key)
    else:
        client = genai.Client(api_key=gemini_key)

    # ── Run the orchestrator ──
    console.print("\n[bold cyan]Starting penetration test...[/bold cyan]\n")
    start_time = time.time()

    try:
        from agent.orchestrator import run_orchestrator
        result = run_orchestrator(
            client=client,
            model_name=model_name,
            target_url=target_url,
            state_store=state_store,
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        result = "Interrupted"
    except Exception as e:
        console.print(f"\n[red]Scan failed: {e}[/red]")
        logging.exception("Orchestrator failed")
        result = f"Failed: {e}"

    elapsed = time.time() - start_time

    # ── Generate report ──
    console.print("\n[bold]Generating report...[/bold]")
    from reporter import generate_report
    report_path = output_dir / "findings_report.md"
    report_text = generate_report(state_store, target_url, report_path, model_name=model_name)

    # ── Print summary ──
    summary = state_store.summary()
    findings = state_store.get_findings()

    console.print("\n")
    console.print(Panel.fit(
        f"[bold green]Scan Complete[/bold green]\n"
        f"Duration: {elapsed:.1f}s\n"
        f"Steps: {summary['steps']}\n"
        f"[bold]Findings: {summary['findings']}[/bold]",
        border_style="green",
    ))

    if findings:
        table = Table(title="Validated Findings", show_header=True)
        table.add_column("#", style="dim", width=3)
        table.add_column("Severity", width=10)
        table.add_column("Type", width=20)
        table.add_column("Title")
        table.add_column("Endpoint")

        sev_colors = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "blue", "info": "white"}
        for i, f in enumerate(findings, 1):
            color = sev_colors.get(f.severity, "white")
            table.add_row(
                str(i),
                f"[{color}]{f.severity.upper()}[/{color}]",
                f.vuln_type,
                f.title[:50],
                f"{f.method} {f.endpoint[:40]}",
            )
        console.print(table)

    console.print(f"\n[bold]Reports saved:[/bold]")
    console.print(f"  📄 Findings: {report_path}")
    console.print(f"  📋 Raw log:  {output_dir / 'session.jsonl'}")
    console.print(f"  🔍 Data:     {output_dir / 'findings.json'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
