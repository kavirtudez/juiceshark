"""
JuiceShark State Store
Persists findings, session logs, and message chains to disk.
Thread-safe, file-backed state. Kept deliberately simple (JSON/JSONL, no DB) so a
single run is self-contained, crash-survivable, and its logs are submittable as-is.
"""

from __future__ import annotations

import json
import time
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    """A validated vulnerability finding."""
    id: str
    title: str
    severity: str          # critical / high / medium / low / info
    vuln_type: str         # sqli, xss, idor, jwt, etc.
    endpoint: str
    method: str
    payload: str
    evidence: str          # raw response snippet or proof
    validation_proof: str  # how we confirmed it's real
    curl_repro: str        # curl command to reproduce
    agent: str             # which agent found it
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    false_positive: bool = False


@dataclass
class SessionLog:
    """One step in the agent session log."""
    step: int
    agent: str
    action: str            # tool_call | tool_result | reflection | thinking
    tool: str = ""
    args: dict = field(default_factory=dict)
    result: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class StateStore:
    """
    Thread-safe state store. Writes to disk on every mutation so logs survive crashes.
    """

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        self._findings: list[Finding] = []
        self._session_log: list[SessionLog] = []
        self._auth_tokens: dict[str, str] = {}   # role -> JWT token
        self._discovered_endpoints: list[dict] = []
        self._step_counter = 0

        # Load existing state if resuming
        self._load()

    # ──────────────────────── Findings ────────────────────────

    def add_finding(self, finding: Finding) -> None:
        with self._lock:
            # Deduplicate purely by vuln_type — the goal is to prove we can
            # find one of each OWASP category, so a second hit on the same
            # category (e.g. /ftp/ vs /ftp/acquisitions.md, or /#/search vs
            # /#/search?q=...) is redundant and should be dropped.
            for existing in self._findings:
                if existing.vuln_type == finding.vuln_type:
                    return
            self._findings.append(finding)
            self._flush_findings()

    def get_findings(self) -> list[Finding]:
        with self._lock:
            return list(self._findings)

    def finding_count(self) -> int:
        with self._lock:
            return len(self._findings)

    # ──────────────────────── Session Log ────────────────────────

    def log_step(
        self,
        agent: str,
        action: str,
        tool: str = "",
        args: dict | None = None,
        result: str = "",
    ) -> int:
        with self._lock:
            self._step_counter += 1
            entry = SessionLog(
                step=self._step_counter,
                agent=agent,
                action=action,
                tool=tool,
                args=args or {},
                result=result[:4000] if result else "",  # truncate huge results
            )
            self._session_log.append(entry)
            self._flush_session()
            return self._step_counter

    # ──────────────────────── Auth Tokens ────────────────────────

    def set_auth_token(self, role: str, token: str) -> None:
        with self._lock:
            self._auth_tokens[role] = token
            self._flush_meta()

    def get_auth_token(self, role: str = "user") -> str | None:
        with self._lock:
            return self._auth_tokens.get(role)

    # ──────────────────────── Endpoints ────────────────────────

    def add_endpoint(self, endpoint: dict) -> None:
        with self._lock:
            key = (endpoint.get("method", "GET"), endpoint.get("path", ""))
            for existing in self._discovered_endpoints:
                if (existing.get("method"), existing.get("path")) == key:
                    return
            self._discovered_endpoints.append(endpoint)
            self._flush_meta()

    def get_endpoints(self) -> list[dict]:
        with self._lock:
            return list(self._discovered_endpoints)

    # ──────────────────────── Summary ────────────────────────

    def summary(self) -> dict:
        with self._lock:
            return {
                "findings": len(self._findings),
                "steps": self._step_counter,
                "endpoints_discovered": len(self._discovered_endpoints),
                "auth_roles": list(self._auth_tokens.keys()),
                "findings_list": [
                    {"id": f.id, "title": f.title, "severity": f.severity, "endpoint": f.endpoint}
                    for f in self._findings
                ],
            }

    # ──────────────────────── Persistence ────────────────────────

    def _flush_findings(self) -> None:
        path = self.output_dir / "findings.json"
        data = [asdict(f) for f in self._findings]
        path.write_text(json.dumps(data, indent=2))

    def _flush_session(self) -> None:
        path = self.output_dir / "session.jsonl"
        with path.open("a") as f:
            entry = self._session_log[-1]
            f.write(json.dumps(asdict(entry)) + "\n")

    def _flush_meta(self) -> None:
        path = self.output_dir / "meta.json"
        data = {
            "auth_tokens": self._auth_tokens,
            "endpoints": self._discovered_endpoints,
        }
        path.write_text(json.dumps(data, indent=2))

    def _load(self) -> None:
        findings_path = self.output_dir / "findings.json"
        if findings_path.exists():
            try:
                data = json.loads(findings_path.read_text())
                self._findings = [Finding(**f) for f in data]
            except Exception:
                pass

        meta_path = self.output_dir / "meta.json"
        if meta_path.exists():
            try:
                data = json.loads(meta_path.read_text())
                self._auth_tokens = data.get("auth_tokens", {})
                self._discovered_endpoints = data.get("endpoints", [])
            except Exception:
                pass

        # Restore the step counter from the persisted session log so that
        # regenerating a report from a saved run (without re-running the scan)
        # reflects the real number of steps instead of 0.
        session_path = self.output_dir / "session.jsonl"
        if session_path.exists():
            try:
                last_step = 0
                with session_path.open() as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            last_step = json.loads(line).get("step", last_step)
                self._step_counter = max(self._step_counter, last_step)
            except Exception:
                pass
