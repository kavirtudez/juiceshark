"""
Terminal Tool — JuiceShark
Executes shell commands locally. Used for CLI security tools like sqlmap, nikto, gobuster.
"""

from __future__ import annotations

import os
import subprocess
import shlex
import tempfile


class TerminalTool:
    """Run shell commands with timeout and output capture."""

    DEFAULT_TIMEOUT = 120

    def execute(self, args: dict) -> str:
        command    = args.get("command", "").strip()
        timeout    = int(args.get("timeout", self.DEFAULT_TIMEOUT))
        working_dir = args.get("working_dir", tempfile.gettempdir())

        if not command:
            return "ERROR: No command provided"

        # Clamp timeout
        timeout = max(1, min(timeout, 300))

        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=working_dir,
                env={**os.environ, "TERM": "dumb"},  # disable color codes
            )

            stdout = result.stdout.strip()
            stderr = result.stderr.strip()

            lines = [
                f"EXIT CODE: {result.returncode}",
                f"COMMAND: {command}",
            ]

            if stdout:
                # Truncate very long output
                if len(stdout) > 10000:
                    stdout = stdout[:5000] + f"\n\n[... truncated {len(stdout) - 5000} chars ...]\n\n" + stdout[-2000:]
                lines.append(f"\nSTDOUT:\n{stdout}")

            if stderr:
                stderr_short = stderr[:3000]
                lines.append(f"\nSTDERR:\n{stderr_short}")

            if not stdout and not stderr:
                lines.append("\n(no output)")

            return "\n".join(lines)

        except subprocess.TimeoutExpired:
            return f"ERROR: Command timed out after {timeout}s\nCOMMAND: {command}"
        except Exception as e:
            return f"ERROR: {e}\nCOMMAND: {command}"
