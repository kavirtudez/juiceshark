"""
Analysis Tool — JuiceShark
Heuristic analysis of HTTP responses and strings for security vulnerability patterns.
"""

from __future__ import annotations

import re
import json
import base64
from typing import Any


# ──────────────────────────────────────────────
# Detection Patterns
# ──────────────────────────────────────────────

SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*?MySQL",
    r"Warning.*?mysql_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your MySQL server",
    r"SQLSTATE\[",
    r"ORA-\d{5}",
    r"Oracle error",
    r"SQLite.*?exception",
    r"Microsoft.*?ODBC.*?SQL Server",
    r"Unclosed quotation mark",
    r"pg_query\(\)",
    r"ERROR:\s+syntax error at or near",
    r"Unknown column '.*?' in 'field list'",
    r"You have an error in your SQL syntax",
    r"Sequelize.*?SequelizeDatabaseError",
]

XSS_INDICATORS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"on(?:click|load|error|mouseover|focus|blur|submit|change)\s*=",
    r"alert\s*\(",
    r"confirm\s*\(",
    r"prompt\s*\(",
    r"<img[^>]+onerror",
    r"<svg[^>]+onload",
    r"<iframe[^>]*src",
    r"expression\s*\(",
    r"vbscript:",
]

JWT_PATTERN = r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"

SENSITIVE_DATA_PATTERNS = [
    (r"password[\"']?\s*[:=]\s*[\"'][^\"']{4,}", "password field"),
    (r"(?:api[_-]?key|apikey)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9]{16,}", "API key"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "private key"),
    (r"(?:secret|token)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9+/=]{20,}", "secret/token"),
    (r"(?:aws|amazon).*?(?:AKIA|ASIA)[A-Z0-9]{16}", "AWS key"),
    (r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", "credit card-like number"),
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "email address"),
    (r'"password"\s*:\s*"[^"]+"', "plaintext password in JSON"),
    # Juice Shop specific
    (r"This document is confidential", "confidential document marker"),
    (r"Do not distribute", "confidential document marker"),
    (r"Planned Acquisitions", "sensitive acquisition document"),
    (r"\.bak\b", "backup file reference"),
    (r"\.kdbx\b", "KeePass password database"),
    (r"incident-support", "security incident database"),
]

ADMIN_INDICATORS = [
    r"admin",
    r"dashboard",
    r"administration",
    r"manage",
    r"panel",
    r"console",
    r"superuser",
    r"isAdmin.*?true",
    r'"role"\s*:\s*"admin"',
]

PATH_TRAVERSAL_INDICATORS = [
    r"root:.*?:/bin/",
    r"\[boot loader\]",
    r"for 16-bit app support",
    r"/etc/passwd",
]

DIRECTORY_LISTING_INDICATORS = [
    r"Index of /",
    r"Directory listing for",
    r"<title>Directory",
    r"Parent Directory",
    # Juice Shop FTP returns JSON array of filenames
    r'\[\s*"[^"]+"\s*,\s*"[^"]+"\s*\]',  # JSON array with 2+ filenames
    r'"acquisitions\.md"',
    r'"package-lock\.json\.bak"',
    r'"coupons_\d+\.md\.bak"',
]

ERROR_DISCLOSURE_PATTERNS = [
    r"at\s+[\w.]+\([\w.]+:\d+\)",  # stack traces
    r"Error\s+trace:",
    r"Traceback \(most recent call last\)",
    r"(?:Node|TypeError|ReferenceError):\s+\w+",
    r"UnhandledPromiseRejectionWarning",
    r"express.*?Error",
]


class AnalysisTool:
    """Analyzes HTTP responses for security vulnerability patterns."""

    def execute(self, args: dict) -> str:
        content = args.get("content", "")
        checks  = args.get("checks", [])
        payload = args.get("payload", "")

        if not content:
            return "ERROR: No content provided to analyze"

        run_all = not checks
        results: list[str] = []

        # SQL injection errors
        if run_all or "sqli_error" in checks:
            matches = self._check_patterns(content, SQLI_ERROR_PATTERNS)
            if matches:
                results.append(f"[SQLI ERROR DETECTED] Patterns found: {matches[:3]}")
            else:
                results.append("[sqli_error] No SQL error patterns detected")

        # XSS reflection
        if run_all or "xss_reflection" in checks:
            if payload:
                # Check if payload is reflected
                if payload in content:
                    results.append(f"[XSS REFLECTION DETECTED] Payload '{payload[:100]}' is reflected in response")
                elif re.sub(r'\s+', '', payload) in re.sub(r'\s+', '', content):
                    results.append(f"[XSS REFLECTION POSSIBLE] Payload reflected with whitespace differences")
                else:
                    results.append("[xss_reflection] Payload not reflected")
            xss_matches = self._check_patterns(content, XSS_INDICATORS)
            if xss_matches:
                results.append(f"[XSS INDICATORS FOUND] {xss_matches[:3]}")

        # JWT tokens
        if run_all or "jwt_token" in checks:
            jwts = re.findall(JWT_PATTERN, content)
            if jwts:
                results.append(f"[JWT TOKENS FOUND] {len(jwts)} token(s)")
                for jwt in jwts[:2]:
                    decoded = self._decode_jwt(jwt)
                    results.append(f"  Token: {jwt[:50]}...")
                    results.append(f"  Decoded header: {decoded['header']}")
                    results.append(f"  Decoded payload: {decoded['payload']}")
            else:
                results.append("[jwt_token] No JWT tokens found")

        # Sensitive data
        if run_all or "sensitive_data" in checks:
            found = []
            for pattern, label in SENSITIVE_DATA_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    found.append(f"{label}: {matches[0][:100]}")
            if found:
                results.append(f"[SENSITIVE DATA FOUND]\n" + "\n".join(f"  - {f}" for f in found[:5]))
            else:
                results.append("[sensitive_data] No obvious sensitive data detected")

        # Admin content
        if run_all or "admin_content" in checks:
            matches = self._check_patterns(content, ADMIN_INDICATORS, re.IGNORECASE)
            if matches:
                results.append(f"[ADMIN INDICATORS FOUND] {matches[:3]}")
            else:
                results.append("[admin_content] No admin indicators found")

        # Error disclosure
        if run_all or "error_disclosure" in checks:
            matches = self._check_patterns(content, ERROR_DISCLOSURE_PATTERNS)
            if matches:
                results.append(f"[ERROR DISCLOSURE DETECTED] {matches[:2]}")
            else:
                results.append("[error_disclosure] No stack traces or error details found")

        # Path traversal
        if run_all or "path_traversal" in checks:
            matches = self._check_patterns(content, PATH_TRAVERSAL_INDICATORS)
            if matches:
                results.append(f"[PATH TRAVERSAL SUCCESS] {matches[:2]}")
            else:
                results.append("[path_traversal] No path traversal indicators")

        # Directory listing
        if run_all or "directory_listing" in checks:
            matches = self._check_patterns(content, DIRECTORY_LISTING_INDICATORS)
            if matches:
                results.append(f"[DIRECTORY LISTING DETECTED] {matches[:2]}")
            else:
                results.append("[directory_listing] No directory listing detected")

        return "\n".join(results)

    def _check_patterns(self, content: str, patterns: list[str], flags: int = 0) -> list[str]:
        found = []
        for pattern in patterns:
            match = re.search(pattern, content, flags)
            if match:
                found.append(match.group(0)[:100])
        return found

    def _decode_jwt(self, token: str) -> dict:
        """Decode a JWT without verifying signature."""
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return {"header": "invalid", "payload": "invalid"}

            def decode_part(part: str) -> dict:
                # Add padding
                padded = part + "=" * (4 - len(part) % 4)
                decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
                return json.loads(decoded)

            return {
                "header": decode_part(parts[0]),
                "payload": decode_part(parts[1]),
            }
        except Exception as e:
            return {"header": f"error: {e}", "payload": ""}
