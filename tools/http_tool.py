"""
HTTP Tool — JuiceShark
Makes HTTP requests to the target application with full response capture.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from typing import Any

import requests
from requests.exceptions import RequestException

logger = logging.getLogger("juiceshark.http")

# JWT pattern: header.payload.signature (signature may be empty for alg=none)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


class HTTPTool:
    """
    Stateful HTTP client that remembers auth tokens and target URL, and acts as
    the single choke point where JWTs and probed endpoints are captured into
    shared state for later agents to reuse.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/html, */*",
        })
        self._auth_tokens: dict[str, str] = {}

    def set_auth_token(self, role: str, token: str) -> None:
        self._auth_tokens[role] = token

    def _capture_tokens(self, response_text: str, state_store=None) -> None:
        """
        Scan a response for JWTs and persist them keyed by role.

        This runs for EVERY agent's request (not just the orchestrator's) because
        the SQLi login that yields the admin JWT is performed by the attacker
        sub-agent. Without this, auth_token="admin" later resolves to nothing and
        every authenticated test (IDOR, broken_auth, misconfig) gets a 401.

        Juice Shop JWTs nest the user under `data`, e.g.
            {"status":"success","data":{"id":1,"role":"admin","email":"admin@juice-sh.op"},"iat":...}
        so the role/email must be read from `data`, not the top level.
        """
        for token in _JWT_RE.findall(response_text)[:1]:
            try:
                parts = token.split(".")
                padded = parts[1] + "=" * (-len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(padded).decode())
                data = payload.get("data", payload)  # fall back to top level
                role_field = str(data.get("role", "")).lower()
                email = str(data.get("email", "")).lower()
                if role_field:
                    role = "admin" if "admin" in role_field else "user"
                else:
                    role = "admin" if "admin" in email else "user"

                self._auth_tokens[role] = token
                if state_store and hasattr(state_store, "set_auth_token"):
                    if state_store.get_auth_token(role) != token:
                        state_store.set_auth_token(role, token)
                        logger.info(f"Captured {role} JWT (email: {email or 'unknown'})")
            except Exception:
                pass

    def execute(self, args: dict, state_store=None) -> str:
        """
        Execute an HTTP request. Returns structured text response.
        """
        method    = args.get("method", "GET").upper()
        url       = args.get("url", "")
        headers   = args.get("headers", {}) or {}
        body      = args.get("body", "")
        auth_ref  = args.get("auth_token", "")
        follow_r  = args.get("follow_redirects", True)
        timeout   = int(args.get("timeout", 15))

        # Resolve relative URLs
        if url.startswith("/"):
            url = self.target_url + url

        # Inject auth token
        if auth_ref:
            token = None
            if auth_ref in ("user", "admin"):
                token = self._auth_tokens.get(auth_ref)
                if token is None and state_store:
                    token = state_store.get_auth_token(auth_ref)
            else:
                token = auth_ref  # raw token provided

            if token:
                headers["Authorization"] = f"Bearer {token}"

        # Parse body
        request_kwargs: dict[str, Any] = {
            "headers": headers,
            "allow_redirects": follow_r,
            "timeout": timeout,
        }

        if body:
            try:
                json_body = json.loads(body)
                request_kwargs["json"] = json_body
                if "Content-Type" not in headers:
                    headers["Content-Type"] = "application/json"
            except (json.JSONDecodeError, TypeError):
                request_kwargs["data"] = body

        start = time.time()
        try:
            resp = self._session.request(method, url, **request_kwargs)
            elapsed = time.time() - start

            # Try to pretty-print JSON response
            body_text = resp.text
            is_json = False
            try:
                body_parsed = resp.json()
                body_text = json.dumps(body_parsed, indent=2)
                is_json = True
            except Exception:
                pass

            # Capture any JWT in the response so later authenticated requests
            # (from any agent) can reuse it via auth_token="admin"/"user".
            self._capture_tokens(resp.text, state_store)

            # Record the probed endpoint (path without query string) so the
            # report's "Endpoints discovered" reflects the mapped attack surface.
            if state_store and hasattr(state_store, "add_endpoint"):
                try:
                    from urllib.parse import urlsplit
                    path = urlsplit(url).path or url
                    state_store.add_endpoint({"method": method, "path": path})
                except Exception:
                    pass

            # Aggressively truncate non-JSON responses to save context window tokens
            body_limit = 8000 if is_json else 1000

            # Build structured response
            lines = [
                f"STATUS: {resp.status_code} {resp.reason}",
                f"URL: {resp.url}",
                f"TIME: {elapsed:.3f}s",
                f"HEADERS: {dict(resp.headers)}",
                "",
                "BODY:",
                body_text[:body_limit],
            ]

            if len(body_text) > body_limit:
                lines.append(f"\n[... truncated {len(body_text) - body_limit} bytes ...]")

            return "\n".join(lines)

        except RequestException as e:
            elapsed = time.time() - start
            return f"ERROR: Request failed after {elapsed:.3f}s\nDetails: {e}"
