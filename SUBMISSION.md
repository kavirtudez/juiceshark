# JuiceShark — Submission

Hi — thanks for reviewing this. I'm Kazz. This doc points you to each deliverable and
walks you through what I built, why I built it that way, and how to verify it yourselves.

---

## Where each deliverable is

| # | You asked for | Where it is |
|---|---------------|-------------|
| 1 | Code — Git repo, clones & runs cleanly | This repo: https://github.com/kavirtudez/juiceshark |
| 2 | Raw agent output logs | [`sample_run/session.jsonl`](sample_run/session.jsonl) — full 205-step trace; plus [`sample_run/findings.json`](sample_run/findings.json) and [`sample_run/meta.json`](sample_run/meta.json) |
| 3 | Findings report | [`sample_run/findings_report.md`](sample_run/findings_report.md) |
| 4 | Reflection doc (≤1 page) | [`reflection.md`](reflection.md) |

How I worked with AI tools is described in the "How I used AI tools" section below.

---

## Running it yourselves

```bash
git clone https://github.com/kavirtudez/juiceshark.git
cd juiceshark
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium          # needed for DOM XSS / admin-panel rendering
cp .env.example .env                 # then paste your own OpenAI key into .env
python3 main.py http://localhost:3000
```

You'll need Juice Shop running on port 3000 (`docker run -d -p 3000:3000 bkimminich/juice-shop`).
There's no key in the repo — `.env` is gitignored, so you'll add your own. A run takes
~10–20 minutes and writes `findings_report.md`, `findings.json`, `session.jsonl`, and
`meta.json` into `./logs/`. The committed `sample_run/` is a complete reference run if you'd
rather read results before running anything.

---

## What it found (latest run: 8/8 categories, 0 false positives)

| # | Category | Severity | Technique | How it was validated |
|---|----------|----------|-----------|----------------------|
| 1 | SQL Injection | Critical | `POST /rest/user/login`, `' OR 1=1--` | 200 + admin JWT returned |
| 2 | Path Traversal | Critical | `GET /ftp/coupons_2013.md.bak%2500.md` | 200 on a non-.md/.pdf file (null-byte bypass) |
| 3 | JWT Manipulation | Critical | `alg:none` + RS256→HS256 confusion | Juice Shop's own JWT challenges flip to `solved` |
| 4 | DOM XSS | High | `/#/search?q=<img src=x onerror=alert('XSS')>` | headless browser actually fires `alert()` |
| 5 | Sensitive Data Exposure | High | `GET /ftp/` | confidential file listing returned |
| 6 | IDOR | High | `GET /rest/basket/2` with admin token | another user's basket returned |
| 7 | Broken Auth | High | `GET /rest/user/change-password?new=…&repeat=…` | password changed with no current password |
| 8 | Security Misconfiguration | High | `GET /api/Users/` with admin token | full user table (emails + roles) |

Full evidence per finding is in [`sample_run/findings_report.md`](sample_run/findings_report.md).

---

## The architecture, and why I built it this way

It's a multi-agent system modeled on how a real pentest actually proceeds —
recon, then exploitation, then validation:

```
Orchestrator  (owns the test plan; only reports validated findings)
├── delegate_recon    → Recon Agent      maps endpoints, fingerprints the app
├── delegate_attack   → Attacker Agent   exploits ONE category at a time
└── delegate_validate → Validator Agent  independently reproduces → report_finding
```

A few decisions worth calling out:

**I made the Validator a hard gate, not a formality.** The Attacker only *proposes* a
finding. A separate Validator agent, with fresh context, re-runs the exploit from scratch and
only then records it. This is the piece that addresses false positives directly — for example,
DOM XSS is confirmed by actually firing `alert()` in a headless browser, and JWT manipulation
by the application's own challenge flags flipping to `solved`, not by string-matching a response.

**I split into specialist agents instead of one mega-agent** because a single agent doing
everything conflates "look around" with "exploit" and drifts. Separate, focused agents keep each
prompt short, which also reduces hallucination and token cost.

**The core loop is a ReAct-style reason/act cycle I wrote from scratch** (`agent/loop.py`): call
the model, run the tool it requests, feed the result back, repeat until a terminal "barrier" tool
(`report_finding` / `done`) fires. I hardened it for unattended runs — a hard iteration ceiling, a
graceful-shutdown window, repeating-call detection to break stuck loops, and bounded retry/back-off
that explicitly handles rate-limits (429) and request timeouts.

**State is plain JSON/JSONL flushed on every mutation** (`state/store.py`). I deliberately avoided
a database: for a single-run CLI this is enough, it survives crashes, and it makes the logs
submittable as evidence as-is. Findings dedupe by category, so the report holds exactly one proven
instance of each.

**It's provider-agnostic and defaults to OpenAI** (`gpt-4o-mini`); it also runs on Gemini. I default
to OpenAI because the free Gemini tier rate-limits partway through a scan.

Honest tradeoffs: it runs sequentially (no parallel agents), the shell tool executes on the host
rather than in a container, and there's no cross-run memory. All acceptable at this scale; all things
I'd change for production, and I cover them in [`reflection.md`](reflection.md).

---

## One finding in depth: JWT manipulation

Juice Shop verifies tokens with `jwt.verify(token, publicKey)` and never pins an `algorithms`
whitelist (it's in `lib/insecurity.ts`), so it accepts two forgeries:

1. **`alg:none`** — a signature-less token (the "Unsigned JWT" challenge, impersonating
   `jwtn3d@juice-sh.op`).
2. **RS256→HS256 confusion** — an HS256 token signed using the *public key* as the HMAC secret.
   When the server verifies an HS256 token with `publicKey`, it uses that key as the HMAC secret —
   exactly what was used to sign it. The public key is downloadable at `/encryptionkeys/jwt.pub`
   with no auth (the "Forged Signed JWT" challenge, `rsa_lord@juice-sh.op`).

The forging logic is in [`tools/jwt_forge.py`](tools/jwt_forge.py) (standard library only). The
Validator runs it; it forges both tokens, sends them, and then reads Juice Shop's challenge status —
both `jwtUnsignedChallenge` and `jwtForgedChallenge` come back `solved: true`. That's the application
itself confirming the forged tokens were accepted, which is as close to ground truth as validation gets.

---

## What went wrong, and how I fixed it

Most of the real work here was debugging from the agent's own logs, not writing new code:

- **A token-capture bug** made IDOR, broken-auth, and misconfig all silently return 401. The SQLi
  login is performed by the Attacker sub-agent, but JWT capture was only running on the orchestrator's
  own requests, so the admin token was never stored. I moved capture into the HTTP tool itself, so any
  agent's login is reusable by every later agent. That single fix unblocked three categories.
- **The broken-auth payload was wrong** at first (`current=WRONG`, which returns 401). Juice Shop only
  skips the current-password check when the parameter is *omitted entirely* — I caught that by reading
  the actual server behavior rather than trusting the assumption.
- **The Validator over-trusted a helper tool** and rejected the (correct) path-traversal 200 because the
  response body was encrypted-coupon gibberish. I changed the criteria to treat the 200 on a disallowed
  extension as conclusive.
- **Provider flakiness** — Gemini 429s and an OpenAI timeout loop when an agent re-rendered the 185 KB
  admin page — is handled with back-off, a higher client timeout, and stripping CSS/scripts from rendered
  pages so requests don't bloat.

---

## How I used AI tools

I drove the architecture decisions — the recon/exploit/validate split, making the Validator a hard gate,
the barrier-tool design. I used Claude Code to scaffold the loop, tool schemas, and per-category playbooks,
then reviewed and corrected its output. The highest-value use was diagnosis rather than generation: I
pointed it at the raw `session.jsonl` to trace the 401s to the token-capture site, and had it pull the
missing-algorithm JWT detail straight from Juice Shop's source. Several first attempts were wrong (the
`current=WRONG` payload is the clearest example) — correcting those against real server behavior is the
collaboration I'd point to, and it shows up directly in the commit history.

---

## How this maps to your criteria

- **Real, validated vulnerabilities:** every finding is independently reproduced by a separate agent
  before it's recorded — `findings.json` holds one proven instance per category.
- **Sound architecture / failure recovery:** retry/back-off, barrier tools, repeating-call detection,
  graceful shutdown, and crash-survivable state persistence.
- **Runs cleanly from a fresh clone:** I verified this end-to-end from a clean checkout and a new venv.
- **Structured, maintainable code:** separated into `agent/`, `tools/`, and `state/` — not a single script.
