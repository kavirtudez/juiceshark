# JuiceShark 🦈

**An AI-powered penetration-testing agent that autonomously discovers and validates vulnerabilities in OWASP Juice Shop.**

Built by Kazz Virtudez. Python, multi-agent. The design mirrors how a human red team actually works — a methodology-driven pipeline of **recon → exploitation → validation** ([PTES](http://www.pentest-standard.org/) / [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)) — implemented as an **orchestrator-worker** agent system with **ReAct-style** tool-use loops. I used **Claude Code** as a coding collaborator throughout — see [`reflection.md`](reflection.md) for how I split work between me and the model.

---

## The Challenge

> Build an AI-powered penetration testing agent that autonomously discovers and validates vulnerabilities in a target web application (OWASP Juice Shop). The agent should find **real** vulnerabilities — not false positives — with sound architecture (state management, error handling, failure recovery), run cleanly from a fresh clone, and be structured and maintainable.

JuiceShark answers that with a **3-role agent pipeline** (recon → attack → validate) driven by an orchestrator, where **nothing is reported until a separate validator independently reproduces it**.

---

## Results — latest run (8/8 categories, 0 false positives)

From [`sample_run/findings_report.md`](sample_run/findings_report.md) — a full autonomous run against a fresh Juice Shop (`gpt-4o-mini`, 205 steps, 13 endpoints mapped):

| # | Category | Severity | Endpoint / Technique | Validated proof |
|---|----------|----------|----------------------|-----------------|
| 1 | SQL Injection | Critical | `POST /rest/user/login` — `' OR 1=1--` | 200 + admin JWT returned |
| 2 | Path Traversal | Critical | `GET /ftp/coupons_2013.md.bak%2500.md` | 200 on a non-.md/.pdf file (null-byte bypass) |
| 3 | JWT Manipulation | Critical | `alg:none` + RS256→HS256 confusion | Juice Shop JWT challenges flip to `solved` |
| 4 | DOM XSS | High | `/#/search?q=<img src=x onerror=alert('XSS')>` | headless browser fires `alert()` |
| 5 | Sensitive Data Exposure | High | `GET /ftp/` | confidential file listing returned |
| 6 | IDOR | High | `GET /rest/basket/2` with admin token | another user's basket returned |
| 7 | Broken Auth | High | `GET /rest/user/change-password?new=…&repeat=…` | password changed with no current password |
| 8 | Security Misconfiguration | High | `GET /api/Users/` with admin token | full user table (emails + roles) |

Every finding is independently re-run by the **Validator** agent before it lands in the report. Raw artifacts for this run are committed under [`sample_run/`](sample_run/) (findings report, machine-readable findings, full step-by-step `session.jsonl`, and captured tokens/endpoints in `meta.json`).

---

## Architecture

```
Orchestrator (drives an 8-item checklist, never reports unvalidated findings)
├── delegate_recon    → Recon Agent      maps endpoints, fingerprints the app
├── delegate_attack   → Attacker Agent   exploits ONE vuln category at a time
└── delegate_validate → Validator Agent  independently reproduces → report_finding
```

Core engine ([`agent/loop.py`](agent/loop.py)) is a ReAct-style reason/act loop (pick a tool → execute → feed the result back → repeat) hardened for autonomous, unattended runs:

- **Agentic loop** with a hard iteration cap and graceful shutdown window.
- **Reflector** — when the LLM emits prose instead of a tool call, inject corrective guidance instead of crashing.
- **Barrier tools** — `report_finding` / `done` cleanly terminate a chain (the orchestrator only stops on `done`, so it keeps going after each finding).
- **Per-agent retry/back-off** with explicit handling of rate-limit (429) and request-timeout errors.
- **Centralized token + endpoint capture** in the HTTP tool, so a JWT captured by one agent is reusable (`auth_token:"admin"`) by every later agent.

Provider-agnostic: the same loop runs on **OpenAI** (default) or **Gemini**.

---

## Quick Start (fresh clone)

### 1. Prerequisites
- **Python 3.9+** (developed/tested on 3.9 and 3.11)
- **Docker** (to host Juice Shop), or a Node install of Juice Shop

### 2. Start OWASP Juice Shop
```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
# wait ~30s, then confirm http://localhost:3000 responds
```

### 3. Install JuiceShark
```bash
cd juiceshark
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium          # for DOM XSS / admin-panel rendering
```

### 4. Add YOUR OWN API key
```bash
cp .env.example .env
```
Open `.env` and paste your OpenAI key (get one at https://platform.openai.com/api-keys):
```
OPENAI_API_KEY=sk-...your key...
```
> The provider auto-detects from `.env`. OpenAI is recommended — the free Gemini tier hits 429 rate limits mid-scan. `.env` is gitignored and never committed.

### 5. Run
```bash
python3 main.py http://localhost:3000
```
A run takes ~10–20 min and writes results to `./logs/`.

**Options**
```bash
python3 main.py http://localhost:3000 --output ./my-run     # custom output dir
python3 main.py http://localhost:3000 --provider openai     # force provider
python3 main.py http://localhost:3000 --model gpt-4o        # different model
python3 main.py http://localhost:3000 --verbose             # debug logging
python3 main.py http://localhost:3000 --no-browser          # skip Playwright
```

---

## Output

| File (in `--output`, default `./logs/`) | Description |
|------|-------------|
| `findings_report.md` | Human-readable report with evidence per finding |
| `findings.json` | Machine-readable findings (one per validated category) |
| `session.jsonl` | Complete agent step-by-step trace (every tool call + result) |
| `meta.json` | Captured auth tokens and discovered endpoints |

A complete reference run is committed under [`sample_run/`](sample_run/).

---

## Project Structure

```
juiceshark/
├── main.py               # CLI entry point + provider/model selection
├── reporter.py           # Findings → Markdown report
├── requirements.txt
├── .env.example          # copy to .env, add your own key
├── agent/
│   ├── loop.py           # core ReAct-style agentic loop + retry/back-off
│   ├── reflector.py      # reflector pattern
│   ├── orchestrator.py   # primary coordinator + 8-item checklist
│   ├── recon.py          # recon sub-agent
│   ├── attacker.py       # attack sub-agent (per-category playbooks)
│   └── validator.py      # validation sub-agent (false-positive killer)
├── tools/
│   ├── registry.py       # tool schemas + per-agent tool sets
│   ├── http_tool.py      # HTTP + central JWT/endpoint capture
│   ├── terminal_tool.py  # sandboxed-ish shell (timeouts, output caps)
│   ├── browser_tool.py   # Playwright headless browser (DOM XSS, admin panel)
│   ├── analysis_tool.py  # response pattern analysis
│   └── jwt_forge.py      # stdlib JWT forger (alg:none + HS256 confusion)
├── state/
│   └── store.py          # thread-safe findings/session/token persistence
└── sample_run/           # committed reference run (8/8, raw logs)
```

---

## Notes for evaluators

- **Validation is the point.** `findings.json` holds exactly one entry per category — the store dedupes by `vuln_type`, and each was reproduced by the Validator before recording. The agent will happily *try* more, but only validated results are reported.
- **JWT manipulation** is solved the way the community does it: the public key is downloadable at `/encryptionkeys/jwt.pub`, and Juice Shop's `jwt.verify` pins no algorithm — so both `alg:none` and an HS256 token signed with the public key are accepted. See [`tools/jwt_forge.py`](tools/jwt_forge.py).
- **Failure recovery is real, not aspirational** — the loop survived Gemini 429s and OpenAI request timeouts during development; both paths have explicit handling. The reflection doc is candid about what broke.

See [`reflection.md`](reflection.md) for architecture decisions, tradeoffs, and the AI-collaboration story.
