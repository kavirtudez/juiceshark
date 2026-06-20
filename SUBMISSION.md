# JuiceShark — Submission & Defense Notes

Hey — this is Kazz. This doc does two things: (1) tells you exactly where each of the
five deliverables lives, and (2) is my read-over script for the call — how I'd explain
the architecture, walk through a finding, and answer the questions I expect.

---

## 1. Where the deliverables are

| # | Asked for | Where it is |
|---|-----------|-------------|
| 1 | Code — Git repo, clones & runs cleanly | https://github.com/kavirtudez/juiceshark (this repo) |
| 2 | Raw agent output logs | [`sample_run/session.jsonl`](sample_run/session.jsonl) (full 205-step trace), [`sample_run/findings.json`](sample_run/findings.json), [`sample_run/meta.json`](sample_run/meta.json) |
| 3 | AI tool transcripts | Exported Claude Code session history (attached separately — this is the dev conversation) |
| 4 | Short findings report | [`sample_run/findings_report.md`](sample_run/findings_report.md) |
| 5 | Reflection doc (≤1 page) | [`reflection.md`](reflection.md) |

Fresh-clone check (I actually ran this): clone → `python3 -m venv .venv` → `pip install -r requirements.txt`
→ `playwright install chromium` → `cp .env.example .env` and paste an OpenAI key → `python3 main.py http://localhost:3000`.
No key in the repo; `.env` is gitignored.

---

## 2. The 30-second pitch (how I'd open)

"JuiceShark is an autonomous pentest agent for OWASP Juice Shop. It's built the way a
human red team actually works — recon, then exploitation, then validation — but as a
multi-agent system. An orchestrator owns the test plan and delegates each phase to a
focused sub-agent. The thing I care most about is the **validator**: nothing gets
reported until a separate agent independently reproduces it from scratch. On the latest
run it found and validated all 8 OWASP categories with zero false positives."

---

## 3. Architecture — and *why* I made each call

**Orchestrator → Recon / Attacker / Validator (orchestrator-worker pattern).**
I split it this way because a single agent doing everything loses the plot — it conflates
"look around" with "exploit" and hallucinates. Separate agents keep each prompt short and
focused, which also keeps token cost and confusion down.

**The validator is a hard gate, not a formality.** The Attacker only *proposes* a finding.
A fresh Validator agent re-runs the exploit independently and only then calls
`report_finding`. This is the direct answer to "real vulns, not false positives" — e.g. it
confirms DOM XSS by actually firing `alert()` in a headless browser, not by string-matching
the response.

**The loop is a ReAct-style reason/act cycle I wrote from scratch** (`agent/loop.py`): call
the model → run the tool it asks for → feed the result back → repeat until a "barrier" tool
(`report_finding`/`done`) fires. I hardened it for unattended runs: a hard iteration cap, a
graceful-shutdown window, repeating-call detection to break stuck loops, and bounded
retry/back-off that explicitly handles rate-limits (429) and request timeouts.

**State is plain JSON/JSONL flushed on every mutation** (`state/store.py`). I deliberately
didn't reach for a database — for a single-run CLI, this is enough, it survives crashes, and
the logs are submittable as evidence as-is. Findings dedupe by `vuln_type` so the report has
exactly one proven instance per category.

**Provider-agnostic, defaults to OpenAI.** Same loop runs on OpenAI (`gpt-4o-mini`) or Gemini.
I default to OpenAI because the free Gemini tier 429s partway through a scan.

**Tradeoffs I'll own:** it's single-process/sequential (no parallel agents), the terminal tool
runs on the host (no container sandbox), and there's no cross-run memory. All fine at this
scale; all things I'd change for production (see reflection).

---

## 4. Walk one finding end-to-end — I'll use JWT manipulation

This is the finding I want them to ask about, because the proof is airtight.

**The bug:** Juice Shop verifies tokens with `jwt.verify(token, publicKey)` and never pins an
`algorithms` whitelist (it's right there in `lib/insecurity.ts`). That means it accepts two
forgeries:
1. **`alg:none`** — a token with no signature at all (the "Unsigned JWT" challenge,
   impersonating `jwtn3d@juice-sh.op`).
2. **RS256→HS256 confusion** — sign an HS256 token using the *public key* as the HMAC secret.
   When the server verifies an HS256 token with `publicKey`, it treats that key as the HMAC
   secret — the exact thing I just signed with. The public key is downloadable at
   `/encryptionkeys/jwt.pub` with no auth (the "Forged Signed JWT" challenge, `rsa_lord@juice-sh.op`).

**How the agent proves it's real:** the forging logic is in `tools/jwt_forge.py`. The Validator
runs it, which forges both tokens, sends them, and then reads Juice Shop's own challenge
status — both `jwtUnsignedChallenge` and `jwtForgedChallenge` flip to `solved: true`. That's
the app *itself* confirming the forged tokens were accepted. Not a heuristic — ground truth.

(If they want a different one: **path traversal** is a nice second — `GET /ftp/coupons_2013.md.bak%2500.md`
returns 200 via a null-byte that bypasses the ".md/.pdf only" filter. The validator treats the
200 on a non-allowed extension as the proof.)

---

## 5. What went wrong — and how I fixed it (they will ask this)

I want to lead with these because the rubric explicitly rewards "what went wrong, what you'd change."

- **The token-capture bug.** IDOR, broken-auth, and misconfig all silently returned 401 at
  first. I read the raw `session.jsonl` and traced it: the SQLi login is done by the *Attacker*
  sub-agent, but JWT capture only ran on the *orchestrator's* own requests — so the admin token
  was never stored. Fix: capture JWTs centrally inside the HTTP tool, so any agent's login is
  reusable by every later agent via `auth_token:"admin"`. That one fix unblocked three categories.
- **Broken-auth payload was just wrong.** The first attempt sent `current=WRONG` — which returns
  401, because Juice Shop only skips the current-password check when the parameter is *omitted
  entirely*. I caught it by reading the actual server behavior, not the AI's assumption.
- **Validator over-trusting a tool.** It rejected the (correct) path-traversal 200 because an
  analysis helper saw only encrypted-coupon gibberish. Fix: make the criteria treat the 200 as
  conclusive and stop running that helper there.
- **Provider flakiness.** Gemini 429s and an OpenAI timeout loop when an agent re-rendered the
  185 KB admin page. Fix: explicit back-off, a higher client timeout, and `js_render` now strips
  CSS/scripts so requests don't bloat.

The throughline: most of the real work was **debugging from the agent's own logs**, not writing
new code.

---

## 6. AI collaboration — how I actually used Claude Code

I drove the architecture decisions myself: the recon→exploit→validate split, making the
validator a hard gate, the barrier-tool design. I had Claude Code scaffold the loop, the tool
schemas, and the per-category playbooks — then I reviewed and corrected it. The highest-value
use wasn't generation, it was **diagnosis**: I pointed it at the raw session log and had it
trace the 401s to the token-capture site, and pull the missing-algorithm JWT detail straight
out of Juice Shop's source. Several of its first passes were wrong (the `current=WRONG` payload
above is the cleanest example) — catching those against real server behavior is the part I'd
point to as genuine collaboration, not copy-paste. The transcript shows this back-and-forth.

---

## 7. How I read against their rubric

**Artifact Quality (50%) — strongest.** 8/8 categories, every one validator-gated; modular
(`agent/`, `tools/`, `state/`), not a 500-line script; verified clean from a fresh clone;
real failure recovery (retry/back-off, barrier tools, repeating-call detection).

**AI Collaboration (25%) — depends on the transcript.** The story's solid; the evidence is the
attached Claude Code session, which shows me reviewing/questioning/correcting. Make sure it's attached.

**Presentation & Reasoning (25%) — covered by sections 3–6 above.** I can explain the
architecture tradeoffs, walk a finding to ground truth, and articulate what broke and why.

**The line I'll be careful about:** they value "3 solid findings over 10 unverified." I have 8,
all validated — so I'll lead with the *validation methodology*, not the number, so it never reads
as count-chasing.

---

## 8. Quick-fire Q&A I'm prepping for

**"How do you know these aren't false positives?"** Every finding is independently reproduced by a
separate Validator agent before it's recorded — different agent, fresh context, re-runs the exploit.
XSS is confirmed by a real browser `alert()`; JWT by the app's own challenge flags flipping to solved.

**"What's the weakest part?"** No cross-run memory and it's sequential. If a run dies at step 150
it restarts clean rather than resuming mid-plan. I'd add a vector store and make recon/attack parallel.

**"Why these 8 categories / did you hardcode the exploits?"** The categories are the orchestrator's
checklist. The playbooks give Juice-Shop-specific *starting points* (it's a known target), but the
agent still has to execute, capture tokens, and the validator independently confirms — it's not a
canned script that prints findings.

**"What would you do with a generic, unknown target?"** Lean much harder on the Recon agent to build
the checklist dynamically instead of seeding category playbooks, and add a broader payload library.
The loop/validator/state machinery is target-agnostic; the Juice-Shop specificity is only in the prompts.

**"Walk me through the code path of one tool call."** Orchestrator calls `delegate_attack` →
`run_attacker` spins a chain → model emits an `http_request` tool call → `HTTPTool.execute` runs it,
captures any JWT + the endpoint into shared state → result goes back into the chain → attacker calls
`done` → orchestrator calls `delegate_validate` → validator reproduces → `report_finding` writes to the store.
