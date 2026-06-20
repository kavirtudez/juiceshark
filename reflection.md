# Reflection — JuiceShark

## What I built
A multi-agent pentest agent for OWASP Juice Shop. An **Orchestrator** works through an 8-item checklist and delegates to three specialists: **Recon** (map the surface), **Attacker** (exploit one category at a time), and **Validator** (independently reproduce before anything is recorded). The split mirrors the standard pentest workflow (PTES / OWASP WSTG: recon → exploitation → reporting), and the engine is a ReAct-style reason/act loop I wrote from scratch. It runs on OpenAI (default `gpt-4o-mini`) or Gemini. Latest run: **8/8 categories, 0 false positives, 205 steps**.

## Architecture decisions & tradeoffs
- **Separate Validator agent.** The single most important call. The rubric rewards validated findings over raw count, so reporting is gated: the Attacker only proposes, and a fresh Validator re-runs the exploit from scratch before `report_finding`. This is what keeps false positives out — e.g. the Validator catches DOM XSS via a real headless `alert()`, not a string match.
- **Specialist agents over one mega-prompt.** Keeping recon/attack/validate in separate contexts stopped the model from conflating "look around" with "exploit," and kept each prompt short and cheap.
- **Barrier tools + non-blocking `report_finding`.** `done` stops a chain; `report_finding` records and *continues*, so the orchestrator keeps testing after each hit. Early on a misconfigured barrier made it quit after the first finding — fixed by making barriers per-agent.
- **Centralized token/endpoint capture in the HTTP tool.** Any agent's login captures the JWT to shared state, so later agents authenticate with `auth_token:"admin"`. This was the key bug: capture originally only ran on the orchestrator's own calls, but the *attacker* performs the login — so IDOR/broken-auth/misconfig all silently 401'd until I moved capture into the HTTP tool itself.
- **JSON-file state, not a database.** A heavier setup (Postgres + a vector store) would buy cross-run memory, but for a single-run CLI, thread-safe JSON/JSONL flushed on every mutation is enough — and it makes the logs directly submittable as evidence.
- **Python, single-process.** Fast iteration in a short window and a mature `requests`/`playwright`/SDK ecosystem. Tradeoff: no real concurrency — the agents run sequentially, which is fine at this scale but leaves wall-clock time on the table.

## What worked
- The reflector (nudge the model when it returns prose instead of a tool call) made long chains reliable.
- The 3-role pipeline genuinely eliminated false positives — every recorded finding is independently reproduced.
- Solving JWT manipulation the real way: pull the public key from `/encryptionkeys/jwt.pub` and exploit the missing algorithm whitelist (`alg:none` **and** RS256→HS256 confusion with the public key as the HMAC secret).

## What didn't (and how I handled it)
- **Provider flakiness.** Free-tier Gemini threw 429s mid-scan; OpenAI occasionally hit request timeouts when an agent re-rendered the 185 KB admin page. Both now have explicit retry/back-off, the client timeout was raised, and `js_render` strips CSS/scripts so requests don't bloat.
- **Model over-trusting a tool.** The Validator initially rejected the (correct) path-traversal 200 because `analyze_response` saw only encrypted-coupon gibberish. Fixed by making the criteria treat the 200 as conclusive and forbidding that check there.
- **Reporting bug I introduced.** Regenerating a report from a fresh store showed `steps: 0`; I made the store restore the step counter from `session.jsonl`.

## Working with Claude Code (AI collaboration)
I treated Claude Code as a pair, not a vending machine. I drove the architecture (the recon→exploit→validate split, the validator-gating decision, what each agent owns); I had it scaffold the loop, tool schemas, and per-category playbooks, then **reviewed and corrected** its output. The biggest wins came from making it *diagnose*, not just generate: I pointed it at the raw `session.jsonl`, and it traced the 401s to the token-capture site and the missing-algorithm JWT detail by reading Juice Shop's own `lib/insecurity.ts`. Several of its first attempts were wrong (the `current=WRONG` broken-auth payload returns 401; the real bug is *omitting* the parameter) — catching those by reading the actual server behavior is where the collaboration paid off.

## What I'd improve with more time
1. **Vector memory** so agents recall prior findings instead of re-injecting context.
2. **Parallel recon + attack** (thread pool) to cut wall-clock time.
3. **Real sandboxing** for the terminal tool (containerized), not host execution.
4. **Tighter finding schema** — auto CVSS, and pin the JWT finding's endpoint to `/encryptionkeys/jwt.pub` rather than the login route the model sometimes labels it with.
5. **CI run** against a Dockerized Juice Shop as a GitHub Action.
