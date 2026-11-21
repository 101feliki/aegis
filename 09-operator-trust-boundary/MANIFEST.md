# 09 · Operator Trust Boundary — "the parts that turn on you"

**Read this segment first for the double-edged story.** It collects every place where ARTEX's power
points back at the person running it, or at innocent third parties. Cross-referenced to `RISK-REGISTER.md`.

## The cluster

| Risk | Capability | File(s) | Blast radius on the operator |
|---|---|---|---|
| **R1** | Browser `debugger` over `<all_urls>` | `extension/manifest.json`, `background.js` | Reads *all* the operator's authenticated sessions (personal bank, email, SSO), not just the target. |
| **R2** | LLM-driven local command execution | `server/customtool.go:514` | Target → agent → **RCE on the operator host** if prompt-injection beats the gates. |
| **R3** | Bank traffic → 3rd-party LLM | `agent/provider.go`, `llmpool/`, `llmrec/` | PII/tokens leave operator control; DPA 2019 / secrecy breach. |
| **R4** | Operator-installed MITM CA | `traffic/` (go-mitmproxy) | A master key to the operator's own HTTPS if it leaks / build tampered. |
| **R5** | Secrets at rest + partial env scrub | `db/secrets.go`, `db/config.go`, `server/env_scrub.go` | Provider keys, target creds, session tokens exposed via logs/DB. |
| **R6** | RSI self-improvement scaffolding | `RSI.md`, `server/lessons.go` | Measurement-only today; a tampered fork could let the agent edit its own guardrails. |
| **R7** | Bind-address foot-gun | `cmd/artex/main.go` (`ARTEX_BIND_ADDR`) | `0.0.0.0` exposes the full attack console to the LAN. |
| **R8** | Notification SSRF / off-box data | `notify/` | Sensitive findings routed to third-party chat. |
| **R9** | Target-controlled prompt injection | `agent/data_envelope.go`, `intercept/prompt.go` | The one guardrail whose failure unlocks R1/R2. |

## Why this matters commercially
1. **A warning product for banks.** "If a staff member, contractor, or attacker runs an AI pentest
   agent like this inside/against you, here is the blast radius — including that it can compromise its
   own operator." Few Kenyan banks have modelled this. That is a briefing you can sell.
2. **Your own rules of engagement** (if you ever run ARTEX in a demo/lab):
   - Dedicated, isolated lab host; **no corporate-network path**.
   - Throwaway MITM CA on a throwaway profile; never on a daily-driver machine.
   - **Ollama local inference only**; no production LLM keys; no real customer data.
   - `ARTEX_BIND_ADDR` left at `127.0.0.1`; gates + target_gate **on**.
   - Written authorization before any target touch (Computer Misuse & Cybercrimes Act 2018).
3. **A supply-chain angle.** Because R1/R2/R4 make a *trojaned ARTEX fork* a potent operator-hacking
   tool, "don't run random AI-pentest builds" is itself a defensive advisory for bank red teams.

## Source in this folder

Actual ARTEX source for this segment lives under `09-operator-trust-boundary/src/` (repo layout preserved, AGPL-3.0 — see root `LICENSE`):

- `agent/data_envelope.go`
- `agent/provider.go`
- `cmd/artex/main.go`
- `db/config.go`
- `db/secrets.go`
- `extension/background.js`
- `extension/manifest.json`
- `intercept/prompt.go`
- `server/customtool.go`
- `server/env_scrub.go`
- `server/lessons.go`
