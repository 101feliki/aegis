# Risk Register — the double-edged functions

Flat list of ARTEX capabilities that can **turn on the operator** (🟠) or **expose the operator** (🟡),
ranked by severity. These are the parts you warn clients about *and* the parts you must handle carefully
if you ever run ARTEX yourself in a lab/demo.

Severity = how badly it bites the person running ARTEX, not the target.

| # | Capability | File(s) | Label | Severity | Why it cuts back on you |
|---|---|---|---|---|---|
| R1 | **Browser `debugger` on `<all_urls>`** | `extension/manifest.json`, `extension/background.js` | 🟠🟡 | **Critical** | A Chrome DevTools-Protocol debugger over *all* sites can read every authenticated session on the operator's machine — personal bank, email, SSO — not just the target. A trojaned or mis-pointed build exfiltrates the operator's own logins. |
| R2 | **LLM-chosen local command execution** | `server/customtool.go:514` (`exec.CommandContext` on a temp script) | 🟠🟡 | **Critical** | The model writes code and ARTEX runs it on the operator's host. A poisoned tool-output / prompt-injection from the *target* can steer the agent into running attacker code locally. Target → operator RCE path. |
| R3 | **Captured traffic shipped to 3rd-party LLMs** | `07-data-egress-llm/*`, `agent/provider.go`, `llmpool/`, `llmrec/` | 🟡 | **High** | Authenticated bank requests/responses (tokens, PII, balances) are sent to Anthropic/OpenAI/Ollama endpoints to "reason" over. For a Kenyan bank engagement this is a Data Protection Act 2019 + banking-secrecy problem, and it leaves the operator's control. |
| R4 | **Operator-installed MITM CA** | `traffic/` (go-mitmproxy v1.9.2), generated CA | 🟠🟡 | **High** | To record HTTPS, the operator trusts ARTEX's CA. Anything holding that CA key can silently MITM the operator's own TLS. If the key leaks or the build is backdoored, the operator's machine is wide open. |
| R5 | **Secrets / API keys at rest + in env** | `db/secrets.go`, `db/config.go` (api_key cols), `server/env_scrub.go` | 🟡 | **High** | LLM provider keys, target creds and session tokens live in Postgres + env. `env_scrub.go` only scrubs a known list (`ARTEX_PG_DSN`, `ARTEX_SECRET_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) — anything else can leak into logs/errors. |
| R6 | **Self-improvement scaffolding (RSI)** | `RSI.md`, `server/lessons.go`, `agent/` lessons | 🟠 | **Medium** | Currently *measurement + shadow memory only* (no self-modifying code, per `RSI.md`). But the contract exists for a future "edit the harness" loop. A tampered fork could flip loop C on and let the agent rewrite its own guardrails. Watch this on version bumps. |
| R7 | **Bind-address foot-gun** | `cmd/artex/main.go` (`ARTEX_BIND_ADDR`), default `127.0.0.1` | 🟡 | **Medium** | Safe by default, but `ARTEX_BIND_ADDR=0.0.0.0` exposes the full operator console (which can drive attacks + read evidence) to the network. One env var away from an open C2-grade panel. |
| R8 | **Notification channels / SSRF surface** | `notify/` (webhook, telegram, feishu, dingtalk, wecom, email) | 🟡 | **Medium** | Outbound webhooks carry finding data off-box to chat platforms. `ssrf_test.go`/`mask.go` show they know the risk; misconfig still routes sensitive bank findings to a third-party chat tenant. |
| R9 | **Target-controlled prompt injection** | `agent/data_envelope.go`, `intercept/prompt.go` | 🟠 | **Medium** | ARTEX frames tool output as untrusted (good), but the whole model rests on that framing holding. A clever target page that breaks out can redirect the agent — back toward R1/R2. This is also *our* best deception lever (see 10). |

## How to read this for the business
- **R1–R4** are the headline "ARTEX can hack its own operator" story. Use them in two ways:
  1. As a **warning to banks**: "if your staff or a vendor runs this, here is the blast radius."
  2. As **your own operating rules** if you demo ARTEX: isolated lab host, throwaway CA, no real
     credentials, no production LLM keys, air-gapped from the corporate network.
- **R3 + R9** are the compliance hooks (DPA 2019, CBK guidance) that make banks pay attention.
