# 04 · Traffic Interception

**Ability:** record authenticated traffic so the agent can test *behind the login*. The most double-edged segment.

## Components

| Source | Ability | Labels |
|---|---|---|
| `traffic/` (proxy.go, stream.go, replay.go, rewrite/, archive.go) | Recording MITM proxy on **:8788** using `go-mitmproxy v1.9.2` with a **generated CA**. Records, rewrites, replays HTTP(S) | 🔴 🟡 🟢 |
| `extension/` (manifest.json, background.js, popup.*) | Chrome MV3 extension "ARTEX Traffic Capture". Permissions: **`debugger`, `storage`, `tabs`** + host `<all_urls>`. Posts batches to `POST /api/traffic/ingest` (≤50 entries, bodies truncated 256 KiB, binary skipped) | 🔴 🟠 🟡 |
| `llmrec/` (capture.go) | Captures LLM-visible records of traffic for the agent | 🟡 |
| `traffic/external.go`, `evidence.go` | Ties captured request/response pairs to findings as evidence | 🟢 |

## The double edge (see RISK-REGISTER R1, R4)
- **R1 — extension `debugger` on `<all_urls>`:** reads *every* site's traffic on the operator's
  machine, not just the target. This is the clearest "turns on the operator" function in ARTEX.
- **R4 — operator-trusted CA:** to decrypt HTTPS the operator installs ARTEX's CA. That CA key is a
  master key to the operator's own TLS if it leaks or the build is tampered.

## Bank relevance
- Lets ARTEX test with a **real logged-in session** (operator-driven auth), reaching authenticated
  API flows a WAF would otherwise consider trusted traffic.
- Session replay + rewrite = probing transaction endpoints with a valid token.

## 🟢 Detection opportunities (→ segment 10)
- **Go TLS client fingerprint (JA3/JA4)** from go-mitmproxy's outbound connections — likely the
  strongest, config-resistant network signal. **Confirm in lab.**
- Replay patterns: identical request shapes resent with small mutations (rewrite engine).
- Authenticated session suddenly exhibiting machine-timing (burst/pause/targeted) = hijacked-session tell.

## Source in this folder

Actual ARTEX source for this segment lives under `04-traffic-interception/src/` (repo layout preserved, AGPL-3.0 — see root `LICENSE`):

- `agent/capture.go`
- `extension/background.js`
- `extension/manifest.json`
- `traffic/archive.go`
- `traffic/evidence.go`
- `traffic/external.go`
- `traffic/replay.go`
- `traffic/stream.go`
