# 06 · Command Execution & Approval Gates

**Ability:** actually run tools/commands on the operator host, behind human-in-the-loop gates.

## Components

| Source | Ability | Labels |
|---|---|---|
| `server/customtool.go:514` | `exec.CommandContext(runCtx, interp, tmp)` — runs an interpreter on an LLM-written temp script. **This is where agent intent becomes local execution.** | |
| `intercept/` (intercept.go, argv.go, prompt.go, risk.go, target.go, target_gate.go, closed_judge.go) | Per-tool approval: `string` / `regex` / `argv-prefix` rules. Records who approved: `human` / `rule` / `model` / `system`. Target gate (off by default) refuses unapproved destinations | |
| `guard/` (guard.go, judge_precedence.go, target_gate.go) | Precedence logic for guard decisions | |
| `egress/pace.go`, `egress.go` | Noise governor: per-host rate/burst/in-flight, jitter, 429/Retry-After backoff; marks proxied bash with `artex-pace` userinfo | |

## The double edge (RISK-REGISTER R2)
- The gates are the **only** thing between "model decided" and "command ran on your box." Note the
  approver can be **`model`** — i.e. the agent can approve some actions itself. A target that wins a
  prompt-injection (R9) aims straight here.
- `target_gate` and interception default to **permissive** (gate off) — security depends on the operator
  configuring rules. Out-of-the-box it is trusting.

## Detection opportunities (→ segment 10)
- `egress/pace.go` back-off behaviour is **weaponisable for defense**: ARTEX honours 429 + `Retry-After`,
  so a bank can **throttle a suspected agent to a crawl** cheaply. Strong, low-cost control to sell.
- The noise profiles are fixed ratios (quiet 2/s burst 4; balanced 5/s burst 10; aggressive 20/s burst 40)
  — rate *shapes* are a soft fingerprint.

## Source in this folder

Actual ARTEX source for this segment lives under `06-command-execution/src/` (repo layout preserved, AGPL-3.0 — see root `LICENSE`):

- `agent/prompt.go`
- `db/intercept.go`
- `egress/egress.go`
- `egress/pace.go`
- `guard/guard.go`
- `intercept/argv.go`
- `intercept/closed_judge.go`
- `intercept/risk.go`
- `intercept/target.go`
- `intercept/target_gate.go`
- `server/customtool.go`
