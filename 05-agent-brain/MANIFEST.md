# 05 · Agent Brain

**Ability:** the autonomy layer — what makes ARTEX more than a scanner. Plans, decides, remembers, retests.

## Components

| Source | Ability | Labels |
|---|---|---|
| `agent/assembly.go`, `chat.go`, planner/worker roles | Decomposes a goal into intents; workers run tools and write facts/assets/findings to two graphs; `prove_goal` closes a task | 🔴 |
| `agent/coldgraph.go`, coverage_ledger.go | The **asset graph** (shared) + per-task **exploration graph**; coverage denominator | 🔴 |
| `agent/budget.go`, constraints.go | Token/turn budgets (`ARTEX_TASK_/INTENT_BUDGET_*`), scope constraints | ⚪ |
| `agent/data_envelope.go` | Frames tool output as **untrusted** to resist target prompt-injection (`artex-data-marker`) | 🟠 🟢 |
| `agent/capture.go`, compaction.go | Context handling, approval capture | ⚪ |
| `sidequestion/` | Spawns bounded "side question" sub-queries to the LLM | 🟡 |
| `RSI.md`, `server/lessons.go` | Recursive self-improvement **contract** — measurement + shadow memory only today (R6) | 🟠 |

## Why this is the real threat
A low-skill operator gets expert-level *adaptation*: ARTEX reads each response and changes its next
move. That adaptive loop is both the danger to banks and the thing a signature can't capture — you
have to detect the **behaviour**.

## The double edge
- `data_envelope.go` is the single guardrail holding target-controlled text out of the control plane.
  If it fails (R9), the target can steer the agent → local execution (R2). The agent's power points
  both ways.
- RSI (R6): no self-modifying code today, but the scaffolding to let the agent edit its own prompts/skills
  is specified. Re-check on every version bump.

## 🟢 Detection opportunities (→ segment 10)
- **Agent rhythm:** burst of requests → pause (model thinking) → *targeted* follow-up derived from the
  last response. Unlike flat scanner timing. This is the flagship behavioural detector.
- Coverage-driven breadth: methodical touch of every discovered asset/endpoint once, then depth on hits.

## Source in this folder

Actual ARTEX source for this segment lives under `05-agent-brain/src/` (repo layout preserved, AGPL-3.0 — see root `LICENSE`):

- `agent/assembly.go`
- `agent/budget.go`
- `agent/capture.go`
- `agent/chat.go`
- `agent/coldgraph.go`
- `agent/compaction.go`
- `agent/constraints.go`
- `agent/coverage_ledger.go`
- `agent/data_envelope.go`
- `server/lessons.go`
