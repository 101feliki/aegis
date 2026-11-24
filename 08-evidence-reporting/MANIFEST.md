# 08 · Evidence & Reporting

**Ability:** keep receipts — tie findings to captured evidence, grade quality, export, notify.

## Components

| Source | Ability | Labels |
|---|---|---|
| `evidence/store.go` | Stores captured request/response evidence per finding | |
| `report/` (findings.go, quality.go, report.go) | Builds findings, scores quality, exports reports | |
| `notify/` (webhook, telegram, feishu, dingtalk, wecom, email, mask.go, redact, ssrf_test) | Sends events/findings to external channels; has masking/redaction + SSRF awareness | |
| `server/server.go:2362` | `artex-finding-export-*` temp staging for exports | |

## The double edge (RISK-REGISTER R8)
- `notify/` ships finding data **off-box** to chat platforms. Redaction/masking exists but is
  opt-in/configurable — a misconfig routes sensitive bank findings into a third-party chat tenant
  (new data-residency + confidentiality exposure).

## Value to us
- The evidence model ("every finding carries the request/response that justifies it") is a **feature to
  copy** in our own detection product: when we flag ARTEX-like activity, attach the captured traffic that
  proves it. Mirrors how banks' SOC analysts want alerts delivered.
- Nothing target-facing here; this is internal plumbing. Listed for completeness.

## Source in this folder

Actual ARTEX source for this segment lives under `08-evidence-reporting/src/` (repo layout preserved, AGPL-3.0 — see root `LICENSE`):

- `db/findings.go`
- `evidence/store.go`
- `notify/mask.go`
- `report/quality.go`
- `report/report.go`
- `server/server.go`
