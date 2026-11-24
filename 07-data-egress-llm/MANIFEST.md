# 07 · Data Egress to LLM Providers

**Ability:** send captured content + reasoning to external LLMs. Primary **operator-exposure** segment.

## Components

| Source | Ability | Labels |
|---|---|---|
| `agent/provider.go` | Outbound LLM client; optional custom UA (`ValidateUserAgent`, max 256B), `ARTEX_LLM_PROXY`, session header key | |
| `llmpool/` (pool.go, health.go) | Multi-provider pool, health/priority routing | |
| `db/config.go` (profile cols incl. `api_key`) | Stores provider profiles + keys | |
| Provider endpoints | Anthropic `/v1/messages`; OpenAI-compatible `/chat/completions` or `/responses`; Ollama `127.0.0.1:11434/v1` | |

## The double edge (RISK-REGISTER R3)
- Whatever the agent reasons over — **authenticated bank requests/responses, tokens, PII, balances** —
  can be sent to a third-party LLM endpoint. For a Kenyan bank engagement that implicates:
  - **Data Protection Act 2019** (cross-border transfer of personal data),
  - **banking secrecy** obligations,
  - **CBK** cybersecurity / outsourcing expectations.
- **Mitigation that becomes a selling point:** run **Ollama (local, keyless)** so nothing leaves the box.
  Advise banks to require local-only inference for any AI pentest tool. This is a concrete policy you can
  write into bank procurement.

## Detection opportunities
- This traffic goes operator → LLM provider, **not** to the bank, so the bank can't see it directly.
- Relevant instead for **the operator's own** egress monitoring, and for your lab discipline
  (use Ollama, no production keys, no real customer data in demos).

## Source in this folder

Actual ARTEX source for this segment lives under `07-data-egress-llm/src/` (repo layout preserved, AGPL-3.0 — see root `LICENSE`):

- `agent/provider.go`
- `db/config.go`
- `llmpool/health.go`
- `llmpool/pool.go`
