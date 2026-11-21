# ARTEX Defense Map

A deconstruction of **BaaRai/ARTEX** (AGPL-3.0, LLM-driven autonomous pentest platform),
segmented by **use case** and **ability**, for building detection + defense services
aimed at Kenyan banks.

> Each segment now carries the **actual ARTEX source files** it analyses under its own
> `src/` subfolder (repo layout preserved). This is an analytical map **plus** the labelled
> code, so each capability can be read next to its real implementation. The code is
> **AGPL-3.0** — the upstream `LICENSE` is copied to the root of this folder and governs all
> files under every `src/`. Nothing here runs ARTEX; the files are for review only.
>
> **Languages:** Go (engine — recon paging, egress governor, intercept, agent planner,
> command execution), TypeScript/React (web UI + browser extension), Python (recon skill
> scripts), Markdown (`SKILL.md` playbooks).

Source reviewed: clone of `main`, 950 commits, history rewritten 2026-10-23. Stats at review: ~6.0k stars.

---

## Label legend (the "double-edged sword")

| Label | Meaning |
|---|---|
| 🔴 **OFFENSIVE-TARGET** | Capability pointed outward at a victim (the bank). The thing we defend against. |
| 🟠 **TURNS-ON-OPERATOR** | Can be turned against the person *running* ARTEX, or against innocent third parties. The dangerous edge. |
| 🟡 **OPERATOR-EXPOSURE** | Leaks or endangers the operator even without malice (data egress, trust, local exec). |
| 🟢 **DETECTABLE** | Produces a signal a bank's blue team can catch. Our product hooks here. |
| ⚪ **INFRA** | Plumbing. Low direct security value, listed for completeness. |

A single module often carries several labels — that is the whole point of this map.

---

## The 10 segments

| # | Folder | What it covers | Dominant labels |
|---|---|---|---|
| 01 | `01-recon-discovery` | Asset discovery, subdomains, API endpoint harvesting | 🔴 🟢 |
| 02 | `02-exploitation` | Web/API attack skills, LFI→RCE, N-day building | 🔴 🟢 |
| 03 | `03-mobile-binary-re` | APK/IPA + binary reverse engineering, source audit | 🔴 |
| 04 | `04-traffic-interception` | MITM proxy + browser `debugger` extension | 🔴 🟠 🟡 🟢 |
| 05 | `05-agent-brain` | Planner/workers, graphs, budgets, self-improvement | 🔴 🟠 |
| 06 | `06-command-execution` | Local interpreter execution + approval gates | 🟠 🟡 |
| 07 | `07-data-egress-llm` | Captured bank traffic shipped to LLM providers | 🟡 🟠 |
| 08 | `08-evidence-reporting` | Findings, reports, notification channels | 🟡 ⚪ |
| 09 | `09-operator-trust-boundary` | **The "turns on you" cluster — read this one** | 🟠 🟡 |
| 10 | `10-defense-signals` | Confirmed + candidate fingerprints → our rules | 🟢 |

---

## How to use this map

1. Start with **09** (operator trust boundary) and **10** (defense signals) — those are the
   two that change what you build and sell.
2. For each bank-facing surface (portal, mobile app, API, M-Pesa integration), trace it through
   01 → 02 → 04 to see how ARTEX would chain an attack.
3. Every 🟢 line in these manifests is a candidate detection rule. `10-defense-signals` collects them.
4. `RISK-REGISTER.md` is the flat list of the 🟠 / 🟡 items — the double-edged functions,
   ranked by how badly they can turn on the operator.

See `RISK-REGISTER.md` for the dual-use ranking.
