# 10 · Defense Signals — our product surface

Every from the other segments, collected and graded. These become our rule packs
(WAF / Suricata / Sigma) and our behavioural detectors. **Status = confirmed in source / needs lab.**

## Signal table

| ID | Signal | Where | Strength | Evasion | Status |
|---|---|---|---|---|---|
| S1 | UA `Mozilla/5.0 (spa-api-recon)` / `(spa-api-recon spider)` | `skills/api-recon/scripts/harvest_static.py:23`, `spider_mpa.py:22` | Medium | Trivial (edit script) | **Confirmed in source** |
| S2 | **Go TLS fingerprint (JA3/JA4)** from recording proxy | `traffic/` go-mitmproxy v1.9.2 | **High** | Hard (needs code change) | Needs lab pcap |
| S3 | Go default `User-Agent` on unbranded requests when `ARTEX_TARGET_USER_AGENT` unset | `egress/egress.go:46,70` | Medium | Easy (set env) | Needs lab |
| S4 | **BOLA/IDOR sweep** — same endpoint, walking object IDs | behavioural; `skills/api-security` | **High** | Hard (it's the attack) | Behavioural — build detector |
| S5 | **Agent rhythm** — burst → pause → targeted follow-up | behavioural; `agent/` loop | **High** | Hard | Behavioural — build detector |
| S6 | Unpaced loud bursts (nuclei/nmap) amid quiet crawl | `egress/pace.go` (scanners not paced) | Medium | Medium | Confirmed in docs |
| S7 | Honours 429 + `Retry-After` → throttle-to-crawl control | `egress/pace.go` | N/A (control, not detector) | N/A | **Confirmed** — ship as mitigation |
| S8 | Noise-profile rate shapes (2/4, 5/10, 20/40) | `egress/pace.go` | Low | Easy | Confirmed in docs |
| S9 | PHP `session.upload_progress` LFI probe pattern | `skills/php2shell` | Medium | Medium | Confirmed in source |
| S10 | nuclei / sqlmap / dalfox / ffuf payload families | external tools | Medium | Medium | Existing community rules |
| S11 | Honeytoken endpoints (esp. RE-only paths from APK/IPA) | deception; vs segment 03 | **High** | Hard (agent reads everything) | Build — deception layer |
| S12 | Archived-URL replay (requests for removed paths) | `skills/bbot-recon` | Low-Med | Medium | Confirmed in docs |

## Build order (first release)
1. **S1 + S9 + S10** — signature pack (ModSecurity/Cloudflare + Suricata + Sigma). Fast, shippable, demoable.
2. **S7** — adaptive throttle control (429/Retry-After) on suspected-agent sessions. Cheap, strong.
3. **S4 + S5** — behavioural detectors (BOLA sweep + agent rhythm). **Our differentiator**, higher effort.
4. **S11** — honeytoken/deception layer, especially endpoints that only exist in the mobile app binary.
5. **S2 + S3** — confirm in lab, then add TLS/UA fingerprinting where the bank can terminate TLS.

## Required next step: lab validation
S2, S3 are inferred from source and **must be confirmed** by running ARTEX in an isolated lab against a
target you own, capturing: full pcap, JA3/JA4, WAF logs, and app/access logs. See `09` for lab discipline.
Do not sell S2/S3 as confirmed until the pcap backs them.

## Mapping to services (ties to the business plan)
- Signature pack + Sigma → **"AI-attack detection pack"** (productized rules, subscription updates).
- S7 + S4/S5 → **managed detection** / MSSP tier for banks.
- S11 + segment 03 → **app-shielding & deception** engagements.
- Everything maps to **CBK Guidance Note on Cybersecurity**, **Computer Misuse & Cybercrimes Act 2018**,
  **Data Protection Act 2019** for the compliance narrative.

## Source in this folder

Actual ARTEX source for this segment lives under `10-defense-signals/src/` (repo layout preserved, AGPL-3.0 — see root `LICENSE`):

- `egress/egress.go`
- `egress/pace.go`
- `skills/api-recon/scripts/harvest_static.py`
- `skills/api-recon/scripts/spider_mpa.py`
