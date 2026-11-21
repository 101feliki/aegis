# 01 · Recon & Discovery

**Ability:** map a bank's attack surface — subdomains, forgotten assets, API endpoints, parameters.
This is stage one of every ARTEX engagement.

## Components

| Source | Ability | Labels |
|---|---|---|
| `skills/api-recon/` (`harvest_static.py`, `spider_mpa.py`) | Pulls API endpoints out of SPA/MPA frontends by crawling JS and pages | 🔴 🟢 |
| `skills/bbot-recon/SKILL.md` | Runs `bbot` recursive scanner: subdomain enum, takeover surface, archived URLs, param mining, IP/ASN enrichment. Gated by program policy (passive when scanners banned) | 🔴 🟢 |
| `enrich/enrich.go` | Lightweight probe that enriches discovered assets; paced by the egress governor | 🔴 🟢 |
| External tools driven here | `httpx`, `katana` (crawl), `nmap` (ports) | 🔴 🟢 |

## Bank relevance
- Finds **agency-banking / merchant / staging** subdomains that are weaker than the main portal.
- Harvests **mobile + open-banking API** endpoints that aren't linked from the website.
- Subdomain-takeover surface = brandable phishing or silent asset capture.

## 🟢 Detection opportunities (→ segment 10)
- Hardcoded UA `Mozilla/5.0 (spa-api-recon)` and `...spa-api-recon spider)` (`skills/api-recon/scripts/*.py:22-23`).
- `bbot` default request signatures + its UA (`--user-agent` configurable, so treat as weak).
- Breadth-first subdomain probing bursts against your DNS/CDN logs.
- Archived-URL replay (requests for old/removed paths) is a tell of Wayback-fed recon.

## Source in this folder

Actual ARTEX source for this segment lives under `01-recon-discovery/src/` (repo layout preserved, AGPL-3.0 — see root `LICENSE`):

- `enrich/enrich.go`
- `skills/api-recon/scripts/harvest_static.py`
- `skills/api-recon/scripts/spider_mpa.py`
- `skills/bbot-recon/SKILL.md`
