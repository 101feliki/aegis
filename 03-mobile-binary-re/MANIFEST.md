# 03 · Mobile & Binary Reverse Engineering

**Ability:** tear apart compiled apps and packages — including **bank mobile apps** — for secrets and endpoints.

## Components

| Source | Ability | Labels |
|---|---|---|
| `skills/rea/SKILL.md` | RE of ELF, PE, Mach-O, **APK, IPA**, HAP, WASM, ZIP/JAR, JS bundles via the `rea` MCP server. Extracts embedded secrets, hardcoded endpoints, native libs, strings/constants, deobfuscation | 🔴 |
| `skills/codeaudit/SKILL.md` | White-box source audit: traces user input → dangerous sinks, builds PoC with measured impact | 🔴 |
| `skills/edr-bypass-re/SKILL.md` | Maps what an EDR/AV monitors (user-mode hooks, kernel callbacks, ETW, AMSI). MITRE T1562. Lab-only framing | 🔴 🟠 |

## Bank relevance
- **`rea` on a bank's APK/IPA** is the sharp one: pulls hardcoded API hosts, keys, cert pins and
  endpoints straight out of the published app — no network noise, nothing for a WAF to see.
  This feeds segment 01/02 with a map the bank never meant to expose.
- **`edr-bypass-re`** is post-breach: understanding the bank's endpoint defenses to evade them.
  Also 🟠 — the same skill run locally profiles the *operator's* own EDR.

## 🟢 Detection opportunities
- **Mostly undetectable at the network layer** — this is static, offline analysis of public app binaries.
- Defensive countermeasures live elsewhere: **app hardening** (strip secrets, move them server-side,
  RASP/obfuscation, cert pinning), and **mobile app-shielding** — a service line in its own right.
- The only network tell is the *follow-on* traffic to endpoints that were only discoverable by RE
  (i.e. never linked publicly). Honeytoken endpoints baked into the app catch exactly this.

## Source in this folder

Actual ARTEX source for this segment lives under `03-mobile-binary-re/src/` (repo layout preserved, AGPL-3.0 — see root `LICENSE`):

- `skills/codeaudit/SKILL.md`
- `skills/edr-bypass-re/SKILL.md`
- `skills/rea/SKILL.md`
