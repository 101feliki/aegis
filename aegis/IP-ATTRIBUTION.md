# You cannot defend by chasing the attacker's IP — but their website leaks plenty

This is the message to land with the betting client. It has two halves, and both
are demonstrated by AEGIS's `webintel` stage.

## Half 1 — An attacker's source IP is an assertion, not an identity

When a request hits the betting platform, the "source IP" on it tells you almost
nothing about who sent it. A competent attacker — and ARTEX-class tooling makes
even a weak one competent — never shows their real address:

| Technique | What you actually see | Why blocking it fails |
|---|---|---|
| Commercial **VPN** | The VPN provider's IP, shared by thousands of real users | Block it and you block legitimate bettors on the same exit |
| **Tor** | A rotating exit-node IP unrelated to the attacker | Rotates faster than you can list it |
| **Residential / mobile proxies** | A real home or phone IP — hijacked or rented | Indistinguishable from a genuine customer; geo looks local |
| **Botnet** | Thousands of real but compromised IPs | No single IP to block; distributed by design |
| **Cloud / VPS** | A server IP created for this attack, destroyed after | Attribution evaporates within the hour |
| Forged **`X-Forwarded-For` / `X-Real-IP`** | Whatever the attacker typed | These headers are attacker-supplied input; trusting them is the bug |

**Conclusion:** IP allow/deny lists and geo-blocks are bypassed in minutes and, worse,
block real customers. **Defense must key on behaviour, not origin.** For a betting
platform the behaviours that matter are in defense-map **segment 10**: settlement
replay, impossible-payout attempts, win-rate anomalies, balance growth without
deposits, and the tool fingerprints (e.g. the `spa-api-recon` User-Agent).

## Half 2 — The client's OWN website leaks a lot, and that IS fixable

The flip side: while the attacker hides, the target usually exposes itself. AEGIS's
`webintel` stage shows, passively, what an attacker harvests before touching anything:

- **Real origin IP behind the CDN.** The main site sits behind Cloudflare/Akamai, but
  a forgotten `mail.`, `dev.`, `cpanel.`, or `staging.` subdomain often resolves
  straight to the origin server. An attacker hits that IP directly and **skips the
  WAF/CDN entirely** — including any protection in front of the settlement API.
  (`origin_exposure` flags these.)
- **Infrastructure via DNS.** `A`/`AAAA`/`NS`/`MX`/`TXT` records reveal hosting, mail
  provider, and SPF/DMARC posture. (`dns_footprint`.)
- **Stack via response headers.** `Server`, `X-Powered-By`, `Via`, `X-Cache` leak the
  framework and version an attacker then matches to known exploits. (`tech_fingerprint`.)
- **Whether a CDN/WAF is even present.** If no CDN signature appears, the origin is
  directly exposed.

**The fixes AEGIS leads to:**
1. Put **every** hostname behind the CDN; move mail/dev/admin off the production domain
   or behind the VPN so no subdomain resolves to the origin.
2. **Lock the origin firewall** to accept traffic only from the CDN's IP ranges — so a
   discovered origin IP is useless.
3. **Strip identifying response headers** (`Server`, `X-Powered-By`, version banners).
4. Enforce **HSTS** and TLS everywhere, including callback endpoints.
5. Build detection on **behaviour + fingerprints** (segment 10), since IP is unreliable.

## The one-line pitch for the client

> "We can't promise to block the attacker's IP — nobody can, and anyone who claims
> otherwise is selling you a false sense of safety. What we do is (a) close the ways
> your own site hands attackers your origin and your stack, and (b) detect the
> *behaviour* of an attack on your money logic, which no VPN can hide."
