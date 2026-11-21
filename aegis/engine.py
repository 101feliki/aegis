"""
Stage orchestrator.

Reads the `targets` block of the scope, runs each authorized stage, applies a
per-host rate limit, and returns the collected results. Every individual action
is already gated and logged by the Authorizer; the engine just sequences them.
"""
from __future__ import annotations

import time
from collections import defaultdict

from .authz import Authorizer
from . import adapters
from .checks import connectivity, passive, settlement, webintel


class RateLimiter:
    def __init__(self, rps: float):
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self._last: dict[str, float] = defaultdict(float)

    def wait(self, host: str) -> None:
        now = time.monotonic()
        elapsed = now - self._last[host]
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last[host] = time.monotonic()


def run(authz: Authorizer, stages: list[str] | None = None) -> dict:
    scope = authz.scope
    targets = scope.raw.get("targets", {})
    enabled = stages or list(scope.allowed_actions)
    rl = RateLimiter(scope.rate_limit_per_host_rps)
    results: dict[str, list] = {"connectivity": [], "passive": [], "webintel": [], "settlement-readonly": []}

    # ---- connectivity -----------------------------------------------------
    if "connectivity" in enabled and "connectivity" in scope.allowed_actions:
        for host_entry in targets.get("hosts", []):
            host = host_entry["host"] if isinstance(host_entry, dict) else host_entry
            ports = host_entry.get("ports", scope.ports) if isinstance(host_entry, dict) else scope.ports
            rl.wait(host)
            res = connectivity.resolve(authz, host)
            results["connectivity"].append(res)
            addrs = res.get("addresses", []) or [None]
            for port in ports:
                for ip in addrs:
                    rl.wait(host)
                    results["connectivity"].append(connectivity.tcp_connect(authz, host, port, ip=ip))
                if port in (443, 8443):
                    rl.wait(host)
                    results["connectivity"].append(connectivity.tls_info(authz, host, port))

    # ---- passive ----------------------------------------------------------
    if "passive" in enabled and "passive" in scope.allowed_actions:
        for domain in targets.get("domains", []):
            rl.wait(domain)
            # Adapter: uses subfinder/amass if installed, else built-in crt.sh.
            results["passive"].append(adapters.enumerate_subdomains(authz, domain))
        for url in targets.get("urls", []):
            host = passive._host_of(url)
            rl.wait(host)
            results["passive"].append(passive.security_headers(authz, url))
            rl.wait(host)
            results["passive"].append(passive.exposed_paths(authz, url))

    # ---- webintel (passive OSINT: what the site/IP leaks) ----------------
    if "webintel" in enabled and "webintel" in scope.allowed_actions:
        # Record the "you can't trust an attacker's IP" reasoning once, up front.
        authz.audit.append("note", action="webintel", target="source-ip-attribution",
                           decision="INFO", detail=webintel.attacker_ip_note())
        results["webintel"].append(webintel.attacker_ip_note())
        for domain in targets.get("domains", []):
            rl.wait(domain)
            fp = webintel.dns_footprint(authz, domain)
            results["webintel"].append(fp)
            # Reuse any crt.sh subdomains already discovered this run for origin-leak hunting.
            subs = []
            for r in results["passive"]:
                if r.get("check") in ("crtsh", "subdomains"):
                    subs = r.get("subdomains", [])
            rl.wait(domain)
            results["webintel"].append(webintel.origin_exposure(authz, domain, subs))
        for url in targets.get("urls", []):
            rl.wait(passive._host_of(url))
            results["webintel"].append(webintel.tech_fingerprint(authz, url))

    # ---- settlement (read-only) ------------------------------------------
    if "settlement-readonly" in enabled and "settlement-readonly" in scope.allowed_actions:
        for url in targets.get("settlement_urls", []):
            host = passive._host_of(url)
            rl.wait(host)
            results["settlement-readonly"].append(settlement.inspect_endpoint(authz, url))

    return results
