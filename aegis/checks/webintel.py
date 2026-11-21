"""
Web / IP intelligence (passive OSINT, read-only).

Demonstrates two things the client needs to understand:

1. You cannot defend by trusting or blocking an attacker's source IP. An attacker
   rides VPNs, Tor, residential proxies and botnets, and can forge X-Forwarded-For.
   The source IP on a request is an assertion, not an identity. (See
   `attacker_ip_note()` and the IP-ATTRIBUTION.md writeup.)

2. Meanwhile the client's OWN website leaks a great deal: the real origin IP behind
   the CDN, server technology, infrastructure and mail records. That is what an
   attacker actually harvests. This module shows exactly what leaks.

Everything here is passive: public DNS lookups and reading the target's own
response headers. No payloads, no exploitation.
"""
from __future__ import annotations

import random
import socket
import struct

from ..authz import Authorizer

ACTION = "webintel"

_CDN_HINTS = {
    "cloudflare": ["cloudflare", "cf-ray"],
    "akamai": ["akamai", "akamaighost"],
    "fastly": ["fastly"],
    "amazon cloudfront": ["cloudfront"],
    "sucuri": ["sucuri"],
    "imperva/incapsula": ["incapsula", "imperva"],
}

# Subdomain labels that commonly bypass the CDN and expose the true origin.
_ORIGIN_LEAK_LABELS = ("mail", "smtp", "ftp", "cpanel", "webmail", "direct", "origin",
                       "dev", "staging", "test", "vpn", "remote", "ns1", "ns2", "mx")

_DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}


# --------------------------------------------------------------------------
# Minimal dependency-free DNS resolver (UDP) against a public resolver.
# --------------------------------------------------------------------------
def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    end = offset
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:  # compression pointer
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode("latin-1"))
        offset += length
    if not jumped:
        end = offset
    return ".".join(labels), end


def dns_query(name: str, qtype: str, server: str = "1.1.1.1", timeout: float = 4.0) -> list[str]:
    qt = _DNS_TYPES[qtype]
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode("idna" if any(ord(c) > 127 for c in p) else "ascii")
                 for p in name.split(".")) + b"\x00"
    q += struct.pack(">HH", qt, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(header + q, (server, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    an_count = struct.unpack(">H", data[6:8])[0]
    _, offset = _read_name(data, 12)
    offset += 4  # qtype + qclass
    out = []
    for _ in range(an_count):
        _, offset = _read_name(data, offset)
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        if rtype == 1 and rdlen == 4:
            out.append(socket.inet_ntoa(rdata))
        elif rtype == 28 and rdlen == 16:
            out.append(socket.inet_ntop(socket.AF_INET6, rdata))
        elif rtype in (2, 5):  # NS / CNAME
            out.append(_read_name(data, offset)[0])
        elif rtype == 15:  # MX
            pref = struct.unpack(">H", rdata[:2])[0]
            out.append(f"{pref} {_read_name(data, offset + 2)[0]}")
        elif rtype == 16:  # TXT
            txt, i = [], 0
            while i < len(rdata):
                ln = rdata[i]
                txt.append(rdata[i + 1:i + 1 + ln].decode("latin-1"))
                i += 1 + ln
            out.append("".join(txt))
        offset += rdlen
    return out


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, OSError):
        return ""


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------
def dns_footprint(authz: Authorizer, domain: str) -> dict:
    """What the public DNS reveals about the client's infrastructure."""
    d = authz.authorize(ACTION, domain)
    if not d:
        return {"check": "dns_footprint", "domain": domain, "authorized": False, "reason": d.reason}
    out = {"check": "dns_footprint", "domain": domain, "authorized": True, "records": {}}
    for rtype in ("A", "AAAA", "NS", "MX", "TXT"):
        try:
            out["records"][rtype] = dns_query(domain, rtype)
        except Exception as e:  # noqa: BLE001
            out["records"][rtype] = [f"<error: {e}>"]
    # Highlight mail / policy records that expose infra.
    txt = out["records"].get("TXT", [])
    out["spf"] = [t for t in txt if t.lower().startswith("v=spf1")]
    out["dmarc_present"] = bool([t for t in txt if "dmarc" in t.lower()])
    for ip in out["records"].get("A", []):
        ptr = _reverse_dns(ip)
        if ptr:
            out.setdefault("reverse_dns", {})[ip] = ptr
    authz.audit.append("check", action=ACTION, target=domain, decision="DONE", detail=out)
    return out


def origin_exposure(authz: Authorizer, domain: str, subdomains: list[str]) -> dict:
    """Does a subdomain bypass the CDN and expose the true origin IP?

    Strategy: the root is usually behind a CDN. Any subdomain that resolves to a
    DIFFERENT IP - especially mail/dev/cpanel-style names - is a candidate origin
    leak an attacker would target directly to skip the CDN/WAF.
    """
    d = authz.authorize(ACTION, domain)
    if not d:
        return {"check": "origin_exposure", "domain": domain, "authorized": False, "reason": d.reason}
    out = {"check": "origin_exposure", "domain": domain, "authorized": True, "candidates": []}
    try:
        root_ips = set(dns_query(domain, "A"))
    except Exception:  # noqa: BLE001
        root_ips = set()
    out["root_ips"] = sorted(root_ips)
    checked = 0
    for sub in subdomains:
        if checked >= 60:
            break
        checked += 1
        label = sub.split(".")[0].lower()
        try:
            ips = dns_query(sub, "A")
        except Exception:  # noqa: BLE001
            continue
        for ip in ips:
            leaky_name = any(label.startswith(x) for x in _ORIGIN_LEAK_LABELS)
            off_cdn = bool(root_ips) and ip not in root_ips
            if leaky_name or off_cdn:
                out["candidates"].append({
                    "subdomain": sub, "ip": ip,
                    "reverse_dns": _reverse_dns(ip),
                    "why": ("suspicious label" if leaky_name else "") +
                           (" / off-CDN IP" if off_cdn else ""),
                })
    out["count"] = len(out["candidates"])
    authz.audit.append("check", action=ACTION, target=domain, decision="DONE", detail=out)
    return out


def tech_fingerprint(authz: Authorizer, url: str) -> dict:
    """What the site's own response headers leak about its stack and CDN/WAF."""
    import urllib.error
    import urllib.request
    from urllib.parse import urlparse
    from .passive import _ua

    host = urlparse(url).hostname or ""
    d = authz.authorize(ACTION, host)
    if not d:
        return {"check": "tech", "url": url, "authorized": False, "reason": d.reason}
    out = {"check": "tech", "url": url, "authorized": True, "leaked": {}, "cdn_waf": []}
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": _ua(authz)})
        resp = urllib.request.build_opener().open(req, timeout=12.0)
        headers = {k.lower(): v for k, v in resp.getheaders()}
        for h in ("server", "x-powered-by", "via", "x-aspnet-version", "x-generator",
                  "x-cache", "x-served-by", "x-backend-server"):
            if h in headers:
                out["leaked"][h] = headers[h]
        blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        for name, hints in _CDN_HINTS.items():
            if any(hint in blob for hint in hints):
                out["cdn_waf"].append(name)
        if not out["cdn_waf"]:
            out["note"] = "no CDN/WAF signature in headers - origin may be directly exposed"
    except urllib.error.HTTPError as e:
        out["status"] = e.code
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    authz.audit.append("check", action=ACTION, target=url, decision="DONE", detail=out)
    return out


def attacker_ip_note() -> dict:
    """Static, factual summary: why a source IP cannot be trusted for defense.
    Recorded in the report so the client sees the reasoning, not just findings."""
    return {
        "check": "attacker_ip_note",
        "summary": "An attacker's source IP is an assertion, not an identity, and must not be the basis of defense.",
        "why_unreliable": [
            "VPNs / commercial proxies: the IP is the provider's, shared by thousands.",
            "Tor: exit-node IP, rotates, unrelated to the attacker.",
            "Residential-proxy & botnet traffic: real but hijacked home/IoT IPs.",
            "X-Forwarded-For / X-Real-IP headers are attacker-supplied and trivially forged.",
            "Cloud/VPS: spun up and discarded per attack; attribution evaporates.",
        ],
        "implication": [
            "IP allow/deny lists and geo-blocks are bypassed in minutes and block real users.",
            "Detection must key on BEHAVIOUR (settlement replay, impossible payouts, win-rate anomaly) "
            "and request fingerprints - see defense-map segment 10 - not on origin IP.",
            "Meanwhile the client's OWN origin IP and infra DO leak (see dns_footprint / origin_exposure); "
            "that is the exposure to fix: hide origin behind the CDN, lock the WAF to CDN ranges.",
        ],
    }
