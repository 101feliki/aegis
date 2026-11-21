"""
Passive exposure checks (read-only HTTP).

Looks at what the public internet already reveals: security-header hygiene,
cookie flags, and whether sensitive paths are reachable. Requests identify
themselves honestly so the client's blue team can see the authorized test in
their logs. Nothing here downloads data dumps or submits input to app logic -
it records status codes and sizes only.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from .. import __version__
from ..authz import Authorizer

ACTION = "passive"

# Sensitive paths that should NOT be publicly reachable. We send a plain GET and
# record the status/size only - we never save the body.
SENSITIVE_PATHS = [
    "/.git/HEAD", "/.env", "/.env.local", "/config.json", "/backup.zip",
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json", "/api-docs",
    "/actuator/health", "/actuator/env", "/server-status", "/.well-known/security.txt",
]

SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
]


def _ua(authz: Authorizer) -> str:
    # Honest, attributable User-Agent - transparency is a requirement here.
    return (f"AEGIS-Authorized-Assessment/{__version__} "
            f"(engagement {authz.scope.engagement_id}; authorized by {authz.scope.authorized_by}; "
            f"contact client SOC)")


def _request(authz: Authorizer, url: str, method: str = "GET", timeout: float = 8.0):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": _ua(authz)})
    opener = urllib.request.build_opener()
    return opener.open(req, timeout=timeout)


def _host_of(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or ""


def security_headers(authz: Authorizer, url: str) -> dict:
    host = _host_of(url)
    d = authz.authorize(ACTION, host)
    if not d:
        return {"check": "headers", "url": url, "authorized": False, "reason": d.reason}
    out = {"check": "headers", "url": url, "authorized": True, "present": {}, "missing": [], "findings": []}
    try:
        resp = _request(authz, url, method="GET")
        headers = {k.lower(): v for k, v in resp.getheaders()}
        out["status"] = resp.status
        for h in SECURITY_HEADERS:
            if h in headers:
                out["present"][h] = headers[h]
            else:
                out["missing"].append(h)
        # Cookie flags
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            low = set_cookie.lower()
            if "secure" not in low:
                out["findings"].append("Set-Cookie without Secure flag")
            if "httponly" not in low:
                out["findings"].append("Set-Cookie without HttpOnly flag")
            if "samesite" not in low:
                out["findings"].append("Set-Cookie without SameSite attribute")
        if "strict-transport-security" not in headers:
            out["findings"].append("HSTS not set (allows SSL-strip downgrade)")
    except urllib.error.HTTPError as e:
        out["status"] = e.code
    except urllib.error.URLError as e:
        out["error"] = str(e.reason)
    except Exception as e:  # noqa: BLE001 - record and move on
        out["error"] = str(e)
    authz.audit.append("check", action=ACTION, target=url, decision="DONE", detail=out)
    return out


# Content a genuinely exposed file should look like. A 200 whose body doesn't
# match is a catch-all/SPA page, not an exposure. Paths without an entry fall
# back to the soft-404 baseline comparison only.
_SIGNATURES = {
    "/.git/HEAD": lambda b, ct: b.lstrip().startswith(b"ref:") or len(b.strip()) == 40,
    "/.env": lambda b, ct: b"=" in b and b"<html" not in b.lower(),
    "/.env.local": lambda b, ct: b"=" in b and b"<html" not in b.lower(),
    "/config.json": lambda b, ct: b.lstrip()[:1] in (b"{", b"["),
    "/backup.zip": lambda b, ct: b.startswith(b"PK"),
    "/swagger.json": lambda b, ct: b"swagger" in b or b"openapi" in b,
    "/swagger/v1/swagger.json": lambda b, ct: b"swagger" in b or b"openapi" in b,
    "/openapi.json": lambda b, ct: b"openapi" in b or b"swagger" in b,
    "/actuator/health": lambda b, ct: b'"status"' in b,
    "/actuator/env": lambda b, ct: b"propertySources" in b or b"activeProfiles" in b,
    "/server-status": lambda b, ct: b"Apache Server Status" in b or b"Server uptime" in b,
    "/.well-known/security.txt": lambda b, ct: b"contact:" in b.lower(),
}
_MAX_BODY = 65536  # read at most this much, hash it, never store it


def _fetch_fingerprint(authz: Authorizer, url: str):
    """Return (status, sha256, length, content_type, head_bytes). Body is not kept."""
    import hashlib
    resp = _request(authz, url, method="GET")
    body = resp.read(_MAX_BODY)
    ct = (resp.headers.get("content-type") or "").lower()
    return resp.status, hashlib.sha256(body).hexdigest(), len(body), ct, body


def exposed_paths(authz: Authorizer, base_url: str) -> dict:
    import secrets
    host = _host_of(base_url)
    d = authz.authorize(ACTION, host)
    if not d:
        return {"check": "exposed", "base": base_url, "authorized": False, "reason": d.reason}
    base = base_url.rstrip("/")
    out = {"check": "exposed", "base": base, "authorized": True, "exposed": [], "soft_404_suppressed": []}

    # Baseline: what does the server return for a path that cannot exist?
    baseline = None
    probe = f"/aegis-nonexistent-{secrets.token_hex(6)}"
    try:
        st, h, n, ct, _ = _fetch_fingerprint(authz, base + probe)
        if st == 200:
            baseline = {"sha256": h, "length": n}
            out["soft_404_baseline"] = {"path": probe, "status": 200, "sha256": h[:16], "length": n}
    except Exception:  # noqa: BLE001 - a real 404 here is the healthy case
        pass

    for path in SENSITIVE_PATHS:
        url = base + path
        try:
            st, h, n, ct, body = _fetch_fingerprint(authz, url)
            if st != 200:
                continue
            rec = {"path": path, "status": 200, "length": n, "sha256": h[:16], "content_type": ct}
            same_as_baseline = baseline and (h == baseline["sha256"] or abs(n - baseline["length"]) <= 16)
            sig = _SIGNATURES.get(path)
            if same_as_baseline or (sig and not sig(body, ct)):
                rec["reason"] = "matches catch-all page" if same_as_baseline else "content does not match expected file"
                out["soft_404_suppressed"].append(rec)
            else:
                out["exposed"].append(rec)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                out.setdefault("protected", []).append(path)
        except Exception:  # noqa: BLE001
            pass
    authz.audit.append("check", action=ACTION, target=base, decision="DONE", detail=out)
    return out


def crt_sh_subdomains(authz: Authorizer, domain: str) -> dict:
    """Certificate-transparency subdomain discovery via the public crt.sh dataset.
    This is OSINT against a public log, authorized under 'passive'."""
    d = authz.authorize(ACTION, domain)
    if not d:
        return {"check": "crtsh", "domain": domain, "authorized": False, "reason": d.reason}
    out = {"check": "crtsh", "domain": domain, "authorized": True, "subdomains": []}
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = _request(authz, url, method="GET", timeout=20.0)
        data = json.loads(resp.read().decode("utf-8", "replace"))
        subs = set()
        for row in data:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lstrip("*.").lower()
                if name.endswith(domain):
                    subs.add(name)
        out["subdomains"] = sorted(subs)
        out["count"] = len(subs)
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    authz.audit.append("check", action=ACTION, target=domain, decision="DONE", detail=out)
    return out
