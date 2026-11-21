"""
Settlement-endpoint safety checks (READ-ONLY, non-destructive).

These target the betting-specific risk: the endpoints that decide payouts and
the provider callbacks that report results. AEGIS confirms these endpoints are
hardened WITHOUT ever moving money:
  - it sends only GET / HEAD / OPTIONS, never a bet or a payout;
  - it checks that unauthenticated access is refused;
  - it checks that plaintext HTTP is not accepted (callbacks must be TLS);
  - it inspects the allowed methods and idempotency surface.

NOT automated here (by design): actually submitting bets, replaying "you won"
events, or mutating amounts. That is active money-logic testing; it must be done
by hand with a client-provisioned TEST account under a per-action authorization,
never by an autonomous tool. Automating it is exactly the ARTEX failure mode we
are defending against.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from urllib.parse import urlparse, urlunparse

from .passive import _ua
from ..authz import Authorizer

ACTION = "settlement-readonly"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def _req(authz: Authorizer, url: str, method: str, timeout: float = 8.0):
    assert method in SAFE_METHODS, "settlement checks are read-only"
    req = urllib.request.Request(url, method=method, headers={"User-Agent": _ua(authz)})
    return urllib.request.build_opener().open(req, timeout=timeout)


def inspect_endpoint(authz: Authorizer, url: str) -> dict:
    """Run the full read-only safety panel against one settlement/callback URL."""
    host = urlparse(url).hostname or ""
    d = authz.authorize(ACTION, host)
    if not d:
        return {"check": "settlement", "url": url, "authorized": False, "reason": d.reason}

    out = {"check": "settlement", "url": url, "authorized": True, "findings": [], "observations": {}}

    # 1) Unauthenticated access should be refused.
    try:
        resp = _req(authz, url, "GET")
        out["observations"]["unauth_get_status"] = resp.status
        if resp.status == 200:
            out["findings"].append(
                "SETTLEMENT endpoint returns 200 to an UNAUTHENTICATED request - verify it is not state-changing")
    except urllib.error.HTTPError as e:
        out["observations"]["unauth_get_status"] = e.code
        if e.code not in (401, 403):
            out["findings"].append(
                f"unauthenticated request returned {e.code} (expected 401/403) - review access control")
    except Exception as e:  # noqa: BLE001
        out["observations"]["unauth_get_error"] = str(e)

    # 2) Allowed methods / idempotency surface (OPTIONS).
    try:
        resp = _req(authz, url, "OPTIONS")
        allow = resp.headers.get("allow", "")
        out["observations"]["allow"] = allow
        idem = [h for h in resp.headers.keys() if "idempot" in h.lower()]
        out["observations"]["idempotency_headers"] = idem
        if "POST" in allow.upper() and not idem:
            out["findings"].append(
                "state-changing POST exposed with no advertised Idempotency-Key support - replay risk")
    except Exception as e:  # noqa: BLE001
        out["observations"]["options_error"] = str(e)

    # 3) Plaintext HTTP must not be accepted for a settlement/callback endpoint.
    parsed = urlparse(url)
    if parsed.scheme == "https":
        http_url = urlunparse(parsed._replace(scheme="http"))
        try:
            resp = _req(authz, http_url, "HEAD")
            loc = resp.headers.get("location", "")
            if resp.status in (301, 302, 307, 308) and loc.startswith("https"):
                out["observations"]["http_redirects_to_https"] = True
            else:
                out["findings"].append("plaintext HTTP is served (no forced TLS redirect) on a settlement host")
        except urllib.error.HTTPError as e:
            out["observations"]["http_head_status"] = e.code
        except Exception:  # noqa: BLE001 - connection refused on :80 is the GOOD outcome
            out["observations"]["http_refused"] = True

    authz.audit.append("check", action=ACTION, target=url, decision="DONE", detail=out)
    return out
