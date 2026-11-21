"""
Connectivity & reachability checks (read-only).

Answers the question counsel and the client both care about: "from where this
tool runs, what of the betting platform can actually be reached - including the
internal hosts where settlement really happens?" It resolves names, tests TCP
reachability, inspects TLS, and reads HTTP response headers. It never sends a
payload at application logic.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from ..authz import Authorizer

ACTION = "connectivity"


def resolve(authz: Authorizer, host: str) -> dict:
    d = authz.authorize(ACTION, host)
    if not d:
        return {"check": "resolve", "host": host, "authorized": False, "reason": d.reason}
    result = {"check": "resolve", "host": host, "authorized": True, "addresses": []}
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = sorted({i[4][0] for i in infos})
        result["addresses"] = addrs
        result["internal"] = [a for a in addrs if authz.scope.is_internal(a)]
    except socket.gaierror as e:
        result["error"] = f"DNS resolution failed: {e}"
    authz.audit.append("check", action=ACTION, target=host, decision="DONE", detail=result)
    return result


def tcp_connect(authz: Authorizer, host: str, port: int, ip: str | None = None, timeout: float = 4.0) -> dict:
    d = authz.authorize(ACTION, host, ip=ip, port=port)
    if not d:
        return {"check": "tcp", "target": f"{host}:{port}", "authorized": False, "reason": d.reason}
    target_ip = ip or host
    out = {"check": "tcp", "host": host, "ip": ip, "port": port, "authorized": True}
    sock = None
    try:
        sock = socket.create_connection((target_ip, port), timeout=timeout)
        out["state"] = "open"
        out["reachable"] = True
        # Passive banner grab only (no probe sent).
        try:
            sock.settimeout(1.5)
            banner = sock.recv(128)
            if banner:
                out["banner"] = banner.decode("latin-1", "replace").strip()
        except (socket.timeout, OSError):
            pass
    except (socket.timeout, TimeoutError):
        out["state"] = "filtered/timeout"
        out["reachable"] = False
    except ConnectionRefusedError:
        out["state"] = "closed"
        out["reachable"] = False
    except OSError as e:
        out["state"] = "error"
        out["reachable"] = False
        out["error"] = str(e)
    finally:
        if sock:
            sock.close()
    if ip:
        out["internal"] = authz.scope.is_internal(ip)
    authz.audit.append("check", action=ACTION, target=f"{host}:{port}", decision="DONE", detail=out)
    return out


def tls_info(authz: Authorizer, host: str, port: int = 443, timeout: float = 5.0) -> dict:
    d = authz.authorize(ACTION, host, port=port)
    if not d:
        return {"check": "tls", "target": f"{host}:{port}", "authorized": False, "reason": d.reason}
    out = {"check": "tls", "host": host, "port": port, "authorized": True}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                out["tls_version"] = tls.version()
                out["cipher"] = tls.cipher()[0] if tls.cipher() else None
                cert = tls.getpeercert()
                out["cert_verified"] = True
                out["subject"] = _rdn(cert.get("subject"))
                out["issuer"] = _rdn(cert.get("issuer"))
                out["not_after"] = cert.get("notAfter")
                out["san"] = [v for (_, v) in cert.get("subjectAltName", [])]
                out["days_to_expiry"] = _days_to(cert.get("notAfter"))
    except ssl.SSLCertVerificationError as e:
        out["cert_verified"] = False
        out["finding"] = "certificate did not validate"
        out["error"] = str(e)
    except (socket.timeout, TimeoutError):
        out["error"] = "timeout"
    except OSError as e:
        out["error"] = str(e)
    authz.audit.append("check", action=ACTION, target=f"{host}:{port}", decision="DONE", detail=out)
    return out


def _rdn(rdns) -> str:
    if not rdns:
        return ""
    parts = []
    for rdn in rdns:
        for (k, v) in rdn:
            if k in ("commonName", "organizationName"):
                parts.append(f"{k}={v}")
    return ", ".join(parts)


def _days_to(not_after: str | None):
    if not not_after:
        return None
    try:
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return (exp - datetime.now(timezone.utc)).days
    except ValueError:
        return None
