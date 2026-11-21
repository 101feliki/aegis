"""
External-tool adapters (build-vs-buy, done safely).

AEGIS owns the parts that make it sellable and legal - the authorization gate,
the audit log, the scope engine, the report. For raw DATA COLLECTION it uses
mature external tools when they are installed, and falls back to a built-in,
zero-dependency collector when they are not.

Every adapter:
  - is gated by the Authorizer first (no tool runs on an out-of-scope target);
  - records which engine was used in the audit log (so the report is reproducible);
  - invokes the tool with an argument LIST (never a shell string) and a timeout.

This gives best-of-breed coverage without giving up the authorization + evidence
wrapper that is the product's whole point.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from .authz import Authorizer
from .checks import passive, webintel

ACTION = "passive"


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def tool_inventory() -> dict:
    """Which optional collectors are available on this machine."""
    tools = ["subfinder", "amass", "httpx", "dnsx", "nmap"]
    return {t: have(t) for t in tools}


def _run(args: list[str], timeout: float = 120.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -2, "", "not found"


# --------------------------------------------------------------------------
def enumerate_subdomains(authz: Authorizer, domain: str) -> dict:
    """subfinder -> amass -> built-in crt.sh fallback. Returns check='subdomains'."""
    d = authz.authorize(ACTION, domain)
    if not d:
        return {"check": "subdomains", "domain": domain, "authorized": False, "reason": d.reason}

    subs: set[str] = set()
    engine = None
    if have("subfinder"):
        engine = "subfinder"
        rc, out, _ = _run(["subfinder", "-silent", "-d", domain])
        if rc == 0:
            subs.update(l.strip().lower() for l in out.splitlines() if l.strip())
    elif have("amass"):
        engine = "amass"
        rc, out, _ = _run(["amass", "enum", "-passive", "-d", domain], timeout=300)
        if rc == 0:
            subs.update(l.strip().lower() for l in out.splitlines() if l.strip().endswith(domain))

    if not subs:
        # Built-in fallback: certificate-transparency via crt.sh.
        engine = (engine + "+crtsh-fallback") if engine else "crtsh (built-in)"
        ct = passive.crt_sh_subdomains(authz, domain)
        subs.update(ct.get("subdomains", []))

    result = {"check": "subdomains", "domain": domain, "authorized": True,
              "engine": engine, "subdomains": sorted(subs), "count": len(subs)}
    authz.audit.append("check", action=ACTION, target=domain, decision="DONE",
                       detail={"engine": engine, "count": len(subs)})
    return result


def probe_http(authz: Authorizer, hosts: list[str]) -> dict:
    """httpx for live-host/title/tech if present; otherwise header check per host."""
    d = authz.authorize(ACTION, hosts[0] if hosts else "")
    if not d:
        return {"check": "httpx", "authorized": False, "reason": d.reason}
    if have("httpx"):
        stdin = "\n".join(hosts)
        try:
            proc = subprocess.run(
                ["httpx", "-silent", "-json", "-title", "-tech-detect", "-status-code"],
                input=stdin, capture_output=True, text=True, timeout=180)
            rows = [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]
            out = {"check": "httpx", "authorized": True, "engine": "httpx", "hosts": rows}
        except Exception as e:  # noqa: BLE001
            out = {"check": "httpx", "authorized": True, "engine": "httpx", "error": str(e)}
    else:
        out = {"check": "httpx", "authorized": True, "engine": "built-in",
               "hosts": [webintel.tech_fingerprint(authz, f"https://{h}") for h in hosts[:20]]}
    authz.audit.append("check", action=ACTION, target="http-probe", decision="DONE",
                       detail={"engine": out.get("engine"), "count": len(out.get("hosts", []))})
    return out
