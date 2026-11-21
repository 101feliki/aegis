"""
AEGIS command-line interface.

    python -m aegis init-scope  --out scope.json
    python -m aegis sign        --scope scope.json --key-file key.txt
    python -m aegis verify      --scope scope.json --key-file key.txt
    python -m aegis run         --scope scope.json --key-file key.txt --out runs/eng1
    python -m aegis verify-audit --audit runs/eng1/audit.jsonl
    python -m aegis report      --audit runs/eng1/audit.jsonl --out runs/eng1/report.md
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

from . import TOOL_NAME, __version__
from .audit import AuditLog
from .authz import Authorizer
from .engine import run as run_engine
from .report import build_markdown
from .scope import Scope, sign, verify_signature

EXAMPLE_SCOPE = {
    "engagement_id": "ENG-2026-BET-001",
    "client": "Example Betting Ltd",
    "nda_ref": "NDA-2026-0042",
    "authorized_by": "Jane Counsel, General Counsel (Example Betting Ltd)",
    "authorized_contact": "soc@example.co.ke",
    "created": "2026-11-17T08:00:00Z",
    "window": {"start": "2026-11-17T08:00:00Z", "end": "2026-11-24T20:00:00Z"},
    "scope": {
        "domains": ["example.co.ke", "*.example.co.ke"],
        "ip_ranges": ["203.0.113.0/24", "10.20.0.0/16"],
        "ports": [80, 443, 8080, 8443],
        "internal_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        "databases": ["mysql://aegis_ro@10.20.0.15:3306/sportsbook", "10.20.0.15:3306",
                      "/var/lib/aegis/mpesa-statements/*.csv", "/var/log/sportsbook/mpesa*"],
        "servers": ["sb-prod-01"],
        "paths": ["/var/www/sportsbook", "/etc/nginx", "/etc/ssh", "/root/.ssh", "/var/lib/aegis/schema"]
    },
    "excluded": {
        "domains": ["payments-live.example.co.ke"],
        "ip_ranges": []
    },
    "allowed_actions": ["passive", "connectivity", "webintel", "settlement-readonly",
                        "db-identify", "ledger-readonly", "mpesa-readonly", "host-checkup", "tamper-watch"],
    "rate_limit_per_host_rps": 2,
    "targets": {
        "domains": ["example.co.ke"],
        "hosts": [
            {"host": "www.example.co.ke", "ports": [80, 443]},
            {"host": "api.example.co.ke", "ports": [443, 8443]}
        ],
        "urls": ["https://www.example.co.ke"],
        "settlement_urls": ["https://api.example.co.ke/v1/bets/settle"]
    }
}


def _read_key(args) -> str | None:
    if getattr(args, "key_file", None):
        with open(args.key_file, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    if getattr(args, "key", None):
        return args.key
    return None


def cmd_init_scope(args) -> int:
    if os.path.exists(args.out) and not args.force:
        print(f"refusing to overwrite {args.out} (use --force)", file=sys.stderr)
        return 2
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(EXAMPLE_SCOPE, fh, indent=2)
    print(f"wrote example scope -> {args.out}")
    print("Edit it with the real engagement details, then `sign` it.")
    return 0


def cmd_sign(args) -> int:
    key = _read_key(args) or getpass.getpass("Signing key: ")
    with open(args.scope, "r", encoding="utf-8") as fh:
        scope = json.load(fh)
    scope["signature"] = sign(scope, key)
    with open(args.scope, "w", encoding="utf-8") as fh:
        json.dump(scope, fh, indent=2)
    print(f"signed {args.scope}")
    return 0


def cmd_verify(args) -> int:
    key = _read_key(args) or getpass.getpass("Signing key: ")
    with open(args.scope, "r", encoding="utf-8") as fh:
        scope = json.load(fh)
    ok = verify_signature(scope, key)
    print("signature VALID" if ok else "signature INVALID")
    return 0 if ok else 1


def cmd_run(args) -> int:
    scope = Scope.load(args.scope)
    key = _read_key(args)
    sig_verified: bool | None = None
    if key is not None:
        sig_verified = verify_signature(scope.raw, key)
    elif scope.signed:
        print("scope is signed but no key supplied; pass --key-file to verify it.", file=sys.stderr)
        if not args.acknowledge:
            return 2

    os.makedirs(args.out, exist_ok=True)
    audit_path = os.path.join(args.out, "audit.jsonl")
    operator = args.operator or getpass.getuser()
    audit = AuditLog(audit_path, operator=operator, engagement_id=scope.engagement_id)

    if sig_verified is None and args.acknowledge:
        audit.append("authorization", action="acknowledge", target=scope.engagement_id,
                     decision="GRANT", detail={"asserted_by": operator, "note": args.acknowledge})

    authz = Authorizer(scope, audit, sig_verified)
    pre = authz.preflight()
    if not pre:
        print(f"PREFLIGHT DENIED: {pre.reason}", file=sys.stderr)
        return 1

    print(f"{TOOL_NAME} {__version__} - engagement {scope.engagement_id} ({scope.client})")
    print(f"authorized by: {scope.authorized_by}")
    print(f"signature: {'VALID' if sig_verified else ('UNVERIFIED' if sig_verified is None else 'INVALID')}")
    print(f"stages: {args.stages or scope.allowed_actions}")
    print("-" * 60)

    stages = args.stages.split(",") if args.stages else None
    results = run_engine(authz, stages)

    with open(os.path.join(args.out, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)

    report = build_markdown(audit_path)
    report_path = os.path.join(args.out, "report.md")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(report)
    print(f"done. audit -> {audit_path}")
    print(f"      report -> {report_path}")
    return 0


def cmd_tools(args) -> int:
    from .adapters import tool_inventory
    inv = tool_inventory()
    print("Optional external collectors (AEGIS uses them if present, else built-in):")
    for tool, present in inv.items():
        print(f"  [{'x' if present else ' '}] {tool}")
    print("\nAll core checks work with none of these installed (zero-dependency).")
    return 0


def normalize_domain(raw: str) -> str:
    """Accept a pasted URL or a bare domain and return just the hostname.

    'https://www.example.co.ke/' -> 'www.example.co.ke'
    'WWW.Example.co.ke:443'      -> 'www.example.co.ke'
    'www.example.co.ke'          -> 'www.example.co.ke'
    """
    from urllib.parse import urlsplit
    s = (raw or "").strip().strip('"').strip("'")
    if not s:
        raise ValueError("no domain provided")
    if "://" not in s:
        s = "//" + s  # let urlsplit treat it as a network location, not a path
    host = urlsplit(s).hostname or ""
    host = host.strip().rstrip(".").lower()
    if not host or "." not in host or " " in host:
        raise ValueError(f"does not look like a domain: {raw!r}")
    return host


def _auto_scope(domain: str, authorized_by: str, days: int) -> dict:
    from datetime import datetime, timedelta, timezone
    domain = normalize_domain(domain)
    now = datetime.now(timezone.utc)
    return {
        "engagement_id": f"ENG-{domain.replace('.', '-').upper()}",
        "client": domain,
        "nda_ref": "",
        "authorized_by": authorized_by,
        "created": now.isoformat(),
        "window": {"start": now.isoformat(), "end": (now + timedelta(days=days)).isoformat()},
        "scope": {"domains": [domain, f"*.{domain}"], "ip_ranges": [], "ports": [80, 443, 8443],
                  "internal_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]},
        "allowed_actions": ["passive", "webintel"],
        "rate_limit_per_host_rps": 2,
        "targets": {"domains": [domain], "hosts": [], "urls": [f"https://{domain}"],
                    "settlement_urls": []},
    }


def cmd_assess(args) -> int:
    """One-shot: give a website, AEGIS builds a passive/webintel scope and runs it.
    Still authorization-first - requires --acknowledge confirming written authorization."""
    if not args.acknowledge:
        print("Refusing to run without authorization. Pass --acknowledge \"<who authorized this test>\".",
              file=sys.stderr)
        print("Passive OSINT is still testing; run it only on assets you are authorized to assess.",
              file=sys.stderr)
        return 2
    os.makedirs(args.out, exist_ok=True)
    scope_dict = _auto_scope(args.domain, args.authorized_by or args.acknowledge, args.days)
    scope_path = os.path.join(args.out, "scope.json")
    with open(scope_path, "w", encoding="utf-8") as fh:
        json.dump(scope_dict, fh, indent=2)
    print(f"built scope for {args.domain} -> {scope_path}")

    scope = Scope.load(scope_path)
    operator = args.operator or getpass.getuser()
    audit = AuditLog(os.path.join(args.out, "audit.jsonl"), operator=operator,
                     engagement_id=scope.engagement_id)
    audit.append("authorization", action="acknowledge", target=scope.engagement_id,
                 decision="GRANT", detail={"asserted_by": operator, "note": args.acknowledge})
    authz = Authorizer(scope, audit, None)
    if not authz.preflight():
        return 1

    from .adapters import tool_inventory
    inv = {k: v for k, v in tool_inventory().items() if v}
    print(f"{TOOL_NAME} {__version__} - assessing {args.domain}")
    print(f"collectors in use: {', '.join(inv) or 'built-in only'}")
    print("-" * 60)
    results = run_engine(authz, ["passive", "webintel"])
    with open(os.path.join(args.out, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    report_path = os.path.join(args.out, "report.md")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(build_markdown(os.path.join(args.out, "audit.jsonl")))
    print(f"done. report -> {report_path}")
    return 0


def cmd_verify_audit(args) -> int:
    ok, msg = AuditLog.verify(args.audit)
    print(("AUDIT INTACT: " if ok else "AUDIT FAILED: ") + msg)
    return 0 if ok else 1


def cmd_report(args) -> int:
    md = build_markdown(args.audit)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"wrote {args.out}")
    else:
        print(md)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegis", description=f"{TOOL_NAME} - authorized, auditable assessment harness")
    from . import build_info
    b = build_info()
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {__version__} ({b['kind']} build, sha256 {b['code_sha256'][:16]}…)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init-scope", help="write an example scope file")
    s.add_argument("--out", default="scope.json")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init_scope)

    s = sub.add_parser("sign", help="HMAC-sign a scope file")
    s.add_argument("--scope", required=True)
    s.add_argument("--key")
    s.add_argument("--key-file")
    s.set_defaults(func=cmd_sign)

    s = sub.add_parser("verify", help="verify a scope file's signature")
    s.add_argument("--scope", required=True)
    s.add_argument("--key")
    s.add_argument("--key-file")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("run", help="run an authorized assessment")
    s.add_argument("--scope", required=True)
    s.add_argument("--key")
    s.add_argument("--key-file")
    s.add_argument("--out", default="run")
    s.add_argument("--operator")
    s.add_argument("--stages", help="comma list: connectivity,passive,settlement-readonly")
    s.add_argument("--acknowledge", help="assert authorization text when running without the signing key")
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("assess", help="one-shot: give a website, AEGIS footprints it (passive + webintel)")
    s.add_argument("--domain", required=True)
    s.add_argument("--acknowledge", help="confirm who authorized this test (required)")
    s.add_argument("--authorized-by")
    s.add_argument("--out", default="assess")
    s.add_argument("--operator")
    s.add_argument("--days", type=int, default=7, help="authorization window length")
    s.set_defaults(func=cmd_assess)

    s = sub.add_parser("tools", help="show which optional external collectors are installed")
    s.set_defaults(func=cmd_tools)

    s = sub.add_parser("ui", help="launch the local operator console (type-a-website field)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    s.set_defaults(func=lambda a: __import__("aegis.ui", fromlist=["serve"]).serve(a.host, a.port))

    from .dbcli import register as register_db
    register_db(sub)
    from .watch import register as register_watch
    register_watch(sub)
    from .insidecli import register as register_inside
    register_inside(sub)
    from .guard import register as register_guard
    register_guard(sub)
    from .selftest import register as register_selftest
    register_selftest(sub)

    s = sub.add_parser("verify-audit", help="verify the audit log hash chain")
    s.add_argument("--audit", required=True)
    s.set_defaults(func=cmd_verify_audit)

    s = sub.add_parser("report", help="build a Markdown report from an audit log")
    s.add_argument("--audit", required=True)
    s.add_argument("--out")
    s.set_defaults(func=cmd_report)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
