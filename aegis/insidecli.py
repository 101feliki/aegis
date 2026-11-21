"""
Inside-the-system modules (wired into cli.py).

    python -m aegis mpesa  --statement stmt.csv --callbacks cb.jsonl --db <wallet db> --map ledger-map.json ...
    python -m aegis host   [--app-dir /var/www/app ...] [--root /]              server check-up
    python -m aegis tamper baseline|check|approve --path /var/www/app ...         tamper alarm

Authorization works as for the database commands: a signed --scope (with the data
sources under scope.databases, this machine under scope.servers and watched folders
under scope.paths), or --acknowledge for a one-off, which writes an auto-scope pinned to
exactly what this command touches. Everything is recorded in the hash-chained audit log.
"""
from __future__ import annotations

import json
import os
import socket
import sys

from . import TOOL_NAME, __version__
from .dbcli import _auth_args, _cred_args, _password, _session


def _write_report(out: str) -> str:
    from .report import build_markdown
    p = os.path.join(out, "report.md")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(build_markdown(os.path.join(out, "audit.jsonl")))
    return p


def print_module(res: dict) -> None:
    cur = res.get("currency", "KES")
    if not res.get("module_findings"):
        print("  no problems found in what was checked")
    for f in res.get("module_findings", []):
        money = f"   {cur} {f['money_at_risk']}" if f.get("money_at_risk") else ""
        print(f"  [{f['severity']:<8}] {f['title']}: {f['count']}{money}")
        for s in f.get("samples", [])[:3]:
            print("             " + ", ".join(f"{k}={v}" for k, v in s.items() if v not in (None, "")))
    for c in res.get("coverage", []):
        print(f"  note: {c}")


# ---------------------------------------------------------------------------
def _allowlist(spec: str | None) -> list[str] | None:
    if not spec:
        return None
    if os.path.isfile(spec):
        with open(spec, "r", encoding="utf-8") as fh:
            return [ln.split("#")[0].strip() for ln in fh if ln.split("#")[0].strip()]
    return [s.strip() for s in spec.split(",") if s.strip()]


def cmd_mpesa(args) -> int:
    from .checks.mpesa import run_mpesa
    from .db.connect import DriverMissing, ReadOnlyViolation, open_readonly

    if not (args.statement or args.callbacks or args.db):
        print("give at least one of --statement, --callbacks, --db", file=sys.stderr)
        return 2
    if args.db and not args.map:
        print("--db needs --map (the reviewed ledger-map.json)", file=sys.stderr)
        return 2
    authz = _session(args, [args.statement, args.callbacks, args.db], ["mpesa-readonly"])
    if not authz:
        return 2
    mapping = None
    if args.map:
        with open(args.map, "r", encoding="utf-8") as fh:
            mapping = json.load(fh)
    cbt = None
    if args.callbacks_table:
        cbt = {"table": args.callbacks_table, "payload_col": args.payload_col,
               "ip_col": args.ip_col, "ts_col": args.received_col}
    db = None
    if args.db:
        try:
            db = open_readonly(args.db, password=_password(args), schema=args.schema)
        except (DriverMissing, ReadOnlyViolation) as e:
            print(f"cannot read database: {e}", file=sys.stderr)
            return 1
    print(f"{TOOL_NAME} {__version__} M-Pesa guard")
    print("-" * 60)
    try:
        res = run_mpesa(authz, statement=args.statement, callbacks=args.callbacks, db=db, mapping=mapping,
                        callbacks_table=cbt, allow=_allowlist(args.allow_ips))
    except (ValueError, OSError) as e:
        authz.audit.append("check", action="mpesa-readonly", target="mpesa-guard", decision="ERROR",
                           detail={"error": str(e)})
        print(f"cannot run the M-Pesa guard: {e}", file=sys.stderr)
        return 1
    finally:
        if db is not None:
            db.close()
    if not res.get("authorized"):
        print(f"DENIED: {res.get('reason')}", file=sys.stderr)
        return 1
    with open(os.path.join(args.out, "mpesa-results.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2, default=str)
    s = res["scanned"]
    print(f"  statement: {s['statement_rows']} rows | callbacks: {s['callbacks']} {s['callback_mix']} | "
          f"wallet: {s['wallet_deposits']} deposits, {s['wallet_withdrawals']} withdrawals, "
          f"{s['wallet_reversals']} reversals")
    print_module(res)
    if res["module_findings"]:
        print(f"  money flagged: {res['currency']} {res['total_at_risk']}")
    print(f"report -> {_write_report(args.out)}")
    return 3 if any(f["severity"] == "CRITICAL" for f in res["module_findings"]) else 0


# ---------------------------------------------------------------------------
def cmd_host(args) -> int:
    from .checks.host import Host, machine_name, run_host

    name = machine_name(Host(args.root))
    authz = _session(args, [], ["host-checkup"], extra_scope={"servers": [name]})
    if not authz:
        return 2
    print(f"{TOOL_NAME} {__version__} server check-up - {name}"
          + (f" (image at {args.root})" if args.root else " (this machine)"))
    print("-" * 60)
    res = run_host(authz, root=args.root, app_dirs=args.app_dir, web_roots=args.web_root)
    if not res.get("authorized"):
        print(f"DENIED: {res.get('reason')}", file=sys.stderr)
        return 1
    with open(os.path.join(args.out, "host-results.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2, default=str)
    if res.get("os"):
        print(f"  system: {res['os']}")
    print_module(res)
    print(f"report -> {_write_report(args.out)}")
    return 3 if any(f["severity"] == "CRITICAL" for f in res["module_findings"]) else 0


def cmd_demo_host(args) -> int:
    from .demo_host import PLANTED_HOST, PLANTED_HOST_POSIX, build
    root = build(args.out)
    print(f"demo server image -> {root}")
    print("planted (answer key): " + ", ".join(f"{k} x{v}" for k, v in PLANTED_HOST.items()))
    print("plus on Linux/Unix only: " + ", ".join(f"{k} x{v}" for k, v in PLANTED_HOST_POSIX.items()))
    print(f'try: python -m aegis host --root "{root}" --acknowledge "demo" --out demo-host-run')
    return 0


# ---------------------------------------------------------------------------
def _seal_key(args) -> str | None:
    return os.environ.get(args.seal_key_env) if getattr(args, "seal_key_env", None) else None


def _tamper_db(args, mapping_tables: list[str]):
    from .db.connect import open_readonly
    if not args.db:
        return None, []
    tables = list(args.db_table or [])
    if args.map:
        with open(args.map, "r", encoding="utf-8") as fh:
            m = json.load(fh)
        tables += [(m.get(s) or {}).get("table") for s in ("bets", "transactions", "balances")]
    return open_readonly(args.db, password=_password(args), schema=args.schema), [t for t in tables + mapping_tables if t]


def cmd_tamper(args) -> int:
    from .checks import tamper as T

    machine = socket.gethostname().lower()
    state = args.out
    bfile = os.path.join(state, "tamper-baseline.json")
    if args.action == "baseline":
        if not args.path:
            print("give at least one --path to watch (application folder, /etc/nginx, /etc/ssh ...)", file=sys.stderr)
            return 2
        if os.path.exists(bfile) and not args.force:
            print(f"a baseline already exists in {state}. After a legitimate change use `aegis tamper approve`; "
                  "--force starts over (the old approval history stays in the audit log).", file=sys.stderr)
            return 2
        paths = args.path
        prev = None
    else:
        if not os.path.exists(bfile):
            print(f"no baseline in {state} - run `aegis tamper baseline --path ... --out {state}` first", file=sys.stderr)
            return 2
        prev = T.load_baseline(state)
        paths = prev["paths"]
        if args.action == "approve" and not (args.note and args.by):
            print("approve needs --by \"<name, role>\" and --note \"<what was deployed / ticket>\" - the approval is "
                  "evidence.", file=sys.stderr)
            return 2

    # The database is only touched when given on this run; if the baseline covers one and it
    # is missing, the check reports that as a coverage gap rather than silently skipping it.
    authz = _session(args, [args.db] if args.db else [], ["tamper-watch"],
                     extra_scope={"servers": [machine], "paths": paths})
    if not authz:
        return 2
    db, tables = None, []
    try:
        if args.db:
            db, tables = _tamper_db(args, (prev or {}).get("db_tables") or [])
        print(f"{TOOL_NAME} {__version__} tamper alarm - {machine} - {args.action}")
        print("-" * 60)
        if args.action in ("baseline", "approve"):
            res = T.take_baseline(authz, machine, paths, (prev or {}).get("excludes") or
                                  (T.DEFAULT_EXCLUDES + list(args.exclude or [])), state, db=db,
                                  db_tables=tables or (prev or {}).get("db_tables"), key=_seal_key(args),
                                  approved_by=args.by or "", note=args.note or "", prev=prev,
                                  accept_risky=args.accept_risky)
            if not res.get("authorized"):
                print(f"DENIED: {res.get('reason')}", file=sys.stderr)
                return 1
            if res.get("refused"):
                print("  APPROVAL REFUSED - the changes include:", file=sys.stderr)
                for c in res["risky"]:
                    print(f"    {c['code']}: {', '.join(map(str, c['paths'][:5]))}", file=sys.stderr)
                print("  A suspected webshell, a script in an upload folder, or an edited baseline is an incident, "
                      "not a deployment. Investigate and preserve the files first. If an investigator has cleared "
                      "it, re-run with --accept-risky (the refusal and the override are both audit-logged).",
                      file=sys.stderr)
                return 3
            print(f"  fingerprinted {res['files']} file(s)"
                  + (f", {len(res['db']['tables'])} table(s), {len(res['db']['triggers'])} trigger(s), "
                     f"{len(res['db']['routines'])} routine(s)" if res.get("db") else ""))
            for m in res["missing"]:
                print(f"  WARNING: path does not exist: {m}")
            if res.get("approved_changes") is not None:
                if res["approved_changes"]:
                    print("  approved changes (recorded in the audit log):")
                    for c in res["approved_changes"]:
                        print(f"    {c['code']}: {c['count']}  e.g. {', '.join(map(str, c['paths'][:3]))}")
                else:
                    print("  nothing had changed since the last approval")
            print(f"  baseline -> {res['baseline']}")
            print(f"  sealed: {'HMAC + audit-log anchor' if _seal_key(args) else 'audit-log anchor only'}")
            return 0
        res = T.run_check(authz, machine, state, db=db, key=_seal_key(args))
    finally:
        if db is not None:
            db.close()
    if not res.get("authorized"):
        print(f"DENIED: {res.get('reason')}", file=sys.stderr)
        return 1
    with open(os.path.join(state, "tamper-results.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2, default=str)
    print_module(res)
    print(f"report -> {_write_report(state)}")
    return 3 if any(f["severity"] == "CRITICAL" for f in res["module_findings"]) else 0


# ---------------------------------------------------------------------------
def register(sub) -> None:
    s = sub.add_parser("mpesa", help="M-Pesa guard: statement vs callback log vs wallet (forged/replayed callbacks)")
    s.add_argument("--statement", help="M-Pesa org portal statement export (CSV)")
    s.add_argument("--callbacks", help="callback log: JSON/JSONL file, log file, or a folder of them")
    s.add_argument("--db", help="wallet database (connection URL, SQLite file or CSV export folder)")
    s.add_argument("--map", help="reviewed ledger-map.json (needed with --db)")
    s.add_argument("--callbacks-table", help="read callbacks from this table in --db instead of a file")
    s.add_argument("--payload-col", default="payload", help="column holding the raw callback JSON")
    s.add_argument("--ip-col", help="column holding the sender's IP address")
    s.add_argument("--received-col", help="column holding the time the callback was received")
    s.add_argument("--allow-ips", help="Safaricom callback addresses: file or comma list (CIDR ok); "
                                       "default = Daraja's published list")
    s.add_argument("--out", default="mpesa-run")
    _auth_args(s)
    _cred_args(s)
    s.set_defaults(func=cmd_mpesa)

    s = sub.add_parser("host", help="server check-up: exposed databases, secrets in the web root, SSH, updates, backdoors")
    s.add_argument("--root", help="check a mounted/copied server image at this folder instead of this machine")
    s.add_argument("--app-dir", action="append", default=[], help="application folder (repeatable)")
    s.add_argument("--web-root", action="append", default=[], help="folder the web server publishes (repeatable; "
                                                                   "nginx/apache roots are found automatically)")
    s.add_argument("--out", default="host-run")
    _auth_args(s)
    s.set_defaults(func=cmd_host)

    s = sub.add_parser("tamper", help="tamper alarm: fingerprint money code, access settings and DB triggers; "
                                      "alert on any unapproved change")
    s.add_argument("action", choices=["baseline", "check", "approve"])
    s.add_argument("--path", action="append", default=[], help="file or folder to watch (repeatable; baseline only)")
    s.add_argument("--exclude", action="append", default=[], help="extra name/path pattern to ignore (baseline only)")
    s.add_argument("--db", help="also fingerprint this database's money tables, triggers and stored routines")
    s.add_argument("--map", help="ledger-map.json: which tables are the money tables")
    s.add_argument("--db-table", action="append", default=[], help="extra table to fingerprint (repeatable)")
    s.add_argument("--by", help="approve: name and role of the person approving the change")
    s.add_argument("--note", help="approve: what was deployed (release, ticket)")
    s.add_argument("--seal-key-env", default="AEGIS_TAMPER_KEY",
                   help="environment variable holding the HMAC key that seals the baseline (keep it off the server)")
    s.add_argument("--force", action="store_true", help="baseline: start over even if one exists")
    s.add_argument("--accept-risky", action="store_true",
                   help="approve: accept changes flagged as webshell / script-in-uploads (after an investigation)")
    s.add_argument("--out", default="tamper-state", help="state folder: baseline, audit log, results")
    _auth_args(s)
    _cred_args(s)
    s.set_defaults(func=cmd_tamper)

    s = sub.add_parser("demo-host", help="build a demo server image with planted misconfigurations")
    s.add_argument("--out", default="demo")
    s.set_defaults(func=cmd_demo_host)
