"""
Database / ledger commands (wired into cli.py).

    python -m aegis db identify <target> [--probe --acknowledge "..."]
    python -m aegis db map      <target> --acknowledge "..."            -> ledger-map.json (review it!)
    python -m aegis ledger      --db <target> --map ledger-map.json --acknowledge "..."
    python -m aegis demo-ledger --out demo

<target> can be a connection URL, an ADO/ODBC string, a SQLite file, a CSV
export folder, or host:port. Passwords are read from the AEGIS_DB_PASSWORD
environment variable (or --ask-password) and are never written anywhere.

Authorization: either a signed scope (--scope/--key-file) whose
`scope.databases` lists the database and whose allowed_actions include
`db-identify` / `ledger-readonly`, or --acknowledge for a one-off, which writes
an auto-scope pinned to exactly this database. Every step is audit-logged.
"""
from __future__ import annotations

import getpass
import json
import os
import sys
from datetime import datetime, timedelta, timezone

from . import TOOL_NAME, __version__
from .audit import AuditLog
from .authz import Authorizer
from .db.identify import identify, redact
from .scope import Scope, verify_signature


def _password(args) -> str | None:
    if getattr(args, "ask_password", False):
        return getpass.getpass("Database password (not stored): ")
    return os.environ.get(getattr(args, "password_env", None) or "AEGIS_DB_PASSWORD")


def _source_label(target: str) -> str:
    return redact(target) if "://" in target or ";" in target else os.path.abspath(target)


def _session(args, target: str | list[str], actions: list[str], extra_scope: dict | None = None) -> Authorizer | None:
    """Build an Authorizer from a signed scope, or an auto-scope under --acknowledge.

    `target` may be a list (e.g. the M-Pesa guard reads a statement, a callback log and a
    database); under --acknowledge the auto-scope is pinned to exactly those sources."""
    os.makedirs(args.out, exist_ok=True)
    operator = getattr(args, "operator", None) or getpass.getuser()
    targets = [t for t in (target if isinstance(target, list) else [target]) if t]
    label = ", ".join(redact(t) for t in targets)

    if getattr(args, "scope", None):
        scope = Scope.load(args.scope)
        key = None
        if getattr(args, "key_file", None):
            with open(args.key_file, "r", encoding="utf-8") as fh:
                key = fh.read().strip()
        sig = verify_signature(scope.raw, key) if key else None
        if sig is None and scope.signed and not args.acknowledge:
            print("scope is signed but no --key-file given; pass it, or --acknowledge.", file=sys.stderr)
            return None
        audit = AuditLog(os.path.join(args.out, "audit.jsonl"), operator, scope.engagement_id)
        if sig is None and args.acknowledge:
            audit.append("authorization", action="acknowledge", target=scope.engagement_id, decision="GRANT",
                         detail={"asserted_by": operator, "note": args.acknowledge})
    else:
        if not args.acknowledge:
            print("Refusing to touch a database without authorization.\n"
                  "Pass --acknowledge \"<who authorized this, e.g. CTO name + engagement letter ref>\" "
                  "or a signed --scope.", file=sys.stderr)
            return None
        now = datetime.now(timezone.utc)
        raw = {
            "engagement_id": f"DB-{now.strftime('%Y%m%d-%H%M%S')}",
            "client": getattr(args, "client", None) or "in-system database review",
            "authorized_by": args.acknowledge,
            "created": now.isoformat(),
            "window": {"start": now.isoformat(), "end": (now + timedelta(days=1)).isoformat()},
            "scope": dict({"domains": [], "ip_ranges": [], "ports": [],
                           "databases": [_source_label(t) for t in targets]}, **(extra_scope or {})),
            "allowed_actions": actions,
        }
        sp = os.path.join(args.out, "scope.json")
        with open(sp, "w", encoding="utf-8") as fh:
            json.dump(raw, fh, indent=2)
        scope = Scope.load(sp)
        sig = None
        audit = AuditLog(os.path.join(args.out, "audit.jsonl"), operator, scope.engagement_id)
        audit.append("authorization", action="acknowledge", target=scope.engagement_id, decision="GRANT",
                     detail={"asserted_by": operator, "note": args.acknowledge, "database": label})

    authz = Authorizer(scope, audit, sig)
    pre = authz.preflight()
    if not pre:
        print(f"PREFLIGHT DENIED: {pre.reason}", file=sys.stderr)
        return None
    return authz


# ---------------------------------------------------------------------------
def _print_identity(res: dict) -> None:
    print(f"  engine      : {res['label']}  ({res['engine']})")
    print(f"  identified  : {res['identified_by']}")
    if res.get("evidence"):
        print(f"  evidence    : {res['evidence']}")
    if res.get("live_check"):
        print(f"  live check  : {res['live_check']}")
    if res["engine"] != "unknown":
        if res.get("readable"):
            print(f"  can read    : yes, via {res['driver']}")
        else:
            print(f"  can read    : not yet - {res.get('install') or 'no driver available'}")
        for drv, why in (res.get("skipped") or {}).items():
            print(f"  skipped     : {drv} - {why}")
        print(f"  ledger check: {'supported' if res.get('ledger_supported') else 'not supported for this engine'}")
    for k in ("advice", "warning", "finding", "note"):
        if res.get(k):
            print(f"  {k:<12}: {res[k]}")


def cmd_db_identify(args) -> int:
    net = bool(args.probe)
    if net:
        authz = _session(args, args.target, ["db-identify"])
        if not authz:
            return 2
        if not authz.authorize_db("db-identify", redact(args.target)):
            print("DENIED: database not in authorized scope", file=sys.stderr)
            return 1
    res = identify(args.target, allow_network=net)
    if net:
        authz.audit.append("check", action="db-identify", target=redact(args.target), decision="DONE", detail=res)
    print(f"{TOOL_NAME} database identifier - {res['target']}")
    _print_identity(res)
    if args.json:
        print(json.dumps(res, indent=2, default=str))
    return 0 if res["engine"] != "unknown" else 1


def cmd_db_map(args) -> int:
    from .db.connect import DriverMissing, ReadOnlyViolation, open_readonly
    from .db.schemamap import propose

    authz = _session(args, args.target, ["db-identify", "ledger-readonly"])
    if not authz:
        return 2
    label = redact(args.target)
    if not authz.authorize_db("ledger-readonly", label):
        print("DENIED: database not in authorized scope", file=sys.stderr)
        return 1
    ident = identify(args.target)
    print(f"{TOOL_NAME} schema mapper - {label}")
    _print_identity(ident)
    try:
        db = open_readonly(args.target, password=_password(args), schema=args.schema)
    except DriverMissing as e:
        print(f"\ncannot read it yet: {e}", file=sys.stderr)
        return 1
    with db:
        m = propose(db)
    authz.audit.append("check", action="ledger-readonly", target=label, decision="DONE",
                       detail={"check": "schema-map", "bets": (m.get("bets") or {}).get("table"),
                               "transactions": (m.get("transactions") or {}).get("table"),
                               "balances": (m.get("balances") or {}).get("table"),
                               "review_required": m["review_required"]})
    save = args.save or os.path.join(args.out, "ledger-map.json")
    with open(save, "w", encoding="utf-8") as fh:
        json.dump(m, fh, indent=2, default=str)

    print(f"\n  scanned {m['tables_seen']} table(s). Best guess:")
    for kind in ("bets", "transactions", "balances"):
        sec = m.get(kind)
        if sec:
            cols = ", ".join(f"{r}={c}" for r, c in sec["columns"].items())
            print(f"   - {kind:<12} -> {sec['table']}  ({'?' if sec.get('rows') is None else sec['rows']} rows)\n       {cols}")
        else:
            print(f"   - {kind:<12} -> NOT FOUND")
    if m.get("bets"):
        print(f"   bet statuses : {m['bets']['status_values']}")
    if m.get("transactions"):
        print(f"   txn types    : {m['transactions']['type_values']}")
        print(f"   amount signs : {m['transactions']['amount_sign']}"
              + (f"   bet ref pattern: {m['transactions']['bet_ref_pattern']}"
                 if m['transactions'].get('bet_ref_pattern') else ""))
    if m["review_required"]:
        print("\n  NEEDS A HUMAN LOOK:")
        for r in m["review_required"]:
            print(f"   ! {r}")
    sheet = os.path.splitext(save)[0] + "-signoff.md"
    with open(sheet, "w", encoding="utf-8") as fh:
        fh.write(signoff_sheet(m))
    print(f"\n  mapping -> {save}")
    print(f"  sign-off sheet for the client -> {sheet}")
    print("  Review it, fix anything wrong, set \"reviewed_by\", then run `aegis ledger`.")
    return 0


ROLE_PLAIN = {
    "id": "bet / transaction number", "user": "customer account key", "stake": "amount staked",
    "odds": "odds", "status": "bet result", "payout": "payout recorded on the bet", "potential": "possible win",
    "settled_at": "time the bet was settled", "created_at": "time created", "amount": "amount",
    "type": "transaction type", "bet_ref": "which bet a credit belongs to", "receipt": "M-Pesa receipt number",
    "direction": "credit / debit flag", "balance": "wallet balance",
}
MEANING_PLAIN = {
    "won": "WON", "lost": "LOST", "void": "VOID / cancelled", "pending": "still OPEN", "cashout": "CASHED OUT",
    "payout": "winnings credited", "refund": "stake refunded", "stake": "stake taken", "deposit": "deposit (M-Pesa)",
    "withdrawal": "withdrawal", "bonus": "bonus", "other": "NOT UNDERSTOOD - excluded",
    "unknown": "NOT UNDERSTOOD - excluded",
}


def signoff_sheet(m: dict) -> str:
    """One page the client's technical owner confirms: what AEGIS reads and how it reads it."""
    L = ["# Ledger mapping - confirmation sheet", "",
         f"Database: `{m.get('database')}` ({m.get('engine')}). Generated by {TOOL_NAME} {__version__}.", "",
         "AEGIS checks that winnings, refunds and wallet balances agree with the bets placed. To do that it needs",
         "to know which tables hold bets and wallet transactions, and what your status and type codes mean. It",
         "worked these out automatically. **Please correct anything that is wrong.** AEGIS reads only the columns",
         "listed here. It never changes data.", ""]
    for kind, title in (("bets", "Bets"), ("transactions", "Wallet transactions"), ("balances", "Wallet balances")):
        sec = m.get(kind)
        L.append(f"## {title}: " + (f"table `{sec['table']}`" if sec else "NOT FOUND - please tell us where this is"))
        if not sec:
            L.append("")
            continue
        L += ["", "| Column | Used as | Correct? |", "|---|---|---|"]
        L += [f"| `{c}` | {ROLE_PLAIN.get(r, r)} | [ ] yes [ ] no: |" for r, c in sec["columns"].items()]
        vals = sec.get("status_values") or sec.get("type_values")
        if vals:
            L += ["", "| Code in your data | AEGIS reads it as | Correct? |", "|---|---|---|"]
            L += [f"| `{v}` | {MEANING_PLAIN.get(meaning, meaning)} | [ ] yes [ ] no: |" for v, meaning in vals.items()]
        if kind == "transactions":
            sign = {"signed": "amounts carry their own +/- sign", "by_direction": "a credit/debit column gives the sign",
                    "by_type": "amounts are positive; the transaction type decides credit or debit"}
            L += ["", f"Money direction: {sign.get(sec.get('amount_sign'), sec.get('amount_sign'))}. [ ] correct"]
            if sec.get("bet_ref_pattern"):
                L.append(f"Bet reference: the bet number is taken from the reference using pattern "
                         f"`{sec['bet_ref_pattern']}`. [ ] correct")
        L.append("")
    L += [f"Currency: {m.get('currency', 'KES')} · rounding tolerance: {m.get('tolerance', '1.00')}", ""]
    if m.get("review_required"):
        L += ["## Points AEGIS was unsure about", ""] + [f"- {r}" for r in m["review_required"]] + [""]
    L += ["## Confirmation", "",
          "I confirm the mapping above (with any corrections noted) describes our system.", "",
          "Name: ______________________  Role: ______________________", "",
          "Signature: __________________  Date: ______________________", ""]
    return "\n".join(L)


def cmd_ledger(args) -> int:
    from .checks.ledger import run_ledger
    from .db.connect import DriverMissing, ReadOnlyViolation, open_readonly
    from .report import build_markdown

    authz = _session(args, args.db, ["db-identify", "ledger-readonly"])
    if not authz:
        return 2
    with open(args.map, "r", encoding="utf-8") as fh:
        mapping = json.load(fh)
    try:
        db = open_readonly(args.db, password=_password(args), schema=args.schema)
    except (DriverMissing, ReadOnlyViolation) as e:
        print(f"cannot read database: {e}", file=sys.stderr)
        return 1
    print(f"{TOOL_NAME} {__version__} ledger watchdog - {db.label} ({db.engine})")
    print("-" * 60)
    try:
        with db:
            res = run_ledger(authz, db, mapping, since=args.since)
    except ValueError as e:              # incomplete map, or a mapped column no longer exists
        authz.audit.append("check", action="ledger-readonly", target=db.label, decision="ERROR",
                           detail={"error": str(e)})
        print(f"cannot run the ledger check: {e}", file=sys.stderr)
        return 1
    if not res.get("authorized"):
        print(f"DENIED: {res.get('reason')}", file=sys.stderr)
        return 1

    with open(os.path.join(args.out, "ledger-results.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2, default=str)
    report_path = os.path.join(args.out, "report.md")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(build_markdown(os.path.join(args.out, "audit.jsonl")))

    s = res["scanned"]
    print(f"scanned {s['bets']} bets, {s['transactions']} transactions, {s['wallets']} wallets")
    if res["ledger_findings"]:
        cur = res["currency"]
        for f in res["ledger_findings"]:
            money = f"  {cur} {f['money_at_risk']}" if f["money_at_risk"] else ""
            print(f"  [{f['severity']:<8}] {f['count']:>4} x {f['title']}{money}")
        print(f"  money flagged (cases may overlap): {cur} {res['total_at_risk']}")
    else:
        print("  no money-integrity problems found in the data scanned")
    for c in res["coverage"]:
        print(f"  note: {c}")
    print(f"\nreport -> {report_path}")
    return 3 if any(f["severity"] == "CRITICAL" for f in res["ledger_findings"]) else 0


def cmd_db_grants(args) -> int:
    """Pure text generation from the map - touches no database, so needs no authorization."""
    from .db.grants import export_commands, grant_sql, pii_warnings

    with open(args.map, "r", encoding="utf-8") as fh:
        mapping = json.load(fh)
    try:
        sql = grant_sql(mapping, args.engine, args.user, args.from_host, args.schema)
        exp = export_commands(mapping, args.engine, args.schema)
        warn = pii_warnings(mapping)
    except ValueError as e:
        print(f"cannot generate: {e}", file=sys.stderr)
        return 1
    if not mapping.get("reviewed_by"):
        print("-- WARNING: this map has not been confirmed by a person (reviewed_by is empty).\n")
    text = sql + "\n\n" + exp + ("\n\n# Check:\n" + "\n".join(f"#  ! {w}" for w in warn) if warn else "") + "\n"
    if args.save:
        with open(args.save, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"access pack -> {args.save}")
    else:
        print(text)
    return 0


def cmd_demo_ledger(args) -> int:
    from .demo_ledger import PLANTED, build
    path = build(args.out, n_bets=args.bets)
    print(f"demo sportsbook -> {path}")
    print(f"same data as CSV -> {os.path.join(args.out, 'csv_export')}")
    print("planted bugs (answer key): " + ", ".join(f"{k} x{v}" for k, v in PLANTED.items()))
    return 0


# ---------------------------------------------------------------------------
def _auth_args(s) -> None:
    s.add_argument("--acknowledge", help="who authorized this (required unless a signed --scope is given)")
    s.add_argument("--scope", help="signed scope file listing this database under scope.databases")
    s.add_argument("--key-file")
    s.add_argument("--operator")
    s.add_argument("--client")


def _cred_args(s) -> None:
    s.add_argument("--password-env", default="AEGIS_DB_PASSWORD",
                   help="environment variable holding the DB password (default AEGIS_DB_PASSWORD)")
    s.add_argument("--ask-password", action="store_true", help="prompt for the password instead")
    s.add_argument("--schema", help="Postgres schema (default public)")


def register(sub) -> None:
    db = sub.add_parser("db", help="identify a database and map its betting ledger")
    dsub = db.add_subparsers(dest="dbcmd", required=True)

    s = dsub.add_parser("identify", help="what kind of database is this? (URL, file, folder, host:port)")
    s.add_argument("target")
    s.add_argument("--probe", action="store_true",
                   help="also confirm by reading the live server's handshake (needs authorization)")
    s.add_argument("--json", action="store_true")
    s.add_argument("--out", default="aegis-db")
    _auth_args(s)
    s.set_defaults(func=cmd_db_identify)

    s = dsub.add_parser("map", help="find the bets / wallet tables and write a mapping to review")
    s.add_argument("target")
    s.add_argument("--save", help="where to write the mapping (default <out>/ledger-map.json)")
    s.add_argument("--out", default="aegis-db")
    _auth_args(s)
    _cred_args(s)
    s.set_defaults(func=cmd_db_map)

    s = dsub.add_parser("grants", help="SQL for a least-privilege monitoring login (mapped columns only) + CSV export commands")
    s.add_argument("--map", required=True, help="reviewed ledger-map.json")
    s.add_argument("--engine", choices=["mysql", "postgres", "mssql", "oracle", "sqlite", "csv"],
                   help="default: the engine recorded in the map")
    s.add_argument("--user", default="aegis_ro")
    s.add_argument("--from-host", default="%", help="MySQL: host/IP the AEGIS machine connects from (default any)")
    s.add_argument("--schema", help="Postgres schema (default public)")
    s.add_argument("--save", help="write to this file instead of printing")
    s.set_defaults(func=cmd_db_grants)

    s = sub.add_parser("ledger", help="money-integrity watchdog: reconcile bets against wallet transactions")
    s.add_argument("--db", required=True, help="connection URL, ADO string, SQLite file or CSV export folder")
    s.add_argument("--map", required=True, help="reviewed ledger-map.json from `aegis db map`")
    s.add_argument("--since", help="only bets placed on/after this date (YYYY-MM-DD)")
    s.add_argument("--out", default="ledger-run")
    _auth_args(s)
    _cred_args(s)
    s.set_defaults(func=cmd_ledger)

    s = sub.add_parser("demo-ledger", help="build a demo sportsbook DB with planted money bugs")
    s.add_argument("--out", default="demo")
    s.add_argument("--bets", type=int, default=400, help="number of bets to generate (scale testing)")
    s.set_defaults(func=cmd_demo_ledger)
