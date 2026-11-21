"""
Continuous ledger watchdog.

    python -m aegis watch --db <target> --map ledger-map.json --scope scope.json --key-file k --out watch1
    python -m aegis watch ... --every 60          # stay running, re-check every 60 minutes

Each cycle re-runs the read-only ledger reconciliation, then compares the result
with the previous cycle (kept in <out>/watch-state.json) and raises an alert for:

  NEW_CASES            a money problem that was not there last time
  RECORDS_DISAPPEARED  fewer bets / transactions than last time (ledgers only grow)
  CASE_CLOSED          a critical case vanished - was it a documented fix, or an edited record?
  MAPPING_CHANGED      the reviewed table mapping was edited between runs
  WATCHDOG_BLIND       the check could not run (DB down, credentials, schema changed)
  AUTHORIZATION_ENDED  the signed authorization window is over - the watchdog stops

Alerts go to <out>/alerts.jsonl, the console, the hash-chained audit log, and
optionally a webhook (Slack / Teams / any HTTPS endpoint). It never writes to the
database and never fixes anything: it tells a person.

Exit codes (for Task Scheduler / cron): 0 quiet, 3 critical alert, 4 watchdog blind,
2 not authorized.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from . import TOOL_NAME, __version__

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load_state(path: str) -> dict | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _write_json_atomic(path: str, obj) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, default=str)
    os.replace(tmp, path)


def _append_jsonl(path: str, obj) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, default=str) + "\n")


# ---------------------------------------------------------------------------
def compare(prev: dict | None, res: dict, mapping_fp: str, since: str | None) -> tuple[list[dict], dict]:
    """Diff this run against the saved state. Returns (events, new_open_state)."""
    from .checks.ledger import SEVERITY, TITLE

    now = _now()
    events: list[dict] = []
    cur_keys: dict[str, list] = res.get("case_keys") or {}
    by_code = {f["code"]: f for f in res["ledger_findings"]}
    baseline = prev is None

    if prev and prev.get("mapping_sha256") != mapping_fp:
        events.append({"severity": "MEDIUM", "kind": "MAPPING_CHANGED",
                       "message": "The table mapping changed since the last run (was "
                                  f"{prev.get('mapping_sha256', '?')[:12]}, now {mapping_fp[:12]}). "
                                  "Confirm the edit was intended and reviewed."})

    prev_open: dict[str, dict] = (prev or {}).get("open") or {}
    new_open: dict[str, dict] = {}
    for code, keys in cur_keys.items():
        old = prev_open.get(code) or {}
        new_open[code] = {k: old.get(k, now) for k in keys}
        fresh = [k for k in keys if k not in old]
        if not fresh:
            continue
        f = by_code.get(code, {})
        samples = (res.get("new_cases") or {}).get(code) or []
        events.append({
            "severity": SEVERITY[code],
            "kind": "BASELINE" if baseline else "NEW_CASES",
            "code": code,
            "title": TITLE[code],
            "count": len(fresh),
            "open_total": f.get("count", len(keys)),
            "money_at_risk_all_open": f.get("money_at_risk"),
            "cases": [k for k in fresh[:25]],
            "evidence": samples[:10],
            "message": (f"{len(fresh)} case(s) already present when monitoring started" if baseline
                        else f"{len(fresh)} NEW case(s) since the last run"),
        })

    for code, old in prev_open.items():
        gone = [k for k in old if k not in set(cur_keys.get(code) or [])]
        if not gone:
            continue
        sev = SEVERITY.get(code, "LOW")
        events.append({
            "severity": "MEDIUM" if sev == "CRITICAL" else "INFO",
            "kind": "CASE_CLOSED",
            "code": code,
            "title": TITLE.get(code, code),
            "count": len(gone),
            "cases": gone[:25],
            "message": (f"{len(gone)} case(s) no longer appear. Confirm each was closed by a documented "
                        "correction - a money problem that disappears without one may mean the record was edited."
                        if sev == "CRITICAL" else f"{len(gone)} case(s) no longer appear."),
        })

    # Old wallet rows edited or deleted (history fingerprint, see checks/ledger.py).
    old_fp, cur_fp = (prev or {}).get("txn_fingerprint"), res.get("txn_fingerprint")
    history_checked = bool(old_fp and cur_fp and old_fp.get("block") == cur_fp.get("block")
                           and old_fp.get("max_id") is not None and cur_fp.get("edge_of") == old_fp["max_id"])
    if history_checked:
        B, pmax = old_fp["block"], old_fp["max_id"]
        changed = []
        for b_s, was in old_fp["blocks"].items():
            b = int(b_s)
            now_ = cur_fp["edge"] if b == pmax // B else cur_fp["blocks"].get(b_s, [0, "0" * 32])
            if list(now_) != list(was):
                changed.append({"ids": f"{b * B}-{min(b * B + B - 1, pmax)}", "rows_before": was[0],
                                "rows_now": now_[0]})
        if changed:
            deleted = sum(max(0, c["rows_before"] - c["rows_now"]) for c in changed)
            rng = ", ".join(c["ids"] for c in changed[:10]) + (" ..." if len(changed) > 10 else "")
            events.append({
                "severity": "CRITICAL", "kind": "HISTORY_TAMPERED", "detail": changed[:200],
                "cases": [c["ids"] for c in changed[:25]],
                "message": ("Wallet transactions that already existed at the last run were "
                            + ("DELETED" if deleted and all(c["rows_now"] < c["rows_before"] for c in changed)
                               else "EDITED or DELETED")
                            + f" (transaction id range(s) {rng}"
                            + (f"; {deleted} row(s) missing" if deleted else "; same row count, so contents changed")
                            + "). Past money records should never change - pull the database's own change log "
                              "for these ids and preserve a copy now."),
            })

    if prev and not since and not res.get("windowed"):
        before, after = prev.get("scanned") or {}, res["scanned"]
        lost = {k: (before[k], after.get(k, 0)) for k in ("bets", "transactions")
                if isinstance(before.get(k), int) and after.get(k, 0) < before[k]
                and not (k == "transactions" and history_checked)}
        if lost:
            what = ", ".join(f"{k}: {a} -> {b} ({a - b} gone)" for k, (a, b) in lost.items())
            events.append({"severity": "CRITICAL", "kind": "RECORDS_DISAPPEARED", "detail": lost,
                           "message": f"Ledger rows were removed since the last run ({what}). Betting and wallet "
                                      "records should only ever grow - deletion destroys evidence and can hide fraud."})

    if res.get("keys_truncated"):
        events.append({"severity": "LOW", "kind": "PRECISION_NOTE",
                       "message": "Very many cases for " + ", ".join(res["keys_truncated"])
                                  + " - new-vs-old tracking capped for those checks."})

    events.sort(key=lambda e: SEV_RANK.get(e["severity"], 9))
    return events, new_open


# ---------------------------------------------------------------------------
def _webhook(url: str, run_id: str, label: str, events: list[dict], title: str = "ledger watchdog") -> str:
    """POST a short alert. Slack and Teams incoming webhooks both accept {"text": ...}."""
    p = urllib.parse.urlparse(url)
    if p.scheme != "https" and p.hostname not in ("127.0.0.1", "localhost"):
        return "refused: webhook must be https (alerts carry money details)"
    lines = [f"AEGIS {title} - {label} - run {run_id}"]
    for e in events[:12]:
        mod = f"{e['module']}: " if e.get("module") else ""
        lines.append(f"[{e['severity']}] {mod}{e.get('title') or e['kind']}: {e['message']}"
                     + (f" e.g. {', '.join(map(str, e['cases'][:5]))}" if e.get("cases") else ""))
    if len(events) > 12:
        lines.append(f"... and {len(events) - 12} more - see the report")
    body = json.dumps({"text": "\n".join(lines),
                       "aegis": {"run": run_id, "target": label,
                                 "events": [{k: e.get(k) for k in ("severity", "module", "kind", "code", "count",
                                                                   "cases")}
                                            for e in events]}}, default=str).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": f"{TOOL_NAME}/{__version__} watchdog"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return f"delivered (HTTP {r.status})"
    except Exception as e:  # noqa: BLE001 - delivery failure must never kill the watchdog
        return f"FAILED: {type(e).__name__}: {e}"


def _blind(out: str, authz, label: str, run_id: str, why: str, args) -> int:
    ev = {"severity": "HIGH", "kind": "WATCHDOG_BLIND",
          "message": f"The ledger check could not run: {why}. Until this is fixed nothing is being watched."}
    if getattr(args, "sink", None) is not None:
        args.sink.append(ev)
    _append_jsonl(os.path.join(out, "alerts.jsonl"), dict(ev, run=run_id, at=_now(), database=label))
    authz.audit.append("note", action="watch", target=label, decision="ALERT", detail={"run": run_id, "events": [ev]})
    print(f"  [HIGH    ] WATCHDOG BLIND - {why}")
    if args.webhook:
        r = _webhook(args.webhook, run_id, label, [ev])
        authz.audit.append("note", action="watch-alert", target=urllib.parse.urlparse(args.webhook).hostname or "",
                           decision="INFO", detail={"run": run_id, "delivery": r})
        print(f"  webhook: {r}")
    return 4


def cycle(args, authz, mapping: dict) -> int:
    from .checks.ledger import mapping_fingerprint, run_ledger
    from .db.connect import open_readonly
    from .db.identify import redact
    from .dbcli import _password
    from .report import build_markdown

    out, label = args.out, redact(args.db)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    print(f"\n{TOOL_NAME} {__version__} watchdog - run {run_id} - {label}")

    pre = authz.preflight()
    if not pre:
        ev = {"severity": "HIGH", "kind": "AUTHORIZATION_ENDED", "message": f"Watchdog stopped: {pre.reason}"}
        if getattr(args, "sink", None) is not None:
            args.sink.append(ev)
        _append_jsonl(os.path.join(out, "alerts.jsonl"), dict(ev, run=run_id, at=_now(), database=label))
        print(f"  {ev['message']}")
        return 2

    state_path = os.path.join(out, "watch-state.json")
    prev = _load_state(state_path)
    if prev and prev.get("database") != label:
        print(f"  state file belongs to {prev.get('database')} - starting a fresh baseline for {label}")
        prev = None
    fp = mapping_fingerprint(mapping)
    known = ({c: set(v) for c, v in (prev.get("open") or {}).items()} if prev else None)

    t0 = time.time()
    try:
        db = open_readonly(args.db, password=_password(args), schema=args.schema)
    except Exception as e:  # noqa: BLE001
        return _blind(out, authz, label, run_id, f"cannot open the database ({type(e).__name__}: {e})", args)
    try:
        with db:
            pfp = (prev or {}).get("txn_fingerprint") or {}
            res = run_ledger(authz, db, mapping, since=args.since, known=known, fingerprint=True,
                             prev_max_id=pfp.get("max_id") if prev and prev.get("mapping_sha256") == fp else None)
    except Exception as e:  # noqa: BLE001 - e.g. a mapped column was renamed/dropped
        return _blind(out, authz, label, run_id, f"scan failed ({type(e).__name__}: {e}) - "
                      "has the schema changed? re-run `aegis db map` and review", args)
    if not res.get("authorized"):
        print(f"  DENIED: {res.get('reason')}", file=sys.stderr)
        return 2
    secs = round(time.time() - t0, 1)

    events, new_open = compare(prev, res, fp, args.since)
    if getattr(args, "sink", None) is not None:          # `aegis guard` collects events for one combined alert
        args.sink.extend(events)

    # -- persist: latest full result, alerts, one history line, state ----------
    _write_json_atomic(os.path.join(out, "latest-results.json"),
                       {k: v for k, v in res.items() if k not in ("case_keys", "txn_fingerprint")})
    for e in events:
        _append_jsonl(os.path.join(out, "alerts.jsonl"), dict(e, run=run_id, at=_now(), database=label))
    open_counts = {c: len(v) for c, v in new_open.items() if v}
    _append_jsonl(os.path.join(out, "history.jsonl"),
                  {"run": run_id, "at": _now(), "seconds": secs, "scanned": res["scanned"],
                   "open": open_counts, "total_at_risk": res["total_at_risk"],
                   "events": [{"severity": e["severity"], "kind": e["kind"], "code": e.get("code"),
                               "count": e.get("count")} for e in events]})
    _write_json_atomic(state_path, {"aegis_watch_state": 1, "database": label, "mapping_sha256": fp,
                                    "last_run": run_id, "scanned": res["scanned"], "open": new_open,
                                    "txn_fingerprint": ({k: v for k, v in res["txn_fingerprint"].items()
                                                         if k in ("block", "max_id", "blocks")}
                                                        if res.get("txn_fingerprint") else None)})

    alerting = [e for e in events if SEV_RANK[e["severity"]] <= SEV_RANK[args.alert_level]]
    authz.audit.append("note", action="watch", target=label, decision="ALERT" if alerting else "QUIET",
                       detail={"run": run_id, "baseline": prev is None, "seconds": secs,
                               "open_cases": open_counts,
                               "events": [{k: e.get(k) for k in ("severity", "kind", "code", "count", "cases")}
                                          for e in events]})
    with open(os.path.join(out, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(build_markdown(os.path.join(out, "audit.jsonl")))

    # -- tell a person ----------------------------------------------------------
    s = res["scanned"]
    print(f"  scanned {s['bets']} bets, {s['transactions']} transactions, {s['wallets']} wallets in {secs}s")
    if prev is None:
        print("  first run: this is the BASELINE - later runs report only what changes")
    if not events:
        print(f"  quiet - nothing new. Open cases: {sum(open_counts.values())}")
    for e in events:
        head = e.get("title") or e["kind"].replace("_", " ")
        print(f"  [{e['severity']:<8}] {head}: {e['message']}")
        if e.get("cases"):
            print(f"             cases: {', '.join(map(str, e['cases'][:8]))}"
                  + (" ..." if len(e["cases"]) > 8 else ""))
    if alerting and args.webhook:
        r = _webhook(args.webhook, run_id, label, alerting)
        authz.audit.append("note", action="watch-alert", target=urllib.parse.urlparse(args.webhook).hostname or "",
                           decision="INFO", detail={"run": run_id, "delivery": r})
        print(f"  webhook: {r}")
    print(f"  alerts -> {os.path.join(out, 'alerts.jsonl')}")
    return 3 if any(e["severity"] == "CRITICAL" for e in events) else 0


def cmd_watch(args) -> int:
    from .dbcli import _session

    if args.alert_level not in SEV_RANK:
        print(f"--alert-level must be one of {', '.join(SEV_RANK)}", file=sys.stderr)
        return 2
    authz = _session(args, args.db, ["db-identify", "ledger-readonly"])
    if not authz:
        return 2
    with open(args.map, "r", encoding="utf-8") as fh:
        mapping = json.load(fh)
    if args.every and not args.scope:
        print("note: running on --acknowledge; that authorization lasts 24 hours, then the watchdog stops.\n"
              "      For unattended monitoring use a signed scope with the agreed end date.")
    if not mapping.get("reviewed_by"):
        print("note: the mapping has not been confirmed by a person (reviewed_by is empty).")

    runs, code = 0, 0
    try:
        while True:
            code = cycle(args, authz, mapping)
            runs += 1
            if code == 2 or not args.every or (args.max_runs and runs >= args.max_runs):
                return code
            print(f"  next check in {args.every} minute(s) - Ctrl+C to stop")
            time.sleep(args.every * 60)
    except KeyboardInterrupt:
        from .db.identify import redact
        authz.audit.append("note", action="watch", target=redact(args.db), decision="INFO",
                           detail={"stopped": "by operator (Ctrl+C)", "runs": runs})
        print("\nwatchdog stopped by operator")
        return code


def register(sub) -> None:
    from .dbcli import _auth_args, _cred_args

    s = sub.add_parser("watch", help="continuous money watchdog: re-check the ledger and alert on what changed")
    s.add_argument("--db", required=True, help="connection URL, ADO string, SQLite file or CSV export folder")
    s.add_argument("--map", required=True, help="reviewed ledger-map.json")
    s.add_argument("--out", default="watch", help="folder for state, alerts, history, audit and report")
    s.add_argument("--every", type=float, default=0,
                   help="minutes between checks; 0 (default) = run once, for Task Scheduler / cron")
    s.add_argument("--max-runs", type=int, default=0, help="stop after N checks (0 = until stopped/expired)")
    s.add_argument("--since", help="only bets placed on/after this date (YYYY-MM-DD)")
    s.add_argument("--webhook", help="HTTPS URL to POST alerts to (Slack/Teams incoming webhook, or your own)")
    s.add_argument("--alert-level", default="HIGH", help="lowest severity sent to the webhook (default HIGH)")
    _auth_args(s)
    _cred_args(s)
    s.set_defaults(func=cmd_watch)
