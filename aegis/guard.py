"""
AEGIS guard - the installed product: one config file, every inside module, one alert.

    python -m aegis guard init      --save aegis-guard.json        write a config to fill in
    python -m aegis guard run       --config aegis-guard.json      one cycle (for Task Scheduler / cron / systemd)
    python -m aegis guard run       --config aegis-guard.json --every 60     stay running
    python -m aegis guard schedule  --config aegis-guard.json      print ready-made schedule entries

Each cycle runs the enabled modules - ledger watchdog, M-Pesa guard, server check-up,
tamper alarm - under ONE authorization (the signed scope), then compares every result
with the previous cycle and raises an alert only for what is NEW:

  NEW / BASELINE     a problem not seen in the previous cycle (first cycle = baseline)
  RESOLVED           a problem that disappeared (for money problems: confirm it was a documented fix)
  MODULE_BLIND       a module could not run (database down, file missing, schema changed)
  AUTHORIZATION_ENDED  the signed window is over - the guard stops

Read-only throughout. It never fixes anything; it tells a person, and it records
everything in the hash-chained audit log for counsel.

Exit codes: 0 quiet, 3 new CRITICAL problem, 4 a module was blind, 2 not authorized.
"""
from __future__ import annotations

import argparse
import getpass
import glob
import json
import os
import socket
import sys
import time
import urllib.parse
from datetime import datetime, timezone

from . import TOOL_NAME, __version__
from .findings import SEV_ORDER

SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}

TEMPLATE = {
    "_help": [
        "AEGIS guard configuration. Paths may be absolute or relative to this file.",
        "authorization: use a SIGNED scope for unattended running (scope + key_file). The scope must list:",
        "  allowed_actions: db-identify, ledger-readonly, mpesa-readonly, host-checkup, tamper-watch (those you use)",
        "  scope.databases: every database / statement folder / callback log below",
        "  scope.servers:   this machine's hostname;  scope.paths: every folder the tamper alarm watches",
        "Database passwords are read from the environment variable named in password_env - never put them here.",
        "mpesa.statement may be a FOLDER: the newest .csv in it is used (drop each day's portal export there).",
        "tamper: run `aegis tamper baseline --path ... --out <out>/tamper` once before enabling it.",
        "Set enabled=false for any module you do not use yet.",
    ],
    "name": "<Client> production",
    "out": "guard-state",
    "authorization": {"scope": "scope.json", "key_file": "scope.key", "acknowledge": ""},
    "operator": "",
    "password_env": "AEGIS_DB_PASSWORD",
    "alerts": {"webhook": "", "alert_level": "HIGH"},
    "modules": {
        "ledger": {"enabled": True, "db": "mysql://aegis_ro@10.0.0.5:3306/sportsbook", "map": "ledger-map.json",
                   "since": None, "schema": None},
        "mpesa": {"enabled": True, "statement": "mpesa-statements/", "callbacks": "/var/log/sportsbook/mpesa/",
                  "db": "mysql://aegis_ro@10.0.0.5:3306/sportsbook", "map": "ledger-map.json",
                  "callbacks_table": None, "payload_col": "payload", "ip_col": None, "received_col": None,
                  "allow_ips": None},
        "host": {"enabled": True, "app_dirs": ["/var/www/sportsbook"], "web_roots": []},
        "tamper": {"enabled": True, "db": "mysql://aegis_ro@10.0.0.5:3306/sportsbook", "map": "ledger-map.json"},
    },
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _append_jsonl(path: str, obj) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, default=str) + "\n")


def _write_json(path: str, obj) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, default=str)
    os.replace(tmp, path)


class Config:
    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self.base = os.path.dirname(self.path)
        with open(self.path, "r", encoding="utf-8") as fh:
            self.raw = json.load(fh)
        self.name = self.raw.get("name") or "AEGIS guard"
        self.out = self.p(self.raw.get("out") or "guard-state")
        self.auth = self.raw.get("authorization") or {}
        self.alerts = self.raw.get("alerts") or {}
        self.modules = {k: v for k, v in (self.raw.get("modules") or {}).items() if v and v.get("enabled", True)}

    def p(self, v):
        """Resolve a path relative to the config file (URLs / connection strings untouched)."""
        if not v or not isinstance(v, str) or "://" in v or ";" in v:
            return v
        return v if os.path.isabs(v) else os.path.normpath(os.path.join(self.base, v))

    def mod(self, name: str) -> dict:
        m = dict(self.modules.get(name) or {})
        for k in ("db", "map", "statement", "callbacks", "allow_ips"):
            if m.get(k):
                m[k] = self.p(m[k])
        m["app_dirs"] = [self.p(x) for x in m.get("app_dirs") or []]
        m["web_roots"] = [self.p(x) for x in m.get("web_roots") or []]
        return m


def newest_statement(path: str | None) -> str | None:
    if not path or not os.path.isdir(path):
        return path
    files = sorted(glob.glob(os.path.join(path, "*.csv")), key=os.path.getmtime)
    return files[-1] if files else None


# ---------------------------------------------------------------------------
def diff(module: str, prev: dict | None, res: dict) -> list[dict]:
    """New / resolved cases for one module, from stable case keys."""
    events = []
    cur = res.get("case_keys") or {}
    by = {f["code"]: f for f in res.get("module_findings") or []}
    baseline = prev is None
    prev = prev or {}
    for code, keys in cur.items():
        fresh = [k for k in keys if k not in set(prev.get(code) or [])]
        if not fresh:
            continue
        f = by.get(code, {})
        events.append({"module": module, "severity": f.get("severity", "MEDIUM"),
                       "kind": "BASELINE" if baseline else "NEW", "code": code, "title": f.get("title", code),
                       "count": len(fresh), "cases": fresh[:25], "money_at_risk_all_open": f.get("money_at_risk"),
                       "evidence": (f.get("samples") or [])[:5],
                       "message": (f"{len(fresh)} case(s) present when monitoring started" if baseline
                                   else f"{len(fresh)} NEW case(s) since the last cycle")})
    for code, keys in prev.items():
        gone = [k for k in keys if k not in set(cur.get(code) or [])]
        if not gone:
            continue
        crit = code in {"FORGED_CREDIT", "CREDIT_EXCEEDS_PAID", "FAILED_PAYMENT_CREDITED",
                        "WITHDRAWAL_PAID_AND_REFUNDED", "PAYOUT_WITHOUT_WALLET_DEBIT"}
        events.append({"module": module, "severity": "MEDIUM" if crit else "INFO", "kind": "RESOLVED", "code": code,
                       "title": code, "count": len(gone), "cases": gone[:25],
                       "message": (f"{len(gone)} case(s) no longer appear - confirm each was closed by a documented "
                                   "correction (a money problem that vanishes without one may mean a record was edited)"
                                   if crit else f"{len(gone)} case(s) no longer appear")})
    return events


def _blind(module: str, why: str) -> dict:
    return {"module": module, "severity": "HIGH", "kind": "MODULE_BLIND", "code": "MODULE_BLIND",
            "title": f"{module} could not run",
            "message": f"{why}. Until this is fixed, this part of the system is not being watched."}


# ---------------------------------------------------------------------------
def _authorizer(cfg: Config, machine: str):
    """Signed scope (unattended), or an --acknowledge auto-scope pinned to this config's sources."""
    from .dbcli import _session
    actions = {"ledger": ["db-identify", "ledger-readonly"], "mpesa": ["mpesa-readonly"],
               "host": ["host-checkup"], "tamper": ["tamper-watch"]}
    acts = sorted({a for m in cfg.modules for a in actions.get(m, [])})
    sources, paths = [], []
    for name in cfg.modules:
        m = cfg.mod(name)
        for k in ("db", "statement", "callbacks"):
            if m.get(k):
                sources.append(newest_statement(m[k]) if k == "statement" else m[k])
    tb = os.path.join(cfg.out, "tamper", "tamper-baseline.json")
    if "tamper" in cfg.modules and os.path.exists(tb):
        with open(tb, "r", encoding="utf-8") as fh:
            paths = json.load(fh).get("paths") or []
    ns = argparse.Namespace(out=cfg.out, operator=cfg.raw.get("operator") or None,
                            scope=cfg.p(cfg.auth.get("scope")) if cfg.auth.get("scope") else None,
                            key_file=cfg.p(cfg.auth.get("key_file")) if cfg.auth.get("key_file") else None,
                            acknowledge=cfg.auth.get("acknowledge") or None, client=cfg.name)
    if ns.scope and not os.path.exists(ns.scope):
        print(f"scope file not found: {ns.scope}", file=sys.stderr)
        return None
    return _session(ns, [s for s in sources if s], acts, extra_scope={"servers": [machine], "paths": paths})


def run_ledger(cfg: Config, authz, sink: list) -> None:
    from .watch import cycle
    m = cfg.mod("ledger")
    with open(m["map"], "r", encoding="utf-8") as fh:
        mapping = json.load(fh)
    ns = argparse.Namespace(db=m["db"], out=cfg.out, since=m.get("since"), webhook=None, alert_level="HIGH",
                            schema=m.get("schema"), password_env=cfg.raw.get("password_env") or "AEGIS_DB_PASSWORD",
                            ask_password=False, sink=[])
    cycle(ns, authz, mapping)
    for e in ns.sink:
        e.setdefault("module", "ledger")
        if e.get("kind") == "WATCHDOG_BLIND":
            e["kind"] = e["code"] = "MODULE_BLIND"
    sink.extend(ns.sink)


def _module_result(cfg: Config, name: str, authz):
    """Run one non-ledger module; returns its result dict (with case_keys)."""
    from .db.connect import open_readonly
    pw = os.environ.get(cfg.raw.get("password_env") or "AEGIS_DB_PASSWORD")
    m = cfg.mod(name)
    if name == "mpesa":
        from .checks.mpesa import run_mpesa
        from .insidecli import _allowlist
        stmt = newest_statement(m.get("statement"))
        if m.get("statement") and not stmt:
            raise FileNotFoundError(f"no statement .csv found in {m['statement']}")
        mapping = None
        if m.get("map"):
            with open(m["map"], "r", encoding="utf-8") as fh:
                mapping = json.load(fh)
        cbt = ({"table": m["callbacks_table"], "payload_col": m.get("payload_col") or "payload",
                "ip_col": m.get("ip_col"), "ts_col": m.get("received_col")} if m.get("callbacks_table") else None)
        db = open_readonly(m["db"], password=pw, schema=m.get("schema")) if m.get("db") else None
        try:
            return run_mpesa(authz, statement=stmt, callbacks=m.get("callbacks"), db=db, mapping=mapping,
                             callbacks_table=cbt, allow=_allowlist(m.get("allow_ips")))
        finally:
            if db is not None:
                db.close()
    if name == "host":
        from .checks.host import run_host
        return run_host(authz, root=m.get("root"), app_dirs=m["app_dirs"], web_roots=m["web_roots"])
    if name == "tamper":
        from .checks.tamper import run_check
        state = os.path.join(cfg.out, "tamper")
        if not os.path.exists(os.path.join(state, "tamper-baseline.json")):
            raise FileNotFoundError(f"no tamper baseline yet - run `aegis tamper baseline --path ... --out {state}` "
                                    "(with the same authorization) first")
        db = open_readonly(m["db"], password=pw, schema=m.get("schema")) if m.get("db") else None
        try:
            # The tamper anchor lives in the tamper state folder's own audit log.
            from .audit import AuditLog
            from .authz import Authorizer
            t_audit = AuditLog(os.path.join(state, "audit.jsonl"), authz.audit.operator, authz.audit.engagement_id)
            t_authz = Authorizer(authz.scope, t_audit, authz.signature_verified)
            res = run_check(t_authz, socket.gethostname().lower(), state, db=db,
                            key=os.environ.get("AEGIS_TAMPER_KEY"))
            if res.get("authorized"):
                authz.audit.append("check", action="tamper-watch", target=res["target"], decision="DONE",
                                   detail={k: v for k, v in res.items() if k != "case_keys"})
            return res
        finally:
            if db is not None:
                db.close()
    raise ValueError(f"unknown module {name!r}")


def cycle(cfg: Config, authz, alert_level: str, webhook: str | None) -> int:
    from .report import build_markdown
    machine = socket.gethostname().lower()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    print(f"\n{TOOL_NAME} {__version__} guard - {cfg.name} - run {run_id}")
    pre = authz.preflight()
    if not pre:
        ev = {"severity": "HIGH", "kind": "AUTHORIZATION_ENDED", "module": "guard",
              "message": f"Guard stopped: {pre.reason}"}
        _append_jsonl(os.path.join(cfg.out, "guard-alerts.jsonl"), dict(ev, run=run_id, at=_now()))
        print(f"  {ev['message']}")
        if webhook:
            from .watch import _webhook
            print(f"  webhook: {_webhook(webhook, run_id, cfg.name, [ev], title='guard')}")
        return 2

    state_path = os.path.join(cfg.out, "guard-state.json")
    try:
        with open(state_path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        state = {"modules": {}}
    events: list[dict] = []
    summary = {}
    for name in ("ledger", "mpesa", "host", "tamper"):
        if name not in cfg.modules:
            continue
        t0 = time.time()
        print(f"  - {name} ...", flush=True)
        try:
            if name == "ledger":
                before = len(events)
                run_ledger(cfg, authz, events)
                summary[name] = {"seconds": round(time.time() - t0, 1),
                                 "events": len(events) - before}
                continue
            res = _module_result(cfg, name, authz)
        except Exception as e:  # noqa: BLE001 - a broken module must not stop the others
            ev = _blind(name, f"{type(e).__name__}: {e}")
            events.append(ev)
            authz.audit.append("note", action="guard", target=name, decision="ALERT", detail={"run": run_id, "event": ev})
            summary[name] = {"error": str(e)}
            continue
        if not res.get("authorized"):
            ev = _blind(name, f"not authorized: {res.get('reason')}")
            events.append(ev)
            summary[name] = {"error": res.get("reason")}
            continue
        prev = (state.get("modules") or {}).get(name)
        evs = diff(name, prev, res)
        events.extend(evs)
        state.setdefault("modules", {})[name] = res.get("case_keys") or {}
        with open(os.path.join(cfg.out, f"{name}-results.json"), "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=1, default=str)
        summary[name] = {"seconds": round(time.time() - t0, 1),
                         "open": {f["code"]: f["count"] for f in res.get("module_findings") or []},
                         "events": len(evs)}

    events.sort(key=lambda e: SEV_RANK.get(e["severity"], 9))
    state.update({"aegis_guard_state": 1, "last_run": run_id, "config": cfg.path})
    _write_json(state_path, state)
    for e in events:
        _append_jsonl(os.path.join(cfg.out, "guard-alerts.jsonl"), dict(e, run=run_id, at=_now()))
    _append_jsonl(os.path.join(cfg.out, "guard-history.jsonl"), {"run": run_id, "at": _now(), "modules": summary})
    alerting = [e for e in events if SEV_RANK.get(e["severity"], 9) <= SEV_RANK[alert_level]]
    authz.audit.append("note", action="guard", target=cfg.name, decision="ALERT" if alerting else "QUIET",
                       detail={"run": run_id, "modules": summary,
                               "events": [{k: e.get(k) for k in ("module", "severity", "kind", "code", "count", "cases")}
                                          for e in events]})
    with open(os.path.join(cfg.out, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(build_markdown(os.path.join(cfg.out, "audit.jsonl")))

    if not events:
        print("  quiet - nothing new")
    for e in events:
        print(f"  [{e['severity']:<8}] {e.get('module', '')}: {e.get('title') or e['kind']} - {e['message']}")
    if alerting and webhook:
        from .watch import _webhook
        r = _webhook(webhook, run_id, cfg.name, alerting, title="guard")
        authz.audit.append("note", action="guard-alert", target=urllib.parse.urlparse(webhook).hostname or "",
                           decision="INFO", detail={"run": run_id, "delivery": r})
        print(f"  webhook: {r}")
    print(f"  report -> {os.path.join(cfg.out, 'report.md')}")
    if any(e["kind"] == "MODULE_BLIND" for e in events):
        return 4
    return 3 if any(e["severity"] == "CRITICAL" and e["kind"] in ("NEW", "BASELINE") for e in events) else 0


# ---------------------------------------------------------------------------
def cmd_init(args) -> int:
    if os.path.exists(args.save) and not args.force:
        print(f"refusing to overwrite {args.save} (use --force)", file=sys.stderr)
        return 2
    with open(args.save, "w", encoding="utf-8") as fh:
        json.dump(TEMPLATE, fh, indent=2)
    print(f"wrote {args.save} - fill in the paths, disable modules you don't use, then:")
    print(f"  python -m aegis guard run --config {args.save}")
    return 0


def cmd_run(args) -> int:
    cfg = Config(args.config)
    os.makedirs(cfg.out, exist_ok=True)
    if not cfg.modules:
        print("no modules enabled in the config", file=sys.stderr)
        return 2
    level = args.alert_level or cfg.alerts.get("alert_level") or "HIGH"
    if level not in SEV_RANK:
        print(f"alert level must be one of {', '.join(SEV_RANK)}", file=sys.stderr)
        return 2
    machine = socket.gethostname().lower()
    authz = _authorizer(cfg, machine)
    if not authz:
        return 2
    if args.every and not cfg.auth.get("scope"):
        print("note: running on 'acknowledge' - that lasts 24 hours, then the guard stops. Use a signed scope for "
              "unattended running.")
    webhook = cfg.alerts.get("webhook") or None
    runs, code = 0, 0
    try:
        while True:
            code = cycle(cfg, authz, level, webhook)
            runs += 1
            if code == 2 or not args.every or (args.max_runs and runs >= args.max_runs):
                return code
            print(f"  next cycle in {args.every} minute(s) - Ctrl+C to stop")
            time.sleep(args.every * 60)
    except KeyboardInterrupt:
        authz.audit.append("note", action="guard", target=cfg.name, decision="INFO",
                           detail={"stopped": "by operator (Ctrl+C)", "runs": runs})
        print("\nguard stopped by operator")
        return code


def cmd_schedule(args) -> int:
    from . import build_info
    cfg = os.path.abspath(args.config)
    py = sys.executable
    b = build_info()
    if b["kind"] == "pyz":                     # single-file release: run the .pyz directly
        here = os.path.dirname(b["location"])
        launch = f"{py} {b['location']}"
    else:
        here = os.path.dirname(b["location"])
        launch = f"{py} -m aegis"
    every = args.every
    user = getpass.getuser()
    print("Run one guard cycle on a timer. Pick the block for the client's server. Nothing below has been executed.\n")
    print("== Linux, systemd (recommended): save as /etc/systemd/system/aegis-guard.service and .timer ==")
    print(f"""[Unit]
Description=AEGIS guard (read-only money and server watchdog)
After=network-online.target

[Service]
Type=oneshot
User=aegis
WorkingDirectory={here}
EnvironmentFile=/etc/aegis/aegis.env
ExecStart={launch} guard run --config {cfg}
SuccessExitStatus=0 3 4
""")
    print(f"""[Unit]
Description=Run AEGIS guard every {every} minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec={every}min
Persistent=true

[Install]
WantedBy=timers.target
""")
    print("  then: systemctl daemon-reload && systemctl enable --now aegis-guard.timer")
    print("  /etc/aegis/aegis.env (chmod 600, owner aegis) holds AEGIS_DB_PASSWORD=... "
          "(NOT AEGIS_TAMPER_KEY - the seal key stays with the assessor)\n")
    print("== Linux, cron ==")
    print(f"*/{every} * * * * cd {here} && {launch} guard run --config {cfg} >> /var/log/aegis-guard.log 2>&1\n"
          if every < 60 else
          f"0 */{max(1, every // 60)} * * * cd {here} && {launch} guard run --config {cfg} >> /var/log/aegis-guard.log 2>&1\n")
    print("== Windows Task Scheduler (run in an elevated prompt) ==")
    tr = (f'\\"{py}\\" \\"{b["location"]}\\"' if b["kind"] == "pyz" else f'\\"{py}\\" -m aegis')
    print(f'schtasks /Create /TN "AEGIS guard" /SC MINUTE /MO {every} /RU "{user}" '
          f'/TR "{tr} guard run --config \\"{cfg}\\"" /F')
    print(f"  (working directory must be {here}; set AEGIS_DB_PASSWORD as a machine environment variable "
          "or use a credential-manager wrapper)")
    return 0


def register(sub) -> None:
    g = sub.add_parser("guard", help="the installed product: run every inside module on a schedule, one combined alert")
    gs = g.add_subparsers(dest="guardcmd", required=True)

    s = gs.add_parser("init", help="write a guard config to fill in")
    s.add_argument("--save", default="aegis-guard.json")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)

    s = gs.add_parser("run", help="run one cycle (or keep running with --every)")
    s.add_argument("--config", required=True)
    s.add_argument("--every", type=float, default=0, help="minutes between cycles; 0 = one cycle (for schedulers)")
    s.add_argument("--max-runs", type=int, default=0)
    s.add_argument("--alert-level", help="lowest severity sent to the webhook (default from config, else HIGH)")
    s.set_defaults(func=cmd_run)

    s = gs.add_parser("schedule", help="print systemd / cron / Task Scheduler entries for this config")
    s.add_argument("--config", required=True)
    s.add_argument("--every", type=int, default=60, help="minutes between cycles (default 60)")
    s.set_defaults(func=cmd_schedule)
