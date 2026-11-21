"""
Build a populated guard state folder from the demo data, for `aegis ui --demo`.

Three guard cycles over the demo sportsbook: the first is the baseline (planted problems
already present), the second is quiet, then a forged M-Pesa deposit and a change to the
settlement code are planted and the third cycle alerts on exactly those.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3


def build(work: str, log=print) -> str:
    from .selftest import _cli
    ack = ("--acknowledge", "DEMO - no real client data")
    os.makedirs(work, exist_ok=True)
    demo = os.path.join(work, "demo")
    log("  building demo sportsbook, M-Pesa statement and callbacks ...")
    _cli("demo-ledger", "--out", demo)
    db_src = os.path.join(demo, "demo_sportsbook.db")
    _cli("db", "map", db_src, "--out", os.path.join(work, "map"), *ack)
    mp = os.path.join(work, "map", "ledger-map.json")
    m = json.load(open(mp, encoding="utf-8"))
    m["reviewed_by"] = "Demo Approver, CTO (demo)"
    json.dump(m, open(mp, "w", encoding="utf-8"), indent=2)

    db = os.path.join(work, "sportsbook.db")
    shutil.copy(db_src, db)
    stmts = os.path.join(work, "statements")
    os.makedirs(stmts, exist_ok=True)
    shutil.copy(os.path.join(demo, "mpesa", "statement.csv"), os.path.join(stmts, "statement-2026-11-14.csv"))
    cbs = os.path.join(work, "callbacks.jsonl")
    shutil.copy(os.path.join(demo, "mpesa", "callbacks.jsonl"), cbs)

    app = os.path.join(work, "app")
    seed = {"app/Services/SettlementService.php": "<?php function settle($b){return $b->stake*$b->odds;}\n",
            "app/Services/MpesaCallbackController.php": "<?php // validates Daraja callbacks\n",
            "app/Http/Kernel.php": "<?php class Kernel {}\n", "config/app.yml": "name: demo-sportsbook\n",
            ".env": "MPESA_CALLBACK_URL=https://sportsbook.example/api/mpesa/callback\n",
            "public/index.php": "<?php require '../bootstrap.php';\n", "public/uploads/logo.png": "PNG"}
    for p, t in seed.items():
        os.makedirs(os.path.dirname(os.path.join(app, p)), exist_ok=True)
        with open(os.path.join(app, p), "w", encoding="utf-8") as fh:
            fh.write(t)

    state = os.path.join(work, "state")
    cfg = {"name": "Demo Sportsbook Ltd (DEMO DATA)", "out": state,
           "authorization": {"acknowledge": "DEMO - no real client data"},
           "alerts": {"webhook": "", "alert_level": "HIGH"},
           "modules": {"ledger": {"db": db, "map": mp},
                       "mpesa": {"statement": stmts, "callbacks": cbs, "db": db, "map": mp},
                       "host": {"root": os.path.join(demo, "demo-server")},
                       "tamper": {"db": db, "map": mp}}}
    _cli("demo-host", "--out", demo)
    cfgp = os.path.join(work, "aegis-guard.json")
    json.dump(cfg, open(cfgp, "w", encoding="utf-8"), indent=2)

    log("  taking the change-alarm baseline ...")
    _cli("tamper", "baseline", "--path", app, "--db", db, "--map", mp, "--out", os.path.join(state, "tamper"),
         "--by", "Demo Approver, CTO", "--note", "go-live baseline", *ack)
    log("  guard cycle 1 (baseline) and 2 (quiet) ...")
    _cli("guard", "run", "--config", cfgp)
    _cli("guard", "run", "--config", cfgp)

    log("  planting a forged M-Pesa deposit and a settlement-code change, cycle 3 ...")
    with open(cbs, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"received_at": "2026-11-02 10:00:00", "source_ip": "102.68.1.1", "payload": {
            "TransactionType": "Pay Bill", "TransID": "SFORGED999", "TransTime": "20261102100000",
            "TransAmount": "50000.00", "BusinessShortCode": "600981", "BillRefNumber": "P1020",
            "MSISDN": "254700000001"}}) + "\n")
    c = sqlite3.connect(db)
    c.execute("INSERT INTO wallet_ledger VALUES (999001, 'P1020', '50000.00', 'DEPOSIT_MPESA', NULL, 'SFORGED999', "
              "'2026-11-02 10:00:05')")
    c.execute("UPDATE punter_wallets SET balance = balance + 50000 WHERE punter_id = 'P1020'")
    c.commit()
    c.close()
    with open(os.path.join(app, "app/Services/SettlementService.php"), "a", encoding="utf-8") as fh:
        fh.write("// if ($b->user == 'P1005') return $b->stake * 50;\n")
    _cli("guard", "run", "--config", cfgp)
    return state
