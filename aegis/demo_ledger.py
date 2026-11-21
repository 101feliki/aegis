"""
Build a realistic DEMO sportsbook database with known, planted money bugs.

It deliberately uses vendor-style names (sb_bet_slips, wallet_ledger,
punter_wallets, 'SLIP-123' references, positive-only amounts) so the schema
mapper has to work for it - just like a real white-label install.

Writes:
    <out>/demo_sportsbook.db      SQLite
    <out>/csv_export/*.csv        the same data as a CSV export

PLANTED is the answer key: the watchdog should find exactly these.
"""
from __future__ import annotations

import csv
import json
import os
import random
import sqlite3
from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal

PLANTED = {
    "PAID_ON_LOSS": 2, "DUPLICATE_PAYOUT": 1, "OVERPAYMENT": 1, "DUPLICATE_RECEIPT": 1,
    "PAID_WRONG_ACCOUNT": 1, "PAID_BEFORE_RESULT": 1, "ORPHAN_PAYOUT": 1, "VOID_OVERPAID": 1,
    "BALANCE_DRIFT": 1, "RECORD_INFLATED": 1, "PAID_BEFORE_SETTLE": 1, "WON_NOT_PAID": 1,
}


def _q(x: Decimal) -> Decimal:
    return x.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _receipt(rng: random.Random) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"
    return "S" + "".join(rng.choice(alphabet) for _ in range(9))


def build(out_dir: str, n_bets: int = 400, seed: int = 7) -> str:
    rng = random.Random(seed)
    os.makedirs(out_dir, exist_ok=True)
    db_path = os.path.join(out_dir, "demo_sportsbook.db")
    if os.path.exists(db_path):
        os.remove(db_path)

    punters = [f"P{1000 + i}" for i in range(max(60, n_bets // 25))]
    spacing = timedelta(days=45) / n_bets          # all bets placed within ~45 days
    t0 = datetime(2026, 10, 1, 8, 0, 0)
    bets, ledger = [], []
    txn_no = [100000]

    def tx(punter, amount, ttype, ref="", receipt="", when=None):
        txn_no[0] += 1
        ledger.append({"txn_id": txn_no[0], "punter_id": punter, "amount": _q(Decimal(amount)),
                       "txn_type": ttype, "reference": ref, "mpesa_receipt": receipt,
                       "created_on": when or t0})
        return ledger[-1]

    # Opening deposits.
    for p in punters:
        tx(p, rng.choice([2000, 5000, 10000, 20000]), "DEPOSIT_MPESA", receipt=_receipt(rng),
           when=t0 - timedelta(days=rng.randint(1, 5)))

    for i in range(n_bets):
        sid = 50000 + i
        p = rng.choice(punters)
        placed = t0 + spacing * i + timedelta(seconds=rng.randint(0, 60))
        stake = _q(Decimal(rng.choice([50, 100, 200, 500, 1000])))
        odds = Decimal(str(round(rng.uniform(1.2, 9.5), 2)))
        status = rng.choices(["WON", "LOST", "VOID", "OPEN", "CASHOUT"], [30, 55, 5, 5, 5])[0]
        settled = placed + timedelta(hours=rng.randint(2, 30)) if status != "OPEN" else None
        win = _q(stake * odds) if status == "WON" else (_q(stake * odds * Decimal("0.6")) if status == "CASHOUT"
                                                        else Decimal("0"))
        bets.append({"slip_id": sid, "punter_id": p, "stake_amount": stake, "total_odds": odds,
                     "slip_status": status, "win_amount": win, "possible_win": _q(stake * odds),
                     "settled_on": settled, "created_on": placed})
        tx(p, stake, "BET_PLACED", ref=f"SLIP-{sid}", when=placed)
        if status in ("WON", "CASHOUT"):
            tx(p, win, "BET_WIN", ref=f"SLIP-{sid}", when=settled + timedelta(seconds=rng.randint(5, 90)))
        elif status == "VOID":
            tx(p, stake, "BET_REFUND", ref=f"SLIP-{sid}", when=settled)
        if rng.random() < 0.15:
            tx(p, rng.choice([500, 1000, 2000]), "DEPOSIT_MPESA", receipt=_receipt(rng), when=placed)
        if rng.random() < 0.05:
            tx(p, 100, "BONUS_CREDIT", when=placed)
        if rng.random() < 0.08:
            tx(p, rng.choice([300, 800]), "WITHDRAW_B2C", when=placed + timedelta(hours=1))

    by_status = lambda s: [b for b in bets if b["slip_status"] == s]  # noqa: E731
    win_tx = {r["reference"]: r for r in ledger if r["txn_type"] == "BET_WIN"}
    won = by_status("WON")
    rng.shuffle(won)
    won.sort(key=lambda b: b["settled_on"])        # earliest first (WON_NOT_PAID needs an old one)
    lost, void, open_ = by_status("LOST"), by_status("VOID"), by_status("OPEN")
    late = datetime(2026, 11, 18, 12, 0)

    # ---- plant the bugs ---------------------------------------------------
    for b in lost[:2]:                                                            # PAID_ON_LOSS x2
        tx(b["punter_id"], _q(b["stake_amount"] * b["total_odds"]), "BET_WIN",
           ref=f"SLIP-{b['slip_id']}", when=b["settled_on"] + timedelta(minutes=3))
    b = won[5]                                                                    # DUPLICATE_PAYOUT
    orig = win_tx[f"SLIP-{b['slip_id']}"]
    tx(b["punter_id"], orig["amount"], "BET_WIN", ref=orig["reference"], when=orig["created_on"] + timedelta(seconds=2))
    b = won[6]                                                                    # OVERPAYMENT
    win_tx[f"SLIP-{b['slip_id']}"]["amount"] = _q(win_tx[f"SLIP-{b['slip_id']}"]["amount"] * 3)
    dep = next(r for r in ledger if r["txn_type"] == "DEPOSIT_MPESA" and r["created_on"] > t0)  # DUPLICATE_RECEIPT
    tx(dep["punter_id"], dep["amount"], "DEPOSIT_MPESA", receipt=dep["mpesa_receipt"],
       when=dep["created_on"] + timedelta(seconds=40))
    b = won[7]                                                                    # PAID_WRONG_ACCOUNT
    other = next(p for p in punters if p != b["punter_id"])
    win_tx[f"SLIP-{b['slip_id']}"]["punter_id"] = other
    b = open_[0]                                                                  # PAID_BEFORE_RESULT
    tx(b["punter_id"], _q(b["stake_amount"] * b["total_odds"]), "BET_WIN", ref=f"SLIP-{b['slip_id']}",
       when=b["created_on"] + timedelta(minutes=20))
    tx(punters[3], 15000, "BET_WIN", ref=f"SLIP-{50000 + n_bets + 99999}", when=late)  # ORPHAN_PAYOUT (no such slip)
    b = void[0]                                                                   # VOID_OVERPAID
    tx(b["punter_id"], b["stake_amount"], "BET_REFUND", ref=f"SLIP-{b['slip_id']}",
       when=b["settled_on"] + timedelta(minutes=1))
    b = won[8]                                                                    # RECORD_INFLATED
    b["win_amount"] = _q(b["win_amount"] * 2)
    b = won[0]                                                                    # WON_NOT_PAID
    ledger.remove(win_tx[f"SLIP-{b['slip_id']}"])
    b = won[9]                                                                    # PAID_BEFORE_SETTLE
    win_tx[f"SLIP-{b['slip_id']}"]["created_on"] = b["settled_on"] - timedelta(hours=3)

    # ---- M-Pesa side: statement + callback log, with planted fraud -----------
    # Separate RNG so the ledger above is byte-for-byte what it was before.
    mp = _mpesa_side(random.Random(seed + 1), ledger, punters, tx, t0, t0 + timedelta(days=45))

    # Balances = what the ledger says...
    bal = {p: Decimal("0") for p in punters}
    sign = {"DEPOSIT_MPESA": 1, "BET_WIN": 1, "BET_REFUND": 1, "BONUS_CREDIT": 1,
            "BET_PLACED": -1, "WITHDRAW_B2C": -1, "WITHDRAW_REVERSAL": 1}
    for r in ledger:
        bal[r["punter_id"]] += sign[r["txn_type"]] * r["amount"]
    bal[punters[11]] += Decimal("50000")                                          # ...except BALANCE_DRIFT

    ledger.sort(key=lambda r: r["created_on"])

    # ---- write SQLite -----------------------------------------------------
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE punters (punter_id TEXT PRIMARY KEY, msisdn TEXT, full_name TEXT, kyc_level INTEGER,
                              registered_on TEXT);
        CREATE TABLE sb_events (event_id INTEGER PRIMARY KEY, sport TEXT, home TEXT, away TEXT, kickoff TEXT);
        CREATE TABLE sb_bet_slips (slip_id INTEGER PRIMARY KEY, punter_id TEXT, stake_amount NUMERIC,
                                   total_odds NUMERIC, slip_status TEXT, win_amount NUMERIC,
                                   possible_win NUMERIC, settled_on TEXT, created_on TEXT);
        CREATE TABLE wallet_ledger (txn_id INTEGER PRIMARY KEY, punter_id TEXT, amount NUMERIC,
                                    txn_type TEXT, reference TEXT, mpesa_receipt TEXT, created_on TEXT);
        CREATE TABLE punter_wallets (punter_id TEXT PRIMARY KEY, balance NUMERIC, currency TEXT,
                                     updated_on TEXT);
    """)
    fmt = lambda d: d.strftime("%Y-%m-%d %H:%M:%S") if d else None  # noqa: E731
    conn.executemany("INSERT INTO punters VALUES (?,?,?,?,?)",
                     [(p, f"2547{rng.randint(10000000, 99999999)}", f"Demo Punter {i}", rng.randint(1, 3),
                       "2026-01-01") for i, p in enumerate(punters)])
    conn.executemany("INSERT INTO sb_events VALUES (?,?,?,?,?)",
                     [(i, "football", f"Home {i}", f"Away {i}", "2026-10-01") for i in range(20)])
    conn.executemany("INSERT INTO sb_bet_slips VALUES (?,?,?,?,?,?,?,?,?)",
                     [(b["slip_id"], b["punter_id"], str(b["stake_amount"]), str(b["total_odds"]),
                       b["slip_status"], str(b["win_amount"]), str(b["possible_win"]),
                       fmt(b["settled_on"]), fmt(b["created_on"])) for b in bets])
    conn.executemany("INSERT INTO wallet_ledger VALUES (?,?,?,?,?,?,?)",
                     [(r["txn_id"], r["punter_id"], str(r["amount"]), r["txn_type"], r["reference"] or None,
                       r["mpesa_receipt"] or None, fmt(r["created_on"])) for r in ledger])
    conn.executemany("INSERT INTO punter_wallets VALUES (?,?,?,?)",
                     [(p, str(v), "KES", "2026-11-19") for p, v in bal.items()])
    conn.commit()

    # ---- CSV export of the same data -------------------------------------
    csv_dir = os.path.join(out_dir, "csv_export")
    os.makedirs(csv_dir, exist_ok=True)
    for (t,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
        cur = conn.execute(f'SELECT * FROM "{t}"')
        with open(os.path.join(csv_dir, f"{t}.csv"), "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow([d[0] for d in cur.description])
            w.writerows(cur.fetchall())
    conn.close()
    _write_mpesa(os.path.join(out_dir, "mpesa"), mp)
    return db_path


# ---------------------------------------------------------------------------
# M-Pesa demo: org statement + Daraja callback log
# ---------------------------------------------------------------------------
PLANTED_MPESA = {
    "FORGED_CREDIT": 1, "CREDIT_EXCEEDS_PAID": 2, "FAILED_PAYMENT_CREDITED": 1,
    "WITHDRAWAL_PAID_AND_REFUNDED": 1, "PAYOUT_WITHOUT_WALLET_DEBIT": 1, "FAKE_CALLBACK": 1,
    "CALLBACK_AMOUNT_MISMATCH": 1, "CALLBACK_FROM_UNKNOWN_SOURCE": 1, "REPLAYED_CALLBACK": 1,
    "PAID_NOT_CREDITED": 1, "WITHDRAWAL_FAILED_NOT_REFUNDED": 1,
}
SAF_IPS = ["196.201.214.200", "196.201.214.206", "196.201.213.114", "196.201.214.207"]
SHORTCODE = "600981"


def _d14(d: datetime) -> str:
    return d.strftime("%Y%m%d%H%M%S")


def _stk(rng, receipt, amount, phone, when, result=0, desc="The service request is processed successfully."):
    co = f"ws_CO_{_d14(when)}{rng.randint(100000, 999999)}"
    s = {"MerchantRequestID": f"{rng.randint(10000, 99999)}-{rng.randint(1000000, 9999999)}-1",
         "CheckoutRequestID": co, "ResultCode": result, "ResultDesc": desc}
    if result == 0:
        s["CallbackMetadata"] = {"Item": [{"Name": "Amount", "Value": float(amount)},
                                          {"Name": "MpesaReceiptNumber", "Value": receipt},
                                          {"Name": "Balance"},
                                          {"Name": "TransactionDate", "Value": int(_d14(when))},
                                          {"Name": "PhoneNumber", "Value": int(phone)}]}
    return {"Body": {"stkCallback": s}}, co


def _c2b(receipt, amount, phone, when, account):
    return {"TransactionType": "Pay Bill", "TransID": receipt, "TransTime": _d14(when),
            "TransAmount": f"{amount:.2f}", "BusinessShortCode": SHORTCODE, "BillRefNumber": account,
            "InvoiceNumber": "", "OrgAccountBalance": "", "ThirdPartyTransID": "",
            "MSISDN": phone, "FirstName": "DEMO"}


def _b2c(orig_conv, conv, result, receipt=None, amount=None, desc=None):
    r = {"ResultType": 0, "ResultCode": result, "OriginatorConversationID": orig_conv, "ConversationID": conv,
         "TransactionID": receipt or "", "ResultDesc": desc or ("The service request is processed successfully."
                                                               if result == 0 else "The initiator information is invalid.")}
    if result == 0:
        r["ResultParameters"] = {"ResultParameter": [
            {"Key": "TransactionAmount", "Value": float(amount)}, {"Key": "TransactionReceipt", "Value": receipt},
            {"Key": "B2CRecipientIsRegisteredCustomer", "Value": "Y"},
            {"Key": "ReceiverPartyPublicName", "Value": "2547XXXXXXXX - DEMO"}]}
    return {"Result": r}


def _mpesa_side(rng, ledger, punters, tx, t0, t_end) -> dict:
    phone = {p: f"2547{rng.randint(10000000, 99999999)}" for p in punters}
    stmt, cbs = [], []                           # statement rows / callback records

    def cb(payload, when, ip=None):
        cbs.append({"received_at": (when + timedelta(seconds=rng.randint(1, 4))).strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": ip or rng.choice(SAF_IPS), "payload": payload})

    def paid_in(rc, amt, p, when, details=None, reason="Pay Bill Online"):
        stmt.append({"Receipt No.": rc, "Completion Time": when, "Details": details or
                     f"Pay Bill from {phone.get(p, '254700000000')} - DEMO PUNTER Acc. {p}",
                     "Transaction Status": "Completed", "Paid In": f"{amt:,.2f}", "Withdrawn": "",
                     "Reason Type": reason, "Other Party Info": phone.get(p, ""), "A/C No.": p})

    def paid_out(rc, amt, p, when, details=None, reason="Business Payment to Customer via API"):
        stmt.append({"Receipt No.": rc, "Completion Time": when, "Details": details or
                     f"Business Payment to {phone.get(p, '254700000000')} - DEMO PUNTER",
                     "Transaction Status": "Completed", "Paid In": "", "Withdrawn": f"-{amt:,.2f}",
                     "Reason Type": reason, "Other Party Info": phone.get(p, ""), "A/C No.": ""})

    def deposit_callback(rc, amt, p, when, ip=None, amount_claimed=None):
        if rng.random() < 0.5:
            payload, _ = _stk(rng, rc, amount_claimed or amt, phone[p], when)
        else:
            payload = _c2b(rc, amount_claimed or amt, phone[p], when, p)
        cb(payload, when, ip)

    # Genuine traffic: every deposit was really paid; every withdrawal really paid out.
    seen = set()
    for r in list(ledger):
        p, amt, when = r["punter_id"], r["amount"], r["created_on"]
        if r["txn_type"] == "DEPOSIT_MPESA":
            rc = r["mpesa_receipt"]
            if rc in seen:                       # ledger's planted DUPLICATE_RECEIPT: paid once, credited twice
                deposit_callback(rc, amt, p, when - timedelta(seconds=5))   # ...and the callback was replayed
                continue
            seen.add(rc)
            paid_in(rc, amt, p, when - timedelta(seconds=5))
            deposit_callback(rc, amt, p, when - timedelta(seconds=5))
        elif r["txn_type"] == "WITHDRAW_B2C":
            rc = _receipt(rng)
            orig = f"{rng.randint(10000, 99999)}-{rng.randint(1000000, 9999999)}-1"
            r["mpesa_receipt"], r["reference"] = rc, orig
            done = when + timedelta(seconds=30)
            paid_out(rc, amt, p, done)
            stmt.append({"Receipt No.": rc, "Completion Time": done, "Details": "Business Payment Charge",
                         "Transaction Status": "Completed", "Paid In": "", "Withdrawn": "-15.27",
                         "Reason Type": "Business Payment Charge", "Other Party Info": "", "A/C No.": ""})
            cb(_b2c(orig, f"AG_{_d14(done)[:8]}_{rng.randint(10**15, 10**16 - 1):x}", 0, rc, amt), done)

    span = t_end - t0
    mid = lambda f: t0 + span * f + timedelta(seconds=rng.randint(0, 3000))  # noqa: E731

    # A  forged STK callback from a non-Safaricom address, credited -> FORGED_CREDIT, FAKE_CALLBACK, UNKNOWN_SOURCE
    when = mid(0.30)
    rc = _receipt(rng)
    payload, _ = _stk(rng, rc, Decimal("25000"), phone[punters[5]], when)
    cb(payload, when, ip="41.90.64.12")
    tx(punters[5], 25000, "DEPOSIT_MPESA", receipt=rc, when=when + timedelta(seconds=3))

    # B  real payment of KES 10, callback rewritten to 10,000 (spoofed X-Forwarded-For) -> EXCEEDS_PAID, MISMATCH
    when = mid(0.45)
    rc = _receipt(rng)
    paid_in(rc, Decimal("10"), punters[8], when)
    deposit_callback(rc, Decimal("10"), punters[8], when, amount_claimed=Decimal("10000"))
    tx(punters[8], 10000, "DEPOSIT_MPESA", receipt=rc, when=when + timedelta(seconds=4))

    # D  customer cancelled the STK prompt, wallet credited anyway -> FAILED_PAYMENT_CREDITED
    when = mid(0.52)
    payload, co = _stk(rng, None, None, phone[punters[9]], when, result=1032, desc="Request cancelled by user")
    cb(payload, when)
    tx(punters[9], 5000, "DEPOSIT_MPESA", receipt=co, when=when + timedelta(seconds=6))

    # E  withdrawal paid out (statement + B2C success) AND reversed into the wallet -> PAID_AND_REFUNDED
    w = next(r for r in ledger if r["txn_type"] == "WITHDRAW_B2C" and r["created_on"] > t0 + span * 0.5)
    tx(w["punter_id"], w["amount"], "WITHDRAW_REVERSAL", ref=str(w["txn_id"]), when=w["created_on"] + timedelta(minutes=10))

    # F  negative control: withdrawal failed at M-Pesa and was correctly reversed -> no finding
    when = mid(0.60)
    orig = "F" + str(rng.randint(10**8, 10**9))
    wf = tx(punters[12], 700, "WITHDRAW_B2C", ref=orig, when=when)
    cb(_b2c(orig, f"AG_F{rng.randint(10**9, 10**10)}", 2001), when + timedelta(seconds=20))
    tx(punters[12], 700, "WITHDRAW_REVERSAL", ref=str(wf["txn_id"]), when=when + timedelta(minutes=2))

    # G  money sent out of the paybill, no wallet withdrawal anywhere -> PAYOUT_WITHOUT_WALLET_DEBIT
    paid_out(_receipt(rng), Decimal("30000"), None, mid(0.66), details="Business Payment to 254711000999 - J DOE")

    # H  customer paid, callback arrived, wallet never credited -> PAID_NOT_CREDITED
    when = mid(0.70)
    rc = _receipt(rng)
    paid_in(rc, Decimal("2000"), punters[14], when)
    deposit_callback(rc, Decimal("2000"), punters[14], when)

    # I  withdrawal failed at M-Pesa, wallet left debited -> WITHDRAWAL_FAILED_NOT_REFUNDED
    when = mid(0.75)
    orig = "I" + str(rng.randint(10**8, 10**9))
    tx(punters[15], 1500, "WITHDRAW_B2C", ref=orig, when=when)
    cb(_b2c(orig, f"AG_I{rng.randint(10**9, 10**10)}", 2001), when + timedelta(seconds=20))

    # Negative controls on the statement: operator float top-up, transfer to bank, a failed row.
    paid_in(_receipt(rng), Decimal("500000"), None, mid(0.10), details="Funds received from 600000 - DEMO HOLDINGS LTD",
            reason="Organization Fund Transfer")
    stmt.append({"Receipt No.": _receipt(rng), "Completion Time": mid(0.80),
                 "Details": "Transfer of funds to bank 0011223344", "Transaction Status": "Completed",
                 "Paid In": "", "Withdrawn": "-250,000.00", "Reason Type": "Organization Withdrawal",
                 "Other Party Info": "DEMO BANK", "A/C No.": ""})
    stmt.append({"Receipt No.": _receipt(rng), "Completion Time": mid(0.40),
                 "Details": "Pay Bill from 254799000111 - DEMO", "Transaction Status": "Failed",
                 "Paid In": "1,000.00", "Withdrawn": "", "Reason Type": "Pay Bill Online",
                 "Other Party Info": "", "A/C No.": ""})
    return {"statement": stmt, "callbacks": cbs}


def _write_mpesa(out: str, mp: dict) -> None:
    os.makedirs(out, exist_ok=True)
    cols = ["Receipt No.", "Completion Time", "Initiation Time", "Details", "Transaction Status", "Paid In",
            "Withdrawn", "Balance", "Balance Confirmed", "Reason Type", "Other Party Info",
            "Linked Transaction ID", "A/C No."]
    rows = sorted(mp["statement"], key=lambda r: r["Completion Time"], reverse=True)   # portal lists newest first
    with open(os.path.join(out, "statement.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["DEMO SPORTSBOOK LTD"])
        w.writerow([f"Short Code: {SHORTCODE}"])
        w.writerow(["Account: Utility Account"])
        w.writerow([])
        w.writerow(cols)
        for r in rows:
            r = dict(r, **{"Completion Time": r["Completion Time"].strftime("%d-%m-%Y %H:%M:%S"),
                           "Initiation Time": r["Completion Time"].strftime("%d-%m-%Y %H:%M:%S"),
                           "Balance Confirmed": "true"})
            w.writerow([r.get(c, "") for c in cols])
    with open(os.path.join(out, "callbacks.jsonl"), "w", encoding="utf-8") as fh:
        for c in sorted(mp["callbacks"], key=lambda c: c["received_at"]):
            fh.write(json.dumps(c) + "\n")
