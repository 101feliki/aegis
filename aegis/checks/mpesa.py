"""
M-Pesa guard - does the money M-Pesa actually moved match what the wallet recorded?
(READ-ONLY)

Betting wallets are credited because a Daraja *callback* said "the customer paid".
A callback is just an HTTP POST to the operator's server, so anyone who finds the
callback URL can send a fake one, replay a real one, or change the amount. The
only ground truth is Safaricom's own record: the M-Pesa organisation statement.

This module lines up three sources:

  1. the M-Pesa statement   (exported from the M-Pesa org portal - what really moved)
  2. the callback log       (what the server was TOLD - raw Daraja JSON payloads)
  3. the wallet ledger      (what the server CREDITED/DEBITED - via the ledger map)

and reports where they disagree:

  CRITICAL  FORGED_CREDIT                 deposit credited with a receipt M-Pesa never issued
  CRITICAL  CREDIT_EXCEEDS_PAID           wallet credited more than M-Pesa received for that receipt
  CRITICAL  FAILED_PAYMENT_CREDITED       wallet credited for a payment M-Pesa reported failed/cancelled
  CRITICAL  WITHDRAWAL_PAID_AND_REFUNDED  M-Pesa paid a withdrawal out AND the wallet got it back
  HIGH      PAYOUT_WITHOUT_WALLET_DEBIT   money sent out of the paybill with no wallet withdrawal behind it
  HIGH      FAKE_CALLBACK                 "payment successful" callback for a receipt not on the statement
  HIGH      CALLBACK_AMOUNT_MISMATCH      callback amount differs from what M-Pesa recorded
  HIGH      CALLBACK_FROM_UNKNOWN_SOURCE  callback came from an address that is not Safaricom
  MEDIUM    DEPOSIT_NO_RECEIPT            deposit credited with no M-Pesa receipt at all
  MEDIUM    REPLAYED_CALLBACK             the same successful payment was announced more than once
  LOW       PAID_NOT_CREDITED             customer paid (on statement) but no wallet credit found
  LOW       WITHDRAWAL_FAILED_NOT_REFUNDED  M-Pesa withdrawal failed, wallet stayed debited

Any source can be missing; checks that need it are skipped and the report says so.
Nothing is written anywhere except AEGIS's own output folder.
"""
from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal

from ..findings import ZERO, Findings, money
from .ledger import _key, to_dec, to_ts

ACTION = "mpesa-readonly"

# Daraja's published callback source addresses. Safaricom changes these from time
# to time: confirm against the current Daraja documentation and override with
# --allow-ips (a file or comma list; CIDR ranges accepted).
SAFARICOM_CALLBACK_IPS = [
    "196.201.214.200", "196.201.214.206", "196.201.213.114", "196.201.214.207",
    "196.201.214.208", "196.201.213.44", "196.201.212.127", "196.201.212.138",
    "196.201.212.129", "196.201.212.136", "196.201.212.74", "196.201.212.69",
]

CATALOGUE = {
    "FORGED_CREDIT": (
        "CRITICAL", "Deposit credited with an M-Pesa receipt that is not on the M-Pesa statement",
        "M-Pesa never received this money, but the wallet was credited. This is the signature of a forged "
        "payment callback (someone POSTed a fake 'payment successful' message to the callback URL) or a "
        "manual credit disguised as an M-Pesa deposit."),
    "CREDIT_EXCEEDS_PAID": (
        "CRITICAL", "Wallet credited more than M-Pesa actually received",
        "The receipt is genuine but the wallet got more than the customer paid: the amount in the callback was "
        "altered, or the same receipt was credited more than once (replay)."),
    "FAILED_PAYMENT_CREDITED": (
        "CRITICAL", "Wallet credited for a payment M-Pesa reported as failed or cancelled",
        "M-Pesa told the server the payment did NOT go through (cancelled, insufficient funds, timeout), yet the "
        "wallet was credited. The callback handler is not checking ResultCode, or the result was tampered with."),
    "WITHDRAWAL_PAID_AND_REFUNDED": (
        "CRITICAL", "Withdrawal paid out by M-Pesa AND refunded to the wallet",
        "The customer received the money on their phone and also got it back in their wallet - they can withdraw "
        "it again. Usually a 'refund on timeout' rule that fires even when the payout later succeeded."),
    "PAYOUT_WITHOUT_WALLET_DEBIT": (
        "HIGH", "Money sent out of the paybill with no matching wallet withdrawal",
        "M-Pesa shows a payment from the business to a phone number, but no wallet was debited for it. Either a "
        "payout was made outside the system (insider / stolen API credentials) or the withdrawal record is missing."),
    "FAKE_CALLBACK": (
        "HIGH", "'Payment successful' callback for a receipt that is not on the M-Pesa statement",
        "The server received a success message for a payment M-Pesa never processed. Even if it was not credited, "
        "someone is sending forged callbacks - the callback URL is known and being tested."),
    "CALLBACK_AMOUNT_MISMATCH": (
        "HIGH", "Callback amount differs from what M-Pesa recorded",
        "The callback claims a different amount than the statement for the same receipt - a tampered callback, "
        "or a proxy in front of the server that rewrites it."),
    "CALLBACK_FROM_UNKNOWN_SOURCE": (
        "HIGH", "Payment callback arrived from an address that is not Safaricom",
        "Genuine Daraja callbacks come from a short list of Safaricom addresses. Anything else is someone else "
        "talking to the payment endpoint. Fix: only accept callbacks from Safaricom's addresses, and confirm "
        "every payment with the Transaction Status API before crediting."),
    "DEPOSIT_NO_RECEIPT": (
        "MEDIUM", "Deposit credited with no M-Pesa receipt at all",
        "A deposit-type credit with nothing linking it to an M-Pesa transaction cannot be verified. Often a "
        "manual or back-office credit - each one needs a documented reason."),
    "REPLAYED_CALLBACK": (
        "MEDIUM", "The same successful payment was announced more than once",
        "Safaricom occasionally retries, but repeated success messages are also how replay attacks look. Harmless "
        "only if the wallet credited it once (see CREDIT_EXCEEDS_PAID)."),
    "PAID_NOT_CREDITED": (
        "LOW", "Customer paid (on M-Pesa statement) but no wallet credit was found",
        "Not a loss to the house, but a customer complaint and regulatory risk - and a sign callbacks are being "
        "lost or rejected."),
    "WITHDRAWAL_FAILED_NOT_REFUNDED": (
        "LOW", "M-Pesa withdrawal failed but the wallet stayed debited",
        "The customer's money left the wallet but never reached their phone. Customer-harm and complaint risk."),
}

CASE_FIELDS = {
    "FORGED_CREDIT": ("txn",), "CREDIT_EXCEEDS_PAID": ("receipt",), "FAILED_PAYMENT_CREDITED": ("txn",),
    "WITHDRAWAL_PAID_AND_REFUNDED": ("reversal_txn",), "PAYOUT_WITHOUT_WALLET_DEBIT": ("receipt",),
    "FAKE_CALLBACK": ("receipt",), "CALLBACK_AMOUNT_MISMATCH": ("receipt",),
    "CALLBACK_FROM_UNKNOWN_SOURCE": ("ip", "ref"), "DEPOSIT_NO_RECEIPT": ("txn",),
    "REPLAYED_CALLBACK": ("receipt",), "PAID_NOT_CREDITED": ("receipt",),
    "WITHDRAWAL_FAILED_NOT_REFUNDED": ("withdrawal_txn",),
}


def _norm(s) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(s or "").lower()).strip("_")


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    paths = [path] if os.path.isfile(path) else sorted(
        os.path.join(path, f) for f in os.listdir(path) if os.path.isfile(os.path.join(path, f)))
    for p in paths:
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    return h.hexdigest()


def _ts14(v) -> datetime | None:
    """Daraja timestamps are YYYYMMDDHHMMSS (sometimes sent as a number)."""
    if v is None:
        return None
    s = str(v).strip()
    if re.fullmatch(r"\d{14}", s):
        try:
            return datetime.strptime(s, "%Y%m%d%H%M%S")
        except ValueError:
            return None
    return to_ts(s)


def _int(v, default=-1) -> int:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# 1. M-Pesa organisation statement (CSV export from the M-Pesa org portal)
# ---------------------------------------------------------------------------
STMT_COLS = {
    "receipt": ["receipt_no", "receipt_number", "receipt", "transaction_id", "trans_id", "mpesa_receipt",
                "transaction_code", "receipt_no_"],
    "completed": ["completion_time", "completed_time", "completion_date", "transaction_date", "trans_time",
                  "date", "time", "initiation_time"],
    "details": ["details", "description", "narration", "transaction_details"],
    "status": ["transaction_status", "status"],
    "paid_in": ["paid_in", "credit", "money_in", "amount_in"],
    "withdrawn": ["withdrawn", "debit", "money_out", "amount_out", "paid_out"],
    "amount": ["amount", "transaction_amount"],
    "party": ["other_party_info", "other_party", "party", "msisdn", "phone"],
    "account": ["a_c_no", "ac_no", "account_no", "account", "bill_ref", "bill_ref_number", "account_reference",
                "acc_no"],
}
CUSTOMER_IN = ("pay bill", "paybill", "customer", "c2b", "buy goods", "merchant payment", "online", "stk")
PAYOUT_OUT = ("business payment", "b2c", "salary payment", "promotion payment", "pay to customer",
              "payment to")


def load_statement(path: str) -> dict:
    """Parse an M-Pesa org statement CSV. Tolerates the portal's preamble lines
    (account name, short code, period) above the column header row."""
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        sample = fh.read(16384)
        fh.seek(0)
        try:
            delim = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
        except csv.Error:
            delim = ","
        rows = list(csv.reader(fh, delimiter=delim))

    header_at, cols = None, {}
    for i, row in enumerate(rows[:60]):
        normed = [_norm(c) for c in row]
        if any(a in normed for a in STMT_COLS["receipt"]) and \
                any(a in normed for a in STMT_COLS["paid_in"] + STMT_COLS["withdrawn"] + STMT_COLS["amount"]):
            header_at = i
            for role, aliases in STMT_COLS.items():
                for a in aliases:
                    if a in normed:
                        cols[role] = normed.index(a)
                        break
            break
    if header_at is None:
        raise ValueError(f"{path}: no statement header row found (need a 'Receipt No.' column and "
                         "'Paid In'/'Withdrawn' or 'Amount'). Export the statement from the M-Pesa org portal as CSV.")

    get = lambda r, k: (r[cols[k]].strip() if k in cols and cols[k] < len(r) else "")  # noqa: E731
    paid_in: dict[str, dict] = {}       # receipt -> {amount, ts, customer, party, account, details}
    paid_out: dict[str, dict] = {}      # receipt -> {amount, ts, payout, party, details}
    skipped_status = 0
    tmin = tmax = None
    n = 0
    for r in rows[header_at + 1:]:
        if not any(c.strip() for c in r):
            continue
        rc = _key(get(r, "receipt"))
        if not rc:
            continue
        status = get(r, "status").lower()
        if status and "complet" not in status:
            skipped_status += 1
            continue
        n += 1
        ts = to_ts(get(r, "completed"))
        if ts:
            tmin = ts if tmin is None or ts < tmin else tmin
            tmax = ts if tmax is None or ts > tmax else tmax
        details = get(r, "details")
        dl = details.lower()
        pin = to_dec(get(r, "paid_in"))
        pout = to_dec(get(r, "withdrawn"))
        if pin is None and pout is None and "amount" in cols:
            a = to_dec(get(r, "amount"))
            if a is not None:
                pin, pout = (a, None) if a > 0 else (None, -a)
        if pin and pin > 0:
            e = paid_in.setdefault(rc, {"amount": ZERO, "ts": ts, "customer": False, "party": get(r, "party"),
                                        "account": get(r, "account"), "details": details})
            e["amount"] += pin
            e["customer"] = e["customer"] or not dl or any(k in dl for k in CUSTOMER_IN)
        if pout and abs(pout) > 0:
            if "charge" in dl:
                continue                                  # transaction fees, not payouts
            e = paid_out.setdefault(rc, {"amount": ZERO, "ts": ts, "payout": False, "party": get(r, "party"),
                                         "details": details})
            e["amount"] += abs(pout)
            e["payout"] = e["payout"] or not dl or any(k in dl for k in PAYOUT_OUT)
    return {"path": path, "rows": n, "skipped_not_completed": skipped_status, "start": tmin, "end": tmax,
            "paid_in": paid_in, "paid_out": paid_out, "columns": sorted(cols)}


# ---------------------------------------------------------------------------
# 2. Callback log (raw Daraja payloads, as the server received them)
# ---------------------------------------------------------------------------
WRAP_PAYLOAD = ("payload", "body", "data", "request_body", "raw", "request", "json")
WRAP_IP = ("source_ip", "ip", "remote_addr", "client_ip", "ip_address", "remote_ip", "peer")
WRAP_TS = ("received_at", "ts", "timestamp", "created_at", "time", "logged_at", "date")
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def parse_payload(p) -> dict | None:
    """Recognise STK-push results, C2B confirmations and B2C results."""
    if not isinstance(p, dict):
        return None
    body = p.get("Body")
    if isinstance(body, dict) and isinstance(body.get("stkCallback"), dict):
        s = body["stkCallback"]
        items = (s.get("CallbackMetadata") or {}).get("Item") or []
        if isinstance(items, dict):
            items = [items]
        meta = {i.get("Name"): i.get("Value") for i in items if isinstance(i, dict)}
        return {"kind": "stk", "result": _int(s.get("ResultCode")), "desc": s.get("ResultDesc"),
                "checkout": _key(s.get("CheckoutRequestID")), "merchant": _key(s.get("MerchantRequestID")),
                "receipt": _key(meta.get("MpesaReceiptNumber")), "amount": to_dec(meta.get("Amount")),
                "phone": _key(meta.get("PhoneNumber")), "when": _ts14(meta.get("TransactionDate"))}
    if "TransID" in p and ("TransAmount" in p or "BusinessShortCode" in p):
        return {"kind": "c2b", "result": 0, "receipt": _key(p.get("TransID")), "amount": to_dec(p.get("TransAmount")),
                "phone": _key(p.get("MSISDN")), "account": _key(p.get("BillRefNumber")),
                "when": _ts14(p.get("TransTime"))}
    res = p.get("Result")
    if isinstance(res, dict) and ("ConversationID" in res or "OriginatorConversationID" in res):
        params = (res.get("ResultParameters") or {}).get("ResultParameter") or []
        if isinstance(params, dict):
            params = [params]
        kv = {x.get("Key"): x.get("Value") for x in params if isinstance(x, dict)}
        return {"kind": "b2c", "result": _int(res.get("ResultCode")), "desc": res.get("ResultDesc"),
                "receipt": _key(kv.get("TransactionReceipt") or res.get("TransactionID")),
                "amount": to_dec(kv.get("TransactionAmount")),
                "conv": _key(res.get("ConversationID")), "orig_conv": _key(res.get("OriginatorConversationID")),
                "when": to_ts(kv.get("TransactionCompletedDateTime")) if kv.get("TransactionCompletedDateTime") else None}
    return None


def _unwrap(obj, ip: str | None = None, received=None) -> dict | None:
    if not isinstance(obj, dict):
        return None
    ev = parse_payload(obj)
    if ev is None:
        low = {str(k).lower(): v for k, v in obj.items()}
        inner = next((low[k] for k in WRAP_PAYLOAD if k in low), None)
        if isinstance(inner, str):
            try:
                inner = json.loads(inner)
            except ValueError:
                inner = None
        ev = parse_payload(inner) if isinstance(inner, dict) else None
        if ev is None:
            return None
        ip = next((str(low[k]).split(",")[0].strip() for k in WRAP_IP if low.get(k)), ip)
        received = next((low[k] for k in WRAP_TS if low.get(k)), received)
    ev["ip"] = ip
    ev["received"] = to_ts(received) if received else None
    return ev


def _iter_text_records(text: str):
    """Yield (obj, ip, ts) from JSON, JSON-lines, or log lines with JSON embedded."""
    t = text.strip()
    if not t:
        return
    if t[0] in "[{":
        try:
            whole = json.loads(t)
            for o in (whole if isinstance(whole, list) else [whole]):
                yield o, None, None
            return
        except ValueError:
            pass
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line), None, None
            continue
        except ValueError:
            pass
        j = line.find("{")
        if j < 0:
            yield None, None, None
            continue
        prefix = line[:j]
        try:
            obj = json.loads(line[j:])
        except ValueError:
            yield None, None, None
            continue
        m = IP_RE.search(prefix)
        ts = re.search(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", prefix)
        yield obj, (m.group(1) if m else None), (ts.group(0) if ts else None)


def load_callbacks(path: str) -> dict:
    files = [path] if os.path.isfile(path) else sorted(
        os.path.join(path, f) for f in os.listdir(path)
        if f.lower().endswith((".json", ".jsonl", ".ndjson", ".log", ".txt")))
    events, unparsed = [], 0
    for f in files:
        with open(f, "r", encoding="utf-8-sig", errors="replace") as fh:
            for obj, ip, ts in _iter_text_records(fh.read()):
                ev = _unwrap(obj, ip, ts) if obj is not None else None
                if ev is None:
                    unparsed += 1
                else:
                    events.append(ev)
    return {"path": path, "files": len(files), "events": events, "unparsed": unparsed}


def load_callbacks_table(db, table: str, payload_col: str, ip_col: str | None, ts_col: str | None) -> dict:
    cols = [c for c in (payload_col, ip_col, ts_col) if c]
    events, unparsed = [], 0
    for r in db.iter_select(table, cols):
        raw = r.get(payload_col)
        try:
            obj = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
        except ValueError:
            obj = None
        ev = _unwrap(obj, r.get(ip_col) if ip_col else None, r.get(ts_col) if ts_col else None) if obj else None
        if ev is None:
            unparsed += 1
        else:
            events.append(ev)
    return {"path": f"{db.label}#{table}.{payload_col}", "files": 0, "events": events, "unparsed": unparsed}


# ---------------------------------------------------------------------------
# 3. Wallet side (deposits, withdrawals, withdrawal reversals) via the ledger map
# ---------------------------------------------------------------------------
def load_wallet(db, mapping: dict) -> dict:
    tm = mapping.get("transactions")
    if not tm:
        raise ValueError("mapping has no 'transactions' section")
    tc = tm["columns"]
    have = {c.lower() for c in db.columns(tm["table"])}
    missing = [c for c in tc.values() if c.lower() not in have]
    if missing:
        raise ValueError(f"table {tm['table']!r} no longer has column(s) {', '.join(missing)}")
    tmap = {str(k): v for k, v in (tm.get("type_values") or {}).items()}
    c_id, c_user, c_amt, c_type, c_rc, c_ref, c_ts = (tc.get(k) for k in
                                                      ("id", "user", "amount", "type", "receipt", "bet_ref",
                                                       "created_at"))
    rows = {"deposit": [], "withdrawal": [], "withdrawal_reversal": []}
    n = 0
    tmin = tmax = None
    for i, r in enumerate(db.iter_select(tm["table"], list(dict.fromkeys(tc.values())))):
        n += 1
        cat = tmap.get(str(r.get(c_type)), "other")
        if cat not in rows:
            continue
        amt = to_dec(r.get(c_amt))
        if amt is None:
            continue
        ts = to_ts(r.get(c_ts)) if c_ts else None
        if ts:
            tmin = ts if tmin is None or ts < tmin else tmin
            tmax = ts if tmax is None or ts > tmax else tmax
        rows[cat].append((_key(r.get(c_id)) if c_id else f"row{i + 1}", _key(r.get(c_user)) if c_user else None,
                          abs(amt), _key(r.get(c_rc)) if c_rc else None, _key(r.get(c_ref)) if c_ref else None, ts))
    return {"rows": rows, "scanned": n, "start": tmin, "end": tmax, "has_receipt_col": bool(c_rc),
            "has_ref_col": bool(c_ref), "has_ts": bool(c_ts), "currency": mapping.get("currency", "KES")}


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def _nets(spec: list[str]) -> list:
    out = []
    for s in spec:
        s = s.strip()
        if s:
            out.append(ipaddress.ip_network(s, strict=False))
    return out


def analyse(stmt: dict | None, cbs: dict | None, wallet: dict | None, allow: list[str],
            tol: Decimal = Decimal("1.00"), grace: timedelta = timedelta(hours=1)) -> dict:
    F = Findings(CATALOGUE, CASE_FIELDS)
    coverage: list[str] = []
    allow_nets = _nets(allow)

    st_in = stmt["paid_in"] if stmt else {}
    st_out = stmt["paid_out"] if stmt else {}
    # Window in which a wallet event can be judged against the statement: a credit just after the
    # statement starts may belong to a payment completed before it, so the start gets a grace period.
    s_lo = stmt["start"] + grace if stmt and stmt["start"] else None
    s_hi = stmt["end"] if stmt else None

    def in_stmt(ts):
        if not stmt:
            return False
        if ts is None or s_lo is None:
            return True
        return s_lo <= ts <= s_hi

    W = wallet["rows"] if wallet else {"deposit": [], "withdrawal": [], "withdrawal_reversal": []}
    w_lo = wallet["start"] if wallet else None
    w_hi = (wallet["end"] - grace) if wallet and wallet["end"] else None

    def in_wallet(ts):
        if not wallet:
            return False
        if ts is None or w_lo is None:
            return True
        return w_lo <= ts <= w_hi

    events = cbs["events"] if cbs else []
    ok_pay = [e for e in events if e["kind"] in ("stk", "c2b") and e["result"] == 0 and e.get("receipt")]
    ok_ids = {x for e in ok_pay for x in (e.get("checkout"), e.get("merchant")) if x}
    failed_ids: dict[str, dict] = {}
    for e in events:
        if e["kind"] == "stk" and e["result"] != 0:
            for x in (e.get("checkout"), e.get("merchant"), e.get("receipt")):
                if x and x not in ok_ids:
                    failed_ids[x] = e

    # ---- deposits ----------------------------------------------------------
    explained: set = set()
    credited: dict[str, list] = defaultdict(list)          # receipt -> [(txn, amount, user, ts)]
    if wallet:
        for txn, user, amt, rc, ref, ts in W["deposit"]:
            hit = failed_ids.get(rc) or failed_ids.get(ref)
            if hit and cbs:
                explained.add(txn)
                F.add("FAILED_PAYMENT_CREDITED", amt, txn=txn, user=user, amount=money(amt),
                      mpesa_result=f"{hit['result']} {hit.get('desc') or ''}".strip(),
                      checkout=hit.get("checkout"))
                continue
            if not rc:
                F.add("DEPOSIT_NO_RECEIPT", amt, txn=txn, user=user, amount=money(amt), at=str(ts or ""))
                continue
            credited[rc].append((txn, amt, user, ts))
        if stmt:
            for rc, lst in credited.items():
                if rc not in st_in:
                    for txn, amt, user, ts in lst:
                        if in_stmt(ts):
                            F.add("FORGED_CREDIT", amt, txn=txn, user=user, receipt=rc, amount=money(amt),
                                  credited_at=str(ts or ""))
                    continue
                total = sum((x[1] for x in lst), ZERO)
                paid = st_in[rc]["amount"]
                if total > paid + tol:
                    F.add("CREDIT_EXCEEDS_PAID", total - paid, receipt=rc, mpesa_received=money(paid),
                          wallet_credited=money(total), times_credited=len(lst), txns=[x[0] for x in lst],
                          user=lst[0][2])
            for rc, e in st_in.items():
                if e["customer"] and rc not in credited and in_wallet(e["ts"]):
                    F.add("PAID_NOT_CREDITED", None, receipt=rc, amount=money(e["amount"]), paid_at=str(e["ts"] or ""),
                          party=e["party"], account=e["account"])

    # ---- withdrawals -------------------------------------------------------
    if wallet:
        wd_by: dict[str, tuple] = {}
        for w in W["withdrawal"]:
            for k in (w[0], w[3], w[4]):
                if k:
                    wd_by.setdefault(k, w)
        b2c_ok: dict[str, dict] = {}
        b2c_fail: list[dict] = []
        for e in events:
            if e["kind"] != "b2c":
                continue
            if e["result"] == 0:
                for k in (e.get("receipt"), e.get("conv"), e.get("orig_conv")):
                    if k:
                        b2c_ok[k] = e
            else:
                b2c_fail.append(e)

        def paid_proof(w) -> str | None:
            if w[3] and w[3] in st_out:
                return "on the M-Pesa statement as paid out"
            for k in (w[3], w[4]):
                if k and k in b2c_ok:
                    return f"M-Pesa B2C success callback ({b2c_ok[k].get('receipt') or k})"
            return None

        reversed_wd: set = set()
        unlinked = 0
        for txn, user, amt, rc, ref, ts in W["withdrawal_reversal"]:
            w = (wd_by.get(ref) if ref else None) or (wd_by.get(rc) if rc else None)
            if not w:
                unlinked += 1
                continue
            reversed_wd.add(w[0])
            proof = paid_proof(w)
            if proof:
                F.add("WITHDRAWAL_PAID_AND_REFUNDED", amt, reversal_txn=txn, withdrawal_txn=w[0], user=user,
                      amount=money(amt), receipt=w[3], proof=proof)
        if unlinked:
            coverage.append(f"{unlinked} withdrawal reversal(s) could not be linked to the withdrawal they reverse "
                            "(the reversal's reference column should hold the withdrawal's id or receipt).")

        for e in b2c_fail:
            w = next((wd_by[k] for k in (e.get("orig_conv"), e.get("conv"), e.get("receipt")) if k and k in wd_by), None)
            if w and w[0] not in reversed_wd and not (w[3] and w[3] in st_out):
                F.add("WITHDRAWAL_FAILED_NOT_REFUNDED", None, withdrawal_txn=w[0], user=w[1], amount=money(w[2]),
                      mpesa_result=f"{e['result']} {e.get('desc') or ''}".strip())

        wd_receipts = {w[3] for w in W["withdrawal"] if w[3]}
        if stmt and st_out:
            if not wd_receipts:
                coverage.append("Wallet withdrawals carry no M-Pesa receipt, so payouts on the statement could not be "
                                "matched to wallet debits (PAYOUT_WITHOUT_WALLET_DEBIT not run).")
            else:
                for rc, e in st_out.items():
                    if e["payout"] and rc not in wd_receipts and in_wallet(e["ts"]):
                        F.add("PAYOUT_WITHOUT_WALLET_DEBIT", e["amount"], receipt=rc, amount=money(e["amount"]),
                              paid_at=str(e["ts"] or ""), to=e["party"], details=e["details"])

    # ---- callbacks ---------------------------------------------------------
    if cbs:
        seen: dict[str, int] = defaultdict(int)
        for e in ok_pay:
            seen[e["receipt"]] += 1
        for rc, n in seen.items():
            if n > 1:
                F.add("REPLAYED_CALLBACK", None, receipt=rc, times=n)
        if stmt:
            flagged: set = set()
            for e in ok_pay:
                rc = e["receipt"]
                if rc in flagged:
                    continue
                when = e.get("when") or e.get("received")
                # Callback-level findings carry no money figure: the money is counted once, where it
                # actually reached a wallet (FORGED_CREDIT / CREDIT_EXCEEDS_PAID), never three times.
                if rc not in st_in:
                    if in_stmt(when):
                        flagged.add(rc)
                        F.add("FAKE_CALLBACK", None, receipt=rc, claimed_amount=money(e.get("amount")),
                              kind=e["kind"], ip=e.get("ip"), phone=e.get("phone"))
                elif e.get("amount") is not None and abs(e["amount"] - st_in[rc]["amount"]) > tol:
                    flagged.add(rc)
                    F.add("CALLBACK_AMOUNT_MISMATCH", None,
                          receipt=rc, callback_says=money(e["amount"]), mpesa_recorded=money(st_in[rc]["amount"]),
                          ip=e.get("ip"))
        with_ip = [e for e in events if e.get("ip")]
        public = []
        for e in with_ip:
            try:
                a = ipaddress.ip_address(e["ip"])
            except ValueError:
                continue
            if a.is_private or a.is_loopback:
                continue
            public.append((e, a))
        if events and not with_ip:
            coverage.append("Callback records carry no source address - CALLBACK_FROM_UNKNOWN_SOURCE not run. "
                            "Log the caller's IP with every callback.")
        elif with_ip and not public:
            coverage.append("Every callback was recorded with a private/loopback address - that is your reverse "
                            "proxy, not the sender. Log the real client address (and do not trust X-Forwarded-For "
                            "unless your own proxy sets it).")
        for e, a in public:
            if not any(a in n for n in allow_nets):
                F.add("CALLBACK_FROM_UNKNOWN_SOURCE", None,
                      ip=e["ip"], ref=e.get("receipt") or e.get("checkout") or e.get("conv"), kind=e["kind"],
                      result=e["result"], amount=money(e.get("amount")))

    # ---- what was / was not checked -----------------------------------------
    if not stmt:
        coverage.append("No M-Pesa statement supplied - receipts and amounts could NOT be verified against "
                        "Safaricom's record (FORGED_CREDIT, CREDIT_EXCEEDS_PAID, FAKE_CALLBACK, "
                        "CALLBACK_AMOUNT_MISMATCH, PAYOUT_WITHOUT_WALLET_DEBIT, PAID_NOT_CREDITED not run).")
    if not cbs:
        coverage.append("No callback log supplied - callback source, failed-payment and replay checks not run.")
    if not wallet:
        coverage.append("No wallet database supplied - nothing was compared with what the wallet credited.")
    if wallet and not wallet["has_receipt_col"]:
        coverage.append("The ledger map has no M-Pesa receipt column - deposits cannot be tied to M-Pesa.")
    if wallet and not wallet["has_ts"]:
        coverage.append("Wallet rows have no timestamp - every deposit was judged against the statement; make sure "
                        "the statement covers the whole period or expect false FORGED_CREDIT leads.")
    if stmt and stmt["start"]:
        coverage.append(f"Statement covers {stmt['start']} .. {stmt['end']}; wallet events outside that window "
                        f"(and the first {int(grace.total_seconds() // 60)} min) were not judged against it.")
    if cbs and cbs["unparsed"]:
        coverage.append(f"{cbs['unparsed']} callback record(s) were not recognisable Daraja payloads and were skipped.")

    kinds = defaultdict(int)
    for e in events:
        kinds[f"{e['kind']}_{'ok' if e['result'] == 0 else 'failed'}"] += 1
    return {"findings": F.list(), "total_at_risk": F.total(), "case_keys": F.case_keys(), "coverage": coverage,
            "plain": F.plain(wallet["currency"] if wallet else "KES"),
            "scanned": {"statement_rows": stmt["rows"] if stmt else 0,
                        "statement_receipts_in": len(st_in), "statement_receipts_out": len(st_out),
                        "callbacks": len(events), "callback_mix": dict(kinds),
                        "wallet_deposits": len(W["deposit"]), "wallet_withdrawals": len(W["withdrawal"]),
                        "wallet_reversals": len(W["withdrawal_reversal"])}}


# ---------------------------------------------------------------------------
# Public entry: authorized, audited
# ---------------------------------------------------------------------------
def run_mpesa(authz, statement: str | None = None, callbacks: str | None = None, db=None,
              mapping: dict | None = None, callbacks_table: dict | None = None,
              allow: list[str] | None = None, tol: Decimal | None = None) -> dict:
    sources = [s for s in (statement, callbacks) if s] + ([db.label] if db is not None else [])
    for s in sources:
        d = authz.authorize_db(ACTION, s)
        if not d:
            return {"check": "mpesa", "authorized": False, "reason": f"{s}: {d.reason}"}

    allow = allow if allow is not None else SAFARICOM_CALLBACK_IPS
    stmt = load_statement(statement) if statement else None
    cbs = load_callbacks(callbacks) if callbacks else None
    wallet = None
    if db is not None and mapping:
        wallet = load_wallet(db, mapping)
        if callbacks_table and not cbs:
            cbs = load_callbacks_table(db, **callbacks_table)
    authz.audit.append("note", action=ACTION, target="mpesa-guard", decision="INFO", detail={
        "statement": statement, "statement_sha256": file_sha256(statement) if statement else None,
        "callbacks": cbs["path"] if cbs else None,
        "callbacks_sha256": file_sha256(callbacks) if callbacks else None,
        "wallet_db": db.label if db is not None else None,
        "allowlist": allow})

    tol = tol if tol is not None else (to_dec((mapping or {}).get("tolerance", "1.00")) or Decimal("1.00"))
    res = analyse(stmt, cbs, wallet, allow, tol=tol)
    cur = wallet["currency"] if wallet else "KES"
    out = {"check": "mpesa", "module_title": "M-Pesa guard (statement vs callbacks vs wallet)",
           "target": " + ".join(sources), "authorized": True, "currency": cur,
           "scanned": res["scanned"], "module_findings": res["findings"], "total_at_risk": res["total_at_risk"],
           "coverage": res["coverage"], "findings": res["plain"],
           "case_keys_sha256": hashlib.sha256(json.dumps(res["case_keys"], sort_keys=True).encode()).hexdigest()}
    authz.audit.append("check", action=ACTION, target=out["target"], decision="DONE", detail=out)
    return dict(out, case_keys=res["case_keys"])
