"""
Ledger watchdog - does the money add up? (READ-ONLY)

This is the client's actual fear, checked directly in their data: was anyone
credited on a losing bet, credited twice, or credited more than the odds allow?
It reads the bets table and the wallet-transactions table (via a human-reviewed
mapping, see db/schemamap.py) and reconciles them, entirely read-only.

Checks (plain-language names are what the report shows):

  CRITICAL  PAID_ON_LOSS        winnings credited on a bet marked LOST
  CRITICAL  DUPLICATE_PAYOUT    the same bet paid out more than once
  CRITICAL  OVERPAYMENT         paid more than stake x odds
  CRITICAL  DUPLICATE_RECEIPT   one M-Pesa receipt credited more than once (replayed callback)
  HIGH      PAID_WRONG_ACCOUNT  winnings went to a different customer than the one who bet
  HIGH      PAID_BEFORE_RESULT  winnings credited while the bet was still open/pending
  HIGH      ORPHAN_PAYOUT       a "win" credit that points at no bet at all
  HIGH      VOID_OVERPAID       a cancelled bet refunded more than its stake
  HIGH      BALANCE_DRIFT       wallet balance differs from the sum of its transactions
                                (money added or removed outside the ledger)
  MEDIUM    RECORD_INFLATED     the bet record's own payout field exceeds stake x odds
  MEDIUM    PAID_BEFORE_SETTLE  credit timestamp earlier than the bet's settlement time
  LOW       WON_NOT_PAID        winning bet with no payout found (customer-harm / complaint risk)

It never writes. It never "fixes" a wallet. It produces evidence: counts, money at
risk, and the exact bet/transaction ids, logged into the hash-chained audit trail.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation

from ..authz import Authorizer
from ..db.connect import ReadOnlyDB

ACTION = "ledger-readonly"
SAMPLES = 15
ZERO = Decimal("0")

SEVERITY = {
    "PAID_ON_LOSS": "CRITICAL", "DUPLICATE_PAYOUT": "CRITICAL", "OVERPAYMENT": "CRITICAL",
    "DUPLICATE_RECEIPT": "CRITICAL", "PAID_WRONG_ACCOUNT": "HIGH", "PAID_BEFORE_RESULT": "HIGH",
    "ORPHAN_PAYOUT": "HIGH", "VOID_OVERPAID": "HIGH", "BALANCE_DRIFT": "HIGH",
    "RECORD_INFLATED": "MEDIUM", "PAID_BEFORE_SETTLE": "MEDIUM", "WON_NOT_PAID": "LOW",
}

TITLE = {
    "PAID_ON_LOSS": "Winnings credited on a bet marked LOST",
    "DUPLICATE_PAYOUT": "Same bet paid out more than once",
    "OVERPAYMENT": "Paid more than stake x odds",
    "DUPLICATE_RECEIPT": "One M-Pesa receipt credited more than once (replayed callback)",
    "PAID_WRONG_ACCOUNT": "Winnings paid to a different customer than the one who placed the bet",
    "PAID_BEFORE_RESULT": "Winnings credited while the bet was still open/pending",
    "ORPHAN_PAYOUT": "Win/payout credit that points at no existing bet",
    "VOID_OVERPAID": "Cancelled (void) bet refunded more than its stake",
    "BALANCE_DRIFT": "Wallet balance does not match the sum of its transactions",
    "RECORD_INFLATED": "Bet record's payout field is larger than stake x odds",
    "PAID_BEFORE_SETTLE": "Payout credited before the bet's recorded settlement time",
    "WON_NOT_PAID": "Winning bet with no payout found",
}

MEANS = {
    "PAID_ON_LOSS": "The core fear: money left the house on a bet the customer lost. Points to a settlement "
                    "bug, a replayed 'win' event, or manual tampering.",
    "DUPLICATE_PAYOUT": "Settlement ran twice for one bet (retry without an idempotency key, race condition, "
                        "or replay).",
    "OVERPAYMENT": "The amount credited exceeds what the odds allow - odds or stake altered between placement "
                   "and settlement, or a rounding/multiplier bug.",
    "DUPLICATE_RECEIPT": "A deposit callback was processed twice. Attackers replay M-Pesa confirmations to "
                         "mint wallet balance.",
    "PAID_WRONG_ACCOUNT": "A winning bet credited someone else's wallet - classic insider or IDOR pattern.",
    "PAID_BEFORE_RESULT": "Money was released before the event had a result.",
    "ORPHAN_PAYOUT": "A credit typed as winnings with no bet behind it - often a manual/back-office credit "
                     "disguised as a win.",
    "VOID_OVERPAID": "A cancelled bet should return the stake only.",
    "BALANCE_DRIFT": "The balance was changed directly, outside the transaction ledger. Every shilling should "
                     "have a ledger line.",
    "RECORD_INFLATED": "The bet row itself was edited or mis-calculated.",
    "PAID_BEFORE_SETTLE": "Timestamps out of order - clock skew, or a credit that preceded its justification.",
    "WON_NOT_PAID": "Not a theft risk to the house, but a regulatory/complaint risk.",
}


# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------
def to_dec(v) -> Decimal | None:
    if v is None:
        return None
    if isinstance(v, Decimal):
        return v
    if isinstance(v, int):
        return Decimal(v)
    if isinstance(v, float):
        return Decimal(str(v))
    try:                                   # fast path: already a clean number
        d = Decimal(v)
        return d if d.is_finite() else None
    except (InvalidOperation, TypeError, ValueError):
        pass
    s = re.sub(r"[^0-9.\-]", "", str(v))
    if s in ("", "-", ".", "-."):
        return None
    try:
        return Decimal(s)
    except InvalidOperation:
        return None


_TS_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d",
               "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y",
               "%d-%m-%Y %H:%M:%S", "%d-%m-%Y %H:%M", "%d-%m-%Y")     # M-Pesa org portal uses dd-mm-yyyy


def to_ts(v) -> datetime | None:
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        return v.replace(tzinfo=None)
    try:                                   # fast path (C): ISO-8601 incl. 'YYYY-MM-DD HH:MM:SS'
        d = datetime.fromisoformat(v) if isinstance(v, str) else None
        if d is not None:
            return d.replace(tzinfo=None)
    except ValueError:
        pass
    s = str(v).strip().replace("Z", "")
    s = re.sub(r"[+-]\d{2}:?\d{2}$", "", s)
    s = s.split(".")[0]
    for f in _TS_FORMATS:
        try:
            return datetime.strptime(s, f)
        except ValueError:
            continue
    return None


def _key(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, int):
        return str(v)
    s = str(v).strip()
    if "." in s and re.fullmatch(r"-?\d+\.0+", s):
        s = s.split(".")[0]
    return s or None


def mapping_fingerprint(mapping: dict) -> str:
    return hashlib.sha256(json.dumps(mapping, sort_keys=True).encode()).hexdigest()


def _money(d: Decimal) -> str:
    return f"{d.quantize(Decimal('0.01')):,}"


# ---------------------------------------------------------------------------
# Streaming scan
# ---------------------------------------------------------------------------
# Memory design: wallet transactions are streamed FIRST and only the rows that
# matter are kept (payout/refund credits keyed by bet, deposit receipts, a running
# net per customer). Stake debits - the bulk of any ledger - are counted, never
# stored. Bets are then streamed past that index and checked one at a time, so
# the bets table is never held in memory either.
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


# Which evidence fields identify a case, so the same problem keeps the same ID
# from one run to the next (used by the continuous watchdog to tell NEW from OLD).
CASE_KEY = {
    "PAID_WRONG_ACCOUNT": ("bet", "txn"),
    "ORPHAN_PAYOUT": ("txn",),
    "DUPLICATE_RECEIPT": ("receipt",),
    "BALANCE_DRIFT": ("user",),
}
MAX_KEYS = 100_000          # per check; beyond this the watchdog notes it lost precision
NEW_SAMPLES = 50            # evidence kept per check for cases not seen in the previous run


def case_key(code: str, ev: dict) -> str:
    return "/".join(str(ev.get(f)) for f in CASE_KEY.get(code, ("bet",)))


class _Hits:
    def __init__(self, known: dict[str, set] | None = None):
        self.cases: dict[str, list] = defaultdict(list)
        self.counts: dict[str, int] = defaultdict(int)
        self.at_risk: dict[str, Decimal] = defaultdict(lambda: ZERO)
        self.keys: dict[str, set] = defaultdict(set)
        self.known = known
        self.new_cases: dict[str, list] = defaultdict(list)
        self.truncated: set = set()

    def add(self, code, excess, **ev):
        self.counts[code] += 1
        if len(self.cases[code]) < SAMPLES:
            self.cases[code].append(ev)
        if excess:
            self.at_risk[code] += excess
        k = case_key(code, ev)
        if len(self.keys[code]) < MAX_KEYS:
            self.keys[code].add(k)
        else:
            self.truncated.add(code)
        if self.known is not None and k not in self.known.get(code, ()) and len(self.new_cases[code]) < NEW_SAMPLES:
            self.new_cases[code].append(dict(ev, case=k))

    def findings(self) -> list[dict]:
        out = []
        for code in sorted(self.counts, key=lambda c: (SEV_ORDER.index(SEVERITY[c]), c)):
            out.append({"code": code, "severity": SEVERITY[code], "title": TITLE[code], "means": MEANS[code],
                        "count": self.counts[code],
                        "money_at_risk": _money(self.at_risk[code]) if self.at_risk[code] else None,
                        "samples": self.cases[code]})
        return out


FP_BLOCK = 100
FP_MASK = (1 << 128) - 1


def scan(db: ReadOnlyDB, mapping: dict, since: str | None, tol: Decimal,
         won_grace: timedelta = timedelta(hours=24), known: dict[str, set] | None = None,
         fingerprint: bool = False, prev_max_id: int | None = None) -> dict:
    bm, tm, balm = mapping.get("bets"), mapping.get("transactions"), mapping.get("balances")
    if not bm or not tm:
        raise ValueError("mapping must define both 'bets' and 'transactions' (edit the map file)")
    # Every mapped column must still exist. Without this, a renamed column can read
    # back as a constant (SQLite treats an unknown "name" as a string literal) and the
    # scan would silently see nothing - a blind watchdog that reports "all clear".
    for sec in (bm, tm, balm):
        if not sec:
            continue
        have = {c.lower() for c in db.columns(sec["table"])}
        if not have:
            raise ValueError(f"table {sec['table']!r} not found or has no readable columns")
        missing = [c for c in sec["columns"].values() if c.lower() not in have]
        if missing:
            raise ValueError(f"table {sec['table']!r} no longer has column(s) {', '.join(missing)}")
    hits = _Hits(known)

    # ---- pass 1: wallet transactions (streamed) ---------------------------
    tc = tm["columns"]
    tmap = {str(k): v for k, v in (tm.get("type_values") or {}).items()}
    dmap = {str(k): v for k, v in (tm.get("direction_values") or {}).items()}
    sbt = tm.get("sign_by_type") or {}
    mode = tm.get("amount_sign", "by_type")
    pat = re.compile(tm["bet_ref_pattern"]) if tm.get("bet_ref_pattern") else None
    c_amt, c_type, c_dir = tc["amount"], tc["type"], tc.get("direction")
    c_id, c_user, c_ref, c_rc, c_ts = (tc.get(k) for k in ("id", "user", "bet_ref", "receipt", "created_at"))
    want_net = balm is not None

    payouts: dict[str, list] = defaultdict(list)     # bet -> [(txn, amount, user, ts, type_raw)]
    refunds: dict[str, Decimal] = defaultdict(lambda: ZERO)
    receipts: dict[str, tuple] = {}                  # receipt -> (txn, amount, user) of first sighting
    dup_receipts: dict[str, list] = defaultdict(list)
    net: dict[str, Decimal] = defaultdict(lambda: ZERO)
    unsigned_users: set = set()
    cats: dict[str, int] = defaultdict(int)
    n_tx = unsigned = 0
    latest_ts = None

    # History fingerprint (watch mode): wallet rows are grouped by id into blocks of
    # FP_BLOCK and each block gets an order-independent hash of its rows. Old rows
    # must never change, so a block whose hash moves = an edited or deleted record,
    # even if the row count was padded back up with new inserts.
    fp_on = bool(fingerprint and c_id)
    fp_cols = sorted(set(tc.values()))
    blocks: dict[int, list] = {}
    edge = [0, 0]                                    # rows <= prev_max_id in the previous run's last block
    edge_b = (prev_max_id // FP_BLOCK) if prev_max_id is not None else None
    max_id = None
    blake = hashlib.blake2b

    for i, r in enumerate(db.iter_select(tm["table"], list(dict.fromkeys(tc.values())))):
        if fp_on:
            try:
                n = int(r.get(c_id))
            except (TypeError, ValueError):
                fp_on = False                            # non-numeric ids: fall back to row counts
            else:
                h = int.from_bytes(blake(repr(tuple(map(r.get, fp_cols))).encode(),
                                         digest_size=16).digest(), "big")
                b = n // FP_BLOCK
                acc = blocks.get(b)
                if acc is None:
                    acc = blocks[b] = [0, 0]
                acc[0] += 1
                acc[1] = (acc[1] + h) & FP_MASK
                if b == edge_b and n <= prev_max_id:
                    edge[0] += 1
                    edge[1] = (edge[1] + h) & FP_MASK
                if max_id is None or n > max_id:
                    max_id = n
        amt = to_dec(r.get(c_amt))
        if amt is None:
            continue
        n_tx += 1
        typ_raw = r.get(c_type)
        cat = tmap.get(str(typ_raw), "other")
        cats[cat] += 1
        amt = abs(amt) if mode != "signed" else amt
        user = _key(r.get(c_user)) if c_user else None

        if want_net and user is not None:
            if mode == "signed":
                signed = amt
            else:
                sgn = dmap.get(str(r.get(c_dir)), "?") if mode == "by_direction" else sbt.get(cat, "?")
                signed = amt if sgn == "+" else (-amt if sgn == "-" else None)
            if signed is None:
                unsigned += 1
                unsigned_users.add(user)
            else:
                net[user] += signed

        if cat not in ("payout", "refund", "deposit"):
            continue                                     # stakes etc: counted, not stored
        tid = _key(r.get(c_id)) if c_id else f"row{i + 1}"
        amt = abs(amt)
        ts = to_ts(r.get(c_ts)) if c_ts else None
        if ts and (latest_ts is None or ts > latest_ts):
            latest_ts = ts
        if cat == "deposit":
            rc = _key(r.get(c_rc)) if c_rc else None
            if rc:
                if rc in receipts:
                    dup_receipts[rc].append((tid, amt, user))
                else:
                    receipts[rc] = (tid, amt, user)
            continue
        ref = _key(r.get(c_ref)) if c_ref else None
        if ref and pat:
            m = pat.search(ref)
            ref = m.group(1) if m else ref
        if cat == "payout":
            if ref:
                payouts[ref].append((tid, amt, user, ts, typ_raw))
            else:
                hits.add("ORPHAN_PAYOUT", amt, txn=tid, user=user, amount=_money(amt), bet_ref="(none)",
                         type=typ_raw)
        elif ref:
            refunds[ref] += amt

    del receipts
    for rc, extra in dup_receipts.items():
        hits.add("DUPLICATE_RECEIPT", sum((x[1] for x in extra), ZERO), receipt=rc, times=len(extra) + 1,
                 txns=[x[0] for x in extra])

    # ---- pass 2: bets (streamed, checked one at a time) --------------------
    bc = bm["columns"]
    smap = {str(k): v for k, v in (bm.get("status_values") or {}).items()}
    since_b = (bc["created_at"], since) if since and "created_at" in bc else None
    g = bc.get
    statuses: dict[str, int] = defaultdict(int)
    seen_with_payout: set = set()
    n_bets = 0

    for r in db.iter_select(bm["table"], list(dict.fromkeys(bc.values())), where_since=since_b):
        bid = _key(r.get(bc["id"]))
        if bid is None:
            continue
        n_bets += 1
        status_raw = r.get(g("status"))
        st = smap.get(str(status_raw), "unknown")
        statuses[st] += 1
        plist = payouts.get(bid)
        if plist:
            seen_with_payout.add(bid)
        if not plist and st not in ("won", "void"):
            continue                                     # nothing to check: unpaid loss/pending
        user = _key(r.get(g("user"))) if "user" in bc else None
        stake = to_dec(r.get(bc["stake"])) or ZERO
        odds = to_dec(r.get(g("odds"))) if "odds" in bc else None
        potential = to_dec(r.get(g("potential"))) if "potential" in bc else None
        settled_at = to_ts(r.get(g("settled_at"))) if "settled_at" in bc else None
        max_return = (stake * odds) if odds else potential
        plist = plist or []
        paid = sum((p[1] for p in plist), ZERO)
        txn_ids = [p[0] for p in plist]

        if plist and st == "lost":
            hits.add("PAID_ON_LOSS", paid, bet=bid, user=user, status=status_raw, stake=_money(stake),
                     paid=_money(paid), txns=txn_ids)
        if plist and st == "pending":
            hits.add("PAID_BEFORE_RESULT", paid, bet=bid, user=user, status=status_raw, paid=_money(paid),
                     txns=txn_ids)
        if len(plist) > 1:
            biggest = max(p[1] for p in plist)
            hits.add("DUPLICATE_PAYOUT", paid - biggest, bet=bid, user=user, times_paid=len(plist),
                     paid=_money(paid), txns=txn_ids)
        if plist and st in ("won", "cashout") and max_return is not None:
            single = max(p[1] for p in plist)
            if single > max_return + tol:
                hits.add("OVERPAYMENT", single - max_return, bet=bid, user=user, stake=_money(stake),
                         odds=str(odds) if odds else "-", allowed=_money(max_return), paid=_money(single),
                         txns=txn_ids)
        if user:
            for p in plist:
                if p[2] and p[2] != user:
                    hits.add("PAID_WRONG_ACCOUNT", p[1], bet=bid, bettor=user, credited=p[2],
                             amount=_money(p[1]), txn=p[0])
        if st == "void":
            back = paid + refunds.get(bid, ZERO)
            if back > stake + tol:
                hits.add("VOID_OVERPAID", back - stake, bet=bid, user=user, stake=_money(stake),
                         returned=_money(back))
        if st == "won" and odds and "payout" in bc:
            pf = to_dec(r.get(bc["payout"]))
            if pf is not None and pf > stake * odds + tol:
                hits.add("RECORD_INFLATED", None, bet=bid, stake=_money(stake), odds=str(odds),
                         record_says=_money(pf), should_be=_money(stake * odds))
        if settled_at and plist:
            early = [p for p in plist if p[3] and p[3] < settled_at - timedelta(minutes=5)]
            if early:
                hits.add("PAID_BEFORE_SETTLE", None, bet=bid, settled_at=str(settled_at),
                         credited_at=str(min(p[3] for p in early)), txns=[p[0] for p in early])
        if st == "won" and not plist:
            if not settled_at or not latest_ts or latest_ts - settled_at > won_grace:
                hits.add("WON_NOT_PAID", None, bet=bid, user=user, owed=_money(max_return or ZERO))

    # Payout credits whose bet never appeared in the bets table.
    if not since_b:
        for ref, plist in payouts.items():
            if ref not in seen_with_payout:
                for p in plist:
                    hits.add("ORPHAN_PAYOUT", p[1], txn=p[0], user=p[2], amount=_money(p[1]), bet_ref=ref,
                             type=p[4])

    # ---- pass 3: wallet balances vs ledger ---------------------------------
    n_wallets = 0
    if balm:
        bl = balm["columns"]
        for r in db.iter_select(balm["table"], list(dict.fromkeys(bl.values()))):
            u = _key(r.get(bl["user"]))
            if u is None:
                continue
            n_wallets += 1
            if u in unsigned_users:
                continue
            bal = to_dec(r.get(bl["balance"])) or ZERO
            diff = bal - net.get(u, ZERO)
            if abs(diff) > tol:
                hits.add("BALANCE_DRIFT", diff if diff > 0 else None, user=u, balance=_money(bal),
                         ledger_says=_money(net.get(u, ZERO)), difference=_money(diff))

    return {"findings": hits.findings(), "total_at_risk": _money(sum(hits.at_risk.values(), ZERO)),
            "drift_checked": balm is not None, "windowed": since_b is not None, "unsigned": unsigned,
            "scanned": {"bets": n_bets, "transactions": n_tx, "wallets": n_wallets},
            "statuses": dict(statuses), "cats": dict(cats),
            "case_keys": {c: sorted(v) for c, v in hits.keys.items()},
            "new_cases": dict(hits.new_cases), "keys_truncated": sorted(hits.truncated),
            "txn_fingerprint": ({"block": FP_BLOCK, "max_id": max_id,
                                 "blocks": {str(b): [a[0], format(a[1], "032x")] for b, a in sorted(blocks.items())},
                                 "edge_of": prev_max_id, "edge": [edge[0], format(edge[1], "032x")]}
                                if fp_on and max_id is not None else None)}


# ---------------------------------------------------------------------------
# Public entry: authorized, audited
# ---------------------------------------------------------------------------
def run_ledger(authz: Authorizer, db: ReadOnlyDB, mapping: dict, since: str | None = None,
               known: dict[str, set] | None = None, fingerprint: bool = False,
               prev_max_id: int | None = None) -> dict:
    d = authz.authorize_db(ACTION, db.label)
    if not d:
        return {"check": "ledger", "target": db.label, "authorized": False, "reason": d.reason}

    fp = mapping_fingerprint(mapping)
    authz.audit.append("note", action=ACTION, target=db.label, decision="INFO",
                       detail={"mapping_sha256": fp, "reviewed_by": mapping.get("reviewed_by") or "",
                               "bets_table": (mapping.get("bets") or {}).get("table"),
                               "transactions_table": (mapping.get("transactions") or {}).get("table"),
                               "balances_table": (mapping.get("balances") or {}).get("table"),
                               "since": since})

    tol = to_dec(mapping.get("tolerance", "1.00")) or Decimal("1.00")
    rec = scan(db, mapping, since, tol, known=known, fingerprint=fingerprint, prev_max_id=prev_max_id)
    cats, statuses, unsigned, windowed = rec["cats"], rec["statuses"], rec["unsigned"], rec["windowed"]

    coverage = []
    if cats.get("other"):
        coverage.append(f"{cats['other']} transaction(s) have a type AEGIS could not interpret - "
                        "they were excluded from payout checks (fix type_values in the map).")
    if statuses.get("unknown"):
        coverage.append(f"{statuses['unknown']} bet(s) have an uninterpreted status - excluded from win/loss checks.")
    if unsigned:
        coverage.append(f"{unsigned} transaction(s) could not be signed +/-; their owners were skipped in the "
                        "balance-drift check.")
    if not rec["drift_checked"]:
        coverage.append("No balance table mapped - balance-drift check NOT run.")
    if windowed:
        coverage.append(f"Bets limited to those placed since {since}; orphan-payout check skipped for the window.")
    can_write = getattr(db, "can_write", None)
    if can_write:
        coverage.append("LEAST-PRIVILEGE FINDING: the database account given to AEGIS can CHANGE data. AEGIS held it "
                        "read-only at the session level, but a monitoring account should only be able to SELECT - "
                        "create a dedicated read-only user.")
    elif can_write is None and db.engine not in ("sqlite", "csv"):
        coverage.append("Could not confirm whether the database account is read-only.")
    if not mapping.get("reviewed_by"):
        coverage.append("Mapping was auto-detected and NOT confirmed by a person - treat findings as leads "
                        "until the map is reviewed.")

    out = {
        "check": "ledger",
        "target": db.label,
        "authorized": True,
        "engine": db.engine,
        "mapping_sha256": fp,
        "account_can_write": can_write,
        "mapping_reviewed_by": mapping.get("reviewed_by") or "",
        "currency": mapping.get("currency", "KES"),
        "scanned": rec["scanned"],
        "bet_status_mix": dict(statuses),
        "txn_type_mix": dict(cats),
        "ledger_findings": rec["findings"],
        "total_at_risk": rec["total_at_risk"],
        "coverage": coverage,
        # Plain strings so the generic Findings table in the report picks them up too.
        "findings": [f"[{f['severity']}] {f['title']}: {f['count']} case(s)"
                     + (f", {mapping.get('currency', 'KES')} {f['money_at_risk']} at risk" if f["money_at_risk"] else "")
                     for f in rec["findings"]],
    }
    # Case IDs can run to thousands: the audit log records their hash (evidence of
    # exactly which cases existed at this moment), the full list goes to the caller.
    keys = rec["case_keys"]
    out["case_keys_sha256"] = hashlib.sha256(json.dumps(keys, sort_keys=True).encode()).hexdigest()
    tfp = rec["txn_fingerprint"]
    if tfp:
        out["history_fingerprint_sha256"] = hashlib.sha256(json.dumps(tfp["blocks"], sort_keys=True).encode()).hexdigest()
    authz.audit.append("check", action=ACTION, target=db.label, decision="DONE", detail=out)
    return dict(out, case_keys=keys, new_cases=rec["new_cases"], keys_truncated=rec["keys_truncated"],
                txn_fingerprint=tfp)
