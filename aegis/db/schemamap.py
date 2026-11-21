"""
Schema mapper - "which tables hold the money?"

Every white-label sportsbook names things differently: `bets`, `sb_bet_slips`,
`tickets`, `coupons`; `wallet_transactions`, `ledger`, `account_movements`...
This module scores every table and column against what a betting ledger must
contain and proposes a MAPPING:

    bets          id, user, stake, odds, status, payout, potential, settled_at, created_at
    transactions  id, user, amount, type, bet_ref, receipt, direction, created_at
    balances      user, balance                    (optional - enables drift check)

It also samples the real values in status/type columns and proposes what each
one means (e.g. 'BET_WIN' -> payout, 'W' -> won, 'B2C' -> withdrawal).

The mapping is written to a JSON file a human REVIEWS and signs off
(`reviewed_by`). AEGIS never silently trusts its own guess: anything uncertain
is listed under `review_required`, and the report states whether the mapping
was human-confirmed.
"""
from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation

from .connect import ReadOnlyDB

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------
TABLE_WORDS = {
    "bets": ["bet", "bets", "slip", "slips", "betslip", "ticket", "tickets", "wager", "wagers", "coupon", "coupons"],
    "transactions": ["transaction", "transactions", "txn", "txns", "trans", "ledger", "wallet", "movement",
                     "movements", "journal", "payment", "payments", "statement"],
    "balances": ["wallet", "wallets", "balance", "balances", "account", "accounts", "user", "users",
                 "customer", "customers", "punter", "punters", "player", "players", "member", "members"],
}

USER_COLS = ["user_id", "customer_id", "player_id", "punter_id", "account_id", "member_id", "client_id",
             "wallet_id", "msisdn", "user", "customer", "player", "punter", "uid"]

ROLE_COLS = {
    "bets": {
        "id": ["bet_id", "slip_id", "betslip_id", "ticket_id", "coupon_id", "id", "bet_ref", "ticket_no",
               "slip_no", "bet_no"],
        "user": USER_COLS,
        "stake": ["stake", "stake_amount", "bet_amount", "wager", "wager_amount", "amount", "stake_kes"],
        "odds": ["odds", "total_odds", "total_odd", "combined_odds", "price", "odd", "odds_value", "final_odds"],
        "status": ["status", "bet_status", "slip_status", "ticket_status", "result", "outcome", "state",
                   "settlement_status"],
        "payout": ["payout", "payout_amount", "win_amount", "winnings", "won_amount", "amount_won",
                   "paid_amount", "return_amount", "settled_amount"],
        "potential": ["potential_win", "possible_win", "potential_payout", "possible_payout", "max_win",
                      "potential_return", "to_win"],
        "settled_at": ["settled_at", "settled_on", "settlement_date", "settled_date", "resulted_at",
                       "settled_time", "date_settled"],
        "created_at": ["created_at", "created_on", "placed_at", "placed_on", "bet_date", "created",
                       "date_created", "timestamp"],
    },
    "transactions": {
        "id": ["txn_id", "transaction_id", "trans_id", "ledger_id", "entry_id", "id"],
        "user": USER_COLS,
        "amount": ["amount", "txn_amount", "transaction_amount", "value", "amount_kes", "trans_amount"],
        "type": ["txn_type", "transaction_type", "trans_type", "type", "kind", "category", "entry_type",
                 "reason", "narration", "description"],
        "bet_ref": ["bet_id", "slip_id", "betslip_id", "ticket_id", "coupon_id", "bet_ref", "reference",
                    "ref", "ref_id", "reference_id", "external_ref", "source_ref"],
        "receipt": ["mpesa_receipt", "mpesa_receipt_number", "receipt", "receipt_no", "receipt_number",
                    "mpesa_code", "mpesa_ref", "trans_code", "transaction_code", "mpesa_trans_id"],
        "direction": ["direction", "dr_cr", "drcr", "cr_dr", "entry_side", "side", "sign", "debit_credit"],
        "created_at": ["created_at", "created_on", "txn_date", "transaction_date", "trans_time", "timestamp",
                       "created", "date", "posted_at"],
    },
    "balances": {
        "user": USER_COLS + ["id"],
        "balance": ["balance", "wallet_balance", "current_balance", "available_balance", "bal", "amount"],
    },
}

REQUIRED = {
    "bets": ["id", "stake", "status"],
    "transactions": ["amount", "type"],
    "balances": ["user", "balance"],
}

# value -> meaning rules. Checked in order; first hit wins.
TYPE_RULES = [
    # A failed M-Pesa withdrawal handed back to the wallet. Checked first so it is not
    # read as a plain withdrawal or a bet refund (the M-Pesa guard needs to tell them apart).
    ("withdrawal_reversal", ["withdraw_reversal", "withdrawal_reversal", "withdraw_refund", "withdrawal_refund",
                             "withdraw_fail", "withdrawal_fail", "withdraw_reverse", "b2c_reversal", "b2c_refund",
                             "b2c_fail", "b2c_reverse", "reversal_b2c", "reverse_withdraw"]),
    ("refund",["refund", "void", "cancel", "rollback", "bet_reversal", "stake_return"]),
    ("bonus", ["bonus", "freebet", "free_bet", "promo", "cashback", "reward"]),
    ("withdrawal", ["withdraw", "b2c", "mpesa_out", "payout_mpesa", "cashout_mpesa"]),
    ("deposit", ["deposit", "topup", "top_up", "c2b", "stk", "mpesa_in", "paybill", "load", "funding"]),
    ("adjustment", ["adjust", "manual", "correction", "admin", "writeoff", "write_off"]),
    ("payout", ["win", "won", "payout", "prize", "jackpot", "settle", "cashout", "cash_out", "return"]),
    ("stake", ["stake", "bet", "wager", "place", "debit"]),
]

STATUS_RULES = [
    ("cashout", ["cashout", "cash_out", "cashed"]),
    ("void", ["void", "cancel", "refund", "push", "reject", "declin"]),
    ("won", ["won", "win", "winner", "paid"]),
    ("lost", ["lost", "lose", "loss", "loser"]),
    ("pending", ["pending", "open", "running", "unsettled", "accepted", "placed", "new", "active", "live"]),
]
SHORT_STATUS = {"w": "won", "l": "lost", "v": "void", "p": "pending", "o": "pending", "c": "void"}

DIRECTION_RULES = {"+": ["cr", "credit", "c", "in", "+", "1"], "-": ["dr", "debit", "d", "out", "-", "-1"]}

SIGN_BY_TYPE = {"deposit": "+", "payout": "+", "refund": "+", "bonus": "+", "withdrawal_reversal": "+",
                "withdrawal": "-", "stake": "-", "adjustment": "?", "other": "?"}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(s).lower()).strip("_")


def _tokens(s: str) -> list[str]:
    return [t for t in _norm(s).split("_") if t]


def classify_value(value, rules) -> str:
    v = _norm(value)
    if not v:
        return "other"
    for meaning, words in rules:
        for w in words:
            if v == w or v.startswith(w) or f"_{w}" in f"_{v}":
                return meaning
    return "other"


def classify_status(value) -> str:
    v = _norm(value)
    if v in SHORT_STATUS:
        return SHORT_STATUS[v]
    c = classify_value(value, STATUS_RULES)
    return c if c != "other" else "unknown"


def classify_direction(value) -> str:
    v = _norm(value) or str(value).strip()
    for sign, words in DIRECTION_RULES.items():
        if v in words:
            return sign
    return "?"


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def _col_score(col: str, synonyms: list[str]) -> int:
    n = _norm(col)
    if n in synonyms:
        return 10 - min(synonyms.index(n), 6)          # earlier synonym = stronger
    toks = set(_tokens(col))
    for s in synonyms:
        st = set(s.split("_"))
        if st and st <= toks:
            return 3
    return 0


def map_columns(kind: str, cols: list[str]) -> tuple[dict, int]:
    roles = ROLE_COLS[kind]
    # Score every (role, col) pair, then assign greedily, best first, one col per role.
    pairs = []
    for role, syns in roles.items():
        for c in cols:
            sc = _col_score(c, syns)
            if sc:
                pairs.append((sc, role, c))
    pairs.sort(reverse=True)
    chosen, used = {}, set()
    for sc, role, c in pairs:
        if role in chosen or c in used:
            continue
        chosen[role] = c
        used.add(c)
    score = sum(_col_score(chosen[r], roles[r]) for r in chosen)
    return chosen, score


def score_table(kind: str, table: str, cols: list[str]) -> tuple[int, dict]:
    mapping, col_score = map_columns(kind, cols)
    missing = [r for r in REQUIRED[kind] if r not in mapping]
    name_hit = any(t in TABLE_WORDS[kind] for t in _tokens(table))
    score = col_score + (15 if name_hit else 0) - 25 * len(missing)
    if kind == "balances" and len(cols) > 25:
        score -= 5          # prefer a narrow wallet table over a wide users table
    return score, mapping


def _dec(v) -> Decimal | None:
    if v is None:
        return None
    s = re.sub(r"[^0-9.\-]", "", str(v))
    if s in ("", "-", ".", "-."):
        return None
    try:
        return Decimal(s)
    except InvalidOperation:
        return None


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------
def propose(db: ReadOnlyDB) -> dict:
    tables = db.tables()
    cols = {t: db.columns(t) for t in tables}
    review: list[str] = []

    best = {}
    ranking = {}
    for kind in ("bets", "transactions", "balances"):
        scored = []
        for t in tables:
            s, m = score_table(kind, t, cols[t])
            scored.append((s, t, m))
        scored.sort(key=lambda x: x[0], reverse=True)
        ranking[kind] = [(t, s) for s, t, _ in scored[:3]]
        # A table can only fill one role; bets & transactions win over balances.
        taken = {v["table"] for v in best.values()}
        for s, t, m in scored:
            if t in taken:
                continue
            if s > 0:
                best[kind] = {"table": t, "columns": m, "score": s}
            break

    out: dict = {
        "aegis_ledger_map": 1,
        "database": db.label,
        "engine": db.engine,
        "currency": "KES",
        "tolerance": "1.00",
        "reviewed_by": "",
        "tables_seen": len(tables),
        "candidates": ranking,
    }

    # ---- bets --------------------------------------------------------------
    b = best.get("bets")
    if not b:
        review.append("No bets/slips table found - set bets.table and bets.columns by hand.")
        out["bets"] = None
    else:
        bc = b["columns"]
        status_values = {}
        if "status" in bc:
            for v in db.sample_distinct(b["table"], bc["status"], 60):
                if v is not None:
                    status_values[str(v)] = classify_status(v)
            unk = [k for k, m in status_values.items() if m == "unknown"]
            if unk:
                review.append(f"bets.status_values: could not interpret {unk} - set each to "
                              "won/lost/void/pending/cashout.")
        if "odds" not in bc:
            review.append("bets: no odds column found - overpayment check will use the potential-win column "
                          "if present, otherwise it is skipped.")
        if "user" not in bc:
            review.append("bets: no user/customer column - 'paid to the wrong account' check is skipped.")
        out["bets"] = {"table": b["table"], "columns": bc, "status_values": status_values,
                       "rows": db.row_count(b["table"])}

    # ---- transactions ------------------------------------------------------
    t = best.get("transactions")
    if not t:
        review.append("No wallet-transactions table found - set transactions.table by hand.")
        out["transactions"] = None
    else:
        tc = t["columns"]
        type_values = {}
        for v in db.sample_distinct(t["table"], tc["type"], 80):
            if v is not None:
                type_values[str(v)] = classify_value(v, TYPE_RULES)
        other = [k for k, m in type_values.items() if m == "other"]
        if other:
            review.append(f"transactions.type_values: could not interpret {other} - set each to "
                          "deposit/stake/payout/refund/withdrawal/withdrawal_reversal/bonus/adjustment.")
        if "payout" not in type_values.values():
            review.append("transactions: no type value looks like a WIN/PAYOUT credit - check type_values.")
        if any(k for k, m in type_values.items() if m == "payout" and "cashout" in _norm(k)):
            review.append("transactions: a 'cashout' type was read as an early bet payout - "
                          "change it to 'withdrawal' if it means an M-Pesa withdrawal.")

        # How are amounts signed?
        amounts = [_dec(v) for v in db.sample_distinct(t["table"], tc["amount"], 500)]
        has_neg = any(a is not None and a < 0 for a in amounts)
        direction_values = {}
        if has_neg:
            sign_mode = "signed"
        elif "direction" in tc:
            sign_mode = "by_direction"
            for v in db.sample_distinct(t["table"], tc["direction"], 20):
                if v is not None:
                    direction_values[str(v)] = classify_direction(v)
        else:
            sign_mode = "by_type"

        # Does bet_ref line up with bet ids? Try raw, then 'digits only'.
        ref_pattern = None
        if b and "bet_ref" in tc and "id" in b["columns"]:
            bet_ids = {str(x).strip() for x in db.sample_distinct(b["table"], b["columns"]["id"], 5000)}
            refs = [str(x).strip() for x in db.sample_distinct(t["table"], tc["bet_ref"], 500) if x is not None]
            if refs:
                raw = sum(1 for r in refs if r in bet_ids) / len(refs)
                digits = sum(1 for r in refs if re.search(r"(\d+)", r)
                             and re.search(r"(\d+)", r).group(1) in bet_ids) / len(refs)
                if digits > raw + 0.2:
                    ref_pattern = r"(\d+)"
                if max(raw, digits) < 0.3:
                    review.append(f"transactions.bet_ref ({tc['bet_ref']}) rarely matches a bet id "
                                  f"({max(raw, digits):.0%}) - confirm the column or set bet_ref_pattern.")
        elif "bet_ref" not in tc:
            review.append("transactions: no bet reference column - payouts cannot be tied to bets; "
                          "most money checks will be skipped.")

        out["transactions"] = {"table": t["table"], "columns": tc, "type_values": type_values,
                               "amount_sign": sign_mode, "direction_values": direction_values,
                               "sign_by_type": SIGN_BY_TYPE, "bet_ref_pattern": ref_pattern,
                               "rows": db.row_count(t["table"])}

    # ---- balances (optional) ---------------------------------------------
    bal = best.get("balances")
    if bal:
        out["balances"] = {"table": bal["table"], "columns": bal["columns"], "rows": db.row_count(bal["table"])}
    else:
        out["balances"] = None
        review.append("No wallet-balance table found - the balance-drift check will be skipped.")

    out["review_required"] = review
    return out
