# Settlement / money-logic testing — manual procedure

The betting risk your client fears (an account credited on a loss, or credited too much) lives in
**business logic**, not in a scanner-findable misconfiguration. AEGIS verifies the *endpoints* are
hardened (read-only). Confirming the *logic* is safe is a **manual, supervised** procedure — it is
kept out of the automated tool on purpose, because an autonomous tool moving money is the exact
operator-risk failure mode we are defending the client against.

Run this only when **all** of these are true:
- The scope file authorizes it and names the settlement endpoints.
- The client has provisioned a **dedicated TEST account** with **play/segregated funds** (never a
  real customer wallet, never the live float).
- You have a **per-action authorization** (a named approver signs off on destructive test cases).
- A client contact is on the call and the test window is agreed.

Capture every request/response as evidence and record it against the engagement.

## Test cases (each is a hypothesis to disprove on the TEST account)

| # | Flaw class | Safe test on the test account | Pass = |
|---|---|---|---|
| 1 | Client-authoritative payout | Place a losing bet; in the settle request, tamper `outcome`, `odds`, `payout`, `stake`. | Server ignores client values; wallet reflects the true (losing) result. |
| 2 | Missing idempotency | Capture a legitimate settle/callback; replay it 5× with the same id. | Credited **once**; replays rejected. |
| 3 | Race / TOCTOU | Fire settle + cancel (and N concurrent settles) within milliseconds. | No double credit; stake not refunded *and* paid. |
| 4 | Sign / decimal handling | Submit negative `stake`, huge `payout`, fractional-cent values. | Rejected by server-side constraints; no credit from a loss. |
| 5 | State-machine bypass | Try to settle **before** the event resolves; try to re-settle a settled bet. | One-way state; both refused. |
| 6 | Forged result callback | POST a self-made "you won" event to the provider callback **without** a valid signature. | Rejected — signature required and checked. |
| 7 | IDOR | Try to settle another (test) account's bet into your test wallet. | Refused — ownership enforced. |

## Rules

- **Test account only.** If you cannot prove a case without touching a real wallet or the live float, **stop** and escalate — do not proceed.
- **Reconcile after every case.** The client confirms the ledger balances and no real money moved.
- **One case at a time**, logged, with the client contact present.
- Anything that *would* move real money is reported as a finding and demonstrated **in theory / on staging**, not executed against production.

## What "good" looks like (the fixes you'll recommend)

1. Server decides stake/odds/outcome/payout from stored state + trusted result feed; the client sends only a bet id.
2. Signed, idempotent result callbacks (verified signature + single-use event id).
3. Double-entry ledger with a hard invariant: every settlement nets to `payout − stake` and the float balances.
4. Atomic settlement inside a locked transaction; one-way `placed → resolved → settled` state machine.
5. Positive, bounded, decimal amounts capped at `stake × max_odds`.
6. Anomaly detection: win-rate outliers, balance growth without deposits, duplicate settlement calls.
