"""
AEGIS - Authorized Engagement & Guarded Inspection Suite
========================================================

A defensive, authorization-first assessment harness. It is the deliberate
counterpart to autonomous offensive tooling: NOTHING runs unless the target is
inside a signed scope and within the authorized window, and EVERY action is
written to a tamper-evident (hash-chained) audit log for legal review.

Design principles
-----------------
1. Authorization at every stage. Each check calls the Authorizer first. A denied
   action does not run; the denial itself is recorded.
2. Read-only by default. AEGIS inspects reachability, configuration and exposure.
   It does not exploit, move money, or alter state.
3. Full transparency. Requests identify themselves (honest User-Agent naming the
   engagement) so the client's blue team sees exactly what the authorized test is
   doing - the opposite of a covert tool.
4. Evidence first. The audit log is append-only and chained; `verify` re-derives
   the chain so counsel can confirm it was not edited after the fact.
"""

__version__ = "1.0.0"
TOOL_NAME = "AEGIS"
