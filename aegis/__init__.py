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

__version__ = "1.1.0"
TOOL_NAME = "AEGIS"

_BUILD = None


def build_info() -> dict:
    """Which exact build is running: version + SHA-256 of the code.

    Recorded in the audit log at every preflight, so counsel can later prove which
    build of the tool produced the evidence (and that it was not modified). For the
    single-file release the hash is of the .pyz itself, matching SHA256SUMS."""
    global _BUILD
    if _BUILD is not None:
        return _BUILD
    import hashlib
    import os
    pkg = os.path.dirname(os.path.abspath(__file__))
    archive = os.path.dirname(pkg)
    h = hashlib.sha256()
    if os.path.isfile(archive):                         # running from aegis-x.y.z.pyz
        kind = "pyz"
        with open(archive, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    else:
        kind = "source"
        for root, dirs, files in os.walk(pkg):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            for f in sorted(files):
                if f.endswith(".py"):
                    p = os.path.join(root, f)
                    h.update(os.path.relpath(p, pkg).replace("\\", "/").encode())
                    with open(p, "rb") as fh:
                        h.update(fh.read().replace(b"\r\n", b"\n"))
    _BUILD = {"tool": f"{TOOL_NAME} {__version__}", "kind": kind, "code_sha256": h.hexdigest(),
              "location": archive if kind == "pyz" else pkg}
    return _BUILD
