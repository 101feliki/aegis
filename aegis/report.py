"""
Report builder.

Turns the audit log into a human-readable Markdown report for counsel and the
client: the authorization record, the chain-integrity verdict, a timeline of
every authorized and denied action, and the findings that need attention.
"""
from __future__ import annotations

import json
from collections import Counter

from .audit import AuditLog


def _load(path: str) -> list[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def build_markdown(audit_path: str) -> str:
    rows = _load(audit_path)
    ok, msg = AuditLog.verify(audit_path)
    header = rows[0] if rows else {}
    eng = header.get("engagement_id", "?")

    grants = sum(1 for r in rows if r.get("decision") == "GRANT")
    denies = sum(1 for r in rows if r.get("decision") == "DENY")
    all_checks = [r for r in rows if r.get("event") == "check"]
    # A watchdog / guard appends a check every cycle: report the LATEST result of each
    # (action, target, check) - the full history stays in the audit log.
    latest: dict = {}
    for r in all_checks:
        latest[(r.get("action"), r.get("target"), (r.get("detail") or {}).get("check"))] = r
    checks = sorted(latest.values(), key=lambda r: r.get("seq", 0))
    repeated = len(all_checks) - len(checks)

    findings = []
    for r in checks:
        det = r.get("detail", {})
        for f in det.get("findings", []):
            findings.append((r.get("target"), f))
        for ex in det.get("exposed", []):
            if ex["path"] == "/.well-known/security.txt":
                continue  # publishing security.txt is good practice, not an exposure
            findings.append((r.get("target"), f"exposed path {ex['path']} (HTTP 200, content verified)"))
        sup = det.get("soft_404_suppressed") or []
        if sup:
            findings.append((r.get("target"),
                             f"info: {len(sup)} path(s) returned HTTP 200 but were the site's catch-all page "
                             f"(soft-404) - not exposures, suppressed"))
        if det.get("cert_verified") is False:
            findings.append((r.get("target"), "TLS certificate did not validate"))
        internal = det.get("internal")
        if isinstance(internal, list) and internal:
            findings.append((r.get("target"), f"resolves to internal address(es): {', '.join(internal)}"))
        elif internal is True:
            findings.append((r.get("target"), "reachable internal host"))
        for cand in det.get("candidates", []):
            findings.append((cand.get("subdomain"),
                             f"possible origin-IP leak -> {cand.get('ip')} ({cand.get('why','').strip()})"))
        if det.get("check") == "tech":
            if det.get("note"):
                findings.append((r.get("target"), det["note"]))
            if det.get("leaked"):
                leaked = ", ".join(f"{k}={v}" for k, v in det["leaked"].items())
                findings.append((r.get("target"), f"server tech leaked in headers: {leaked}"))

    # ---- Run coverage: did each HTTP probe actually get through? ----------
    HTTP_CHECKS = {"headers", "exposed", "tech"}
    coverage = []          # (check, target, outcome, blocked_or_errored)
    for r in checks:
        det = r.get("detail", {})
        chk = det.get("check")
        if chk not in HTTP_CHECKS:
            continue
        status = det.get("status")
        error = det.get("error")
        protected = det.get("protected") or []
        if error:
            outcome, bad = f"ERROR: {error}", True
        elif status in (401, 403, 429, 503):
            outcome, bad = f"BLOCKED (HTTP {status})", True
        elif chk == "exposed" and protected and not det.get("exposed"):
            outcome, bad = f"BLOCKED (HTTP 403 on probed paths)", True
        elif status:
            outcome, bad = f"ok (HTTP {status})", False
        else:
            outcome, bad = "ran", False
        coverage.append((chk, r.get("target"), outcome, bad))
    http_ran = len(coverage)
    http_blocked = sum(1 for *_ , bad in coverage if bad)
    inconclusive = (not findings) and http_ran > 0 and http_blocked == http_ran

    lines = []
    lines.append(f"# AEGIS Assessment Report - {eng}")
    lines.append("")
    lines.append("## Authorization record")
    lines.append("")
    lines.append(f"- **Engagement:** {eng}")
    lines.append(f"- **Operator:** {header.get('operator','?')}")
    lines.append(f"- **First action:** {header.get('ts','?')}")
    lines.append(f"- **Actions authorized (GRANT):** {grants}")
    lines.append(f"- **Actions refused (DENY):** {denies}")
    builds = sorted({(r["detail"].get("tool"), r["detail"].get("tool_sha256")) for r in rows
                     if r.get("action") == "preflight" and (r.get("detail") or {}).get("tool_sha256")})
    for tool, sha in builds:
        lines.append(f"- **Tool build:** {tool}, code SHA-256 `{sha}`")
    if len(builds) > 1:
        lines.append("  _(more than one build ran during this engagement - each is listed above)_")
    lines.append("")
    lines.append("## Evidence integrity")
    lines.append("")
    lines.append(f"- **Audit chain:** {'VERIFIED - intact' if ok else 'FAILED'} ({msg})")
    lines.append(f"- **Total logged events:** {len(rows)}")
    if repeated:
        lines.append(f"- **Repeated runs:** {len(all_checks)} check results logged; this report shows the latest "
                     "of each - every earlier run is preserved in the audit log.")
    lines.append("")
    # Honesty banner: empty findings can mean "clean" OR "we were blocked".
    if inconclusive:
        lines.append("> **⚠ INCONCLUSIVE RUN - DO NOT READ AS 'CLEAN'.** "
                     f"All {http_ran} HTTP probe(s) were blocked or errored "
                     "(the edge/WAF returned 403/429/503 or the host was unreachable), "
                     "so the passive HTTP checks could not evaluate the site. "
                     "Absence of findings here means *we could not see*, not that nothing is wrong. "
                     "See **Run coverage** below. A manual or authenticated test is needed.")
        lines.append("")
    elif http_blocked:
        lines.append(f"> **Note:** {http_blocked} of {http_ran} HTTP probe(s) were blocked by the edge/WAF; "
                     "those specific checks are inconclusive. See **Run coverage**.")
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    if findings:
        lines.append("| Target | Finding |")
        lines.append("|---|---|")
        for tgt, f in findings:
            lines.append(f"| `{tgt}` | {f} |")
    elif inconclusive:
        lines.append("_No findings - but see the inconclusive-run warning above. The site blocked our probes; "
                     "this is **not** a clean bill of health._")
    else:
        lines.append("_No configuration findings recorded in this run._")
    lines.append("")

    # ---- Money integrity (ledger watchdog) --------------------------------
    for r in checks:
        det = r.get("detail", {})
        if det.get("check") != "ledger":
            continue
        cur = det.get("currency", "KES")
        sc = det.get("scanned", {})
        lines.append("## Money integrity (ledger watchdog)")
        lines.append("")
        lines.append(f"- **Database:** `{det.get('target')}` ({det.get('engine')}), read-only")
        lines.append(f"- **Scanned:** {sc.get('bets', 0):,} bets, {sc.get('transactions', 0):,} wallet "
                     f"transactions, {sc.get('wallets', 0):,} wallets")
        lines.append(f"- **Table mapping:** SHA-256 `{det.get('mapping_sha256', '')[:16]}…`, "
                     + (f"confirmed by **{det['mapping_reviewed_by']}**" if det.get("mapping_reviewed_by")
                        else "**auto-detected, not yet confirmed by a person**"))
        lf = det.get("ledger_findings", [])
        if lf:
            lines.append(f"- **Money flagged:** {cur} {det.get('total_at_risk')} "
                         "(summed across checks; one case can appear in two checks)")
            lines.append("")
            lines.append("| Severity | Problem | Cases | Money at risk |")
            lines.append("|---|---|---|---|")
            for f in lf:
                money = f"{cur} {f['money_at_risk']}" if f.get("money_at_risk") else "-"
                lines.append(f"| {f['severity']} | {f['title']} | {f['count']} | {money} |")
            lines.append("")
            lines.append("### What each problem means, with evidence")
            lines.append("")
            for f in lf:
                lines.append(f"**{f['severity']} - {f['title']}** ({f['count']} case(s))")
                lines.append("")
                lines.append(f"{f['means']}")
                lines.append("")
                for smp in f.get("samples", [])[:5]:
                    lines.append("- " + ", ".join(f"{k}=`{v}`" for k, v in smp.items()))
                if f["count"] > 5:
                    lines.append(f"- _…and {f['count'] - 5} more in ledger-results.json_")
                lines.append("")
        else:
            lines.append("")
            lines.append("_No money-integrity problems found in the data scanned._")
            lines.append("")
        if det.get("coverage"):
            lines.append("**Limits of this run:**")
            for c in det["coverage"]:
                lines.append(f"- {c}")
            lines.append("")

    # ---- Inside modules: M-Pesa guard, server check-up, tamper alarm -------
    for r in checks:
        det = r.get("detail", {})
        if "module_findings" not in det:
            continue
        cur = det.get("currency", "KES")
        lines.append(f"## {det.get('module_title') or det.get('check')}")
        lines.append("")
        lines.append(f"- **Checked:** `{det.get('target')}` at {r.get('ts', '?')}")
        if det.get("os"):
            lines.append(f"- **System:** {det['os']}")
        sc = det.get("scanned") or {}
        if sc:
            lines.append("- **Scope of this run:** " + ", ".join(
                f"{k.replace('_', ' ')} {v}" for k, v in sc.items() if not isinstance(v, dict)))
        mf = det.get("module_findings") or []
        if det.get("total_at_risk") and mf and det.get("check") == "mpesa":
            lines.append(f"- **Money flagged:** {cur} {det['total_at_risk']} (one incident can appear under two checks)")
        lines.append("")
        if mf:
            lines.append("| Severity | Problem | Cases | Money at risk |")
            lines.append("|---|---|---|---|")
            for f in mf:
                money = f"{cur} {f['money_at_risk']}" if f.get("money_at_risk") else "-"
                lines.append(f"| {f['severity']} | {f['title']} | {f['count']} | {money} |")
            lines.append("")
            lines.append("### What each problem means, with evidence")
            lines.append("")
            for f in mf:
                lines.append(f"**{f['severity']} - {f['title']}** ({f['count']} case(s))")
                lines.append("")
                lines.append(f["means"])
                lines.append("")
                for smp in f.get("samples", [])[:5]:
                    lines.append("- " + ", ".join(f"{k}=`{v}`" for k, v in smp.items() if v not in (None, "", [])))
                if f["count"] > 5:
                    lines.append(f"- _…and {f['count'] - 5} more in the results file_")
                lines.append("")
        else:
            lines.append("_No problems found in what was checked._")
            lines.append("")
        if det.get("coverage"):
            lines.append("**Limits of this run:**")
            for c in det["coverage"]:
                lines.append(f"- {c}")
            lines.append("")

    # ---- Run coverage section --------------------------------------------
    if coverage:
        lines.append("## Run coverage")
        lines.append("")
        if http_blocked:
            lines.append(f"**{http_blocked} of {http_ran} HTTP probes were blocked or errored.** "
                         "A 403/429 from the edge is itself a signal the client has protection in front of "
                         "the origin - but it also means these checks did not assess the application.")
            lines.append("")
        lines.append("| Check | Target | Outcome |")
        lines.append("|---|---|---|")
        for chk, tgt, outcome, _ in coverage:
            lines.append(f"| {chk} | `{tgt}` | {outcome} |")
        lines.append("")

    # Attribution note (why attacker IP can't be trusted) if webintel ran.
    note = next((r.get("detail", {}) for r in rows
                 if r.get("event") == "note" and r.get("detail", {}).get("check") == "attacker_ip_note"), None)
    if note:
        lines.append("## Attribution: why blocking the attacker's IP fails")
        lines.append("")
        lines.append(f"> {note.get('summary','')}")
        lines.append("")
        lines.append("**The source IP cannot be trusted because:**")
        for w in note.get("why_unreliable", []):
            lines.append(f"- {w}")
        lines.append("")
        lines.append("**What to do instead:**")
        for impl in note.get("implication", []):
            lines.append(f"- {impl}")
        lines.append("")

    lines.append("## Denied / out-of-scope attempts")
    lines.append("")
    deny_rows = [r for r in rows if r.get("decision") == "DENY"]
    if deny_rows:
        lines.append("| Target | Action | Reason |")
        lines.append("|---|---|---|")
        for r in deny_rows:
            lines.append(f"| `{r.get('target')}` | {r.get('action')} | {r.get('detail',{}).get('reason','')} |")
    else:
        lines.append("_None - every attempted action was within authorized scope._")
    lines.append("")

    lines.append("## Action timeline")
    lines.append("")
    kinds = Counter(f"{r.get('event')}:{r.get('action')}" for r in rows)
    lines.append("| Event:Action | Count |")
    lines.append("|---|---|")
    for k, v in kinds.most_common():
        lines.append(f"| {k} | {v} |")
    lines.append("")
    lines.append("---")
    lines.append("_Generated by AEGIS. The audit log is hash-chained; re-run `aegis verify` to confirm integrity._")
    return "\n".join(lines)
