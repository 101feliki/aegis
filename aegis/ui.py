"""
Minimal local operator console (the "type a website" field).

A single-page web UI, bound to 127.0.0.1 only, that runs the same authorized
`assess` pipeline as the CLI. You enter a domain, confirm who authorized the
test, and AEGIS structures the footprint and shows the report. It is an operator
console for YOUR machine - not a public service - so it binds to localhost and
still enforces the authorization acknowledgement before running anything.

    python -m aegis ui              # then open http://127.0.0.1:8787
"""
from __future__ import annotations

import html
import json
import os
import tempfile
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import TOOL_NAME, __version__
from .adapters import tool_inventory
from .audit import AuditLog
from .authz import Authorizer
from .cli import _auto_scope
from .engine import run as run_engine
from .report import build_markdown
from .scope import Scope

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{tool} Console</title>
<style>
 :root{{--bg:#0f1115;--card:#171a21;--line:#2a2f3a;--fg:#e6e9ef;--mut:#9aa4b2;--ac:#4f8cff;--warn:#ffb34d;--ok:#49d08b}}
 *{{box-sizing:border-box}}
 body{{margin:0;font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}}
 .wrap{{max-width:860px;margin:0 auto;padding:24px 16px}}
 h1{{font-size:20px;margin:0 0 4px}} .sub{{color:var(--mut);margin:0 0 20px}}
 .card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:16px}}
 label{{display:block;font-size:13px;color:var(--mut);margin:12px 0 4px}}
 input[type=text]{{width:100%;padding:11px 12px;border-radius:9px;border:1px solid var(--line);background:#0c0e13;color:var(--fg);font-size:15px}}
 .row{{display:flex;gap:12px;flex-wrap:wrap}} .row>div{{flex:1;min-width:220px}}
 .chk{{display:flex;gap:9px;align-items:flex-start;margin-top:16px;color:var(--mut);font-size:13px}}
 button{{margin-top:18px;background:var(--ac);color:#fff;border:0;border-radius:9px;padding:12px 20px;font-size:15px;font-weight:600;cursor:pointer}}
 button:disabled{{opacity:.5;cursor:not-allowed}}
 .tools span{{display:inline-block;font-size:12px;padding:3px 9px;border-radius:999px;border:1px solid var(--line);margin:3px 4px 0 0;color:var(--mut)}}
 .tools span.on{{color:var(--ok);border-color:var(--ok)}}
 pre{{white-space:pre-wrap;word-wrap:break-word;background:#0c0e13;border:1px solid var(--line);border-radius:10px;padding:16px;font:13px/1.55 ui-monospace,Consolas,monospace;overflow:auto}}
 .warn{{color:var(--warn);font-size:13px;margin-top:10px}}
 a{{color:var(--ac)}}
</style></head><body><div class="wrap">
 <h1>{tool} <span style="color:var(--mut);font-weight:400">v{ver}</span></h1>
 <p class="sub">Authorized, auditable footprinting. Enter a website — AEGIS structures the IP/infra exposure. Local console (127.0.0.1) only.</p>
 <div class="card">
  <form method="POST" action="/run">
   <div class="row">
    <div><label>Website / domain</label><input type="text" name="domain" placeholder="example.co.ke" required></div>
    <div><label>Authorized by (name / counsel)</label><input type="text" name="authorized_by" placeholder="Jane Counsel, General Counsel" required></div>
   </div>
   <label class="chk"><input type="checkbox" name="ack" value="yes" required>
    I confirm this assessment is authorized in writing (NDA / engagement letter) for this domain. AEGIS runs passive OSINT only; every action is logged.</label>
   <button type="submit">Run assessment</button>
   <div class="warn">Passive is still testing. Only run against assets you are authorized to assess.</div>
  </form>
  <div class="tools" style="margin-top:18px"><label>Collectors on this machine</label>{tools}</div>
 </div>
 {result}
</div></body></html>"""


def _tools_html() -> str:
    return "".join(
        f'<span class="{"on" if present else ""}">{"●" if present else "○"} {t}</span>'
        for t, present in tool_inventory().items())


def _run_assessment(domain: str, authorized_by: str, operator: str) -> str:
    out = tempfile.mkdtemp(prefix="aegis_ui_")
    scope_dict = _auto_scope(domain, authorized_by, 7)
    scope_path = os.path.join(out, "scope.json")
    with open(scope_path, "w", encoding="utf-8") as fh:
        json.dump(scope_dict, fh, indent=2)
    scope = Scope.load(scope_path)
    audit = AuditLog(os.path.join(out, "audit.jsonl"), operator=operator, engagement_id=scope.engagement_id)
    audit.append("authorization", action="acknowledge", target=scope.engagement_id,
                 decision="GRANT", detail={"asserted_by": operator, "note": f"UI: authorized by {authorized_by}"})
    authz = Authorizer(scope, audit, None)
    if not authz.preflight():
        return "preflight denied"
    run_engine(authz, ["passive", "webintel"])
    return build_markdown(os.path.join(out, "audit.jsonl")) + f"\n\n_Artifacts: {out}_"


class Handler(BaseHTTPRequestHandler):
    def _page(self, result_md: str = ""):
        result = ""
        if result_md:
            result = f'<div class="card"><h1 style="font-size:16px">Report</h1><pre>{html.escape(result_md)}</pre></div>'
        body = PAGE.format(tool=TOOL_NAME, ver=__version__, tools=_tools_html(), result=result)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._page()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != "/run":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
        domain = (form.get("domain", [""])[0] or "").strip()
        authorized_by = (form.get("authorized_by", [""])[0] or "").strip()
        ack = form.get("ack", [""])[0] == "yes"
        if not (domain and authorized_by and ack):
            self._page("ERROR: domain, authorizer and the authorization confirmation are all required.")
            return
        try:
            from .cli import normalize_domain
            normalize_domain(domain)  # fail fast with a clear message on bad input
        except Exception as e:  # noqa: BLE001
            self._page(f"ERROR: {e}. Enter a website like www.example.com or https://www.example.com/")
            return
        try:
            md = _run_assessment(domain, authorized_by, operator="ui")
        except Exception as e:  # noqa: BLE001
            md = f"ERROR running assessment: {e}"
        self._page(md)

    def log_message(self, *a):  # quiet
        pass


def serve(host: str = "127.0.0.1", port: int = 8787) -> int:
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"{TOOL_NAME} console -> http://{host}:{port}  (Ctrl+C to stop)")
    print("Local only. Every run is authorization-gated and written to a hash-chained audit log.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0
