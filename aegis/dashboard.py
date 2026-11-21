"""
AEGIS dashboard - what the client's team sees.

    python -m aegis ui --state /var/lib/aegis/guard        dashboard for an installed guard
    python -m aegis ui --config /etc/aegis/aegis-guard.json
    python -m aegis ui --demo                               build demo data and show it

A read-only web page served by AEGIS itself (Python standard library, no internet, no
external scripts). It reads the guard's state folder - results, alerts, run history and
the audit log - and shows it in plain language. It cannot start, stop or change anything
except the existing "website check" form.

Safety:
  - binds to 127.0.0.1 by default; from another machine use an SSH tunnel
    (ssh -L 8787:127.0.0.1:8787 <server>). Binding elsewhere requires AEGIS_UI_PASSWORD.
  - every value from the client's data is rendered as text (never as HTML), and a strict
    Content-Security-Policy with a per-response nonce blocks any injected script.
  - downloads are limited to a fixed list of evidence files in the state folder.
"""
from __future__ import annotations

import base64
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer

from . import TOOL_NAME, __version__

DOWNLOADS = {"report.md": "text/markdown", "audit.jsonl": "application/x-ndjson",
             "guard-alerts.jsonl": "application/x-ndjson", "guard-history.jsonl": "application/x-ndjson"}
MODULE_FILES = {"ledger": "latest-results.json", "mpesa": "mpesa-results.json", "host": "host-results.json",
                "tamper": "tamper-results.json"}
MODULE_NAMES = {"ledger": "Money check", "mpesa": "M-Pesa check", "host": "Server health", "tamper": "Change alarm"}
MODULE_BLURB = {"ledger": "Do bets and wallet payouts add up?",
                "mpesa": "Does what M-Pesa moved match what wallets got?",
                "host": "Is the money server set up safely?",
                "tamper": "Did anyone change the money code or access?"}
SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _read_jsonl(path, limit=None):
    rows = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        continue
    except OSError:
        return []
    return rows[-limit:] if limit else rows


def _num(s) -> float:
    try:
        return float(str(s).replace(",", ""))
    except (TypeError, ValueError):
        return 0.0


def load_state(state_dir: str) -> dict:
    """Everything the page shows, assembled from the guard's state folder."""
    from .audit import AuditLog
    from .scope import Scope

    audit_path = os.path.join(state_dir, "audit.jsonl")
    audit = _read_jsonl(audit_path)
    ok, msg = AuditLog.verify(audit_path) if audit else (False, "no audit log yet")
    gstate = _read_json(os.path.join(state_dir, "guard-state.json")) or {}
    history = _read_jsonl(os.path.join(state_dir, "guard-history.jsonl"))
    alerts = _read_jsonl(os.path.join(state_dir, "guard-alerts.jsonl"), limit=400)

    last_check = {}
    for r in audit:
        if r.get("event") == "check":
            last_check[(r.get("detail") or {}).get("check")] = r.get("ts")
    pre = [r for r in audit if r.get("action") == "preflight" and r.get("decision") == "GRANT"]
    builds = sorted({((r.get("detail") or {}).get("tool"), (r.get("detail") or {}).get("tool_sha256"))
                     for r in pre if (r.get("detail") or {}).get("tool_sha256")})
    authorized_by = (pre[-1].get("detail") or {}).get("authorized_by") if pre else None
    denied = sum(1 for r in audit if r.get("decision") == "DENY")

    # Name, authorization window: from the guard config / scope the guard used.
    name, window_end, signed = None, None, None
    cfg = _read_json(gstate.get("config") or "") if gstate.get("config") else None
    if cfg:
        name = cfg.get("name")
        sp = (cfg.get("authorization") or {}).get("scope")
        if sp and not os.path.isabs(sp):
            sp = os.path.join(os.path.dirname(gstate["config"]), sp)
        if not sp or not os.path.exists(sp):
            sp = os.path.join(state_dir, "scope.json")
        try:
            sc = Scope.load(sp)
            window_end = sc.window_end.isoformat()
            signed = sc.signed
        except Exception:  # noqa: BLE001
            pass

    modules = {}
    enabled = set((cfg or {}).get("modules", {}).keys()) or set(MODULE_FILES)
    for m, fn in MODULE_FILES.items():
        res = _read_json(os.path.join(state_dir, fn))
        if m not in enabled and res is None:
            continue
        if res is None:
            modules[m] = {"name": MODULE_NAMES[m], "blurb": MODULE_BLURB[m], "status": "not run yet",
                          "findings": [], "coverage": []}
            continue
        fl = res.get("ledger_findings") if m == "ledger" else res.get("module_findings")
        fl = fl or []
        modules[m] = {
            "name": MODULE_NAMES[m], "blurb": MODULE_BLURB[m],
            "status": "ok", "target": res.get("target"),
            "checked_at": last_check.get(m) or datetime.fromtimestamp(
                os.path.getmtime(os.path.join(state_dir, fn)), timezone.utc).isoformat(timespec="seconds"),
            "currency": res.get("currency", "KES"),
            "money": res.get("total_at_risk") if m in ("ledger", "mpesa") else None,
            "findings": [{k: f.get(k) for k in ("code", "severity", "title", "means", "count", "money_at_risk",
                                                 "samples")} for f in fl],
            "coverage": res.get("coverage") or [],
            "scanned": res.get("scanned") or {},
        }

    last_run = history[-1] if history else None
    last_run_id = last_run.get("run") if last_run else None
    run_alerts = [a for a in alerts if a.get("run") == last_run_id]
    for a in run_alerts:
        if a.get("kind") == "MODULE_BLIND" and a.get("module") in modules:
            modules[a["module"]]["status"] = "blind"
            modules[a["module"]]["blind_reason"] = a.get("message")

    new_events = [a for a in run_alerts if a.get("kind") in ("NEW", "BASELINE")]
    blind = [a for a in run_alerts if a.get("kind") == "MODULE_BLIND"]
    ended = [a for a in alerts[-5:] if a.get("kind") == "AUTHORIZATION_ENDED"]
    first = bool(run_alerts) and all(a.get("kind") in ("BASELINE", "MODULE_BLIND", "RESOLVED") for a in run_alerts) \
        and len(history) == 1
    if ended:
        status = {"level": "stopped", "text": "Monitoring has stopped: the authorization period is over.",
                  "detail": ended[-1].get("message")}
    elif blind:
        status = {"level": "blind",
                  "text": f"{len(blind)} part(s) of the system could not be checked in the last run.",
                  "detail": "; ".join(f"{MODULE_NAMES.get(a.get('module'), a.get('module'))}: {a.get('message')}"
                                      for a in blind)}
    elif first:
        status = {"level": "baseline", "text": "First run complete: this is the starting picture.",
                  "detail": "Problems already present are listed below. From now on you will be alerted only to "
                            "what is new."}
    elif new_events:
        crit = sum(1 for a in new_events if a.get("severity") == "CRITICAL")
        status = {"level": "alert" if crit else "warn",
                  "text": f"{sum(a.get('count') or 1 for a in new_events)} new problem(s) since the previous check"
                          + (f", {crit} critical" if crit else "") + ".",
                  "detail": "See Alerts for what changed."}
    elif history:
        status = {"level": "quiet", "text": "All quiet: nothing new since the previous check.",
                  "detail": "Problems found earlier stay listed until they are fixed."}
    else:
        status = {"level": "none", "text": "No monitoring run yet.", "detail": "Run: aegis guard run --config ..."}

    money = {}
    for m in ("ledger", "mpesa"):
        if m in modules and modules[m].get("money"):
            money[m] = {"amount": modules[m]["money"], "currency": modules[m]["currency"]}
    sev_counts = {s: 0 for s in SEV}
    for mod in modules.values():
        for f in mod["findings"]:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + (f.get("count") or 0)

    return {
        "tool": f"{TOOL_NAME} {__version__}", "name": name or "AEGIS monitor", "state_dir": state_dir,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": status, "modules": modules, "money": money, "severity_counts": sev_counts,
        "last_run": last_run, "runs": history[-60:][::-1], "alerts": alerts[::-1][:200],
        "evidence": {"audit_ok": ok, "audit_msg": msg, "events": len(audit), "denied": denied,
                     "builds": [{"tool": t, "sha256": s} for t, s in builds], "authorized_by": authorized_by,
                     "window_end": window_end, "signed": signed,
                     "downloads": [f for f in DOWNLOADS if os.path.exists(os.path.join(state_dir, f))]},
    }


# ---------------------------------------------------------------------------
# Page (all data is inserted by script with textContent - never as HTML)
# ---------------------------------------------------------------------------
PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AEGIS Monitor</title>
<style nonce="__NONCE__">
:root{--bg:#f5f6f8;--card:#fff;--line:#e2e5ea;--fg:#16191f;--mut:#5f6b7a;--soft:#eef1f5;
 --crit:#c62828;--crit-bg:#fdecec;--high:#d9480f;--high-bg:#fff0e6;--med:#a86b00;--med-bg:#fff6dc;
 --low:#3b6fb6;--low-bg:#e9f1fc;--ok:#1d7f4e;--ok-bg:#e5f5ec;--ac:#2f5bd3}
@media (prefers-color-scheme:dark){:root{--bg:#0f1216;--card:#171b21;--line:#2a313b;--fg:#e7eaef;--mut:#9aa5b4;
 --soft:#1e242c;--crit:#ff6b6b;--crit-bg:#3a1717;--high:#ff9a5a;--high-bg:#3a2414;--med:#f2c14e;--med-bg:#352c12;
 --low:#7fb0ff;--low-bg:#162539;--ok:#4cd38a;--ok-bg:#12301f;--ac:#7fa2ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:20px 16px 60px}
header{display:flex;flex-wrap:wrap;align-items:center;gap:10px 18px;margin-bottom:16px}
header h1{font-size:20px;margin:0;letter-spacing:.2px} header .who{color:var(--mut)}
.pill{font-size:12px;padding:3px 10px;border-radius:999px;border:1px solid var(--line);color:var(--mut);background:var(--card)}
.spacer{flex:1}
.banner{border-radius:14px;padding:18px 20px;margin-bottom:16px;border:1px solid var(--line);background:var(--card);
 display:flex;gap:14px;align-items:flex-start}
.banner .dot{width:14px;height:14px;border-radius:50%;margin-top:5px;flex:none}
.banner h2{margin:0 0 2px;font-size:18px} .banner p{margin:0;color:var(--mut)}
.lv-alert{background:var(--crit-bg);border-color:var(--crit)} .lv-alert .dot{background:var(--crit)}
.lv-warn{background:var(--high-bg);border-color:var(--high)} .lv-warn .dot{background:var(--high)}
.lv-blind,.lv-stopped{background:var(--med-bg);border-color:var(--med)} .lv-blind .dot,.lv-stopped .dot{background:var(--med)}
.lv-quiet{background:var(--ok-bg);border-color:var(--ok)} .lv-quiet .dot{background:var(--ok)}
.lv-baseline,.lv-none{background:var(--low-bg);border-color:var(--low)} .lv-baseline .dot,.lv-none .dot{background:var(--low)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:16px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.kpi .l{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.5px}
.kpi .v{font-size:24px;font-weight:650;margin-top:2px;font-variant-numeric:tabular-nums}
.kpi .s{font-size:13px;color:var(--mut)}
.mods{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px;margin-bottom:20px}
.mod{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;cursor:pointer}
.mod:hover{border-color:var(--ac)} .mod h3{margin:0;font-size:16px} .mod .b{color:var(--mut);font-size:13px;margin:2px 0 10px}
.mod .st{font-size:13px;margin-top:10px;color:var(--mut)}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{font-size:12px;font-weight:600;padding:2px 9px;border-radius:999px}
.s-CRITICAL{color:var(--crit);background:var(--crit-bg)} .s-HIGH{color:var(--high);background:var(--high-bg)}
.s-MEDIUM{color:var(--med);background:var(--med-bg)} .s-LOW{color:var(--low);background:var(--low-bg)}
.s-INFO,.s-OK{color:var(--ok);background:var(--ok-bg)}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin-bottom:14px;overflow-x:auto}
.tab{background:none;border:0;border-bottom:2px solid transparent;padding:10px 14px;font:inherit;color:var(--mut);cursor:pointer;white-space:nowrap}
.tab.on{color:var(--fg);border-bottom-color:var(--ac);font-weight:600}
.panel{display:none} .panel.on{display:block}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.filters button{font:inherit;font-size:13px;padding:5px 12px;border-radius:999px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}
.filters button.on{border-color:var(--ac);color:var(--ac)}
.f{background:var(--card);border:1px solid var(--line);border-radius:12px;margin-bottom:10px;overflow:hidden}
.f summary{list-style:none;display:flex;gap:12px;align-items:center;padding:13px 16px;cursor:pointer}
.f summary::-webkit-details-marker{display:none}
.f .t{flex:1;font-weight:550} .f .m{font-size:13px;color:var(--mut);white-space:nowrap}
.f .body{padding:0 16px 16px;border-top:1px solid var(--line)}
.f .means{margin:12px 0}
.ev{font:12.5px/1.5 ui-monospace,Consolas,monospace;background:var(--soft);border-radius:8px;padding:8px 10px;margin:6px 0;overflow-wrap:anywhere}
.ev b{font-weight:600;color:var(--mut)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);font-size:14px;vertical-align:top}
th{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.4px;background:var(--soft)}
td.num{font-variant-numeric:tabular-nums;white-space:nowrap}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:12px}
.card h3{margin:0 0 8px;font-size:16px}
.ok{color:var(--ok);font-weight:600} .bad{color:var(--crit);font-weight:600}
.cov{font-size:13px;color:var(--mut);margin:4px 0}
a{color:var(--ac)} .mut{color:var(--mut)} .small{font-size:13px}
.dl a{display:inline-block;margin:4px 10px 4px 0}
.empty{color:var(--mut);padding:20px;text-align:center;background:var(--card);border:1px dashed var(--line);border-radius:12px}
@media (max-width:640px){.f .m{display:none} th:nth-child(4),td:nth-child(4){display:none}}
</style></head><body><div class="wrap">
<header><h1>AEGIS</h1><span class="who" id="name"></span><span class="pill">Read-only monitor</span>
<span class="spacer"></span><span class="mut small" id="updated"></span></header>
<div class="banner" id="banner"><span class="dot"></span><div><h2 id="btext"></h2><p id="bdetail"></p></div></div>
<div class="kpis" id="kpis"></div>
<div class="mods" id="mods"></div>
<div class="tabs" id="tabs"></div>
<section class="panel" id="p-problems"><div class="filters" id="filters"></div><div id="flist"></div></section>
<section class="panel" id="p-alerts"><div id="alist"></div></section>
<section class="panel" id="p-runs"><div id="rlist"></div></section>
<section class="panel" id="p-evidence"><div id="evid"></div></section>
<section class="panel" id="p-website"><div class="card"><h3>Website check (outside view)</h3>
<p class="small mut">Passive look at a website you are authorized to assess: what it leaks about its servers, missing
protections, exposed files. Opens in a new page.</p><a href="/website">Open the website check &rarr;</a></div></section>
<script nonce="__NONCE__">
const MODS = {ledger:"Money check", mpesa:"M-Pesa check", host:"Server health", tamper:"Change alarm"};
const SEVS = ["CRITICAL","HIGH","MEDIUM","LOW"];
const SEVWORD = {CRITICAL:"Critical",HIGH:"High",MEDIUM:"Medium",LOW:"Low",INFO:"Info"};
const KIND = {NEW:"New problem", BASELINE:"Found at first run", RESOLVED:"No longer seen", MODULE_BLIND:"Check could not run",
              AUTHORIZATION_ENDED:"Authorization ended"};
let S = null, tab = "problems", sevFilter = "ALL", modFilter = "ALL";

function el(tag, cls, text){const e=document.createElement(tag); if(cls) e.className=cls; if(text!==undefined&&text!==null) e.textContent=String(text); return e;}
function clear(n){while(n.firstChild) n.removeChild(n.firstChild); return n;}
function chip(sev, text){return el("span","chip s-"+sev, text);}
function ago(iso){ if(!iso) return "never"; const s=(Date.now()-Date.parse(iso))/1000;
  if(isNaN(s)) return iso; if(s<90) return "just now"; if(s<3600) return Math.round(s/60)+" min ago";
  if(s<86400) return Math.round(s/3600)+" h ago"; return Math.round(s/86400)+" days ago";}
function when(iso){ if(!iso) return ""; const d=new Date(iso); return isNaN(d)?iso:d.toLocaleString();}

function render(){
  document.getElementById("name").textContent = S.name;
  const lr = S.last_run ? S.last_run.at : null;
  document.getElementById("updated").textContent = lr ? "Last check: " + ago(lr) + " (" + when(lr) + ")" : "No check yet";
  const b = document.getElementById("banner"); b.className = "banner lv-" + S.status.level;
  document.getElementById("btext").textContent = S.status.text;
  document.getElementById("bdetail").textContent = S.status.detail || "";

  const k = clear(document.getElementById("kpis"));
  const money = Object.values(S.money);
  const total = money.reduce((a,m)=>a+parseFloat(String(m.amount).replace(/,/g,""))||0,0);
  const cur = money.length ? money[0].currency : "KES";
  kpi(k, "Money flagged", money.length ? cur+" "+total.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2}) : "None",
      money.length ? "money check + M-Pesa check (one incident can appear in both)" : "no money problems found");
  const sc = S.severity_counts;
  kpi(k, "Critical / high cases", (sc.CRITICAL||0)+" / "+(sc.HIGH||0), ((sc.MEDIUM||0)+(sc.LOW||0))+" medium or low");
  kpi(k, "Checks run", S.runs.length, S.runs.length ? "most recent "+ago(S.last_run.at) : "none yet");
  const ev = S.evidence;
  kpi(k, "Evidence record", ev.audit_ok ? "Intact" : "PROBLEM", ev.events+" logged actions, "+ev.denied+" refused", ev.audit_ok ? "ok":"bad");

  const m = clear(document.getElementById("mods"));
  for (const [key, mod] of Object.entries(S.modules)){
    const c = el("div","mod"); c.onclick=()=>{modFilter=key; sevFilter="ALL"; setTab("problems");};
    c.appendChild(el("h3",null,mod.name)); c.appendChild(el("div","b",mod.blurb));
    const ch = el("div","chips");
    if (mod.status==="blind") ch.appendChild(chip("MEDIUM","Could not run"));
    else if (mod.status==="not run yet") ch.appendChild(chip("LOW","Not run yet"));
    else {
      const per = {}; for (const f of mod.findings) per[f.severity]=(per[f.severity]||0)+f.count;
      let any=false; for (const s of SEVS) if(per[s]){ch.appendChild(chip(s, per[s]+" "+SEVWORD[s].toLowerCase())); any=true;}
      if(!any) ch.appendChild(chip("OK","No problems"));
    }
    c.appendChild(ch);
    let st = mod.checked_at ? "Checked "+ago(mod.checked_at) : "";
    if (mod.money && parseFloat(String(mod.money).replace(/,/g,""))>0) st += " · "+mod.currency+" "+mod.money+" flagged";
    if (mod.status==="blind") st = mod.blind_reason || "Could not run";
    c.appendChild(el("div","st",st));
    m.appendChild(c);
  }

  const t = clear(document.getElementById("tabs"));
  const nprob = Object.values(S.modules).reduce((a,x)=>a+x.findings.length,0);
  for (const [id,label] of [["problems","Problems ("+nprob+")"],["alerts","Alerts"],["runs","Check history"],["evidence","Evidence for legal"],["website","Website check"]]){
    const btn = el("button","tab"+(tab===id?" on":""),label); btn.onclick=()=>setTab(id); t.appendChild(btn);}
  for (const p of document.querySelectorAll(".panel")) p.classList.toggle("on", p.id==="p-"+tab);
  renderProblems(); renderAlerts(); renderRuns(); renderEvidence();
}
function kpi(parent, l, v, s, cls){const d=el("div","kpi"); d.appendChild(el("div","l",l)); const vv=el("div","v "+(cls||""),v); d.appendChild(vv); d.appendChild(el("div","s",s)); parent.appendChild(d);}
function setTab(id){tab=id; render(); window.scrollTo({top:document.getElementById("tabs").offsetTop-10, behavior:"smooth"});}

function renderProblems(){
  const fl = clear(document.getElementById("filters"));
  const mk=(label,on,fn)=>{const b=el("button",on?"on":"",label); b.onclick=fn; fl.appendChild(b);};
  mk("All parts", modFilter==="ALL", ()=>{modFilter="ALL"; render();});
  for (const key of Object.keys(S.modules)) mk(MODS[key]||key, modFilter===key, ()=>{modFilter=key; render();});
  fl.appendChild(el("span","mut small","  |  "));
  mk("All severities", sevFilter==="ALL", ()=>{sevFilter="ALL"; render();});
  for (const s of SEVS) mk(SEVWORD[s], sevFilter===s, ()=>{sevFilter=s; render();});

  const list = clear(document.getElementById("flist"));
  let rows = [];
  for (const [key, mod] of Object.entries(S.modules)) for (const f of mod.findings) rows.push([key, mod, f]);
  rows = rows.filter(([k,,f])=>(modFilter==="ALL"||modFilter===k)&&(sevFilter==="ALL"||sevFilter===f.severity));
  rows.sort((a,b)=>SEVS.indexOf(a[2].severity)-SEVS.indexOf(b[2].severity));
  if (!rows.length){ list.appendChild(el("div","empty","No open problems for this selection.")); }
  for (const [key, mod, f] of rows){
    const d = el("details","f"); const s = el("summary");
    s.appendChild(chip(f.severity, SEVWORD[f.severity])); s.appendChild(el("span","t",f.title));
    s.appendChild(el("span","m", MODS[key]+" · "+f.count+" case"+(f.count===1?"":"s")+(f.money_at_risk?" · "+mod.currency+" "+f.money_at_risk:"")));
    d.appendChild(s);
    const body = el("div","body"); body.appendChild(el("p","means",f.means));
    if ((f.samples||[]).length){ body.appendChild(el("div","small mut","Evidence"+(f.count>f.samples.length?" (first "+f.samples.length+" of "+f.count+")":"")+":"));
      for (const smp of f.samples){ const e = el("div","ev");
        for (const [kk,vv] of Object.entries(smp)){ if(vv===null||vv===""||(Array.isArray(vv)&&!vv.length)) continue;
          e.appendChild(el("b",null,kk.replace(/_/g," ")+": ")); e.appendChild(document.createTextNode((Array.isArray(vv)?vv.join(", "):String(vv))+"   ")); }
        body.appendChild(e);} }
    d.appendChild(body); list.appendChild(d);
  }
  if (modFilter!=="ALL" && S.modules[modFilter] && S.modules[modFilter].coverage.length){
    const c = el("div","card"); c.appendChild(el("h3",null,"Limits of the last "+MODS[modFilter].toLowerCase()));
    for (const x of S.modules[modFilter].coverage) c.appendChild(el("div","cov","• "+x)); list.appendChild(c);
  }
}
function renderAlerts(){
  const list = clear(document.getElementById("alist"));
  if (!S.alerts.length){ list.appendChild(el("div","empty","No alerts yet.")); return; }
  const tbl = el("table"); const h = el("tr");
  for (const x of ["When","Part","What happened","Details"]) h.appendChild(el("th",null,x)); tbl.appendChild(h);
  for (const a of S.alerts){ const r = el("tr");
    r.appendChild(el("td","num",when(a.at)));
    r.appendChild(el("td",null,MODS[a.module]||a.module||""));
    const w = el("td"); w.appendChild(chip(a.kind==="RESOLVED"?"OK":(a.severity||"INFO"), KIND[a.kind]||a.kind)); w.appendChild(document.createTextNode(" "+(a.title||"")));
    r.appendChild(w);
    r.appendChild(el("td","small",(a.message||"")+(a.cases&&a.cases.length?" e.g. "+a.cases.slice(0,4).join(", "):"")));
    tbl.appendChild(r);}
  list.appendChild(tbl);
}
function renderRuns(){
  const list = clear(document.getElementById("rlist"));
  if (!S.runs.length){ list.appendChild(el("div","empty","No checks have run yet.")); return; }
  const tbl = el("table"); const h = el("tr");
  for (const x of ["Check","Money","M-Pesa","Server","Changes"]) h.appendChild(el("th",null,x)); tbl.appendChild(h);
  for (const r of S.runs){ const tr = el("tr"); tr.appendChild(el("td","num",when(r.at)));
    for (const key of ["ledger","mpesa","host","tamper"]){ const m = (r.modules||{})[key]; const td = el("td","small");
      if(!m) td.textContent="—";
      else if(m.error){ td.appendChild(chip("MEDIUM","could not run")); }
      else { const open = m.open ? Object.values(m.open).reduce((a,b)=>a+b,0) : null;
        td.textContent = (open!==null? open+" open":"ran") + (m.events? " · "+m.events+" alert"+(m.events===1?"":"s"):"") + (m.seconds!==undefined? " · "+m.seconds+"s":""); }
      tr.appendChild(td);} tbl.appendChild(tr);}
  list.appendChild(tbl);
}
function renderEvidence(){
  const box = clear(document.getElementById("evid")); const ev = S.evidence;
  const c1 = el("div","card"); c1.appendChild(el("h3",null,"Is the record intact?"));
  const p = el("p"); p.appendChild(el("span",ev.audit_ok?"ok":"bad", ev.audit_ok?"Yes - verified.":"NO - "+ev.audit_msg));
  p.appendChild(document.createTextNode(" Every action AEGIS took, every check result and every refusal is chained together; changing any past entry would break the chain. "+ev.audit_msg+"."));
  c1.appendChild(p); box.appendChild(c1);
  const c2 = el("div","card"); c2.appendChild(el("h3",null,"Authorization"));
  c2.appendChild(el("p",null,"Authorized by: "+(ev.authorized_by||"(not recorded)")));
  c2.appendChild(el("p",null,"Valid until: "+(ev.window_end?when(ev.window_end):"(unknown)")+(ev.signed===true?" · signed scope":ev.signed===false?" · NOT signed (acknowledgement only)":"")));
  c2.appendChild(el("p","small mut","Actions outside this authorization are refused and recorded: "+ev.denied+" so far."));
  box.appendChild(c2);
  const c3 = el("div","card"); c3.appendChild(el("h3",null,"Which version of AEGIS produced this"));
  if(!ev.builds.length) c3.appendChild(el("p","mut","Not recorded (older version)."));
  for (const b of ev.builds){ const q = el("p"); q.appendChild(document.createTextNode(b.tool+" - fingerprint ")); q.appendChild(el("code",null,b.sha256)); c3.appendChild(q);}
  box.appendChild(c3);
  const c4 = el("div","card dl"); c4.appendChild(el("h3",null,"Download for your lawyers / auditors"));
  const names = {"report.md":"Full report","audit.jsonl":"Audit log (the evidence)","guard-alerts.jsonl":"All alerts","guard-history.jsonl":"Check history"};
  for (const f of ev.downloads){ const a = el("a",null,names[f]||f); a.href="/download/"+encodeURIComponent(f); c4.appendChild(a);}
  c4.appendChild(el("p","small mut","Verify the audit log independently with: aegis verify-audit --audit audit.jsonl"));
  box.appendChild(c4);
}
async function load(){
  try{ const r = await fetch("/api/state",{cache:"no-store"}); if(!r.ok) throw new Error(r.status); S = await r.json(); render(); }
  catch(e){ document.getElementById("btext").textContent="Cannot load monitor data ("+e.message+")"; }
}
load(); setInterval(load, 60000);
</script></div></body></html>"""


from .ui import Handler as _Website  # noqa: E402  (the existing website-check form)


class Dashboard(_Website):
    state_dir = "."
    password = None

    def _auth(self) -> bool:
        if not self.password:
            return True
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                user_pw = base64.b64decode(h[6:]).decode("utf-8", "replace")
                if hmac.compare_digest(user_pw.split(":", 1)[-1], self.password):
                    return True
            except ValueError:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="AEGIS monitor"')
        self.end_headers()
        return False

    def _send(self, code: int, body: bytes, ctype: str, nonce: str | None = None, extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        csp = "default-src 'none'; connect-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; " \
              "frame-ancestors 'none'"
        if nonce:
            csp += f"; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'"
        self.send_header("Content-Security-Policy", csp)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._auth():
            return
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            nonce = secrets.token_urlsafe(16)
            self._send(200, PAGE.replace("__NONCE__", nonce).encode(), "text/html; charset=utf-8", nonce)
        elif path == "/api/state":
            try:
                body = json.dumps(load_state(self.state_dir), default=str).encode()
                self._send(200, body, "application/json")
            except Exception as e:  # noqa: BLE001
                self._send(500, json.dumps({"error": str(e)}).encode(), "application/json")
        elif path.startswith("/download/"):
            name = path[len("/download/"):]
            if name not in DOWNLOADS or not os.path.exists(os.path.join(self.state_dir, name)):
                self.send_error(404)
                return
            with open(os.path.join(self.state_dir, name), "rb") as fh:
                data = fh.read()
            self._send(200, data, DOWNLOADS[name] + "; charset=utf-8", extra={
                "Content-Disposition": f'attachment; filename="{name}"'})
        elif path == "/website":
            self._page()                          # website-check form (from ui.py)
        else:
            self.send_error(404)

    def do_POST(self):
        if not self._auth():
            return
        super().do_POST()                         # only /run (website check) is accepted

    def log_message(self, *a):
        pass


def serve(state_dir: str, host: str = "127.0.0.1", port: int = 8787) -> int:
    password = os.environ.get("AEGIS_UI_PASSWORD") or None
    if host not in ("127.0.0.1", "localhost", "::1") and not password:
        print("Refusing to listen on a network address without a password. Set AEGIS_UI_PASSWORD, or keep the "
              "default 127.0.0.1 and use an SSH tunnel: ssh -L 8787:127.0.0.1:8787 <server>")
        return 2
    Dashboard.state_dir = os.path.abspath(state_dir)
    Dashboard.password = password
    srv = ThreadingHTTPServer((host, port), Dashboard)
    print(f"{TOOL_NAME} monitor -> http://{host}:{port}   (showing {Dashboard.state_dir}; Ctrl+C to stop)")
    print("Read-only view. From another machine: ssh -L 8787:127.0.0.1:8787 <this server>, then open "
          "http://127.0.0.1:8787")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0
