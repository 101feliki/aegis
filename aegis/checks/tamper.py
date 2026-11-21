"""
Tamper alarm - did anyone change the money code, the server's access settings, or
the money tables' structure? (READ-ONLY)

The cheapest way to steal from a sportsbook is not to hack it from outside: it is to
change one line in the settlement or M-Pesa callback code on the server, or to add a
database trigger that quietly inflates a credit. This module takes a fingerprint
(SHA-256 of every file in the watched folders, plus the structure, triggers and stored
routines of the money tables) and on every later run reports what changed:

  CRITICAL  MONEY_CODE_CHANGED     settlement / wallet / M-Pesa code added, changed or deleted
  CRITICAL  WEBSHELL_SUSPECT       new or changed code contains remote-control (webshell) patterns
  CRITICAL  SCRIPT_IN_UPLOAD_DIR   a program file appeared in an uploads / public storage folder
  CRITICAL  DB_TRIGGER_CHANGED     a database trigger was added, changed or removed
  CRITICAL  BASELINE_TAMPERED      the fingerprint file itself was edited outside AEGIS
  HIGH      ACCESS_CHANGED         SSH keys, sudoers, sshd or cron configuration changed
  HIGH      CONFIG_CHANGED         application / web-server configuration changed
  HIGH      NEW_CODE_FILE          a new program file appeared in the application
  HIGH      PERMISSIONS_WEAKENED   a file became writable by everyone, or gained setuid
  HIGH      DB_SCHEMA_CHANGED      columns of a money table were added, removed or retyped
  HIGH      DB_ROUTINE_CHANGED     a stored procedure / function was added, changed or removed
  HIGH      WATCHED_PATH_MISSING   a watched folder disappeared
  MEDIUM    CODE_CHANGED           other application code changed
  MEDIUM    FILE_DELETED           code or configuration file deleted
  LOW       OTHER_FILES_CHANGED    non-code files changed (count only)

Legitimate deployments are expected: after a deploy, a named person runs
`aegis tamper approve --note "release 2.4, ticket 118"`, which re-fingerprints and
records the approval (and exactly what changed) in the hash-chained audit log.

The fingerprint is anchored in the audit log (its SHA-256 is recorded at every approval)
and, when a key is supplied, HMAC-signed - so editing it to hide a change is itself detected.
"""
from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import os
import re
import stat
from datetime import datetime, timezone

from ..findings import Findings

ACTION = "tamper-watch"

CATALOGUE = {
    "MONEY_CODE_CHANGED": ("CRITICAL", "Money-handling code was added, changed or deleted",
                           "Settlement, wallet, payout or M-Pesa code changed without an approved deployment. One "
                           "changed line here can pay out on losing bets or credit fake deposits. Find out who "
                           "changed it, compare with the version in source control, and keep a copy now."),
    "WEBSHELL_SUSPECT": ("CRITICAL", "Code contains remote-control (webshell) patterns",
                         "Patterns like eval(base64_decode(...)) or system($_GET[...]) let an attacker run commands "
                         "on the server from a browser. Treat the server as compromised."),
    "SCRIPT_IN_UPLOAD_DIR": ("CRITICAL", "A program file appeared in an uploads / public storage folder",
                             "Upload folders should only ever hold images and documents. A script there is the "
                             "usual way a webshell is planted through an upload form."),
    "DB_TRIGGER_CHANGED": ("CRITICAL", "A database trigger was added, changed or removed",
                           "A trigger runs automatically on every insert/update. A malicious trigger on the wallet "
                           "table can inflate credits or rewrite results invisibly to the application."),
    "BASELINE_TAMPERED": ("CRITICAL", "The tamper-alarm fingerprint itself was edited outside AEGIS",
                          "Someone changed the reference fingerprint, which is how a change would be hidden. The "
                          "audit-log anchor / signature no longer matches."),
    "ACCESS_CHANGED": ("HIGH", "Who-can-get-in settings changed (SSH keys, sudo, SSH, scheduled tasks)",
                       "A new SSH key, sudo rule or scheduled task is how attackers keep access. Confirm each change "
                       "with a named administrator."),
    "CONFIG_CHANGED": ("HIGH", "Application or web-server configuration changed",
                       "Configuration holds the M-Pesa callback URL, API credentials and database settings. "
                       "A changed callback URL or credential can redirect money."),
    "NEW_CODE_FILE": ("HIGH", "A new program file appeared in the application",
                      "New code outside an approved deployment."),
    "PERMISSIONS_WEAKENED": ("HIGH", "A file became writable by everyone, or gained setuid",
                             "Weakened permissions let any account change the file, or run it with elevated rights."),
    "DB_SCHEMA_CHANGED": ("HIGH", "Structure of a money table changed",
                          "Columns were added, removed or retyped on the bets / wallet tables. Confirm it was a "
                          "planned migration - and re-run `aegis db map`, the ledger mapping may need updating."),
    "DB_ROUTINE_CHANGED": ("HIGH", "A stored procedure or function was added, changed or removed",
                           "Stored routines often perform settlement and wallet updates inside the database."),
    "WATCHED_PATH_MISSING": ("HIGH", "A watched folder or file disappeared", "The alarm can no longer see it."),
    "CODE_CHANGED": ("MEDIUM", "Application code changed", "Code changed without an approved deployment."),
    "FILE_DELETED": ("MEDIUM", "Code or configuration file deleted", "A deletion outside an approved deployment."),
    "OTHER_FILES_CHANGED": ("LOW", "Other (non-code) files changed", "Images, documents etc. - counted, not judged."),
}
RISKY_TO_APPROVE = ("WEBSHELL_SUSPECT", "SCRIPT_IN_UPLOAD_DIR", "BASELINE_TAMPERED")
CASE_FIELDS = {c: ("path", "now") for c in CATALOGUE}
CASE_FIELDS.update({"OTHER_FILES_CHANGED": ("count", "sample"), "BASELINE_TAMPERED": ("why",),
                    "WATCHED_PATH_MISSING": ("path",)})

DEFAULT_EXCLUDES = [".git", ".svn", "node_modules", "__pycache__", "*.pyc", "*.log", "*.log.*", "*.tmp", "*.swp",
                    "storage/logs", "storage/framework", "bootstrap/cache", "var/cache", "var/log", "tmp", "cache",
                    ".cache", "sessions", "*.sock", "*.pid"]
MONEY_WORDS = ("settle", "payout", "wallet", "mpesa", "m_pesa", "daraja", "callback", "payment", "withdraw",
               "deposit", "ledger", "betslip", "bet_slip", "odds", "jackpot", "stk", "b2c", "c2b", "bonus",
               "balance", "cashout", "cash_out", "transaction", "credit", "debit", "stake", "winning", "refund")
CODE_EXT = (".php", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".go", ".java", ".jar", ".war", ".class", ".sh",
            ".pl", ".cs", ".dll", ".so", ".jsp", ".jspx", ".aspx", ".asp", ".phtml", ".php5", ".php7", ".phar",
            ".exe", ".bat", ".ps1", ".sql")
CONFIG_NAMES = (".env", ".env.*", "*.conf", "*.cnf", "*.ini", "*.yml", "*.yaml", "*.toml", "*.properties",
                "*.xml", "*.config", "appsettings*.json", "config*.json", "settings*.json", ".htaccess",
                "nginx.conf", "php.ini", "docker-compose*")
ACCESS_NAMES = ("authorized_keys", "authorized_keys2", "sudoers", "sshd_config", "ssh_config", "crontab", "passwd",
                "shadow", "group", "gshadow")
ACCESS_DIRS = ("/sudoers.d/", "/cron.d/", "/cron.daily/", "/cron.hourly/", "/crontabs/", "/sshd_config.d/",
               "/.ssh/", "/systemd/system/")
UPLOAD_DIRS = ("/uploads/", "/upload/", "/storage/app/public/", "/media/", "/user_files/", "/files/", "/images/",
               "/img/", "/attachments/", "/avatars/")
WEBSHELL = re.compile(
    r"eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_(POST|GET|REQUEST|COOKIE|SERVER))"
    r"|assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)"
    r"|(system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)"
    r"|preg_replace\s*\(\s*['\"].*/e['\"]"
    r"|create_function\s*\(.*\$_(POST|GET|REQUEST)"
    r"|child_process['\"]?\)?\.?\s*(exec|spawn)\w*\s*\(\s*req\.(query|body|params)"
    r"|FilesMan|WSO\s*Shell|b374k|c99shell|r57shell|weevely",
    re.I)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _norm(p: str) -> str:
    return os.path.abspath(p).replace("\\", "/")


def _excluded(rel: str, name: str, excludes: list[str]) -> bool:
    rel_l, name_l = rel.lower(), name.lower()
    for pat in excludes:
        p = pat.lower()
        if "/" in p:
            if rel_l == p or rel_l.startswith(p + "/") or ("/" + p + "/") in ("/" + rel_l + "/"):
                return True
        elif fnmatch.fnmatch(name_l, p):
            return True
    return False


def _sha256(path: str, size: int) -> str:
    if size > 64 * 1024 * 1024:
        return f"large:{size}:{int(os.path.getmtime(path))}"
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fingerprint_files(paths: list[str], excludes: list[str]) -> tuple[dict, list[str], int]:
    """{abs_path: [sha256, size, mode]}, missing roots, unreadable count."""
    files: dict[str, list] = {}
    missing, unreadable = [], 0
    for top in paths:
        t = _norm(top)
        if os.path.isfile(t):
            try:
                st = os.stat(t)
                files[t] = [_sha256(t, st.st_size), st.st_size, st.st_mode & 0o7777]
            except OSError:
                unreadable += 1
            continue
        if not os.path.isdir(t):
            missing.append(t)
            continue
        for dirpath, dirnames, filenames in os.walk(t):
            rel_dir = os.path.relpath(dirpath, t).replace("\\", "/")
            rel_dir = "" if rel_dir == "." else rel_dir + "/"
            dirnames[:] = [d for d in dirnames if not _excluded(rel_dir + d, d, excludes)
                           and not os.path.islink(os.path.join(dirpath, d))]
            for fn in filenames:
                if _excluded(rel_dir + fn, fn, excludes):
                    continue
                full = os.path.join(dirpath, fn)
                try:
                    st = os.lstat(full)
                    if stat.S_ISLNK(st.st_mode):
                        files[_norm(full)] = ["link:" + os.readlink(full), 0, 0]
                    elif stat.S_ISREG(st.st_mode):
                        files[_norm(full)] = [_sha256(full, st.st_size), st.st_size, st.st_mode & 0o7777]
                except OSError:
                    unreadable += 1
    return files, missing, unreadable


# ---------------------------------------------------------------------------
# Database structure fingerprint (money tables, triggers, routines)
# ---------------------------------------------------------------------------
def _h(s) -> str:
    return hashlib.sha256(str(s).encode("utf-8", "replace")).hexdigest()[:24]


def _q(s: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_$ .]+", s):
        raise ValueError(f"illegal name {s!r}")
    return s


def fingerprint_db(db, tables: list[str]) -> dict:
    e = db.engine
    tables = [t for t in dict.fromkeys(tables) if t]
    out = {"engine": e, "tables": {}, "triggers": {}, "routines": {}, "visibility": []}
    names = [t.split(".")[-1] for t in tables]
    inlist = ", ".join(f"'{_q(n)}'" for n in names) or "''"

    def q(sql):
        return db.try_query(sql)

    if e in ("sqlite", "csv"):
        r = q("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE type IN ('table', 'trigger', 'view')")
        for typ, name, tbl, sql in (r[1] if r else []):
            if typ == "table" and name in names:
                out["tables"][name] = {c: "" for c in db.columns(name)} | {"__ddl": _h(sql)}
            elif typ == "trigger":
                out["triggers"][name] = {"table": tbl, "def": _h(sql)}
        return out
    for t in tables:
        out["tables"][t.split(".")[-1]] = {}
    if e == "mysql":
        r = q("SELECT table_name, column_name, column_type FROM information_schema.columns "
              f"WHERE table_schema = DATABASE() AND table_name IN ({inlist})")
        trg = q("SELECT trigger_name, event_object_table, action_timing, event_manipulation, action_statement "
                "FROM information_schema.triggers WHERE trigger_schema = DATABASE()")
        rt = q("SELECT routine_name, routine_type, routine_definition FROM information_schema.routines "
               "WHERE routine_schema = DATABASE()")
        if trg:
            for n, tb, tm, ev, body in trg[1]:
                out["triggers"][n] = {"table": tb, "def": _h(f"{tm} {ev} {body}")}
        if rt:
            for n, typ, body in rt[1]:
                out["routines"][n] = {"type": typ, "def": _h(body)}
        if not out["triggers"]:
            out["visibility"].append(
                "MySQL hides triggers from accounts without the TRIGGER privilege - and that privilege also allows "
                "creating triggers, so AEGIS does not ask for it. Triggers were therefore NOT checked. Workaround: the "
                "DBA schedules a schema-only dump that the tamper alarm watches as a file, e.g. "
                "`mysqldump --no-data --triggers --routines --skip-dump-date sportsbook | "
                "sed 's/ AUTO_INCREMENT=[0-9]*//' > /var/lib/aegis/sportsbook-schema.sql` and add that file with "
                "--path. (A trigger that alters money still shows up in the ledger / M-Pesa reconciliation.)")
        if rt is not None and any(v.get("def") == _h(None) for v in out["routines"].values()):
            out["visibility"].append("Some MySQL routine bodies are hidden - GRANT SHOW_ROUTINE ON *.* (read-only, "
                                     "MySQL 8.0.20+) to the monitoring login to fingerprint them.")
    elif e == "postgres":
        sch = _q(db.schema or "public")
        r = q("SELECT table_name, column_name, data_type FROM information_schema.columns "
              f"WHERE table_schema = '{sch}' AND table_name IN ({inlist})")
        trg = q("SELECT t.tgname, c.relname, pg_get_triggerdef(t.oid) FROM pg_trigger t "
                "JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
                f"WHERE NOT t.tgisinternal AND n.nspname = '{sch}'")
        rt = q("SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')', p.prokind, p.prosrc "
               "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
               f"WHERE n.nspname = '{sch}'")
        if trg:
            for n, tb, d in trg[1]:
                out["triggers"][n] = {"table": tb, "def": _h(d)}
        if rt:
            for n, k, body in rt[1]:
                out["routines"][n] = {"type": str(k), "def": _h(body)}
    elif e == "mssql":
        r = q("SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS "
              f"WHERE TABLE_NAME IN ({inlist})")
        trg = q("SELECT t.name, OBJECT_NAME(t.parent_id), OBJECT_DEFINITION(t.object_id) FROM sys.triggers t "
                "WHERE t.parent_class = 1")
        rt = q("SELECT name, type, OBJECT_DEFINITION(object_id) FROM sys.objects WHERE type IN ('P','FN','IF','TF')")
        if trg:
            for n, tb, d in trg[1]:
                out["triggers"][n] = {"table": tb, "def": _h(d)}
        if rt:
            for n, k, body in rt[1]:
                out["routines"][n] = {"type": str(k).strip(), "def": _h(body)}
        out["visibility"].append("SQL Server shows trigger/routine definitions only with VIEW DEFINITION - grant it "
                                 "to the monitoring login for full coverage.")
    elif e == "oracle":
        r = q("SELECT table_name, column_name, data_type FROM user_tab_columns "
              f"WHERE table_name IN ({inlist.upper()})")
        trg = q("SELECT trigger_name, table_name, status FROM user_triggers")
        if trg:
            for n, tb, s in trg[1]:
                out["triggers"][n] = {"table": tb, "def": _h(s)}
        out["visibility"].append("Oracle: trigger bodies are not fingerprinted (names/status only).")
    else:
        r = None
    for tb, col, typ in (r[1] if r else []):
        key = next((k for k in out["tables"] if k.lower() == str(tb).lower()), str(tb))
        out["tables"].setdefault(key, {})[col] = str(typ)
    if r is None:
        out["visibility"].append("Column catalogue could not be read.")
    if trg is None:
        out["visibility"].append("Trigger catalogue could not be read by this account.")
    return out


# ---------------------------------------------------------------------------
# Baseline file: signing + audit-log anchor
# ---------------------------------------------------------------------------
def canonical(b: dict) -> bytes:
    return json.dumps({k: v for k, v in b.items() if k != "signature"}, sort_keys=True,
                      separators=(",", ":")).encode()


def sign_baseline(b: dict, key: str | None) -> dict:
    if key:
        b["signature"] = hmac.new(key.encode(), canonical(b), hashlib.sha256).hexdigest()
    else:
        b.pop("signature", None)
    return b


def file_sha(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def last_anchor(audit_path: str) -> str | None:
    last = None
    try:
        with open(audit_path, "r", encoding="utf-8") as fh:
            for line in fh:
                if '"BASELINE"' not in line:
                    continue
                e = json.loads(line)
                if e.get("action") == ACTION and e.get("decision") == "BASELINE":
                    last = (e.get("detail") or {}).get("baseline_sha256")
    except OSError:
        return None
    return last


# ---------------------------------------------------------------------------
# Compare
# ---------------------------------------------------------------------------
def classify(path: str) -> str:
    p = path.lower()
    name = p.rsplit("/", 1)[-1]
    if name in ACCESS_NAMES or name.startswith("sudoers") or any(d in p for d in ACCESS_DIRS):
        return "access"
    if any(fnmatch.fnmatch(name, c) for c in CONFIG_NAMES):
        return "config"
    if name.endswith(".sql") and "schema" in name:
        return "dbschema"                       # DBA-produced schema dump (triggers/routines on MySQL)
    if name.endswith(CODE_EXT):
        stem = re.sub(r"[^a-z0-9]+", "_", p)
        return "money" if any(w in stem for w in MONEY_WORDS) else "code"
    return "other"


def _webshell(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            m = WEBSHELL.search(fh.read(2_000_000))
        return m.group(0)[:80] if m else None
    except OSError:
        return None


def compare(base: dict, cur_files: dict, missing: list[str], cur_db: dict | None) -> Findings:
    F = Findings(CATALOGUE, CASE_FIELDS)
    old = base.get("files") or {}
    for m in missing:
        F.add("WATCHED_PATH_MISSING", None, path=m)
    gone_roots = tuple(m.rstrip("/") + "/" for m in missing)
    other, other_samples = 0, []

    def note_other(p):
        nonlocal other
        other += 1
        if len(other_samples) < 5:
            other_samples.append(p)

    for p, (sha, size, mode) in cur_files.items():
        was = old.get(p)
        kind = classify(p)
        if was is None:
            change = "added"
        elif was[0] != sha:
            change = "changed"
        else:
            change = None
        if change:
            short = sha[:12]
            ev = {"path": p, "change": change, "now": short, "was": (was[0][:12] if was else None)}
            if kind in ("money", "code"):
                ws = _webshell(p)
                if ws:
                    F.add("WEBSHELL_SUSPECT", None, path=p, now=short, pattern=ws)
            if kind == "money":
                F.add("MONEY_CODE_CHANGED", None, **ev)
            elif kind == "dbschema":
                F.add("DB_SCHEMA_CHANGED", None, **ev, note="schema dump changed - diff it against the previous copy "
                                                           "(triggers / routines / columns)")
            elif kind == "access":
                F.add("ACCESS_CHANGED", None, **ev)
            elif kind == "config":
                F.add("CONFIG_CHANGED", None, **ev)
            elif kind == "code":
                low = "/" + p.lower()
                if change == "added" and any(u in low for u in UPLOAD_DIRS):
                    F.add("SCRIPT_IN_UPLOAD_DIR", None, **ev)
                elif change == "added":
                    F.add("NEW_CODE_FILE", None, **ev)
                else:
                    F.add("CODE_CHANGED", None, **ev)
            else:
                note_other(p)
        if was is not None and os.name != "nt":
            om = was[2]
            weakened = []
            if mode & stat.S_IWOTH and not om & stat.S_IWOTH:
                weakened.append("now writable by everyone")
            if mode & (stat.S_ISUID | stat.S_ISGID) and not om & (stat.S_ISUID | stat.S_ISGID):
                weakened.append("gained setuid/setgid")
            if weakened:
                F.add("PERMISSIONS_WEAKENED", None, path=p, now=oct(mode), was=oct(om), what=", ".join(weakened))

    for p in old:
        if p in cur_files or p.startswith(gone_roots):
            continue
        kind = classify(p)
        ev = {"path": p, "change": "deleted", "now": "deleted", "was": old[p][0][:12]}
        if kind == "money":
            F.add("MONEY_CODE_CHANGED", None, **ev)
        elif kind == "access":
            F.add("ACCESS_CHANGED", None, **ev)
        elif kind in ("config", "code", "dbschema"):
            F.add("FILE_DELETED", None, **ev)
        else:
            note_other(p)
    if other:
        F.add("OTHER_FILES_CHANGED", None, count=other, sample=other_samples[0], examples=other_samples)

    bdb = base.get("db")
    if bdb and cur_db:
        for sect, code, label in (("triggers", "DB_TRIGGER_CHANGED", "trigger"),
                                  ("routines", "DB_ROUTINE_CHANGED", "routine")):
            a, b = bdb.get(sect) or {}, cur_db.get(sect) or {}
            for n in sorted(set(a) | set(b)):
                if a.get(n) == b.get(n):
                    continue
                change = "added" if n not in a else ("removed" if n not in b else "changed")
                F.add(code, None, path=f"{label}:{n}", change=change, table=(b.get(n) or a.get(n) or {}).get("table"),
                      now=(b.get(n) or {}).get("def", "removed")[:12])
        ta, tb = bdb.get("tables") or {}, cur_db.get("tables") or {}
        for t in sorted(set(ta) | set(tb)):
            ca, cb = ta.get(t) or {}, tb.get(t) or {}
            if ca == cb:
                continue
            added = sorted(set(cb) - set(ca) - {"__ddl"})
            removed = sorted(set(ca) - set(cb) - {"__ddl"})
            retyped = sorted(c for c in set(ca) & set(cb) if ca[c] != cb[c] and c != "__ddl")
            F.add("DB_SCHEMA_CHANGED", None, path=f"table:{t}", added=added, removed=removed, retyped=retyped,
                  now=_h(json.dumps(cb, sort_keys=True))[:12])
    return F


# ---------------------------------------------------------------------------
# Public entry points (authorized, audited)
# ---------------------------------------------------------------------------
def _authorize(authz, machine: str, paths: list[str], db) -> str | None:
    d = authz.authorize_local(ACTION, machine, paths)
    if not d:
        return d.reason
    if db is not None:
        d = authz.authorize_db(ACTION, db.label)
        if not d:
            return d.reason
    return None


def take_baseline(authz, machine: str, paths: list[str], excludes: list[str], state_dir: str,
                  db=None, db_tables: list[str] | None = None, key: str | None = None,
                  approved_by: str = "", note: str = "", prev: dict | None = None,
                  accept_risky: bool = False) -> dict:
    why = _authorize(authz, machine, paths, db)
    if why:
        return {"check": "tamper", "authorized": False, "reason": why}
    files, missing, unreadable = fingerprint_files(paths, excludes)
    dbfp = fingerprint_db(db, db_tables or []) if db is not None else None
    approved = None
    if prev is not None:
        F = compare(prev, files, missing, dbfp)
        for w in baseline_integrity(authz.audit.path, os.path.join(state_dir, "tamper-baseline.json"), prev, key):
            F.add("BASELINE_TAMPERED", None, why=w)
        approved = [{k: f[k] for k in ("code", "count")}
                    | {"paths": [s.get("path") or s.get("sample") or s.get("why") for s in f["samples"]]}
                    for f in F.list()]
        risky = [a for a in approved if a["code"] in RISKY_TO_APPROVE]
        if risky and not accept_risky:
            authz.audit.append("note", action=ACTION, target=machine, decision="REFUSED", detail={
                "why": "approval would accept a suspected webshell / script in an upload folder",
                "changes": risky, "requested_by": approved_by, "note": note})
            return {"check": "tamper", "authorized": True, "refused": True, "risky": risky}
    b = {"aegis_tamper_baseline": 1, "created": _now(), "machine": machine,
         "paths": [_norm(p) for p in paths], "excludes": excludes, "files": files,
         "db": dbfp, "db_label": db.label if db is not None else None, "db_tables": db_tables or [],
         "approved_by": approved_by, "note": note, "signed": bool(key)}
    sign_baseline(b, key)
    os.makedirs(state_dir, exist_ok=True)
    path = os.path.join(state_dir, "tamper-baseline.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(b, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)
    authz.audit.append("note", action=ACTION, target=machine, decision="BASELINE", detail={
        "baseline_sha256": file_sha(path), "files": len(files), "paths": b["paths"], "missing": missing,
        "unreadable": unreadable, "db": b["db_label"], "triggers": len((dbfp or {}).get("triggers") or {}),
        "routines": len((dbfp or {}).get("routines") or {}), "approved_by": approved_by, "note": note,
        "signed": bool(key), "approved_changes": approved})
    return {"check": "tamper", "authorized": True, "baseline": path, "files": len(files), "missing": missing,
            "unreadable": unreadable, "db": dbfp, "approved_changes": approved}


def load_baseline(state_dir: str) -> dict:
    with open(os.path.join(state_dir, "tamper-baseline.json"), "r", encoding="utf-8") as fh:
        return json.load(fh)


def baseline_integrity(audit_path: str, bpath: str, base: dict, key: str | None,
                       notes: list | None = None) -> list[str]:
    """Reasons to distrust the baseline file (empty list = trustworthy).

    A signed baseline checked WITHOUT the key is not a tamper sign - the key is meant to
    stay off the server. The audit-log anchor is still verified; the unverified seal is
    added to `notes` (coverage) instead."""
    from ..audit import AuditLog
    out = []
    ok, msg = AuditLog.verify(audit_path)
    if not ok:
        out.append(f"the audit log itself fails verification ({msg})")
    anchor = last_anchor(audit_path)
    now_sha = file_sha(bpath)
    if anchor is None:
        out.append("no baseline approval recorded in this audit log")
    elif anchor != now_sha:
        out.append(f"fingerprint file hash {now_sha[:12]} != hash recorded at approval {anchor[:12]}")
    if base.get("signed"):
        if not key:
            if notes is not None:
                notes.append("The baseline's HMAC seal was not verified this run (seal key not present - by design it "
                             "stays off the server). The audit-log anchor WAS verified. Run `aegis tamper check` with "
                             "AEGIS_TAMPER_KEY set from the assessor's machine to verify the seal.")
        elif not hmac.compare_digest(base.get("signature", ""),
                                     hmac.new(key.encode(), canonical(base), hashlib.sha256).hexdigest()):
            out.append("HMAC signature does not match")
    return out


def run_check(authz, machine: str, state_dir: str, db=None, key: str | None = None) -> dict:
    bpath = os.path.join(state_dir, "tamper-baseline.json")
    base = load_baseline(state_dir)
    why = _authorize(authz, machine, base["paths"], db)
    if why:
        return {"check": "tamper", "authorized": False, "reason": why}

    seal_notes: list[str] = []
    integrity = baseline_integrity(authz.audit.path, bpath, base, key, seal_notes)
    now_sha = file_sha(bpath)

    files, missing, unreadable = fingerprint_files(base["paths"], base.get("excludes") or DEFAULT_EXCLUDES)
    dbfp = fingerprint_db(db, base.get("db_tables") or []) if db is not None and base.get("db") else None
    F = compare(base, files, missing, dbfp)
    for w in integrity:
        F.add("BASELINE_TAMPERED", None, why=w)
    coverage = [f"Watching {len(base['paths'])} path(s), {len(files)} file(s); baseline approved "
                f"{base.get('created')} by {base.get('approved_by') or '(not named)'}"
                + (f" - {base['note']}" if base.get("note") else "") + "."]
    coverage.extend(seal_notes)
    if unreadable:
        coverage.append(f"{unreadable} file(s) could not be read (permissions) and were not compared.")
    if base.get("db") and db is None:
        coverage.append("The baseline includes the database structure, but no database was given this run - "
                        "trigger/schema checks NOT run.")
    for v in (dbfp or {}).get("visibility") or []:
        coverage.append(v)
    if not base.get("signed"):
        coverage.append("Baseline is not HMAC-signed (no seal key at approval); it is protected by the audit-log "
                        "anchor only. Set AEGIS_TAMPER_KEY (kept off the server) when approving for a second, "
                        "independent seal.")
    res = F.list()
    out = {"check": "tamper", "module_title": f"Tamper alarm - {machine}", "target": machine, "authorized": True,
           "module_findings": res, "coverage": coverage, "findings": F.plain(),
           "scanned": {"files": len(files), "paths": len(base["paths"]),
                       "db_triggers": len((dbfp or {}).get("triggers") or {}),
                       "db_routines": len((dbfp or {}).get("routines") or {})},
           "baseline_sha256": now_sha}
    authz.audit.append("check", action=ACTION, target=machine, decision="DONE", detail=out)
    return dict(out, case_keys=F.case_keys())
