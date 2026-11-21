"""
Database identifier - "what am I looking at?"

Give it almost anything and it tells you the database engine, with zero
third-party dependencies:

  * a connection URL       mysql://u@10.0.0.5/bets, postgresql://..., mssql://...,
                           jdbc:mysql://..., mongodb+srv://..., sqlite:///x.db
  * an ADO / ODBC string   Server=10.0.0.5;Database=Bets;User Id=ro;
  * a file or folder       .db/.sqlite (magic bytes), .mdb/.accdb, DuckDB, Parquet,
                           mysqldump / pg_dump files, a CSV export folder
  * a live host:port       reads the server's own handshake (MySQL/MariaDB greeting,
                           PostgreSQL SSL reply, SQL Server TDS pre-login, MongoDB
                           hello, Redis PING). Never logs in, never sends a query.

It also reports whether AEGIS can READ that engine on this machine (which Python
driver is installed, or exactly what to install).

Network probing is an action against a target, so the caller (cli / ledger) must
authorize it first; this module only does the identification.
"""
from __future__ import annotations

import importlib.util
import os
import re
import socket
import struct
from urllib.parse import unquote, urlsplit

# ---------------------------------------------------------------------------
# Engine catalogue
# ---------------------------------------------------------------------------
ENGINES = {
    "sqlite":   {"label": "SQLite",               "port": None,  "drivers": ["sqlite3"],                         "ledger": True},
    "csv":      {"label": "CSV export",           "port": None,  "drivers": ["csv"],                             "ledger": True},
    "mysql":    {"label": "MySQL / MariaDB",      "port": 3306,  "drivers": ["pymysql", "mysql.connector", "MySQLdb"], "ledger": True},
    "postgres": {"label": "PostgreSQL",           "port": 5432,  "drivers": ["psycopg", "psycopg2", "pg8000"],   "ledger": True},
    "mssql":    {"label": "Microsoft SQL Server", "port": 1433,  "drivers": ["pyodbc", "pymssql"],               "ledger": True},
    "oracle":   {"label": "Oracle",               "port": 1521,  "drivers": ["oracledb"],                        "ledger": True},
    "mongodb":  {"label": "MongoDB",              "port": 27017, "drivers": ["pymongo"],                         "ledger": False},
    "redis":    {"label": "Redis",                "port": 6379,  "drivers": ["redis"],                           "ledger": False},
    "access":   {"label": "Microsoft Access",     "port": None,  "drivers": ["pyodbc"],                          "ledger": False},
    "duckdb":   {"label": "DuckDB",               "port": None,  "drivers": ["duckdb"],                          "ledger": False},
    "parquet":  {"label": "Parquet file",         "port": None,  "drivers": ["pyarrow"],                         "ledger": False},
}

PIP_NAME = {"mysql.connector": "mysql-connector-python", "MySQLdb": "mysqlclient",
            "psycopg": "psycopg[binary]", "redis": "redis"}

SCHEME_ALIASES = {
    "mysql": "mysql", "mariadb": "mysql", "mysqlx": "mysql",
    "postgres": "postgres", "postgresql": "postgres", "pgsql": "postgres", "redshift": "postgres",
    "cockroachdb": "postgres", "timescale": "postgres",
    "mssql": "mssql", "sqlserver": "mssql", "sql-server": "mssql", "jtds": "mssql",
    "oracle": "oracle", "oracle+oracledb": "oracle",
    "sqlite": "sqlite", "sqlite3": "sqlite", "file": "sqlite",
    "mongodb": "mongodb", "mongodb+srv": "mongodb",
    "redis": "redis", "rediss": "redis",
    "csv": "csv",
}

PORT_HINT = {3306: "mysql", 3307: "mysql", 5432: "postgres", 5433: "postgres", 1433: "mssql",
             1521: "oracle", 27017: "mongodb", 6379: "redis"}


_LOADABLE: dict[str, str | None] = {}


def _loads(module: str) -> str | None:
    """None if the driver really imports; otherwise the reason it doesn't.

    Installed is not enough: on locked-down hosts (e.g. Windows Application
    Control) a driver's compiled DLL can be present but blocked from loading."""
    if module not in _LOADABLE:
        if importlib.util.find_spec(module.split(".")[0]) is None:
            _LOADABLE[module] = "not installed"
        else:
            try:
                importlib.import_module(module)
                _LOADABLE[module] = None
            except Exception as e:  # noqa: BLE001
                _LOADABLE[module] = f"installed but fails to load ({str(e).splitlines()[0][:100]})"
    return _LOADABLE[module]


def driver_status(engine: str) -> dict:
    """Which driver AEGIS would use for `engine`, or what to install."""
    info = ENGINES.get(engine, {})
    drivers = info.get("drivers", [])
    builtin = {"sqlite3", "csv"}
    broken = {}
    for d in drivers:
        if d in builtin:
            return {"readable": True, "driver": d, "install": None}
        why = _loads(d)
        if why is None:
            return {"readable": True, "driver": d, "install": None, **({"skipped": broken} if broken else {})}
        if why != "not installed":
            broken[d] = why
    # Prefer suggesting a pure-Python driver if a compiled one was blocked.
    pure = {"postgres": "pg8000", "mysql": "pymysql"}
    hint = pure.get(engine) if broken else None
    hint = hint or (PIP_NAME.get(drivers[0], drivers[0]) if drivers else None)
    out = {"readable": False, "driver": None, "install": f"pip install {hint}" if hint else None}
    if broken:
        out["skipped"] = broken
    return out


def _result(engine: str | None, how: str, *, target: str, evidence: str = "", **extra) -> dict:
    info = ENGINES.get(engine or "", {})
    out = {
        "check": "db-identify",
        "target": target,
        "engine": engine or "unknown",
        "label": info.get("label", "Unknown"),
        "identified_by": how,
        "evidence": evidence,
        "ledger_supported": bool(info.get("ledger")),
    }
    if engine:
        out.update(driver_status(engine))
    out.update(extra)
    return out


# ---------------------------------------------------------------------------
# Connection strings
# ---------------------------------------------------------------------------
def redact(target: str) -> str:
    """Strip passwords from a URL or ADO string so it is safe to log/print."""
    s = re.sub(r"(://[^:/@]+):[^@]*@", r"\1:***@", target)
    s = re.sub(r"(?i)\b(password|pwd)\s*=\s*[^;]*", r"\1=***", s)
    return s


def parse_url(url: str) -> dict:
    """Split a DB URL into parts. Password is returned but must never be logged."""
    s = url.strip()
    if s.lower().startswith("jdbc:"):
        s = s[5:]
    # jdbc:sqlserver://host:1433;databaseName=Bets;user=x
    params = {}
    if ";" in s and "://" in s:
        head, *rest = s.split(";")
        for kv in rest:
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k.strip().lower()] = v.strip()
        s = head
    parts = urlsplit(s)
    scheme = parts.scheme.lower()
    engine = SCHEME_ALIASES.get(scheme) or SCHEME_ALIASES.get(scheme.split("+")[0])
    if engine == "sqlite":
        path = s.split("://", 1)[1] if "://" in s else s
        if path.startswith("/") and re.match(r"^/[A-Za-z]:", path):
            path = path[1:]                     # sqlite:///C:/x.db -> C:/x.db
        elif path.startswith("//"):
            path = path[1:]                     # sqlite:////abs/x.db -> /abs/x.db
        elif path.startswith("/"):
            path = path[1:]                     # sqlite:///rel.db -> rel.db
        return {"engine": "sqlite", "path": path, "host": None, "port": None,
                "database": os.path.basename(path), "user": None, "password": None}
    database = (parts.path or "").lstrip("/") or params.get("databasename") or params.get("database")
    return {
        "engine": engine,
        "host": parts.hostname,
        "port": parts.port or (ENGINES.get(engine or "", {}).get("port")),
        "database": unquote(database) if database else None,
        "user": unquote(parts.username) if parts.username else params.get("user"),
        "password": unquote(parts.password) if parts.password else params.get("password"),
        "path": None,
    }


def parse_ado(conn: str) -> dict | None:
    """Server=...;Database=...;User Id=...;Password=...  (SQL Server / ODBC style)."""
    kv = {}
    for part in conn.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            kv[k.strip().lower()] = v.strip()
    server = kv.get("server") or kv.get("data source") or kv.get("address")
    if not server:
        return None
    driver = kv.get("driver", "").lower()
    provider = kv.get("provider", "").lower()
    engine = "mssql"
    if "mysql" in driver or "mysql" in provider:
        engine = "mysql"
    elif "postgres" in driver or "psql" in driver:
        engine = "postgres"
    elif "oracle" in driver or "oracle" in provider:
        engine = "oracle"
    host, port = server, None
    host = re.sub(r"^tcp:", "", host, flags=re.I)
    if "," in host:
        host, p = host.split(",", 1)
        port = int(p) if p.strip().isdigit() else None
    elif ":" in host:
        host, p = host.rsplit(":", 1)
        port = int(p) if p.isdigit() else None
    host = host.split("\\")[0]  # named instance
    return {"engine": engine, "host": host, "port": port or ENGINES[engine]["port"],
            "database": kv.get("database") or kv.get("initial catalog"),
            "user": kv.get("user id") or kv.get("uid") or kv.get("user"),
            "password": kv.get("password") or kv.get("pwd"), "path": None}


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------
def sniff_file(path: str) -> dict:
    if os.path.isdir(path):
        csvs = [f for f in os.listdir(path) if f.lower().endswith((".csv", ".tsv"))]
        if csvs:
            return _result("csv", "folder of CSV exports", target=path,
                           evidence=f"{len(csvs)} CSV file(s): {', '.join(sorted(csvs)[:8])}")
        return _result(None, "folder", target=path, evidence="no CSV/TSV files found")
    with open(path, "rb") as fh:
        head = fh.read(4096)
    name = path.lower()
    if head.startswith(b"SQLite format 3\x00"):
        return _result("sqlite", "file signature", target=path, evidence="header 'SQLite format 3'")
    if head[4:19] in (b"Standard Jet DB", b"Standard ACE DB"):
        return _result("access", "file signature", target=path, evidence=head[4:19].decode(),
                       advice="Export the tables to CSV (or attach to SQL Server) and point AEGIS at that.")
    if head[8:12] == b"DUCK":
        return _result("duckdb", "file signature", target=path, evidence="DuckDB header",
                       advice="Run `COPY tbl TO 'tbl.csv'` for the bets/wallet tables and use the CSV folder.")
    if head.startswith(b"PAR1"):
        return _result("parquet", "file signature", target=path, evidence="Parquet 'PAR1' magic")
    if head.startswith(b"PGDMP"):
        return _result("postgres", "file signature", target=path, evidence="pg_dump custom-format archive",
                       dump=True, advice="Restore into a scratch Postgres (pg_restore) and connect read-only.")
    text = head.decode("utf-8", "replace")
    if "MySQL dump" in text or "MariaDB dump" in text:
        return _result("mysql", "dump header", target=path, evidence="mysqldump header",
                       dump=True, advice="Restore into a scratch MySQL and connect read-only.")
    if "PostgreSQL database dump" in text:
        return _result("postgres", "dump header", target=path, evidence="pg_dump plain-SQL header",
                       dump=True, advice="Restore into a scratch Postgres (psql -f) and connect read-only.")
    if head.startswith(b"PK\x03\x04") and name.endswith((".xlsx", ".xlsm")):
        return _result(None, "file signature", target=path, evidence="Excel workbook",
                       advice="Save each sheet as CSV into one folder and point AEGIS at the folder.")
    if name.endswith((".csv", ".tsv")):
        return _result("csv", "file extension", target=path, evidence="single CSV file")
    if name.endswith((".db", ".sqlite", ".sqlite3")) and not head:
        return _result("sqlite", "file extension (empty file)", target=path)
    return _result(None, "file", target=path, evidence=f"unrecognised header {head[:16]!r}")


# ---------------------------------------------------------------------------
# Live handshake probes (no login, no queries)
# ---------------------------------------------------------------------------
def _recv(sock: socket.socket, n: int = 1024) -> bytes:
    try:
        return sock.recv(n)
    except (socket.timeout, OSError):
        return b""


def _open(host: str, port: int, timeout: float) -> socket.socket:
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    return s


def _parse_mysql_greeting(data: bytes) -> str | None:
    if len(data) < 6:
        return None
    payload = data[4:]
    if payload[0] == 0x0A:                        # protocol v10 greeting
        ver = payload[1:].split(b"\x00", 1)[0].decode("latin-1", "replace")
        return f"server version {ver}" + (" (MariaDB)" if "mariadb" in ver.lower() else "")
    if payload[0] == 0xFF:                        # error packet - still MySQL
        msg = payload[3:].decode("latin-1", "replace")
        return f"MySQL error packet: {msg.strip()[:120]}"
    return None


def _probe_postgres(host: str, port: int, timeout: float) -> str | None:
    with _open(host, port, timeout) as s:
        s.sendall(struct.pack("!ii", 8, 80877103))      # SSLRequest
        r = _recv(s, 1)
    if r in (b"S", b"N"):
        return f"answered SSLRequest with {r.decode()!r} ({'TLS supported' if r == b'S' else 'no TLS'})"
    return None


def _probe_mssql(host: str, port: int, timeout: float) -> str | None:
    # TDS PRELOGIN with just VERSION + terminator.
    opts = bytes([0x00]) + struct.pack("!HH", 6, 6) + bytes([0xFF])
    payload = opts + bytes(6)
    header = struct.pack("!BBHHBB", 0x12, 0x01, 8 + len(payload), 0, 1, 0)
    with _open(host, port, timeout) as s:
        s.sendall(header + payload)
        r = _recv(s, 512)
    if len(r) >= 8 and r[0] == 0x04:
        ver = ""
        try:
            body = r[8:]
            off, ln = struct.unpack("!HH", body[1:5])
            major, minor = body[off], body[off + 1]
            build = struct.unpack("!H", body[off + 2:off + 4])[0]
            ver = f" version {major}.{minor}.{build}"
        except Exception:  # noqa: BLE001
            pass
        return f"answered TDS pre-login{ver}"
    return None


def _bson_hello() -> bytes:
    e1 = b"\x10hello\x00" + struct.pack("<i", 1)
    db = b"admin\x00"
    e2 = b"\x02$db\x00" + struct.pack("<i", len(db)) + db
    body = e1 + e2 + b"\x00"
    return struct.pack("<i", 4 + len(body)) + body


def _probe_mongodb(host: str, port: int, timeout: float) -> str | None:
    doc = _bson_hello()
    msg = struct.pack("<I", 0) + b"\x00" + doc          # flagBits + section kind 0
    header = struct.pack("<iiii", 16 + len(msg), 1, 0, 2013)
    with _open(host, port, timeout) as s:
        s.sendall(header + msg)
        r = _recv(s, 2048)
    if len(r) >= 16 and struct.unpack("<i", r[12:16])[0] in (2013, 1):
        return "answered MongoDB OP_MSG hello"
    return None


def _probe_redis(host: str, port: int, timeout: float) -> str | None:
    with _open(host, port, timeout) as s:
        s.sendall(b"PING\r\n")
        r = _recv(s, 256)
    if r.startswith((b"+PONG", b"-NOAUTH", b"-ERR", b"-DENIED")):
        note = "NO PASSWORD REQUIRED" if r.startswith(b"+PONG") else "auth required"
        return f"answered PING ({note})"
    return None


def probe(host: str, port: int, timeout: float = 4.0) -> dict:
    """Identify the service on host:port from its own handshake."""
    target = f"{host}:{port}"
    try:
        with _open(host, port, timeout) as s:
            first = _recv(s, 1024)            # MySQL speaks first
    except OSError as e:
        return _result(None, "tcp", target=target, evidence=f"connection failed: {e}", reachable=False)
    if first:
        mv = _parse_mysql_greeting(first)
        if mv:
            return _result("mysql", "server greeting", target=target, evidence=mv, reachable=True)
        return _result(None, "server banner", target=target,
                       evidence=f"unrecognised banner {first[:40]!r}", reachable=True)

    hinted = PORT_HINT.get(port)
    order = ["postgres", "mssql", "mongodb", "redis"]
    if hinted in order:
        order.remove(hinted)
        order.insert(0, hinted)
    probes = {"postgres": _probe_postgres, "mssql": _probe_mssql,
              "mongodb": _probe_mongodb, "redis": _probe_redis}
    for eng in order:
        try:
            ev = probes[eng](host, port, timeout)
        except OSError:
            ev = None
        if ev:
            extra = {"reachable": True}
            if eng == "redis" and "NO PASSWORD" in ev:
                extra["finding"] = "Redis reachable with no password - anyone on this network can read/write it"
            if eng == "mongodb":
                extra["note"] = "MongoDB answered without credentials; check that auth is enforced"
            return _result(eng, "handshake", target=target, evidence=ev, **extra)

    if hinted == "oracle":
        return _result("oracle", "port 1521 (silent listener)", target=target,
                       evidence="no banner; port convention only - confirm with the DBA", reachable=True)
    return _result(None, "handshake", target=target, evidence="port open but no known database answered",
                   reachable=True)


# ---------------------------------------------------------------------------
# One entry point
# ---------------------------------------------------------------------------
HOSTPORT = re.compile(r"^\[?([A-Za-z0-9_.:-]+?)\]?:(\d{1,5})$")


def classify(target: str) -> tuple[str, dict]:
    """Decide what KIND of target this is without touching the network.

    Returns (kind, parsed) where kind is 'url', 'ado', 'file', 'hostport' or 'unknown'.
    """
    t = target.strip().strip('"').strip("'")
    if os.path.exists(t):
        return "file", {"path": t}
    if "://" in t or t.lower().startswith("jdbc:"):
        return "url", parse_url(t)
    if ";" in t and "=" in t:
        ado = parse_ado(t)
        if ado:
            return "ado", ado
    m = HOSTPORT.match(t)
    if m:
        return "hostport", {"host": m.group(1), "port": int(m.group(2))}
    return "unknown", {}


def identify(target: str, *, allow_network: bool = False, timeout: float = 4.0) -> dict:
    kind, parsed = classify(target)
    safe = redact(target)
    if kind == "file":
        return sniff_file(parsed["path"])
    if kind in ("url", "ado"):
        eng = parsed.get("engine")
        res = _result(eng, "connection string" if kind == "ado" else "URL scheme", target=safe,
                      evidence=f"host={parsed.get('host')} port={parsed.get('port')} db={parsed.get('database')}")
        if eng == "sqlite" and parsed.get("path") and os.path.exists(parsed["path"]):
            res = sniff_file(parsed["path"])
            res["target"] = safe
        if allow_network and parsed.get("host") and parsed.get("port"):
            live = probe(parsed["host"], int(parsed["port"]), timeout)
            res["live_check"] = {k: live[k] for k in ("engine", "evidence") if k in live}
            if live.get("finding"):
                res["finding"] = live["finding"]
            if eng and live["engine"] not in ("unknown", eng):
                res["warning"] = f"URL says {eng} but the server answered like {live['engine']}"
        return res
    if kind == "hostport":
        if not allow_network:
            return _result(PORT_HINT.get(parsed["port"]), "port number only (network probe not authorized)",
                           target=safe, evidence="re-run with network probing authorized to confirm")
        return probe(parsed["host"], parsed["port"], timeout)
    return _result(None, "unrecognised input", target=safe,
                   evidence="give a connection URL, an ADO string, a file/folder path, or host:port")
