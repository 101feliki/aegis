"""
One read-only interface over every SQL engine AEGIS supports.

    db = open_readonly("mysql://aegis_ro@10.0.0.5/sportsbook", password=...)
    db.tables()                 -> ["bets", "wallet_transactions", ...]
    db.columns("bets")          -> ["id", "user_id", "stake", ...]
    db.select("bets", ["id", "stake"], where_since=("created_at", "2026-11-01"))

Safety layers (defence in depth - any one is enough to stop a write):
  1. Session is opened READ ONLY wherever the engine supports it
     (SQLite mode=ro + query_only, MySQL/Postgres/Oracle read-only transactions,
     SQL Server ApplicationIntent=ReadOnly).
  2. Every statement passes a guard: one statement only, must start with SELECT/WITH.
  3. AEGIS never calls commit(); the connection is rolled back and closed at the end.
  4. Table/column names come from a mapping file, so they are validated and quoted
     per dialect - a tampered mapping cannot inject SQL.
  The client should ALSO give AEGIS a database user with SELECT-only grants.

CSV exports need no database at all: the folder is loaded into a private
in-memory SQLite, so the same checks run on an offline export.
"""
from __future__ import annotations

import csv
import os
import re
import sqlite3
import ssl

from .identify import classify, driver_status, redact

IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_$ ]*$")
SAFE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?$")


class ReadOnlyViolation(Exception):
    pass


class DriverMissing(Exception):
    pass


def guard(sql: str) -> str:
    s = sql.strip().rstrip(";").strip()
    if ";" in s:
        raise ReadOnlyViolation("multiple statements are not allowed")
    first = s.split(None, 1)[0].upper() if s else ""
    if first not in ("SELECT", "WITH"):
        raise ReadOnlyViolation(f"only SELECT queries are allowed (got {first or 'empty'})")
    return s


class ReadOnlyDB:
    """Thin wrapper around a DB-API connection."""

    def __init__(self, conn, engine: str, label: str, schema: str | None = None):
        self._conn = conn
        self.engine = engine
        self.label = label                      # redacted, safe to log
        self.schema = schema
        self.can_write: bool | None = False if engine in ("sqlite", "csv") else None

    # ---- identifiers -----------------------------------------------------
    def quote(self, name: str) -> str:
        parts = name.split(".")
        for p in parts:
            if not IDENT.match(p):
                raise ReadOnlyViolation(f"illegal identifier {name!r}")
        if self.engine == "mysql":
            return ".".join(f"`{p}`" for p in parts)
        if self.engine == "mssql":
            return ".".join(f"[{p}]" for p in parts)
        return ".".join(f'"{p}"' for p in parts)

    # ---- queries ---------------------------------------------------------
    def query(self, sql: str, limit: int | None = None):
        sql = guard(sql)
        cur = self._conn.cursor()
        try:
            cur.execute(sql)
            cols = [d[0] for d in cur.description]
            rows = cur.fetchmany(limit) if limit else cur.fetchall()
            return cols, [tuple(r) for r in rows]
        finally:
            try:
                cur.close()
            except Exception:  # noqa: BLE001
                pass

    def _select_sql(self, table: str, columns: list[str], where_since: tuple[str, str] | None) -> str:
        cols = ", ".join(self.quote(c) for c in columns)
        sql = f"SELECT {cols} FROM {self.quote(table)}"
        if where_since:
            col, since = where_since
            if not SAFE_DATE.match(since):
                raise ReadOnlyViolation(f"bad date {since!r}")
            sql += f" WHERE {self.quote(col)} >= '{since}'"
        return sql

    def select(self, table: str, columns: list[str], where_since: tuple[str, str] | None = None):
        return list(self.iter_select(table, columns, where_since))

    def iter_select(self, table: str, columns: list[str], where_since: tuple[str, str] | None = None,
                    batch: int = 20000):
        """Stream rows as dicts, `batch` at a time - memory stays flat on huge tables."""
        sql = guard(self._select_sql(table, columns, where_since))
        cur = self._conn.cursor()
        try:
            cur.execute(sql)
            while True:
                rows = cur.fetchmany(batch)
                if not rows:
                    break
                for r in rows:
                    yield dict(zip(columns, r))
        finally:
            try:
                cur.close()
            except Exception:  # noqa: BLE001
                pass

    def sample_distinct(self, table: str, column: str, limit: int = 40) -> list:
        q = f"SELECT DISTINCT {self.quote(column)} FROM {self.quote(table)}"
        if self.engine == "mssql":
            q = f"SELECT DISTINCT TOP {int(limit)} {self.quote(column)} FROM {self.quote(table)}"
        elif self.engine == "oracle":
            q += f" FETCH FIRST {int(limit)} ROWS ONLY"
        else:
            q += f" LIMIT {int(limit)}"
        _, rows = self.query(q)
        return [r[0] for r in rows]

    def try_query(self, sql: str):
        """query() that returns None on a database error (e.g. permission denied) and
        rolls back, so an aborted Postgres transaction doesn't poison later reads."""
        try:
            return self.query(sql)
        except ReadOnlyViolation:
            raise
        except Exception:  # noqa: BLE001 - driver-specific error classes
            try:
                self._conn.rollback()
            except Exception:  # noqa: BLE001
                pass
            return None

    def row_count(self, table: str) -> int | None:
        # COUNT(*) needs table-wide SELECT on some engines; under column-level grants
        # (the recommended least-privilege setup) it is refused - that's fine, it's info only.
        res = self.try_query(f"SELECT COUNT(*) FROM {self.quote(table)}")
        return int(res[1][0][0]) if res else None

    # ---- introspection ---------------------------------------------------
    def tables(self) -> list[str]:
        e = self.engine
        if e in ("sqlite", "csv"):
            _, rows = self.query("SELECT name FROM sqlite_master WHERE type IN ('table','view') "
                                 "AND name NOT LIKE 'sqlite_%' ORDER BY name")
        elif e == "mysql":
            _, rows = self.query("SELECT table_name FROM information_schema.tables "
                                 "WHERE table_schema = DATABASE() ORDER BY table_name")
        elif e == "postgres":
            sch = self.schema or "public"
            if not IDENT.match(sch):
                raise ReadOnlyViolation("bad schema")
            _, rows = self.query("SELECT table_name FROM information_schema.tables "
                                 f"WHERE table_schema = '{sch}' ORDER BY table_name")
        elif e == "mssql":
            _, rows = self.query("SELECT TABLE_SCHEMA + '.' + TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
                                 "ORDER BY TABLE_SCHEMA, TABLE_NAME")
            rows = [(r[0][4:] if r[0].startswith("dbo.") else r[0],) for r in rows]
        elif e == "oracle":
            _, rows = self.query("SELECT table_name FROM user_tables ORDER BY table_name")
        else:
            rows = []
        return [r[0] for r in rows]

    def columns(self, table: str) -> list[str]:
        e = self.engine
        if e in ("sqlite", "csv"):
            cur = self._conn.cursor()
            cur.execute(f"PRAGMA table_info({self.quote(table)})")   # read-only pragma
            return [r[1] for r in cur.fetchall()]
        q = self.quote(table)                      # validates every part against IDENT (no quotes possible)
        # Catalog first: it works when the account was granted SELECT on specific
        # columns only (SELECT * would be refused) and lists just the columns it may read.
        parts = table.split(".")
        name = parts[-1]
        cat = None
        if e == "mysql":
            cat = ("SELECT column_name FROM information_schema.columns WHERE table_schema = "
                   + (f"'{parts[0]}'" if len(parts) > 1 else "DATABASE()")
                   + f" AND table_name = '{name}' ORDER BY ordinal_position")
        elif e == "postgres":
            sch = parts[0] if len(parts) > 1 else (self.schema or "public")
            if IDENT.match(sch):
                cat = ("SELECT column_name FROM information_schema.columns "
                       f"WHERE table_schema = '{sch}' AND table_name = '{name}' ORDER BY ordinal_position")
        elif e == "mssql":
            sch = parts[0] if len(parts) > 1 else "dbo"
            cat = ("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
                   f"WHERE TABLE_SCHEMA = '{sch}' AND TABLE_NAME = '{name}' ORDER BY ORDINAL_POSITION")
        if cat:
            res = self.try_query(cat)
            if res and res[1]:
                return [r[0] for r in res[1]]
        if e == "mssql":
            sql = f"SELECT TOP 0 * FROM {q}"
        elif e == "oracle":
            sql = f"SELECT * FROM {q} WHERE 1=0"
        else:
            sql = f"SELECT * FROM {q} LIMIT 0"
        cols, _ = self.query(sql)
        return cols

    def write_capable(self) -> bool | None:
        """Can the account AEGIS logged in with change data? None = could not tell."""
        e = self.engine
        try:
            if e == "mssql":
                _, rows = self.query(
                    "SELECT CAST(ISNULL(IS_SRVROLEMEMBER('sysadmin'),0) AS INT) "
                    "+ CAST(ISNULL(IS_ROLEMEMBER('db_owner'),0) AS INT) "
                    "+ CAST(ISNULL(IS_ROLEMEMBER('db_datawriter'),0) AS INT) "
                    "+ CAST(ISNULL(IS_ROLEMEMBER('db_ddladmin'),0) AS INT) "
                    "+ HAS_PERMS_BY_NAME(DB_NAME(),'DATABASE','INSERT') "
                    "+ HAS_PERMS_BY_NAME(DB_NAME(),'DATABASE','UPDATE') "
                    "+ HAS_PERMS_BY_NAME(DB_NAME(),'DATABASE','DELETE')")
                return int(rows[0][0] or 0) > 0
            if e == "postgres":
                _, rows = self.query(
                    "SELECT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) OR COALESCE(("
                    "SELECT bool_or(has_table_privilege(c.oid, 'INSERT') OR has_table_privilege(c.oid, 'UPDATE') "
                    "OR has_table_privilege(c.oid, 'DELETE')) FROM pg_class c "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE c.relkind = 'r' AND n.nspname NOT IN ('pg_catalog', 'information_schema')), false)")
                return bool(rows[0][0])
            if e == "mysql":
                cur = self._conn.cursor()
                cur.execute("SHOW GRANTS")             # read-only statement, not routed through the guard
                grants = " ".join(str(r[0]) for r in cur.fetchall()).upper()
                cur.close()
                return any(k in grants for k in ("ALL PRIVILEGES", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER"))
            if e in ("sqlite", "csv"):
                return False                            # opened mode=ro / in-memory copy
        except Exception:  # noqa: BLE001
            return None
        return None

    def close(self) -> None:
        try:
            self._conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ---------------------------------------------------------------------------
# Openers
# ---------------------------------------------------------------------------
def _sqlite(path: str) -> sqlite3.Connection:
    uri = "file:" + os.path.abspath(path).replace("\\", "/") + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.execute("PRAGMA query_only = ON")
    return conn


def _table_name(stem: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "_", stem)
    return name if re.match(r"^[A-Za-z_]", name) else "t_" + name


def _csv_folder(path: str) -> sqlite3.Connection:
    files = [path] if os.path.isfile(path) else [
        os.path.join(path, f) for f in sorted(os.listdir(path)) if f.lower().endswith((".csv", ".tsv"))]
    conn = sqlite3.connect(":memory:")
    for f in files:
        delim = "\t" if f.lower().endswith(".tsv") else ","
        with open(f, "r", encoding="utf-8-sig", newline="") as fh:
            sample = fh.read(8192)
            fh.seek(0)
            if delim == ",":
                try:
                    delim = csv.Sniffer().sniff(sample, delimiters=",;|\t").delimiter
                except csv.Error:
                    pass
            reader = csv.reader(fh, delimiter=delim)
            header = next(reader, None)
            if not header:
                continue
            cols = []
            for i, h in enumerate(header):
                c = re.sub(r"[^A-Za-z0-9_]", "_", h.strip()) or f"col{i}"
                if not re.match(r"^[A-Za-z_]", c):
                    c = "c_" + c
                while c in cols:
                    c += "_"
                cols.append(c)
            tname = _table_name(os.path.splitext(os.path.basename(f))[0])
            coldefs = ", ".join(f'"{c}" TEXT' for c in cols)
            conn.execute(f'CREATE TABLE "{tname}" ({coldefs})')
            ph = ", ".join("?" for _ in cols)
            n = len(cols)
            conn.executemany(f'INSERT INTO "{tname}" VALUES ({ph})',
                             ((row + [None] * n)[:n] for row in reader if row))
    conn.commit()
    conn.execute("PRAGMA query_only = ON")    # loaded; from here on it is read-only too
    return conn


def _network(engine: str, p: dict, password: str | None):
    st = driver_status(engine)
    if not st["readable"]:
        raise DriverMissing(f"no Python driver for {engine} on this machine - {st['install']}")
    drv = st["driver"]
    host, port, db, user = p["host"], p["port"], p["database"], p["user"]
    pw = password if password is not None else p.get("password")

    if engine == "mysql":
        if drv == "pymysql":
            import pymysql
            # TLS whenever the server offers it (MySQL 8 does by default): the money data is encrypted in
            # transit, and MySQL 8's default login (caching_sha2_password) then needs no compiled crypto
            # library - so the single-file release works on a bare server. AEGIS_DB_CA = verify the cert.
            ca = os.environ.get("AEGIS_DB_CA")
            if ca:
                ctx = ssl.create_default_context(cafile=ca)
            else:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            try:
                conn = pymysql.connect(host=host, port=int(port), user=user, password=pw or "", database=db, ssl=ctx)
            except RuntimeError as e:
                if "cryptography" in str(e):
                    raise DriverMissing(
                        "this MySQL server offers no TLS, and its login method (caching_sha2_password) then needs the "
                        "'cryptography' package. Options: enable TLS on the server (recommended - also encrypts the "
                        "data AEGIS reads), or `pip install cryptography`, or have the DBA create the monitoring login "
                        "WITH mysql_native_password (MySQL 8.0 only).") from e
                raise
        elif drv == "mysql.connector":
            import mysql.connector
            conn = mysql.connector.connect(host=host, port=int(port), user=user, password=pw or "", database=db)
        else:
            import MySQLdb
            conn = MySQLdb.connect(host=host, port=int(port), user=user, passwd=pw or "", db=db)
        cur = conn.cursor()
        cur.execute("SET SESSION TRANSACTION READ ONLY")
        conn.commit()
        cur.execute("SELECT @@session.transaction_read_only")
        if str(cur.fetchone()[0]) not in ("1", "True"):
            conn.close()
            raise ReadOnlyViolation("could not put the MySQL session into read-only mode - refusing to continue")
        cur.close()
        return conn
    if engine == "postgres":
        if drv == "psycopg":
            import psycopg
            conn = psycopg.connect(host=host, port=int(port), user=user, password=pw, dbname=db)
        elif drv == "psycopg2":
            import psycopg2
            conn = psycopg2.connect(host=host, port=int(port), user=user, password=pw, dbname=db)
        else:
            import pg8000.dbapi
            conn = pg8000.dbapi.connect(host=host, port=int(port), user=user, password=pw, database=db)
        cur = conn.cursor()
        # Postgres applies session characteristics to the NEXT transaction, and DB-API drivers
        # silently open one on first execute. Commit here (it only contains this SET) so every
        # transaction AEGIS runs afterwards is read-only - verified against a live server.
        cur.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
        conn.commit()
        cur.execute("SHOW default_transaction_read_only")
        if str(cur.fetchone()[0]).lower() != "on":
            conn.close()
            raise ReadOnlyViolation("could not put the Postgres session into read-only mode - refusing to continue")
        cur.close()
        return conn
    if engine == "mssql":
        if drv == "pyodbc":
            import pyodbc
            odbc = [d for d in pyodbc.drivers() if "SQL Server" in d]
            dname = sorted(odbc)[-1] if odbc else "ODBC Driver 18 for SQL Server"
            cs = (f"DRIVER={{{dname}}};SERVER={host},{port};DATABASE={db};UID={user};PWD={pw or ''};"
                  "ApplicationIntent=ReadOnly;TrustServerCertificate=yes")
            return pyodbc.connect(cs, autocommit=False)
        import pymssql
        return pymssql.connect(server=host, port=int(port), user=user, password=pw or "", database=db)
    if engine == "oracle":
        import oracledb
        conn = oracledb.connect(user=user, password=pw, dsn=f"{host}:{port}/{db}")
        cur = conn.cursor()
        cur.execute("SET TRANSACTION READ ONLY")
        cur.close()
        return conn
    raise DriverMissing(f"AEGIS cannot run ledger checks on {engine} (not a SQL ledger engine)")


def open_readonly(target: str, password: str | None = None, schema: str | None = None) -> ReadOnlyDB:
    kind, p = classify(target)
    label = redact(target)
    if kind == "file":
        path = p["path"]
        if os.path.isdir(path) or path.lower().endswith((".csv", ".tsv")):
            return ReadOnlyDB(_csv_folder(path), "csv", label)
        with open(path, "rb") as fh:
            if fh.read(16).startswith(b"SQLite format 3"):
                return ReadOnlyDB(_sqlite(path), "sqlite", label)
        raise DriverMissing(f"{path}: not a SQLite file or CSV export - run `aegis db identify` for advice")
    if kind in ("url", "ado"):
        eng = p.get("engine")
        if eng == "sqlite":
            return ReadOnlyDB(_sqlite(p["path"]), "sqlite", label)
        if eng == "csv":
            return ReadOnlyDB(_csv_folder(p.get("host") or ""), "csv", label)
        if not eng:
            raise DriverMissing(f"unrecognised database URL: {label}")
        db = ReadOnlyDB(_network(eng, p, password), eng, label, schema=schema)
        db.can_write = db.write_capable()
        if eng == "mssql" and db.can_write is not False:
            # SQL Server has no read-only session mode, so the account itself must be read-only.
            db.close()
            raise ReadOnlyViolation(
                "this SQL Server login can change data (or its rights could not be confirmed). SQL Server has no "
                "read-only session mode, so AEGIS only runs with a read-only login: "
                "CREATE LOGIN aegis_ro ...; CREATE USER aegis_ro FOR LOGIN aegis_ro; "
                "ALTER ROLE db_datareader ADD MEMBER aegis_ro;")
        return db
    raise DriverMissing(f"cannot open {label!r}: give a connection URL, ADO string, or file/folder path")
