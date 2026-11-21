"""
Least-privilege access pack, generated from a REVIEWED ledger map.

    python -m aegis db grants --map ledger-map.json [--engine mysql] [--user aegis_ro] [--from-host 10.20.0.40]

Produces, for the client's DBA:
  1. SQL that creates a monitoring login able to SELECT only the mapped columns
     (customer names, phone numbers, ID numbers etc. are NOT readable - Kenya DPA 2019
     data minimisation), plus the statement that removes it at engagement end.
  2. The offline alternative: export commands that write exactly those columns to CSV.

Nothing here is executed by AEGIS - it is text for a human to review and run.
"""
from __future__ import annotations

from .connect import IDENT
from .identify import parse_url

PII_HINTS = ("msisdn", "phone", "mobile", "name", "email", "id_number", "national", "passport", "kra", "dob")


def _sections(mapping: dict) -> list[tuple[str, str, list[str]]]:
    out = []
    for kind in ("bets", "transactions", "balances"):
        sec = mapping.get(kind)
        if not sec:
            continue
        cols = list(dict.fromkeys(sec["columns"].values()))
        for n in [sec["table"], *cols]:
            for p in n.split("."):
                if not IDENT.match(p):
                    raise ValueError(f"illegal identifier in map: {n!r}")
        out.append((kind, sec["table"], cols))
    if not out:
        raise ValueError("the map defines no tables")
    return out


def _dbname(mapping: dict) -> str | None:
    label = mapping.get("database") or ""
    if "://" in label:
        try:
            return parse_url(label).get("database") or None
        except Exception:  # noqa: BLE001
            return None
    return None


def pii_warnings(mapping: dict) -> list[str]:
    w = []
    for kind, table, cols in _sections(mapping):
        for c in cols:
            if any(h in c.lower() for h in PII_HINTS):
                w.append(f"{table}.{c} looks like personal data - check it is really needed "
                         "(e.g. a phone number used as the customer key). If so, it will be readable.")
    return w


def grant_sql(mapping: dict, engine: str | None = None, user: str = "aegis_ro",
              from_host: str = "%", schema: str | None = None) -> str:
    engine = engine or mapping.get("engine")
    secs = _sections(mapping)
    db = _dbname(mapping) or "<database>"
    if not IDENT.match(user):
        raise ValueError("bad user name")
    L = [f"-- AEGIS monitoring login for {db} ({engine}) - generated from the reviewed ledger map.",
         "-- It can READ only the columns below. It cannot change anything and cannot see other columns",
         "-- (customer names, phone numbers, ID numbers ...). Replace <STRONG-PASSWORD>; share it out of band.",
         ""]
    if engine == "mysql":
        who = f"'{user}'@'{from_host}'"
        L += [f"CREATE USER {who} IDENTIFIED BY '<STRONG-PASSWORD>';"]
        for kind, t, cols in secs:
            L.append(f"GRANT SELECT ({', '.join(f'`{c}`' for c in cols)}) ON `{db}`.`{t}` TO {who};   -- {kind}")
        L += ["", "-- At engagement end:", f"DROP USER {who};"]
    elif engine == "postgres":
        sch = schema or "public"
        L += [f"CREATE ROLE {user} LOGIN PASSWORD '<STRONG-PASSWORD>';",
              f"ALTER ROLE {user} SET default_transaction_read_only = on;",
              f'GRANT CONNECT ON DATABASE "{db}" TO {user};',
              f'GRANT USAGE ON SCHEMA "{sch}" TO {user};']
        for kind, t, cols in secs:
            L.append(f'GRANT SELECT ({", ".join(chr(34) + c + chr(34) for c in cols)}) ON "{sch}"."{t}" TO {user};   -- {kind}')
        L += ["", "-- At engagement end:",
              f'REVOKE ALL ON ALL TABLES IN SCHEMA "{sch}" FROM {user};',
              f'REVOKE USAGE ON SCHEMA "{sch}" FROM {user};',
              f'REVOKE CONNECT ON DATABASE "{db}" FROM {user};',
              f"DROP ROLE {user};"]
    elif engine == "mssql":
        L += ["USE [master];",
              f"CREATE LOGIN [{user}] WITH PASSWORD = '<STRONG-PASSWORD>', CHECK_POLICY = ON;",
              f"USE [{db}];",
              f"CREATE USER [{user}] FOR LOGIN [{user}];"]
        for kind, t, cols in secs:
            tq = ".".join(f"[{p}]" for p in (t.split(".") if "." in t else ["dbo", t]))
            L.append(f"GRANT SELECT ON {tq} ({', '.join(f'[{c}]' for c in cols)}) TO [{user}];   -- {kind}")
        L += ["-- Do NOT add this user to db_datareader / db_owner: AEGIS refuses logins that can write,",
              "-- and db_datareader would expose every column.",
              "", "-- At engagement end:", f"USE [{db}]; DROP USER [{user}];", f"USE [master]; DROP LOGIN [{user}];"]
    elif engine == "oracle":
        L += ["-- Oracle has no column-level SELECT grant: expose read-only views instead (UNTESTED with AEGIS).",
              f"CREATE USER {user} IDENTIFIED BY \"<STRONG-PASSWORD>\";",
              f"GRANT CREATE SESSION TO {user};"]
        for kind, t, cols in secs:
            L.append(f"CREATE OR REPLACE VIEW AEGIS_{t.split('.')[-1].upper()} AS SELECT {', '.join(cols)} FROM {t} "
                     "WITH READ ONLY;")
            L.append(f"GRANT SELECT ON AEGIS_{t.split('.')[-1].upper()} TO {user};   -- {kind}")
        L += ["-- Then point the ledger map at the AEGIS_* view names.",
              "", "-- At engagement end:", f"DROP USER {user} CASCADE;"]
    else:
        L += [f"-- {engine}: no login needed - use the CSV export below, or give AEGIS a copy of the file."]
    return "\n".join(L)


def export_commands(mapping: dict, engine: str | None = None, schema: str | None = None) -> str:
    """Offline route: write exactly the mapped columns to CSV files (one per table)."""
    engine = engine or mapping.get("engine")
    db = _dbname(mapping) or "<database>"
    L = ["# Offline alternative: export ONLY these columns to CSV, put the files in one folder,",
         "# and run AEGIS against that folder. AEGIS then never touches the live system.", ""]
    for kind, t, cols in _sections(mapping):
        sel = f"SELECT {', '.join(cols)} FROM {t}"
        f = f"{t.split('.')[-1]}.csv"
        if engine == "postgres":
            sch = schema or "public"
            L.append(f'psql -h <host> -U <user> -d {db} -c "\\copy (SELECT {", ".join(cols)} FROM {sch}.{t}) '
                     f'TO \'{f}\' CSV HEADER"')
        elif engine == "mysql":
            L.append(f'mysql -h <host> -u <user> -p --batch -e "{sel}" {db} > {f}     # tab-separated, header included')
        elif engine == "mssql":
            L.append(f'Invoke-Sqlcmd -ServerInstance <host> -Database {db} -Query "{sel}" '
                     f'| Export-Csv {f} -NoTypeInformation     # PowerShell, SqlServer module')
        else:
            L.append(f"{sel};   -- save as {f} with a header row")
    return "\n".join(L)
