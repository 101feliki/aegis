# AEGIS — Authorized Engagement & Guarded Inspection Suite

A production-ready, **authorization-first** assessment harness. It is the deliberate
counterpart to autonomous offensive tooling such as ARTEX: nothing runs unless the target
is inside a **signed scope** and within the **authorized window**, and **every action** —
including every refusal — is written to a **tamper-evident, hash-chained audit log** for
legal review.

Built for the betting-operator engagement: it proves what an authorized tester can reach
(including internal settlement hosts) and whether the money-handling endpoints are hardened,
**without ever moving money or exploiting logic**.

- **Zero dependencies.** Pure Python 3.11+ standard library. Runs on Windows, Linux, macOS.
- **Read-only by default.** Inspects reachability, configuration and exposure. No payloads at app logic.
- **Transparent.** Requests carry an honest `User-Agent` naming the engagement, so the client's
  blue team sees the authorized test in their own logs — the opposite of a covert tool.

## Why it satisfies your legal experts

| Requirement from counsel | How AEGIS meets it |
|---|---|
| Authorization at every stage | Every check calls the `Authorizer` first; a denied action does not run. |
| Can't be run outside what was approved | Scope file is **HMAC-signed**; a tampered scope fails verification and the run aborts. Actions outside the time window, action list, target list or port list are refused. |
| Show exactly what was done | Hash-chained `audit.jsonl` records grants, **denials**, and every check result. `verify-audit` re-derives the chain. |
| Evidence can't be edited after the fact | Each entry hashes the previous one; changing any past entry breaks every later hash. |
| Don't touch the live money logic | Settlement checks are **read-only** (GET/HEAD/OPTIONS only). Bet/payout manipulation is intentionally **not** automated. |

## Install

Nothing to install. Copy the `aegis/` folder and run it with Python 3.11+.

```
python -m aegis --version
```

## Quick start — "type a website"

Two front doors onto the same authorized pipeline:

```bash
# A) Local operator console (a web form): enter a domain, confirm authorization, get the report.
python -m aegis ui          # open http://127.0.0.1:8787  (localhost only)

# B) One-shot command line.
python -m aegis assess --domain example.co.ke --acknowledge "Jane Counsel (engagement letter)" --out assess1

# See which optional external collectors are installed (AEGIS uses them if present).
python -m aegis tools
```

Both refuse to run without the authorization acknowledgement, build a passive+webintel scope
automatically, and write a hash-chained audit log + report. For a full engagement with
connectivity/internal and settlement checks, use the signed-scope workflow below.

## Inside the system — database identifier + ledger watchdog

Installed inside the client's environment, AEGIS checks whether the **money adds up**, read-only.

```bash
# 1. What database is this? (URL, ADO/ODBC string, SQLite file, CSV export folder, or host:port)
python -m aegis db identify "mysql://aegis_ro@10.20.0.15:3306/sportsbook"
python -m aegis db identify 10.20.0.15:5432 --probe --acknowledge "CTO J. Doe, letter ENG-001"

# 2. Find the bets / wallet / balance tables automatically -> ledger-map.json (a person reviews it)
set AEGIS_DB_PASSWORD=...        # never stored or logged
python -m aegis db map "mysql://aegis_ro@10.20.0.15/sportsbook" --acknowledge "..." --out eng1

# 3. Reconcile every bet against every wallet credit
python -m aegis ledger --db "mysql://aegis_ro@10.20.0.15/sportsbook" --map eng1/ledger-map.json --acknowledge "..." --out eng1

# Try it on a demo sportsbook with planted bugs
python -m aegis demo-ledger --out demo
```

| Identifies (zero dependencies) | Reads for ledger checks |
|---|---|
| MySQL/MariaDB, PostgreSQL, SQL Server, Oracle, SQLite, MongoDB, Redis, Access, DuckDB, Parquet, mysqldump/pg_dump files, CSV exports — from URL, connection string, file signature, or the live server handshake (no login) | SQLite + CSV built in; MySQL (`pymysql`), Postgres (`psycopg`), SQL Server (`pyodbc`), Oracle (`oracledb`) when the driver is installed — AEGIS tells you which to install |

**Watchdog checks:** winnings on a LOST bet · same bet paid twice · paid more than stake × odds ·
M-Pesa receipt credited twice · winnings to the wrong customer · paid while bet still open ·
"win" credit with no bet · void bet over-refunded · wallet balance ≠ sum of its transactions ·
inflated bet record · payout before settlement time · winning bet never paid.

**Read-only, four layers deep:** read-only DB session · SELECT-only statement guard · never commits ·
validated, quoted identifiers. Give AEGIS a SELECT-only database user as well.

| Engine | Tested live | Read-only enforcement | Admin account given? |
|---|---|---|---|
| MySQL 8 (pymysql) | ✅ 13/13 | Session `READ ONLY`, verified before any read | Runs read-only + **least-privilege finding** in report |
| PostgreSQL 16 (pg8000, or psycopg) | ✅ 13/13 | Session `READ ONLY`, verified before any read | Runs read-only + **least-privilege finding** in report |
| SQL Server 2022 (pyodbc) | ✅ 13/13 | No session mode exists → **login must be read-only** | **Refuses to run** (use a `db_datareader` login) |
| SQLite / CSV export | ✅ 13/13 | File opened `mode=ro` / private in-memory copy | n/a |
| Oracle (oracledb) | ⚠ coded, not yet tested | `SET TRANSACTION READ ONLY` | — |

On locked-down hosts (e.g. Windows Application Control) compiled drivers can be blocked from loading;
AEGIS detects this, skips them, and uses a pure-Python driver (`pymysql`, `pg8000`). Exit code `3` = critical
money finding (usable from a scheduler/cron as an alarm). Offline option: the client exports the
tables to CSV and AEGIS runs the same checks with no access to the live system at all.

### Least-privilege access and the client pack

`aegis db map` also writes `ledger-map-signoff.md`, a one-page sheet the client's technical owner corrects and signs.
From the confirmed map, `aegis db grants --map ledger-map.json --save access.sql` writes the SQL for a login that
can read **only the mapped columns** (no customer names, phones or ID numbers; Kenya DPA data minimisation). The same
file has the lines that remove the login at engagement end, plus CSV export commands for the offline route.
Tested on MySQL 8, PostgreSQL 16 and SQL Server 2022: 13/13 problems found, personal data refused, no write access,
and the login gone after removal. To send to the client: [client-pack/CLIENT-REQUEST.md](client-pack/CLIENT-REQUEST.md).
Our step-by-step: [client-pack/ENGAGEMENT-RUNBOOK.md](client-pack/ENGAGEMENT-RUNBOOK.md).

### Continuous watchdog — keeps watching after the audit

`aegis watch` re-runs the ledger check on a schedule and reports **only what changed** since the last run.
The first run is the baseline. After that, every check compares against the saved state in `<out>/watch-state.json`.

```bash
# Stay running, check every hour (signed scope: it stops by itself when the authorization window ends)
python -m aegis watch --db "mysql://aegis_ro@10.20.0.15/sportsbook" --map eng1/ledger-map.json \
       --scope scope.json --key-file signing.key --out watch1 --every 60 --webhook https://hooks.slack.com/...

# Or run once per call from Windows Task Scheduler / cron (exit code is the alarm)
schtasks /Create /SC HOURLY /TN AEGIS-watch /TR "python -m aegis watch --db ... --map ... --scope ... --key-file ... --out C:\aegis\watch1"
0 * * * *  cd /opt && python3 -m aegis watch --db ... --map ... --scope ... --key-file ... --out /var/lib/aegis/watch1
```

| Alert | Severity | What it means |
|---|---|---|
| New money case (any of the 12 checks) | that check's severity | A problem that was not there at the last run, e.g. a new win credited on a lost bet |
| `HISTORY_TAMPERED` | CRITICAL | A wallet transaction that already existed was **edited or deleted**. Old rows are fingerprinted in blocks of 100 ids, so this is caught even when the row count is padded back up with new inserts. The alert names the id range to investigate |
| `RECORDS_DISAPPEARED` | CRITICAL | Fewer bets than last time (also used for transactions when ids are not numeric) |
| `CASE_CLOSED` | MEDIUM for critical cases | A money problem vanished. Was it a documented correction, or was the record edited (e.g. a LOST bet flipped to WON)? |
| `MAPPING_CHANGED` | MEDIUM | Someone edited the reviewed table mapping between runs |
| `WATCHDOG_BLIND` | HIGH | The check could not run: database down, credentials, or **schema changed** (mapped columns are verified every run, so it never silently reports "all clear") |
| `AUTHORIZATION_ENDED` | HIGH | The signed window is over. The watchdog stops |

Outputs in `--out`: `alerts.jsonl` (every alert, with evidence), `history.jsonl` (one line per run),
`latest-results.json`, `report.md`, and the hash-chained `audit.jsonl`. Each run's audit entry records a SHA-256 of
the open case list and of the history fingerprint, so you can later prove exactly what existed at each check.
Webhooks must be HTTPS. Slack and Teams incoming webhooks work as-is. Exit codes: `0` quiet · `3` critical · `4` blind · `2` not authorized.

### M-Pesa guard — what M-Pesa really moved vs what the wallet credited

Wallets are credited because a Daraja **callback** said "the customer paid". A callback is just an HTTP POST, so
anyone who finds the URL can forge, replay or alter one. The only ground truth is Safaricom's **organisation
statement**. `aegis mpesa` lines up three sources — the statement (CSV export from the M-Pesa org portal), the
callback log (raw Daraja JSON as received: JSONL, log files with embedded JSON, a folder, or a DB table), and the
wallet (via the reviewed `ledger-map.json`) — and reports where they disagree.

```bash
python -m aegis mpesa --statement stmt.csv --callbacks /var/log/sportsbook/mpesa/ \
       --db "mysql://aegis_ro@10.20.0.15/sportsbook" --map eng1/ledger-map.json --scope scope.json --key-file k --out mp1
```

| Severity | Finding |
|---|---|
| CRITICAL | Deposit credited with a receipt **not on the M-Pesa statement** (forged callback / disguised manual credit) · credited **more than M-Pesa received** (altered amount or replay) · credited for a payment M-Pesa reported **failed/cancelled** · withdrawal **paid out AND refunded** to the wallet |
| HIGH | Money sent out of the paybill with **no wallet withdrawal** behind it · "payment successful" callback for a receipt not on the statement · callback amount ≠ statement amount · callback from an address that is **not Safaricom** |
| MEDIUM / LOW | Deposit with no receipt · repeated success callback · customer paid but never credited · failed withdrawal left debited |

Any source may be missing; checks that need it are skipped and the report says so. The statement window is honoured
(credits outside it are not judged). The Safaricom callback address list is built in — confirm it against current
Daraja documentation and override with `--allow-ips`. If every callback shows a private address, the report says the
proxy is hiding the sender. Statement and callback files are SHA-256'd into the audit log, so you can prove exactly
what was analysed. In the demo, a forged deposit that **balances in the wallet's own books** (the ledger watchdog
correctly stays quiet) is caught only here.

### Server check-up — is the money server set up safely?

`aegis host` runs **on** the client's server (or against a copied/mounted disk image with `--root`). It reads
configuration only: never changes a setting, never prints a secret's value (file and setting **names** only).

```bash
python -m aegis host --app-dir /var/www/sportsbook --scope scope.json --key-file k --out host1    # as root for full coverage
```

Finds: databases / Redis / MongoDB / Docker API / PHP-FPM listening on **every** interface · `.env`, `.git`, SQL dumps
or keys **inside the web root** (nginx/apache roots found automatically) · phpinfo/adminer/backups in the web root ·
secret files readable by every account · debug mode on · world-writable code · extra UID-0 accounts · empty
passwords · password-less sudo · SSH root/password login (reads `Include`d files, stops at `Match`) · OS out of
support · reboot pending · stale/non-automatic updates · firewall off · cron entries that download-and-run, decode
base64, run from `/tmp` or mine crypto · nginx version banner / no HSTS · clock not synchronised (evidence timestamps).
Linux in full; on Windows the network, firewall and file checks run.

### Tamper alarm — did anyone change the money code, access settings or DB triggers?

```bash
python -m aegis tamper baseline --path /var/www/sportsbook --path /etc/nginx --path /etc/ssh --path /root/.ssh \
       --db "postgresql://aegis_ro@10.20.0.15/sportsbook" --map eng1/ledger-map.json --by "J. Ops, CTO" --note "go-live" --out tamper1 ...
python -m aegis tamper check   --db ... --out tamper1 ...          # alerts on anything not approved
python -m aegis tamper approve --by "J. Ops, CTO" --note "release 2.4, ticket 118" --out tamper1 ...   # after a real deploy
```

SHA-256 of every watched file plus the columns, **triggers** and **stored routines** of the money tables. Alerts:
money code changed (settlement/wallet/M-Pesa by name) · **webshell** patterns · script in an **uploads** folder ·
**DB trigger** added/changed · SSH keys / sudo / cron changed · config changed · new code file · permissions weakened
(world-writable, setuid) · schema / routine changed · code changed · deleted · watched path missing. The baseline is
anchored in the audit log (and HMAC-sealed if `AEGIS_TAMPER_KEY` is set at approval — keep that key off the server),
so editing it to hide a change raises `BASELINE_TAMPERED`. **Approval is refused** when the changes include a
suspected webshell, a script in an upload folder or an edited baseline — that is an incident, not a deploy
(`--accept-risky` after an investigation; both refusal and override are logged).

| Engine | Triggers | Routines | Columns |
|---|---|---|---|
| PostgreSQL 16 | ✅ tested live (read-only login) | ✅ | ✅ |
| MySQL 8 | ⚠ **hidden** from read-only logins (seeing them needs the TRIGGER privilege, which can also create them — not requested). Workaround tested live: DBA schedules `mysqldump --no-data --triggers --routines --skip-dump-date db \| sed 's/ AUTO_INCREMENT=[0-9]*//' > …/db-schema.sql`, watched with `--path` | ✅ with `GRANT SHOW_ROUTINE` (read-only) | ✅ |
| SQLite | ✅ | n/a | ✅ |
| SQL Server / Oracle | coded, not yet tested live (SQL Server needs `VIEW DEFINITION`) | | |

### AEGIS guard — the installed product

One config file, every module, one alert channel, one authorization:

```bash
python -m aegis guard init --save aegis-guard.json      # fill in paths; disable modules you don't use
python -m aegis guard run  --config aegis-guard.json    # one cycle; first cycle = baseline
python -m aegis guard schedule --config aegis-guard.json --every 60   # prints systemd timer / cron / schtasks entries
```

Each cycle runs the ledger watchdog, M-Pesa guard, server check-up and tamper alarm, then reports only what is
**new** since the last cycle (stable case keys per finding), plus `RESOLVED` (for money problems: "confirm it was a
documented fix") and `MODULE_BLIND` (a module could not run — never a silent "all clear"). A broken module does not
stop the others. `mpesa.statement` may be a folder: the newest CSV is used, so ops just drops each day's portal export
there. Outputs: `guard-alerts.jsonl`, `guard-history.jsonl`, per-module results, one `report.md` (latest result per
module; every run stays in the audit log). Exit codes: `0` quiet · `3` new critical · `4` a module was blind · `2` not authorized.

### Selftest — proof for you and for the client

```bash
python -m aegis selftest
```

Builds every demo (sportsbook DB + CSV export, M-Pesa statement + callbacks, a server image, an app to tamper with),
runs each module and compares with the planted answer keys — nothing missed, nothing invented — and verifies each
audit chain. Current result: **6/6 on Windows and Linux** (ledger 13/13 SQLite and CSV, M-Pesa 12/12, server 22/22 on
Windows and 25/25 with Linux file permissions, tamper 7/7, edited-baseline + refused-approval check).

## Build-vs-buy: external-tool adapters

AEGIS builds the parts that make it legal and sellable in-house — the **authorization gate,
audit log, scope engine and report** — and *borrows* mature tools for raw data collection via
adapters in [`adapters.py`](./adapters.py):

| Capability | Uses if installed | Built-in fallback |
|---|---|---|
| Subdomain enumeration | `subfinder`, then `amass` | certificate-transparency (crt.sh) |
| HTTP probing / tech | `httpx` | built-in header fingerprint |
| (Optional) ports/services | `nmap` | built-in TCP connect |

Every adapter is gated by the Authorizer and records which engine it used, so a run is
reproducible and nothing touches an out-of-scope target — the guarantee raw scanners can't give.

## Workflow

```bash
# 1. Create a scope file and fill in the real engagement details.
python -m aegis init-scope --out scope.json

# 2. Have the authorizing party sign it (key held by the engagement lead, not in the repo).
python -m aegis sign   --scope scope.json --key-file signing.key
python -m aegis verify --scope scope.json --key-file signing.key   # -> signature VALID

# 3. Run the authorized assessment.
python -m aegis run --scope scope.json --key-file signing.key --out runs/eng1 \
       --operator "your.name" --stages connectivity,passive,settlement-readonly

# 4. Prove the evidence is intact, then produce the report for counsel/client.
python -m aegis verify-audit --audit runs/eng1/audit.jsonl   # -> AUDIT INTACT
python -m aegis report       --audit runs/eng1/audit.jsonl --out runs/eng1/report.md
```

Each run writes to `--out`:
- `audit.jsonl` — the tamper-evident action log (the legal record)
- `results.json` — structured findings
- `report.md` — the human-readable report (authorization record, integrity verdict, findings, denials)

## The scope file

The scope **is** the authorization. Key fields:

| Field | Meaning |
|---|---|
| `engagement_id`, `client`, `nda_ref`, `authorized_by` | Who approved this and under what paper. |
| `window.start` / `window.end` | Testing is refused outside this window. |
| `scope.domains` / `scope.ip_ranges` / `scope.ports` | The only targets that can be touched. Wildcards (`*.example.co.ke`) allowed. |
| `scope.internal_networks` | Ranges classified as "internal" so the report flags reachable internal settlement hosts. |
| `excluded` | Hard carve-outs (e.g. the live payments host) that are always refused. |
| `scope.databases` | Data sources the inside modules may read: connection URLs, SQLite files, CSV folders, M-Pesa statement files, callback logs (glob patterns allowed). |
| `scope.servers` | Hostnames of machines AEGIS may be installed on / inspect (`host`, `tamper`, `guard`). |
| `scope.paths` | Folders the tamper alarm may fingerprint. |
| `allowed_actions` | Any of `passive`, `connectivity`, `webintel`, `settlement-readonly`, `db-identify`, `ledger-readonly`, `mpesa-readonly`, `host-checkup`, `tamper-watch`. An action not listed here cannot run. |
| `targets` | The concrete hosts / URLs / settlement endpoints to assess. |
| `signature` | HMAC-SHA256 over the whole file, added by `sign`. |

## Stages

- **connectivity** — DNS resolution, TCP reachability (incl. whether in-scope **internal** hosts
  are reachable from the tester's position), TLS version/cert validation and expiry.
- **passive** — security headers, cookie flags (`Secure`/`HttpOnly`/`SameSite`), exposed sensitive
  paths (`/.env`, `/.git/HEAD`, `/swagger.json`, …), and certificate-transparency subdomain discovery.
- **webintel** — passive OSINT showing (a) why an attacker's source IP can't be trusted or blocked,
  and (b) what the client's OWN site leaks: real origin IP behind the CDN (via leaky subdomains),
  DNS/mail infrastructure, and server tech in response headers. Dependency-free DNS resolver built in.
  See [`IP-ATTRIBUTION.md`](./IP-ATTRIBUTION.md).
- **settlement-readonly** — for each settlement/callback URL: confirms unauthenticated access is
  refused, that plaintext HTTP is not accepted, and inspects allowed methods / idempotency surface.
  **Never submits a bet or a payout.**

## The boundary AEGIS will not cross (by design)

Active money-logic testing — submitting bets, replaying "you won" events, mutating `stake`/`odds`/
`payout`, probing race conditions — is **not** automated here. That work is done **by hand**, with a
client-provisioned **test** account, under a **per-action** authorization, following
[`SETTLEMENT-TESTING.md`](./SETTLEMENT-TESTING.md). Automating money manipulation is exactly the
operator-risk failure mode documented in the ARTEX defense map; AEGIS deliberately does not reproduce it.
