# Ledger engagement runbook (internal)

The steps from "client said yes" to "watchdog running", with the evidence each step leaves behind.
Send the client [CLIENT-REQUEST.md](CLIENT-REQUEST.md) first.

| # | Step | Command | Evidence produced |
|---|---|---|---|
| 0 | Signed authorization: databases, window, actions `db-identify` + `ledger-readonly` | `aegis init-scope` → fill `scope.databases`, `window` → `aegis sign` | `scope.json` (HMAC-signed) |
| 1 | Identify the engine. No login needed; `--probe` reads the handshake only | `aegis db identify <host:port> --probe --scope scope.json --key-file k` | audit entry with server version |
| 2 | Map with the temporary schema-wide read-only login | `aegis db map <url> --scope … --out eng1` | `ledger-map.json`, `ledger-map-signoff.md`, audit entry |
| 3 | Client corrects and signs the sheet. Apply corrections to the JSON and set `"reviewed_by": "<name, role, date>"` | (edit by hand) | signed sheet (keep the PDF/scan with the evidence) |
| 4 | Generate the least-privilege login for the confirmed columns. Client's DBA runs it and removes the temporary login | `aegis db grants --map eng1/ledger-map.json --from-host <aegis-ip> --save eng1/access.sql` | `access.sql` (also holds the removal lines) |
| 5 | First full check | `aegis ledger --db <url> --map … --scope … --out eng1` | `report.md`, `ledger-results.json`, audit |
| 6 | Optional: hourly watchdog until the authorization end date | `aegis watch --db <url> --map … --scope … --out watch1 --every 60 --webhook <https-url>` or Task Scheduler/cron with no `--every` | `alerts.jsonl`, `history.jsonl`, audit per run |
| 7 | Close: client runs the removal lines from `access.sql`. Verify the audit log and hand over | `aegis verify-audit --audit eng1/audit.jsonl` | "AUDIT INTACT" + final report |

**Rules**
- Passwords come from the `AEGIS_DB_PASSWORD` environment variable or `--ask-password`, never from the command
  line or the URL.
- A critical finding (exit code 3) gets a phone call to the client's named contact the same day, not only email.
- Never "fix" data. If the client asks us to correct a balance, that is their change through their own process.
- A SQL Server login that can write is refused by AEGIS. MySQL/Postgres logins that can write are held read-only
  and reported as a least-privilege finding. Either way, ask for the `access.sql` login.
- Oracle: column grants don't exist, so `access.sql` uses read-only views. This route has not been tested yet.
  Test it on a copy before using it with a client.

## Phase 2: M-Pesa guard, server check-up, tamper alarm, guard

Send [CLIENT-REQUEST-PHASE2.md](CLIENT-REQUEST-PHASE2.md). Re-sign the scope with the new actions
(`mpesa-readonly`, `host-checkup`, `tamper-watch`), the statement/callback locations under `scope.databases`, the
server hostname under `scope.servers` and the watched folders under `scope.paths`.

| # | Step | Command | Evidence produced |
|---|---|---|---|
| 8 | Before the meeting, run the selftest on the machine you will use (proves the install and makes a good demo) | `aegis selftest` | 6/6 scorecard |
| 9 | M-Pesa reconciliation for the agreed period | `aegis mpesa --statement s.csv --callbacks <log> --db <url> --map … --scope … --out mp1` | `mpesa-results.json`, report, statement/callback SHA-256 in the audit log |
| 10 | Server check-up, run on the server (as root for full coverage) | `aegis host --app-dir <app> --scope … --out host1` | `host-results.json`, report |
| 11 | Tamper baseline with the client's change approver present. MySQL: point `--path` at the DBA's nightly schema dump | `aegis tamper baseline --path <app> --path /etc/nginx --path /etc/ssh --path /root/.ssh --db <url> --map … --by "<approver>" --note "baseline" --out <guard-out>/tamper …` | baseline + BASELINE entry in the audit log |
| 12 | Install the guard: `guard init`, fill in the config, one manual cycle (the baseline), then schedule it | `aegis guard run --config aegis-guard.json`, then `aegis guard schedule …` and install the printed timer | `guard-alerts.jsonl`, `guard-history.jsonl`, report |
| 13 | After every client deployment, their named approver approves | `aegis tamper approve --by … --note "release, ticket" --out <guard-out>/tamper …` | approval + exact change list in the audit log |

**Phase 2 rules**
- A `WEBSHELL_SUSPECT`, `SCRIPT_IN_UPLOAD_DIR` or `BASELINE_TAMPERED` alert is an **incident**: phone call the same
  day, preserve the files (copy plus SHA-256) before anyone deletes anything. AEGIS refuses to approve these. Only use
  `--accept-risky` after the client's investigator has cleared the change in writing.
- `FORGED_CREDIT` / `CREDIT_EXCEEDS_PAID` / `WITHDRAWAL_PAID_AND_REFUNDED` are money incidents: same-day call, and
  ask the client to freeze withdrawals for the named wallets while they check (their decision, their system).
- Keep `AEGIS_TAMPER_KEY` (the baseline seal) **off the client's server**. Set it only when approving.
- The Safaricom callback IP list in AEGIS must be checked against the current Daraja documentation at the start of
  each engagement (`--allow-ips` to override).

**Tested (2026-11-21, demo data):** M-Pesa guard 12/12 (wallet read from SQLite, live MySQL 8 and live PostgreSQL 16,
identical). Server check-up 25/25 on Linux (22/22 on Windows without file permissions), plus a crash-free live run on
Debian 13. Tamper alarm 7/7 plus edited-baseline detection and refused webshell approval. Database triggers detected
live on PostgreSQL. On MySQL they were hidden from the read-only login as expected, and the schema-dump workaround
detected them. Guard: a 4-module, 3-cycle run alerted on exactly the new forged deposit and code change.

**Tested (2026-11-20, demo data):** column-only logins on MySQL 8, PostgreSQL 16 and SQL Server 2022 found 13/13
planted problems, were refused customer phone numbers, and could not write. CSV exports from the generated MySQL
and Postgres commands found 13/13. The removal lines left each login unable to connect.
