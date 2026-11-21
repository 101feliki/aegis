# Installing AEGIS @VERSION@ on a Linux server

For the client's system administrator. AEGIS only **reads**: it never changes data, settings or services, and it
opens no network port.

## Requirements

- Linux with **Python 3.10 or newer**. Ubuntu 22.04/24.04, Debian 12/13 and RHEL/Rocky/Alma 9 already have it.
  Run `python3 -V` to check.
- Root access for the install itself.
- Nothing else. The MySQL/MariaDB and PostgreSQL drivers are inside `aegis.pyz`, so no `pip` and no internet are
  needed. SQL Server needs `pyodbc` with Microsoft's ODBC driver; Oracle needs `oracledb`.
- MySQL 8: keep TLS enabled on the database server (it is by default). AEGIS connects encrypted, and to also verify
  the server's certificate add `AEGIS_DB_CA=/path/to/ca.pem` to `/etc/aegis/aegis.env`.

## Install

```sh
tar xzf aegis-@VERSION@-linux.tar.gz
cd aegis-@VERSION@
sha256sum -c SHA256SUMS            # must say: aegis.pyz: OK
sudo ./install.sh --check          # prerequisites only, changes nothing
sudo ./install.sh                  # install (or upgrade: config and evidence are kept)
```

The installer:

| Creates | Purpose |
|---|---|
| `aegis` system account | No login shell, no password. AEGIS runs as this account. |
| `/opt/aegis/aegis.pyz` | The tool. Owned by root, so the service account cannot modify it. |
| `/usr/local/bin/aegis` | The command. Use it with `sudo`; it switches to the `aegis` account. |
| `/etc/aegis/` | Configuration. `aegis.env` (database password, mode 600) and `aegis-guard.json`. |
| `/var/lib/aegis/` | State and evidence (audit logs, reports, alerts). The only place AEGIS writes. |
| `aegis-guard.service` + `.timer` | The schedule. **Installed but not started.** |

Finally it runs the built-in selftest to prove AEGIS works on this server.

**Access model:** the service runs as `aegis` with one Linux capability, `CAP_DAC_READ_SEARCH`, which lets it read
any file (needed to check SSH, sudo and firewall settings). It cannot write anywhere except `/var/lib/aegis` and
`/var/log/aegis`; systemd makes the rest of the filesystem read-only for it.

## Configure and start

1. Copy the signed scope (`scope.json`) and its key (`scope.key`) from the assessor into `/etc/aegis/`:
   `sudo install -o root -g aegis -m 640 scope.json scope.key /etc/aegis/`
2. Edit `/etc/aegis/aegis.env` and set the password of the read-only database login.
3. Edit `/etc/aegis/aegis-guard.json`: the database address, the confirmed `ledger-map.json`, the payment-callback
   log folder and the application folder. Set `"enabled": false` for anything you do not use.
4. M-Pesa statements: save each CSV export from the M-Pesa portal into `/var/lib/aegis/statements/`. The newest
   one is used.
5. Take the change-alarm baseline with your change approver present (the assessor gives you the exact command).
6. Run one cycle by hand: `sudo aegis guard run --config /etc/aegis/aegis-guard.json`
7. Start the schedule: `sudo systemctl enable --now aegis-guard.timer`

Logs are in `/var/log/aegis/guard.log`, and the latest report is `/var/lib/aegis/guard/report.md`.

## After every deployment of your betting system

Your named approver confirms the change, so the change alarm stops reporting it. The approval is recorded as
evidence:

```sh
sudo aegis tamper approve --by "Name, role" --note "release 2.4, ticket 118" --out /var/lib/aegis/guard/tamper \
     --scope /etc/aegis/scope.json --key-file /etc/aegis/scope.key
```

## Remove at the end of the engagement

```sh
sudo ./uninstall.sh            # stops and removes AEGIS; archives the evidence to /root/ first
sudo ./uninstall.sh --purge    # after the archive has been handed over: deletes the evidence and the account
```

Then remove the read-only database login with the removal lines at the end of `access.sql`.
