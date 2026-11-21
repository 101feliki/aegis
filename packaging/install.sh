#!/bin/sh
# AEGIS @VERSION@ installer (Linux). Read-only money & server watchdog.
#
#   sudo ./install.sh              install / upgrade (keeps existing config and evidence)
#   sudo ./install.sh --check      only check prerequisites, change nothing
#   sudo ./install.sh --every 30   guard cycle interval in minutes (default 60)
#
# What it does - nothing else:
#   /opt/aegis/aegis.pyz           the tool (owned by root: the service account cannot modify it)
#   /usr/local/bin/aegis           command wrapper (runs as the aegis account, read-only access to files)
#   /etc/aegis/                    config (root-owned): aegis-guard.json, aegis.env (DB password, mode 600)
#   /var/lib/aegis/                state + evidence (audit logs, reports) - the only place AEGIS writes
#   aegis system account           no login shell, no password
#   aegis-guard.service/.timer     systemd units, installed but NOT started - you enable them after the
#                                  config, scope and tamper baseline are in place
# It does not open any port, change any other service, or touch the betting system.
set -eu

VERSION="@VERSION@"
EVERY=60
CHECK_ONLY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --check) CHECK_ONLY=1 ;;
        --every) shift; EVERY="$1" ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done
case "$EVERY" in ''|*[!0-9]*) echo "--every must be whole minutes" >&2; exit 2 ;; esac

HERE=$(cd "$(dirname "$0")" && pwd)
say() { printf '  %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

echo "AEGIS $VERSION installer"

# ---- prerequisites -----------------------------------------------------------
[ "$(id -u)" -eq 0 ] || fail "run as root (sudo ./install.sh)"
[ -f "$HERE/aegis.pyz" ] || fail "aegis.pyz not found next to install.sh"
PY=""
for c in python3.13 python3.12 python3.11 python3.10 python3; do
    p=$(command -v "$c" 2>/dev/null || true)
    if [ -n "$p" ] && "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
        PY="$p"; break
    fi
done
if [ -z "$PY" ]; then
    have=$(python3 -V 2>&1 || echo "none")
    fail "Python 3.10 or newer is required (found: $have). On Ubuntu 20.04 / Debian 11: apt install python3.10 \
(deadsnakes PPA / backports) or run AEGIS from another machine against a CSV export."
fi
say "python: $PY ($("$PY" -V 2>&1))"
HAS_SYSTEMD=0
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then HAS_SYSTEMD=1; fi
say "systemd: $([ $HAS_SYSTEMD -eq 1 ] && echo yes || echo 'no (cron line will be printed instead)')"
SETPRIV=$(command -v setpriv 2>/dev/null || true)
say "setpriv: ${SETPRIV:-not found (manual commands will run without read access to protected files)}"
"$PY" "$HERE/aegis.pyz" --version >/dev/null || fail "aegis.pyz does not run with $PY"
SHA=$(sha256sum "$HERE/aegis.pyz" | cut -d' ' -f1)
say "aegis.pyz sha256: $SHA"
if [ -f "$HERE/SHA256SUMS" ] && ! grep -q "$SHA" "$HERE/SHA256SUMS"; then
    fail "aegis.pyz does not match SHA256SUMS - do not install a modified package"
fi
if [ $CHECK_ONLY -eq 1 ]; then echo "prerequisites OK (nothing changed)"; exit 0; fi

# ---- account and folders -------------------------------------------------------
if ! id aegis >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/aegis --no-create-home --shell /usr/sbin/nologin \
            --comment "AEGIS read-only watchdog" aegis
    say "created system account: aegis"
fi
install -d -o root -g root -m 0755 /opt/aegis
install -d -o root -g aegis -m 0750 /etc/aegis
install -d -o aegis -g aegis -m 0750 /var/lib/aegis /var/lib/aegis/guard /var/lib/aegis/statements
install -d -o aegis -g aegis -m 0750 /var/log/aegis

if [ -f /opt/aegis/aegis.pyz ]; then
    say "upgrading: previous build $(sha256sum /opt/aegis/aegis.pyz | cut -c1-16)..."
fi
install -o root -g root -m 0755 "$HERE/aegis.pyz" /opt/aegis/aegis.pyz
[ -d "$HERE/THIRD-PARTY-LICENSES" ] && cp -r "$HERE/THIRD-PARTY-LICENSES" /opt/aegis/ && chmod -R a+rX /opt/aegis

cat > /usr/local/bin/aegis <<EOF
#!/bin/sh
# AEGIS command wrapper: runs as the 'aegis' account with READ-ONLY access to every file
# (CAP_DAC_READ_SEARCH), so evidence files stay owned by the service account.
[ -r /etc/aegis/aegis.env ] && { set -a; . /etc/aegis/aegis.env; set +a; }
if [ "\$(id -un)" = "aegis" ]; then exec $PY /opt/aegis/aegis.pyz "\$@"; fi
[ "\$(id -u)" -eq 0 ] || { echo "run with sudo (AEGIS runs as its own read-only account)" >&2; exit 2; }
cd /var/lib/aegis
SP="setpriv --reuid=aegis --regid=aegis --init-groups --inh-caps=+dac_read_search --ambient-caps=+dac_read_search"
if command -v setpriv >/dev/null 2>&1 && \$SP true 2>/dev/null; then
    exec \$SP $PY /opt/aegis/aegis.pyz "\$@"
fi
# No read-only capability available here (e.g. a restricted container): protected files are skipped
# and the check-up report says so.
exec runuser -u aegis -- $PY /opt/aegis/aegis.pyz "\$@"
EOF
chmod 0755 /usr/local/bin/aegis

# ---- config (never overwritten on upgrade) --------------------------------------
if [ ! -f /etc/aegis/aegis.env ]; then
    umask 077
    cat > /etc/aegis/aegis.env <<'EOF'
# Read by AEGIS only. Mode 600, owner root.
# Password of the read-only monitoring database login (created from `aegis db grants`).
AEGIS_DB_PASSWORD=
# Do NOT put AEGIS_TAMPER_KEY here - the tamper seal key stays with the assessor.
EOF
    chmod 0600 /etc/aegis/aegis.env
    say "created /etc/aegis/aegis.env (fill in the DB password)"
fi
if [ ! -f /etc/aegis/aegis-guard.json ]; then
    "$PY" /opt/aegis/aegis.pyz guard init --save /etc/aegis/aegis-guard.json >/dev/null
    "$PY" - /etc/aegis/aegis-guard.json <<'EOF'
import json, sys
p = sys.argv[1]
c = json.load(open(p))
c["out"] = "/var/lib/aegis/guard"
c["authorization"] = {"scope": "/etc/aegis/scope.json", "key_file": "/etc/aegis/scope.key", "acknowledge": ""}
c["modules"]["mpesa"]["statement"] = "/var/lib/aegis/statements/"
json.dump(c, open(p, "w"), indent=2)
EOF
    chown root:aegis /etc/aegis/aegis-guard.json
    chmod 0640 /etc/aegis/aegis-guard.json
    say "created /etc/aegis/aegis-guard.json (fill it in)"
fi

# ---- schedule (installed, not started) ---------------------------------------------
if [ $HAS_SYSTEMD -eq 1 ]; then
    cat > /etc/systemd/system/aegis-guard.service <<EOF
[Unit]
Description=AEGIS guard - read-only money and server watchdog
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=aegis
Group=aegis
WorkingDirectory=/var/lib/aegis
EnvironmentFile=/etc/aegis/aegis.env
ExecStart=$PY /opt/aegis/aegis.pyz guard run --config /etc/aegis/aegis-guard.json
# exit 3 = new critical finding, 4 = a module was blind: the run itself succeeded
SuccessExitStatus=3 4
# Read every file, write nothing outside AEGIS's own folders.
AmbientCapabilities=CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/aegis /var/log/aegis
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
StandardOutput=append:/var/log/aegis/guard.log
StandardError=append:/var/log/aegis/guard.log
EOF
    cat > /etc/systemd/system/aegis-guard.timer <<EOF
[Unit]
Description=Run the AEGIS guard every $EVERY minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=${EVERY}min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    say "installed aegis-guard.service + aegis-guard.timer (every $EVERY min) - NOT started"
fi

# ---- prove the install works ---------------------------------------------------------
say "running the selftest as the aegis account..."
rm -rf /var/lib/aegis/selftest
if /usr/local/bin/aegis selftest --out /var/lib/aegis/selftest > /var/log/aegis/selftest.log 2>&1; then
    say "selftest: $(tail -n 1 /var/log/aegis/selftest.log)"
    rm -rf /var/lib/aegis/selftest
else
    cat /var/log/aegis/selftest.log >&2
    fail "selftest failed - see above (install files are in place; nothing is scheduled)"
fi
printf '%s installed AEGIS %s sha256=%s python=%s\n' "$(date -u +%FT%TZ)" "$VERSION" "$SHA" "$PY" \
    >> /var/lib/aegis/install.log
chown aegis:aegis /var/lib/aegis/install.log

cat <<EOF

AEGIS $VERSION installed. Monitoring is NOT running yet. Next:
  1. Put the signed scope and its key in /etc/aegis/ (scope.json, scope.key):
       sudo install -o root -g aegis -m 640 scope.json scope.key /etc/aegis/
  2. Fill in /etc/aegis/aegis.env (DB password) and /etc/aegis/aegis-guard.json
     (database URL, ledger-map.json path, callback log folder, app folders; disable unused modules).
     M-Pesa statements: drop each CSV export into /var/lib/aegis/statements/ (newest is used).
  3. Tamper baseline, with the client's change approver present:
       sudo aegis tamper baseline --path /var/www/<app> --path /etc/nginx --path /etc/ssh --path /root/.ssh \\
            --by "<name, role>" --note "baseline" --out /var/lib/aegis/guard/tamper --scope /etc/aegis/scope.json \\
            --key-file /etc/aegis/scope.key
  4. One manual cycle (this is the baseline):  sudo aegis guard run --config /etc/aegis/aegis-guard.json
EOF
if [ $HAS_SYSTEMD -eq 1 ]; then
    echo "  5. Start the schedule:  sudo systemctl enable --now aegis-guard.timer"
    echo "     Logs: /var/log/aegis/guard.log   Report: /var/lib/aegis/guard/report.md"
else
    echo "  5. No systemd here - add to root's crontab (sudo crontab -e):"
    echo "     0 * * * * /usr/local/bin/aegis guard run --config /etc/aegis/aegis-guard.json >> /var/log/aegis/guard.log 2>&1"
fi
echo "  Remove at the end of the engagement:  sudo ./uninstall.sh   (archives the evidence first)"
