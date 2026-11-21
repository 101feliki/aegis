#!/bin/sh
# AEGIS @VERSION@ uninstaller (Linux).
#
#   sudo ./uninstall.sh          stop and remove AEGIS; KEEP the evidence and config, archived
#   sudo ./uninstall.sh --purge  also delete /var/lib/aegis and /etc/aegis - only AFTER the archive
#                                below has been handed over, as agreed in the NDA
#
# The evidence (audit logs, reports, alerts) is always archived to
# /root/aegis-evidence-<host>-<date>.tar.gz before anything is removed, and the archive's
# SHA-256 is printed for the hand-over record.
set -eu
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo ./uninstall.sh)" >&2; exit 1; }

echo "AEGIS uninstaller"
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now aegis-guard.timer 2>/dev/null || true
    systemctl stop aegis-guard.service 2>/dev/null || true
    rm -f /etc/systemd/system/aegis-guard.service /etc/systemd/system/aegis-guard.timer
    systemctl daemon-reload
    echo "  schedule stopped and removed"
fi
if crontab -l 2>/dev/null | grep -q "aegis guard run"; then
    echo "  NOTE: root's crontab still has an 'aegis guard run' line - remove it with: crontab -e"
fi

if [ -d /var/lib/aegis ] || [ -d /etc/aegis ]; then
    ARCH="/root/aegis-evidence-$(hostname)-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
    # Config is archived WITHOUT aegis.env (passwords) and scope.key (signing key).
    tar -czf "$ARCH" --exclude=aegis.env --exclude=scope.key --exclude='selftest' \
        $( [ -d /var/lib/aegis ] && echo /var/lib/aegis ) $( [ -d /var/log/aegis ] && echo /var/log/aegis ) \
        $( [ -d /etc/aegis ] && echo /etc/aegis ) 2>/dev/null || true
    chmod 600 "$ARCH"
    echo "  evidence archived: $ARCH"
    echo "  sha256: $(sha256sum "$ARCH" | cut -d' ' -f1)   (record this in the hand-over note)"
fi

rm -f /usr/local/bin/aegis
rm -rf /opt/aegis
echo "  removed /opt/aegis and /usr/local/bin/aegis"

if [ $PURGE -eq 1 ]; then
    rm -rf /var/lib/aegis /var/log/aegis /etc/aegis
    echo "  purged /var/lib/aegis, /var/log/aegis, /etc/aegis"
    if id aegis >/dev/null 2>&1; then userdel aegis 2>/dev/null || true; echo "  removed account: aegis"; fi
else
    echo "  kept /var/lib/aegis, /var/log/aegis, /etc/aegis and the aegis account (re-run with --purge after hand-over)"
fi
echo "  Also remove the read-only database login (removal lines at the end of access.sql)."
