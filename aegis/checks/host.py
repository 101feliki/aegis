"""
Server check-up - is the machine that holds the money set up safely? (READ-ONLY)

Runs ON the client's server (or against a mounted copy of its disk with --root).
It only reads configuration files and the kernel's socket table; it never changes
a setting, never restarts anything, and never prints a secret's value - only the
file and the name of the setting.

What it looks for (plain-language titles are what the report shows):

  network      databases / admin panels listening on every network interface
  web root     .env files, .git folders, SQL dumps, backups inside the folder the web server publishes
  secrets      secret files readable by every account on the machine; debug mode left on
  accounts     extra root accounts, empty passwords, password-less sudo
  SSH          root login allowed, password login allowed
  updates      operating system out of support, reboot pending, updates stale / not automatic
  firewall     host firewall switched off
  persistence  scheduled tasks that download-and-run, decode, or run from /tmp (backdoor / miner signs)
  web server   version banner leaked, no HSTS
  evidence     clock not synchronised (timestamps in logs become disputable)

Linux is checked in full. On Windows the network, firewall and file checks run;
Linux-only checks are skipped and the report says so.
"""
from __future__ import annotations

import fnmatch
import glob
import os
import re
import socket
import stat
import subprocess
import time
from datetime import date

from ..findings import Findings

ACTION = "host-checkup"

CATALOGUE = {
    "EXPOSED_DATABASE": ("HIGH", "Database listening on every network interface",
                         "The database accepts connections from any network the server is on, not just from the app. "
                         "If the cloud firewall / security group is ever loosened, it is on the internet. Bind it to "
                         "127.0.0.1 or the private network only."),
    "EXPOSED_NOAUTH_STORE": ("CRITICAL", "Data store that usually has no password is listening on every interface",
                             "Redis, MongoDB, Elasticsearch, Memcached and etcd ship with no password by default. "
                             "Reachable = readable and writable by anyone (sessions, cached balances, queues)."),
    "EXPOSED_ADMIN_SERVICE": ("HIGH", "Remote-control / admin service listening on every interface",
                              "Admin interfaces (Docker API, PHP-FPM, VNC, Webmin, Kubelet...) give whoever reaches "
                              "them control of the server."),
    "SECRET_IN_WEB_ROOT": ("CRITICAL", "Secret file inside the folder the web server publishes",
                           "A .env file, .git folder, SQL dump or private key inside the web root can often be "
                           "downloaded by anyone with a browser - database passwords and M-Pesa API keys included."),
    "RISKY_FILE_IN_WEB_ROOT": ("HIGH", "Backup or admin tool inside the web root",
                               "Backups, phpinfo and database admin tools in the web root leak data or give a "
                               "database console to whoever finds them."),
    "SECRETS_WORLD_READABLE": ("HIGH", "File holding secrets is readable by every account on the server",
                               "Any process or user on the machine (including a hacked plugin running as another "
                               "user) can read the database and M-Pesa credentials. Make it readable by the app "
                               "account only (chmod 600 / 640)."),
    "DEBUG_MODE_ON": ("HIGH", "Application debug mode is switched on",
                      "Debug error pages print configuration, queries and sometimes secrets to anyone who triggers "
                      "an error."),
    "APP_CODE_WORLD_WRITABLE": ("HIGH", "Application code can be changed by every account on the server",
                                "Anyone with any foothold on the machine can rewrite settlement or payment code."),
    "EXTRA_ROOT_ACCOUNT": ("CRITICAL", "Account other than root has full administrator (UID 0) rights",
                           "A second UID-0 account is a classic backdoor."),
    "EMPTY_PASSWORD": ("HIGH", "Account with an empty password", "Anyone can log in as this account."),
    "SUDO_NOPASSWD": ("MEDIUM", "Account can become administrator without a password",
                      "If that account's key or session is stolen, the attacker is root immediately."),
    "SSH_ROOT_LOGIN": ("HIGH", "SSH allows logging in directly as root",
                       "Attackers guess root's password around the clock. Log in as a named user and use sudo."),
    "SSH_PASSWORD_LOGIN": ("MEDIUM", "SSH accepts passwords (not only keys)",
                           "Password login can be brute-forced; key-only login cannot."),
    "OS_OUT_OF_SUPPORT": ("HIGH", "Operating system no longer receives security updates",
                          "New vulnerabilities in this OS version are never fixed."),
    "REBOOT_PENDING": ("MEDIUM", "Security updates installed but the server has not been rebooted",
                       "Kernel and library fixes are not active until a reboot."),
    "UPDATES_STALE": ("MEDIUM", "Package lists have not been refreshed for over 30 days",
                      "The server is probably missing recent security fixes."),
    "NO_AUTO_SECURITY_UPDATES": ("LOW", "Automatic security updates are not enabled",
                                 "Fixes depend on someone remembering to apply them."),
    "FIREWALL_DISABLED": ("MEDIUM", "Host firewall is switched off",
                          "Only the cloud firewall (if any) stands between the services and the network."),
    "SUSPICIOUS_SCHEDULED_TASK": ("HIGH", "Scheduled task looks like a backdoor or crypto-miner",
                                  "Download-and-run, base64-decoding, or running programs from /tmp are how attackers "
                                  "keep access after a break-in."),
    "WEB_SERVER_VERSION_LEAK": ("LOW", "Web server announces its exact version",
                                "Tells attackers which known bugs to try (set server_tokens off)."),
    "NO_HSTS": ("LOW", "HTTPS site does not send HSTS",
                "Browsers can be downgraded to plain HTTP on hostile networks (public Wi-Fi), exposing logins."),
    "CLOCK_NOT_SYNCED": ("LOW", "Clock synchronisation could not be confirmed",
                         "Log and audit timestamps are evidence; an unsynchronised clock makes them disputable."),
}
CASE_FIELDS = {"EXPOSED_DATABASE": ("port",), "EXPOSED_NOAUTH_STORE": ("port",), "EXPOSED_ADMIN_SERVICE": ("port",),
               "SECRET_IN_WEB_ROOT": ("path",), "RISKY_FILE_IN_WEB_ROOT": ("path",),
               "SECRETS_WORLD_READABLE": ("path",), "DEBUG_MODE_ON": ("path", "setting"),
               "APP_CODE_WORLD_WRITABLE": ("path",), "EXTRA_ROOT_ACCOUNT": ("account",),
               "EMPTY_PASSWORD": ("account",), "SUDO_NOPASSWD": ("file", "rule"),
               "SUSPICIOUS_SCHEDULED_TASK": ("file", "line")}

DB_PORTS = {3306: "MySQL/MariaDB", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle", 9042: "Cassandra",
            33060: "MySQL X protocol"}
NOAUTH_PORTS = {6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached", 5984: "CouchDB",
                2379: "etcd"}
ADMIN_PORTS = {2375: ("CRITICAL", "Docker API without TLS (full root on the host)"), 2376: ("HIGH", "Docker API"),
               9000: ("HIGH", "PHP-FPM / FastCGI (remote code execution if reachable)"),
               10250: ("HIGH", "Kubernetes kubelet"), 5900: ("HIGH", "VNC remote desktop"),
               10000: ("HIGH", "Webmin"), 8500: ("HIGH", "Consul"), 3389: ("MEDIUM", "Windows Remote Desktop"),
               15672: ("MEDIUM", "RabbitMQ management"), 5601: ("MEDIUM", "Kibana"),
               9090: ("MEDIUM", "Prometheus / Cockpit"), 8161: ("HIGH", "ActiveMQ console")}

SECRET_NAMES = [".env", ".env.*", "*.env", "wp-config.php", "settings.py", "local_settings.py", "config.php",
                "database.php", "application.properties", "application.yml", "appsettings.json",
                "appsettings.*.json", "config.json", "secrets.json", "docker-compose.yml", "docker-compose.yaml",
                ".npmrc", ".pgpass", ".my.cnf"]
SECRET_KEYS = re.compile(
    r"^\s*(?:export\s+)?[\"']?([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|PASSKEY|PRIVATE_KEY|API_KEY|ACCESS_KEY|TOKEN|"
    r"CONSUMER_KEY|SECURITY_CREDENTIAL|DATABASE_URL|DB_URL|APP_KEY|DSN)[A-Z0-9_]*)[\"']?\s*[:=]\s*[\"']?(\S+)",
    re.I | re.M)
DEBUG_SETTINGS = re.compile(r"^\s*(APP_DEBUG|DEBUG|FLASK_DEBUG|DJANGO_DEBUG|NODE_ENV|APP_ENV)\s*[:=]\s*[\"']?"
                            r"(true|1|yes|on|development|local|dev)[\"']?\s*$", re.I | re.M)
WEBROOT_SECRET = [".env", ".env.*", "*.sql", "*.sql.gz", "*.sql.zip", "*.dump", "*.pem", "*.key", "id_rsa",
                  "id_ed25519", ".htpasswd", "*.sqlite", "*.db"]
WEBROOT_RISKY = ["*.bak", "*.old", "*.orig", "*.swp", "backup*.zip", "backup*.tar*", "*.tar.gz", "phpinfo.php",
                 "info.php", "adminer*.php", "phpmyadmin"]
CODE_EXT = (".php", ".py", ".js", ".mjs", ".ts", ".rb", ".go", ".java", ".jar", ".war", ".sh", ".pl", ".cs",
            ".dll", ".so", ".jsp", ".aspx")
SKIP_DIRS = {"node_modules", "vendor", ".cache", "__pycache__", "cache", "logs", "log", "tmp", ".npm", "storage"}
CRON_BAD = [
    (re.compile(r"(curl|wget)\b[^|;#]*\|\s*(ba|z|da)?sh\b"), "downloads a script and runs it"),
    (re.compile(r"base64\s+(-d|--decode)"), "decodes hidden (base64) commands"),
    (re.compile(r"(^|\s)/(tmp|dev/shm|var/tmp)/\S+"), "runs a program from a temporary folder"),
    (re.compile(r"\bnc(at)?\b[^#]*\s-(e|c)\b"), "opens a reverse shell (netcat -e)"),
    (re.compile(r"xmrig|minerd|cpuminer|stratum\+tcp|cryptonight", re.I), "crypto-miner"),
    (re.compile(r"/dev/tcp/"), "opens a network shell (/dev/tcp)"),
]

# Standard (free) security-support end dates. Paid extended support (Ubuntu Pro ESM, Debian
# ELTS, RHEL ELS) can push these out - the report says so.
EOL = {
    ("ubuntu", "14.04"): "2019-04-30", ("ubuntu", "16.04"): "2021-04-30", ("ubuntu", "18.04"): "2023-05-31",
    ("ubuntu", "20.04"): "2025-05-31", ("ubuntu", "22.04"): "2027-06-30", ("ubuntu", "24.04"): "2029-06-30",
    ("ubuntu", "23.04"): "2024-01-25", ("ubuntu", "23.10"): "2024-07-11", ("ubuntu", "24.10"): "2025-07-10",
    ("ubuntu", "25.04"): "2026-01-15", ("ubuntu", "25.10"): "2026-07-09", ("ubuntu", "26.04"): "2031-05-31",
    ("debian", "13"): "2030-06-30",
    ("debian", "8"): "2020-06-30", ("debian", "9"): "2022-06-30", ("debian", "10"): "2024-06-30",
    ("debian", "11"): "2026-08-31", ("debian", "12"): "2028-06-30",
    ("centos", "6"): "2020-11-30", ("centos", "7"): "2024-06-30", ("centos", "8"): "2021-12-31",
    ("rhel", "7"): "2024-06-30", ("rhel", "8"): "2029-05-31", ("rhel", "9"): "2032-05-31",
    ("rocky", "8"): "2029-05-31", ("almalinux", "8"): "2029-05-31",
}


class Host:
    """File access relative to a root, so the same checks run on the live machine
    ('/') or on a mounted / copied server image."""

    def __init__(self, root: str | None):
        self.root = root
        self.live = root is None
        self.windows = self.live and os.name == "nt"

    def p(self, path: str) -> str:
        if self.root is None:
            return path
        return os.path.join(self.root, path.lstrip("/").replace("/", os.sep))

    def read(self, path: str, limit: int = 2_000_000) -> str | None:
        try:
            with open(self.p(path), "r", encoding="utf-8", errors="replace") as fh:
                return fh.read(limit)
        except (OSError, UnicodeError):
            return None

    def exists(self, path: str) -> bool:
        return os.path.exists(self.p(path))

    def glob(self, pattern: str) -> list[str]:
        base = self.p(pattern)
        out = sorted(glob.glob(base))
        if self.root is None:
            return out
        r = os.path.abspath(self.root)
        return ["/" + os.path.relpath(x, r).replace(os.sep, "/") for x in out]

    def display(self, real: str) -> str:
        if self.root is None:
            return real
        return "/" + os.path.relpath(real, os.path.abspath(self.root)).replace(os.sep, "/")


# ---------------------------------------------------------------------------
# Network: who listens on every interface?
# ---------------------------------------------------------------------------
def _hex_ip(h: str) -> str:
    if len(h) == 8:
        return socket.inet_ntoa(bytes.fromhex(h)[::-1])
    b = bytes.fromhex(h)
    b = b"".join(b[i:i + 4][::-1] for i in range(0, 16, 4))
    return socket.inet_ntop(socket.AF_INET6, b)


def listening(h: Host) -> tuple[list[tuple[str, int]], str]:
    """[(address, port)] of TCP listeners, and how it was learned."""
    out = []
    if h.windows:
        try:
            txt = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True, text=True, timeout=30).stdout
            txt += subprocess.run(["netstat", "-ano", "-p", "TCPv6"], capture_output=True, text=True, timeout=30).stdout
        except (OSError, subprocess.SubprocessError):
            return [], "unavailable"
        for ln in txt.splitlines():
            parts = ln.split()
            if len(parts) >= 4 and parts[0].upper() == "TCP" and parts[3].upper() == "LISTENING":
                addr, _, port = parts[1].rpartition(":")
                if port.isdigit():
                    out.append((addr.strip("[]"), int(port)))
        return out, "netstat"
    found = False
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        txt = h.read(f)
        if txt is None:
            continue
        found = True
        for ln in txt.splitlines()[1:]:
            parts = ln.split()
            if len(parts) < 4 or parts[3] != "0A":          # 0A = LISTEN
                continue
            ip_h, port_h = parts[1].split(":")
            try:
                out.append((_hex_ip(ip_h), int(port_h, 16)))
            except (ValueError, OSError):
                continue
    return out, ("/proc/net/tcp" if found else "unavailable")


def check_network(h: Host, F: Findings, cov: list) -> None:
    socks, how = listening(h)
    if how == "unavailable":
        cov.append("Could not read the list of listening network ports - exposure checks not run.")
        return
    seen = set()
    for addr, port in socks:
        if addr not in ("0.0.0.0", "::", "*", "") or port in seen:
            continue
        seen.add(port)
        if port in NOAUTH_PORTS:
            F.add("EXPOSED_NOAUTH_STORE", None, port=port, service=NOAUTH_PORTS[port], bound=f"{addr}:{port}")
        elif port in DB_PORTS:
            F.add("EXPOSED_DATABASE", None, port=port, service=DB_PORTS[port], bound=f"{addr}:{port}")
        elif port in ADMIN_PORTS:
            sev, what = ADMIN_PORTS[port]
            F.add("EXPOSED_ADMIN_SERVICE", None, port=port, service=what, bound=f"{addr}:{port}", level=sev)
    cov.append(f"Listening ports read from {how}. 'Every interface' means reachable from any network the server is "
               "on - whether the internet can reach it also depends on the cloud firewall; confirm with the outside "
               "scan (`aegis assess`).")


# ---------------------------------------------------------------------------
# Web server config, web roots and application folders
# ---------------------------------------------------------------------------
def web_config(h: Host) -> dict:
    files = []
    for pat in ("/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/*", "/etc/nginx/conf.d/*.conf",
                "/etc/apache2/sites-enabled/*", "/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf",
                "/etc/httpd/conf.d/*.conf"):
        files.extend(h.glob(pat) if "*" in pat else ([pat] if h.exists(pat) else []))
    roots, nginx_text, apache = set(), "", False
    for f in files:
        txt = h.read(f) or ""
        clean = "\n".join(ln.split("#", 1)[0] for ln in txt.splitlines())
        if "/nginx/" in f:
            nginx_text += clean + "\n"
            roots.update(m.strip().strip("'\"") for m in re.findall(r"^\s*root\s+([^;]+);", clean, re.M))
        else:
            apache = True
            roots.update(m.strip().strip("'\"") for m in re.findall(r"^\s*DocumentRoot\s+(\S+)", clean, re.M | re.I))
    return {"files": files, "roots": sorted(r for r in roots if r.startswith("/")), "nginx": nginx_text,
            "apache": apache}


def _walk(h: Host, top: str, max_depth: int = 6, max_files: int = 50_000):
    """Yield (display_path, real_path, is_dir, name)."""
    real_top = h.p(top)
    if not os.path.isdir(real_top):
        return
    base_depth = real_top.rstrip(os.sep).count(os.sep)
    n = 0
    for dirpath, dirnames, filenames in os.walk(real_top):
        depth = dirpath.count(os.sep) - base_depth
        keep = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            yield h.display(full), full, True, d
            if d not in SKIP_DIRS and d != ".git" and depth < max_depth and not os.path.islink(full):
                keep.append(d)
        dirnames[:] = keep
        for fn in filenames:
            n += 1
            if n > max_files:
                return
            full = os.path.join(dirpath, fn)
            yield h.display(full), full, False, fn


def _match(name: str, patterns) -> bool:
    low = name.lower()
    return any(fnmatch.fnmatch(low, p) for p in patterns)


def check_files(h: Host, F: Findings, cov: list, app_dirs: list[str], web_roots: list[str], web: dict) -> None:
    roots = sorted(set(web_roots) | set(web["roots"]))
    for r in roots:
        for disp, real, is_dir, name in _walk(h, r, max_depth=4):
            if is_dir and name in (".git", ".svn", ".hg"):
                F.add("SECRET_IN_WEB_ROOT", None, path=disp, what="source-control history (may contain old passwords)")
            elif is_dir and name.lower() == "phpmyadmin":
                F.add("RISKY_FILE_IN_WEB_ROOT", None, path=disp, what="database admin tool")
            elif not is_dir and _match(name, WEBROOT_SECRET):
                F.add("SECRET_IN_WEB_ROOT", None, path=disp, what=_what(name))
            elif not is_dir and _match(name, WEBROOT_RISKY):
                F.add("RISKY_FILE_IN_WEB_ROOT", None, path=disp, what=_what(name))

    dirs = sorted(set(app_dirs) | {os.path.dirname(r.rstrip("/")) if r.rstrip("/").endswith(
        ("/public", "/public_html", "/html", "/web", "/www", "/dist", "/static")) else r for r in roots})
    if not dirs:
        dirs = [d for d in ("/var/www", "/srv", "/opt") if h.exists(d)]
    if not dirs:
        cov.append("No application folder found or given (--app-dir) - secret-file and code-permission checks not run.")
        return
    posix = not h.windows and os.name != "nt"
    ww_count, ww_samples = 0, []
    for d in dirs:
        for disp, real, is_dir, name in _walk(h, d):
            if is_dir:
                continue
            try:
                st = os.lstat(real)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            if _match(name, SECRET_NAMES) and st.st_size < 1_000_000:
                txt = h.read(disp) or ""
                keys = sorted({m.group(1) for m in SECRET_KEYS.finditer(txt)
                               if m.group(2).strip("'\"") not in ("", "null", "none", "changeme", "${", "<")})
                if keys and posix and st.st_mode & stat.S_IROTH:
                    F.add("SECRETS_WORLD_READABLE", None, path=disp, mode=oct(st.st_mode & 0o777),
                          settings=", ".join(keys[:8]) + (" ..." if len(keys) > 8 else ""))
                for m in DEBUG_SETTINGS.finditer(txt):
                    F.add("DEBUG_MODE_ON", None, path=disp, setting=f"{m.group(1)}={m.group(2)}")
            if posix and name.lower().endswith(CODE_EXT) and st.st_mode & stat.S_IWOTH:
                ww_count += 1
                if len(ww_samples) < 10:
                    ww_samples.append(disp)
    if ww_count:
        F.add("APP_CODE_WORLD_WRITABLE", None, path=os.path.commonpath(ww_samples) if len(ww_samples) > 1
              else ww_samples[0], files=ww_count, examples=ww_samples[:5])
    if not posix:
        cov.append("File-permission checks (world-readable secrets, world-writable code) need a Linux/Unix host.")
    cov.append("Application folders checked: " + ", ".join(dirs) + ". Secret VALUES are never read into the "
               "report - only the file and setting names.")


def _what(name: str) -> str:
    n = name.lower()
    if n.startswith(".env") or n.endswith(".env"):
        return "environment file (database / M-Pesa credentials)"
    if ".sql" in n or n.endswith((".dump", ".sqlite", ".db")):
        return "database dump / file"
    if n.endswith((".pem", ".key")) or n.startswith("id_"):
        return "private key"
    if n == ".htpasswd":
        return "password file"
    if "phpinfo" in n or n == "info.php":
        return "phpinfo page (prints server configuration)"
    if "adminer" in n:
        return "database admin tool"
    return "backup / editor copy of a file"


def check_web_server(h: Host, F: Findings, web: dict) -> None:
    ng = web["nginx"]
    if not ng.strip():
        return
    if not re.search(r"^\s*server_tokens\s+off\s*;", ng, re.M):
        F.add("WEB_SERVER_VERSION_LEAK", None, server="nginx", fix="add `server_tokens off;` to the http block")
    if re.search(r"listen\s+[^;]*443|ssl_certificate\s", ng) and "strict-transport-security" not in ng.lower():
        F.add("NO_HSTS", None, server="nginx",
              fix='add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;')


# ---------------------------------------------------------------------------
# Accounts, SSH
# ---------------------------------------------------------------------------
def check_accounts(h: Host, F: Findings, cov: list) -> None:
    pw = h.read("/etc/passwd")
    if pw is None:
        return
    for ln in pw.splitlines():
        parts = ln.split(":")
        if len(parts) >= 4 and parts[2] == "0" and parts[0] != "root":
            F.add("EXTRA_ROOT_ACCOUNT", None, account=parts[0], shell=parts[-1] if len(parts) > 6 else "")
    sh = h.read("/etc/shadow")
    if sh is None:
        cov.append("/etc/shadow not readable (run as root to check for empty passwords).")
    else:
        for ln in sh.splitlines():
            parts = ln.split(":")
            if len(parts) > 1 and parts[1] == "":
                F.add("EMPTY_PASSWORD", None, account=parts[0])
    sud = ["/etc/sudoers"] + h.glob("/etc/sudoers.d/*")
    unreadable = 0
    for f in sud:
        txt = h.read(f)
        if txt is None:
            unreadable += h.exists(f)
            continue
        for ln in txt.splitlines():
            s = ln.strip()
            if s and not s.startswith("#") and "NOPASSWD" in s.upper():
                F.add("SUDO_NOPASSWD", None, file=f, rule=s[:120])
    if unreadable:
        cov.append("sudoers files not readable (run as root to check password-less sudo).")


def _sshd_effective(h: Host) -> dict | None:
    main = h.read("/etc/ssh/sshd_config")
    if main is None:
        return None
    eff: dict[str, str] = {}

    def feed(text: str, depth: int = 0) -> bool:
        for ln in text.splitlines():
            s = ln.split("#", 1)[0].strip()
            if not s:
                continue
            k, _, v = s.partition(" ")
            k, v = k.lower(), v.strip()
            if k == "match":
                return False                                  # global section ends here
            if k == "include" and depth < 3:
                for pat in v.split():
                    pat = pat if pat.startswith("/") else "/etc/ssh/" + pat
                    for f in h.glob(pat):
                        if not feed(h.read(f) or "", depth + 1):
                            return False
                continue
            eff.setdefault(k, v.lower())                      # sshd: first value wins
        return True

    feed(main)
    return eff


def check_ssh(h: Host, F: Findings) -> None:
    eff = _sshd_effective(h)
    if eff is None:
        return
    if eff.get("permitrootlogin") == "yes":
        F.add("SSH_ROOT_LOGIN", None, setting="PermitRootLogin yes", fix="PermitRootLogin no")
    pa = eff.get("passwordauthentication")
    if pa in (None, "yes"):
        F.add("SSH_PASSWORD_LOGIN", None, setting=f"PasswordAuthentication {pa or '(not set - OpenSSH default is yes)'}",
              fix="PasswordAuthentication no (after confirming key login works)")


# ---------------------------------------------------------------------------
# Updates, firewall, persistence, clock
# ---------------------------------------------------------------------------
def os_release(h: Host) -> dict:
    txt = h.read("/etc/os-release") or h.read("/usr/lib/os-release") or ""
    out = {}
    for ln in txt.splitlines():
        k, _, v = ln.partition("=")
        if k:
            out[k.strip()] = v.strip().strip('"')
    return out


def check_updates(h: Host, F: Findings, cov: list, today: date) -> dict:
    osr = os_release(h)
    oid, ver = osr.get("ID", "").lower(), osr.get("VERSION_ID", "")
    if oid:
        key = (oid, ver if oid == "ubuntu" else ver.split(".")[0])
        end = EOL.get(key)
        if end and date.fromisoformat(end) < today:
            F.add("OS_OUT_OF_SUPPORT", None, os=osr.get("PRETTY_NAME", f"{oid} {ver}"), support_ended=end,
                  note="paid extended support (e.g. Ubuntu Pro) may still cover it - confirm")
        elif not end:
            cov.append(f"Support end date for {osr.get('PRETTY_NAME', oid + ' ' + ver)} not in AEGIS's table - check manually.")
    if h.exists("/var/run/reboot-required") or h.exists("/run/reboot-required"):
        pk = (h.read("/var/run/reboot-required.pkgs") or h.read("/run/reboot-required.pkgs") or "").split()
        F.add("REBOOT_PENDING", None, packages=", ".join(pk[:8]) or "(not listed)")
    if oid in ("ubuntu", "debian") or h.exists("/var/lib/apt"):
        stamp = h.p("/var/lib/apt/periodic/update-success-stamp")
        if not os.path.exists(stamp):
            stamp = h.p("/var/lib/apt/lists")
        if os.path.exists(stamp):
            age = (time.time() - os.path.getmtime(stamp)) / 86400
            if age > 30:
                F.add("UPDATES_STALE", None, last_refresh_days_ago=int(age))
        au = h.read("/etc/apt/apt.conf.d/20auto-upgrades") or ""
        if not re.search(r'Unattended-Upgrade\s+"1"', au):
            F.add("NO_AUTO_SECURITY_UPDATES", None, fix="apt install unattended-upgrades && dpkg-reconfigure unattended-upgrades")
    return osr


def check_firewall(h: Host, F: Findings, cov: list) -> None:
    if h.windows:
        try:
            txt = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"], capture_output=True,
                                 text=True, timeout=30).stdout
        except (OSError, subprocess.SubprocessError):
            cov.append("Windows firewall state could not be read.")
            return
        prof = None
        for ln in txt.splitlines():
            m = re.match(r"^(\w+) Profile Settings", ln.strip())
            if m:
                prof = m.group(1)
            elif ln.strip().upper().startswith("STATE") and "OFF" in ln.upper():
                F.add("FIREWALL_DISABLED", None, profile=prof or "?")
        return
    ufw = h.read("/etc/ufw/ufw.conf")
    if ufw is not None:
        if re.search(r"^\s*ENABLED\s*=\s*no", ufw, re.M | re.I):
            F.add("FIREWALL_DISABLED", None, firewall="ufw", fix="ufw allow OpenSSH && ufw allow 443 && ufw enable")
        return
    if h.exists("/etc/firewalld/firewalld.conf") or h.exists("/etc/nftables.conf") or h.exists("/etc/iptables"):
        cov.append("A firewall is installed (firewalld / nftables / iptables) but its live state needs root tools - "
                   "confirm it is active.")
    else:
        cov.append("No host firewall configuration found - confirm the cloud firewall / security group restricts ports.")


def check_cron(h: Host, F: Findings, cov: list) -> None:
    files = (["/etc/crontab"] + h.glob("/etc/cron.d/*") + h.glob("/var/spool/cron/crontabs/*")
             + h.glob("/var/spool/cron/*"))
    unread = 0
    for f in files:
        if os.path.isdir(h.p(f)):
            continue
        txt = h.read(f)
        if txt is None:
            unread += h.exists(f)                 # missing is fine; present-but-unreadable is a gap
            continue
        for ln in txt.splitlines():
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            for rx, why in CRON_BAD:
                if rx.search(s):
                    F.add("SUSPICIOUS_SCHEDULED_TASK", None, file=f, line=s[:160], why=why)
                    break
    if unread:
        cov.append(f"{unread} scheduled-task file(s) not readable (run as root to check every user's crontab).")


def check_clock(h: Host, F: Findings) -> None:
    if h.windows or not h.exists("/run/systemd/system"):
        return
    if any(h.exists(p) for p in ("/run/systemd/timesync/synchronized", "/run/chrony", "/var/run/chrony",
                                 "/run/chronyd.pid", "/var/run/ntpd.pid", "/run/ntpd.pid")):
        return
    F.add("CLOCK_NOT_SYNCED", None, fix="timedatectl set-ntp true (or install chrony)")


# ---------------------------------------------------------------------------
def machine_name(h: Host) -> str:
    if h.live:
        return socket.gethostname().lower()
    n = (h.read("/etc/hostname") or "").strip().lower()
    return n or os.path.basename(os.path.abspath(h.root)).lower()


def checkup(root: str | None = None, app_dirs: list[str] | None = None, web_roots: list[str] | None = None,
            today: date | None = None) -> dict:
    h = Host(root)
    F = Findings(CATALOGUE, CASE_FIELDS)
    cov: list[str] = []
    today = today or date.today()
    check_network(h, F, cov)
    if h.windows:
        check_firewall(h, F, cov)
        web = {"files": [], "roots": [], "nginx": "", "apache": False}
        check_files(h, F, cov, app_dirs or [], web_roots or [], web)
        cov.append("Windows host: Linux-specific checks (accounts, SSH, OS support, updates, scheduled tasks) skipped.")
        import platform
        osr = {"PRETTY_NAME": f"Windows {platform.release()} (build {platform.version()})"}
    else:
        web = web_config(h)
        check_files(h, F, cov, app_dirs or [], web_roots or [], web)
        check_web_server(h, F, web)
        check_accounts(h, F, cov)
        check_ssh(h, F)
        osr = check_updates(h, F, cov, today)
        check_firewall(h, F, cov)
        check_cron(h, F, cov)
        check_clock(h, F)
        if h.live and hasattr(os, "geteuid") and os.geteuid() != 0:
            cov.append("Not running as root: some files could not be read (noted above). Read-only root access "
                       "gives a complete check-up.")
    # Admin-port findings carry their own level (e.g. Docker API = CRITICAL): reflect it in the title severity.
    res = F.list()
    for f in res:
        if f["code"] == "EXPOSED_ADMIN_SERVICE":
            lv = [s.get("level") for s in f["samples"]]
            for top in ("CRITICAL", "HIGH"):
                if top in lv:
                    f["severity"] = top
                    break
            else:
                f["severity"] = "MEDIUM"
    from ..findings import SEV_ORDER
    res.sort(key=lambda f: (SEV_ORDER.index(f["severity"]), f["code"]))
    return {"machine": machine_name(h), "os": osr.get("PRETTY_NAME", ""), "root": root or "/",
            "findings": res, "case_keys": F.case_keys(), "coverage": cov,
            "web_roots": web["roots"], "web_config_files": web["files"],
            "plain": [f"[{f['severity']}] {f['title']}: {f['count']}" for f in res]}


def run_host(authz, root: str | None = None, app_dirs: list[str] | None = None,
             web_roots: list[str] | None = None, today: date | None = None) -> dict:
    h = Host(root)
    name = machine_name(h)
    d = authz.authorize_local(ACTION, name)
    if not d:
        return {"check": "host", "authorized": False, "reason": d.reason, "target": name}
    res = checkup(root, app_dirs, web_roots, today)
    out = {"check": "host", "module_title": f"Server check-up - {res['machine']}", "target": res["machine"],
           "authorized": True, "os": res["os"], "root": res["root"], "web_roots": res["web_roots"],
           "module_findings": res["findings"], "coverage": res["coverage"], "findings": res["plain"],
           "scanned": {"web_config_files": len(res["web_config_files"]), "web_roots": len(res["web_roots"])}}
    authz.audit.append("check", action=ACTION, target=res["machine"], decision="DONE", detail=out)
    return dict(out, case_keys=res["case_keys"])
