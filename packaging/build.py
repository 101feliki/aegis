"""
Build the AEGIS release artefacts.

    python packaging/build.py            -> dist/

Produces:
  dist/aegis-<ver>.pyz                 single-file AEGIS: `python3 aegis-<ver>.pyz --help`
                                       (bundles the pure-Python MySQL/Postgres drivers, so it reads
                                       MySQL/MariaDB and PostgreSQL with nothing installed on the server)
  dist/aegis-<ver>-linux.tar.gz        pyz + install.sh + uninstall.sh + INSTALL.md + third-party licences
  dist/SHA256SUMS                      checksums - the pyz hash is what AEGIS records in every audit log

The build is reproducible: files are added in sorted order with fixed timestamps, so the same
source + same drivers give the same .pyz hash.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as md
import io
import os
import re
import sys
import tarfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
FIXED = (2026, 1, 1, 0, 0, 0)                 # reproducible zip timestamps
MAIN = b'''"""AEGIS single-file release. Run: python3 aegis.pyz --help"""
import sys
if sys.version_info < (3, 10):
    sys.exit("AEGIS needs Python 3.10 or newer (this is %d.%d)" % sys.version_info[:2])
from aegis.cli import main
sys.exit(main())
'''


def version() -> str:
    txt = open(os.path.join(ROOT, "aegis", "__init__.py"), encoding="utf-8").read()
    return re.search(r'__version__\s*=\s*"([^"]+)"', txt).group(1)


def _add(zf: zipfile.ZipFile, arc: str, data: bytes) -> None:
    zi = zipfile.ZipInfo(arc, FIXED)
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.external_attr = 0o644 << 16
    zf.writestr(zi, data)


def _tree(src: str, prefix: str):
    for root, dirs, files in os.walk(src):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for f in sorted(files):
            if f.endswith((".pyc", ".pyo")):
                continue
            p = os.path.join(root, f)
            yield prefix + "/" + os.path.relpath(p, src).replace(os.sep, "/"), p


def vendor_sources() -> tuple[list[tuple[str, str]], dict[str, str]]:
    """(files to add, {distribution: licence text}) for the bundled drivers.

    Installs the PINNED versions in vendor-requirements.txt into build/vendor (fresh each time),
    so the bundle never depends on what happens to be installed on the build machine."""
    import shutil
    import subprocess
    target = os.path.join(ROOT, "build", "vendor")
    shutil.rmtree(target, ignore_errors=True)
    r = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "--no-deps", "--no-compile",
                        "--disable-pip-version-check", "--target", target,
                        "-r", os.path.join(HERE, "vendor-requirements.txt")], capture_output=True, text=True)
    if r.returncode != 0:
        raise ImportError(f"pip could not fetch the pinned drivers: {r.stderr.strip()[-400:]}")
    files, licences = [], {}
    for entry in sorted(os.listdir(target)):
        p = os.path.join(target, entry)
        if entry in ("bin", "__pycache__"):
            continue
        # .dist-info is kept: some drivers read their own version via importlib.metadata at import
        # time (scramp does), and importlib.metadata finds it inside the zip.
        if os.path.isdir(p):
            files += list(_tree(p, entry))
        elif entry.endswith(".py"):
            files.append((entry, p))
    for d in md.distributions(path=[target]):
        texts = []
        for f in d.files or []:
            if os.path.basename(str(f)).upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE")):
                try:
                    texts.append(f.read_text())
                except (OSError, UnicodeError):
                    pass
        name = d.metadata["Name"]
        lic = d.metadata.get("License-Expression") or d.metadata.get("License") or "see project"
        licences[f"{name} {d.version}"] = (f"{name} {d.version} - licence: {lic}\n"
                                           f"Requires-Python: {d.metadata.get('Requires-Python')}\n\n"
                                           + ("\n\n".join(texts) or "(licence text not shipped in the wheel)"))
    return files, licences


def build_pyz(out: str, with_drivers: bool) -> tuple[str, dict]:
    path = os.path.join(out, f"aegis-{version()}.pyz")
    licences = {}
    entries = list(_tree(os.path.join(ROOT, "aegis"), "aegis"))
    if with_drivers:
        vf, licences = vendor_sources()
        entries += vf
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        _add(zf, "__main__.py", MAIN)
        for arc, p in sorted(entries):
            if arc.startswith("aegis/") and not arc.endswith(".py") and "/client-pack/" not in arc \
                    and not arc.endswith(".md"):
                continue
            with open(p, "rb") as fh:
                data = fh.read()
            if arc.endswith((".py", ".md")):
                data = data.replace(b"\r\n", b"\n")
            _add(zf, arc, data)
        for name, text in sorted(licences.items()):
            _add(zf, f"THIRD-PARTY-LICENSES/{name.split()[0]}.txt", text.encode())
    with open(path, "wb") as fh:
        fh.write(b"#!/usr/bin/env python3\n" + buf.getvalue())
    return path, licences


def _tar_add(tf: tarfile.TarFile, arc: str, data: bytes, mode: int = 0o644) -> None:
    ti = tarfile.TarInfo(arc)
    ti.size, ti.mode, ti.mtime, ti.uname, ti.gname = len(data), mode, 1767225600, "root", "root"
    tf.addfile(ti, io.BytesIO(data))


def build_tarball(out: str, pyz: str, licences: dict) -> str:
    ver = version()
    base = f"aegis-{ver}"
    path = os.path.join(out, f"{base}-linux.tar.gz")
    import gzip
    with open(path, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz, \
            tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tf:
        with open(pyz, "rb") as fh:
            _tar_add(tf, f"{base}/aegis.pyz", fh.read(), 0o755)
        _tar_add(tf, f"{base}/SHA256SUMS", f"{sha256(pyz)}  aegis.pyz\n".encode())
        for name, mode in (("install.sh", 0o755), ("uninstall.sh", 0o755), ("INSTALL.md", 0o644)):
            with open(os.path.join(HERE, name), "rb") as fh:
                _tar_add(tf, f"{base}/{name}", fh.read().replace(b"\r\n", b"\n").replace(b"@VERSION@", ver.encode()),
                         mode)
        for name, text in sorted(licences.items()):
            _tar_add(tf, f"{base}/THIRD-PARTY-LICENSES/{name.split()[0]}.txt", text.encode())
    return path


def sha256(p: str) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="build AEGIS release artefacts")
    ap.add_argument("--out", default=os.path.join(ROOT, "dist"))
    ap.add_argument("--no-drivers", action="store_true", help="do not bundle the MySQL/Postgres drivers")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    try:
        pyz, lic = build_pyz(a.out, not a.no_drivers)
    except ImportError as e:
        print(f"cannot bundle drivers ({e}); install them (pip install pymysql pg8000) or use --no-drivers",
              file=sys.stderr)
        return 1
    tgz = build_tarball(a.out, pyz, lic)
    sums = os.path.join(a.out, "SHA256SUMS")
    with open(sums, "w", encoding="utf-8", newline="\n") as fh:
        for p in (pyz, tgz):
            fh.write(f"{sha256(p)}  {os.path.basename(p)}\n")
    for p in (pyz, tgz, sums):
        print(f"{os.path.getsize(p):>10,}  {p}")
    print("bundled drivers: " + (", ".join(sorted(lic)) if lic else "none"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
