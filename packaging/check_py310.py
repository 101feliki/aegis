"""Static check that every module in a built aegis.pyz parses with the Python 3.10 grammar
and uses no 3.12-only same-quote nesting inside f-strings.

    python packaging/check_py310.py dist/aegis-<ver>.pyz
"""
import ast
import re
import sys
import zipfile

pyz = sys.argv[1]
z = zipfile.ZipFile(pyz)
problems = 0
names = [n for n in z.namelist() if n.endswith(".py")]
for n in names:
    src = z.read(n).decode("utf-8")
    try:
        ast.parse(src, n, feature_version=(3, 10))
    except SyntaxError as e:
        problems += 1
        print(f"3.10 syntax: {n}:{e.lineno} {e.msg}")
    # Same quote reused inside an f-string replacement field is only legal from 3.12 (PEP 701).
    for i, line in enumerate(src.splitlines(), 1):
        for q in ('"', "'"):
            for m in re.finditer(r"\bf" + q + r"((?:[^" + q + r"\\\n]|\\.)*)" + q, line):
                body = m.group(1)
                depth = 0
                for ch in body:
                    depth += ch == "{"
                    depth -= ch == "}"
                if depth > 0:
                    problems += 1
                    print(f"f-string quote nesting (3.12+): {n}:{i} {line.strip()[:90]}")
print(f"{len(names)} modules checked, {problems} problem(s)")
sys.exit(1 if problems else 0)
