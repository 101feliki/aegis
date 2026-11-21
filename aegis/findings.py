"""
Shared finding collector for the inside modules (M-Pesa guard, server check-up,
tamper alarm).

Every module describes its checks in a catalogue:

    CATALOGUE = {"CODE": ("SEVERITY", "Plain-language title", "What it means / why it matters"), ...}

and records hits with `Findings.add(code, money, **evidence)`. Each hit gets a
stable case key (from the evidence fields named in `case_fields`), so the
continuous runner (`aegis guard`) can tell a NEW problem from one it has already
reported.
"""
from __future__ import annotations

from collections import defaultdict
from decimal import Decimal

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SAMPLES = 15
MAX_KEYS = 100_000
ZERO = Decimal("0")


def money(d: Decimal | None) -> str | None:
    if d is None:
        return None
    return f"{d.quantize(Decimal('0.01')):,}"


class Findings:
    def __init__(self, catalogue: dict[str, tuple[str, str, str]],
                 case_fields: dict[str, tuple[str, ...]] | None = None):
        self.cat = catalogue
        self.case_fields = case_fields or {}
        self.samples: dict[str, list] = defaultdict(list)
        self.counts: dict[str, int] = defaultdict(int)
        self.at_risk: dict[str, Decimal] = defaultdict(lambda: ZERO)
        self.keys: dict[str, set] = defaultdict(set)

    def key(self, code: str, ev: dict) -> str:
        fields = self.case_fields.get(code)
        if not fields:
            fields = tuple(sorted(k for k in ev if k not in ("amount", "detail", "fix")))[:3]
        return "/".join(str(ev.get(f)) for f in fields)

    def add(self, code: str, at_risk: Decimal | None = None, /, **ev) -> None:
        if code not in self.cat:
            raise KeyError(f"unknown finding code {code}")
        self.counts[code] += 1
        if len(self.samples[code]) < SAMPLES:
            self.samples[code].append(ev)
        if at_risk:
            self.at_risk[code] += at_risk
        if len(self.keys[code]) < MAX_KEYS:
            self.keys[code].add(self.key(code, ev))

    def __len__(self) -> int:
        return sum(self.counts.values())

    def list(self) -> list[dict]:
        out = []
        for code in sorted(self.counts, key=lambda c: (SEV_ORDER.index(self.cat[c][0]), c)):
            sev, title, means = self.cat[code]
            out.append({"code": code, "severity": sev, "title": title, "means": means,
                        "count": self.counts[code],
                        "money_at_risk": money(self.at_risk[code]) if self.at_risk[code] else None,
                        "samples": self.samples[code]})
        return out

    def total(self) -> str:
        return money(sum(self.at_risk.values(), ZERO)) or "0.00"

    def case_keys(self) -> dict[str, list]:
        return {c: sorted(v) for c, v in self.keys.items()}

    def plain(self, currency: str = "KES") -> list[str]:
        """One line per finding, for the generic Findings table in the report."""
        return [f"[{f['severity']}] {f['title']}: {f['count']} case(s)"
                + (f", {currency} {f['money_at_risk']} at risk" if f["money_at_risk"] else "")
                for f in self.list()]
