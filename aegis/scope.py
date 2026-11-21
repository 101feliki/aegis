"""
Scope & authorization record.

A scope file is the signed statement of what counsel authorized: who, what
targets, which actions, and for how long. It is signed with HMAC-SHA256 so it
cannot be silently edited after sign-off - the tool refuses to run against a
tampered scope.
"""
from __future__ import annotations

import fnmatch
import hashlib
import hmac
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

SIGNATURE_FIELD = "signature"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_ts(value: str) -> datetime:
    """Parse an ISO-8601 timestamp, tolerating a trailing Z."""
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def canonical_bytes(scope: dict) -> bytes:
    """Deterministic serialization of the scope, excluding the signature."""
    payload = {k: v for k, v in scope.items() if k != SIGNATURE_FIELD}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(scope: dict, key: str) -> str:
    return hmac.new(key.encode("utf-8"), canonical_bytes(scope), hashlib.sha256).hexdigest()


def verify_signature(scope: dict, key: str) -> bool:
    sig = scope.get(SIGNATURE_FIELD)
    if not sig:
        return False
    return hmac.compare_digest(sig, sign(scope, key))


# Standard RFC1918 / internal ranges used to classify a target as "internal".
DEFAULT_INTERNAL = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"]

ALL_ACTIONS = ["passive", "connectivity", "webintel", "settlement-readonly",
               "db-identify", "ledger-readonly", "mpesa-readonly", "host-checkup", "tamper-watch"]


@dataclass
class Scope:
    raw: dict
    engagement_id: str
    client: str
    authorized_by: str
    window_start: datetime
    window_end: datetime
    domains: list[str] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    internal_networks: list[str] = field(default_factory=lambda: list(DEFAULT_INTERNAL))
    allowed_actions: list[str] = field(default_factory=list)
    excluded_domains: list[str] = field(default_factory=list)
    excluded_ips: list[str] = field(default_factory=list)
    rate_limit_per_host_rps: float = 2.0
    signed: bool = False
    databases: list[str] = field(default_factory=list)
    servers: list[str] = field(default_factory=list)      # machines AEGIS may be installed on / inspect
    paths: list[str] = field(default_factory=list)        # folders the tamper alarm may fingerprint

    @classmethod
    def load(cls, path: str) -> "Scope":
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        for req in ("engagement_id", "client", "authorized_by", "window"):
            if req not in raw:
                raise ValueError(f"scope is missing required field: {req!r}")
        sc = raw["scope"] if isinstance(raw.get("scope"), dict) else raw
        return cls(
            raw=raw,
            engagement_id=raw["engagement_id"],
            client=raw["client"],
            authorized_by=raw["authorized_by"],
            window_start=parse_ts(raw["window"]["start"]),
            window_end=parse_ts(raw["window"]["end"]),
            domains=sc.get("domains", []),
            ip_ranges=sc.get("ip_ranges", []),
            ports=sc.get("ports", [80, 443]),
            internal_networks=sc.get("internal_networks", list(DEFAULT_INTERNAL)),
            allowed_actions=raw.get("allowed_actions", []),
            excluded_domains=raw.get("excluded", {}).get("domains", []) if isinstance(raw.get("excluded"), dict) else [],
            excluded_ips=raw.get("excluded", {}).get("ip_ranges", []) if isinstance(raw.get("excluded"), dict) else [],
            rate_limit_per_host_rps=float(raw.get("rate_limit_per_host_rps", 2.0)),
            signed=bool(raw.get(SIGNATURE_FIELD)),
            databases=sc.get("databases", []),
            servers=sc.get("servers", []),
            paths=sc.get("paths", []),
        )

    # ---- membership tests -------------------------------------------------
    def host_in_scope(self, host: str) -> bool:
        host = host.lower().strip(".")
        if any(fnmatch.fnmatch(host, d.lower()) for d in self.excluded_domains):
            return False
        return any(fnmatch.fnmatch(host, d.lower()) for d in self.domains)

    def ip_in_scope(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for net in self.excluded_ips:
            if addr in ipaddress.ip_network(net, strict=False):
                return False
        for net in self.ip_ranges:
            if addr in ipaddress.ip_network(net, strict=False):
                return True
        return False

    def is_internal(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in ipaddress.ip_network(net, strict=False) for net in self.internal_networks)

    def port_in_scope(self, port: int) -> bool:
        return (not self.ports) or (port in self.ports)

    def window_active(self, now: datetime | None = None) -> bool:
        now = now or _utcnow()
        return self.window_start <= now <= self.window_end
