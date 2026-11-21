"""
The authorization gate.

Every check in AEGIS must obtain a GRANT from here before touching a target.
The gate enforces, in order:
  1. The scope signature is valid (if a key was supplied).
  2. The current time is inside the authorized window.
  3. The action is on the allowed-actions list.
  4. The target host/IP is in scope and not excluded.
  5. The port (if given) is in scope.

Both grants and denials are written to the audit log, so the record shows not
only what was done but also what was refused.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .audit import AuditLog
from .scope import Scope


@dataclass
class Decision:
    allowed: bool
    reason: str

    def __bool__(self) -> bool:
        return self.allowed


class Authorizer:
    def __init__(self, scope: Scope, audit: AuditLog, signature_verified: bool | None):
        self.scope = scope
        self.audit = audit
        # None  -> no key supplied, running on asserted authorization
        # True  -> signature checked and valid
        # False -> signature checked and INVALID (hard stop)
        self.signature_verified = signature_verified

    def preflight(self) -> Decision:
        """One-time gate checked before any stage runs."""
        if self.signature_verified is False:
            return self._deny("preflight", "scope", "scope signature INVALID - refusing to run")
        if not self.scope.window_active():
            return self._deny("preflight", "scope",
                              f"outside authorized window ({self.scope.window_start} .. {self.scope.window_end})")
        self.audit.append("authorization", action="preflight", target=self.scope.engagement_id,
                          decision="GRANT",
                          detail={"signed": self.signature_verified,
                                  "authorized_by": self.scope.authorized_by})
        return Decision(True, "preflight ok")

    def authorize(self, action: str, host: str, ip: str | None = None, port: int | None = None) -> Decision:
        if action not in self.scope.allowed_actions:
            return self._deny(action, host, f"action {action!r} not in allowed_actions")
        if not self.scope.window_active():
            return self._deny(action, host, "outside authorized window")

        in_scope = False
        if host and self.scope.host_in_scope(host):
            in_scope = True
        if ip and self.scope.ip_in_scope(ip):
            in_scope = True
        if not in_scope:
            return self._deny(action, host or ip or "?", "target not in authorized scope")

        if port is not None and not self.scope.port_in_scope(port):
            return self._deny(action, f"{host or ip}:{port}", f"port {port} not in authorized scope")

        target = host or ip or "?"
        if port is not None:
            target = f"{target}:{port}"
        self.audit.append("authorization", action=action, target=target, decision="GRANT")
        return Decision(True, "authorized")

    def authorize_db(self, action: str, db_label: str) -> Decision:
        """Gate for in-system database work (identify / map / ledger).

        The database must be listed in the scope's `databases` (glob patterns allowed,
        compared against the password-redacted connection string or path)."""
        import fnmatch
        import os

        if action not in self.scope.allowed_actions:
            return self._deny(action, db_label, f"action {action!r} not in allowed_actions")
        if not self.scope.window_active():
            return self._deny(action, db_label, "outside authorized window")

        def norm(s: str) -> str:
            s = re.sub(r"(://[^:/@]+):[^@]*@", r"\1@", s.strip())
            return s.replace("\\", "/").rstrip("/").lower()

        label = norm(db_label)
        candidates = {label, norm(os.path.abspath(db_label)) if "://" not in db_label else label}
        for pattern in self.scope.databases:
            p = norm(pattern)
            if any(fnmatch.fnmatch(c, p) for c in candidates):
                self.audit.append("authorization", action=action, target=db_label, decision="GRANT",
                                  detail={"matched": pattern})
                return Decision(True, "authorized")
        return self._deny(action, db_label, "database not listed in authorized scope.databases")

    def authorize_local(self, action: str, server: str, paths: list[str] | None = None) -> Decision:
        """Gate for work done ON a client machine (server check-up, tamper alarm).

        The machine's hostname must match the scope's `servers` (glob patterns), and every
        folder to be fingerprinted must sit inside one of the scope's `paths`."""
        import fnmatch
        import os

        if action not in self.scope.allowed_actions:
            return self._deny(action, server, f"action {action!r} not in allowed_actions")
        if not self.scope.window_active():
            return self._deny(action, server, "outside authorized window")
        host = (server or "").lower()
        if not any(fnmatch.fnmatch(host, s.lower()) for s in self.scope.servers):
            return self._deny(action, server, "this machine is not listed in authorized scope.servers")

        def norm(p: str) -> str:
            return os.path.normcase(os.path.abspath(p)).replace("\\", "/").rstrip("/")

        allowed = [norm(p) for p in self.scope.paths]
        for p in paths or []:
            n = norm(p)
            if not any(n == a or n.startswith(a + "/") or fnmatch.fnmatch(n, a) for a in allowed):
                return self._deny(action, f"{server}:{p}", "path not inside authorized scope.paths")
        self.audit.append("authorization", action=action, target=server, decision="GRANT",
                          detail={"paths": paths or []})
        return Decision(True, "authorized")

    def _deny(self, action: str, target: str, reason: str) -> Decision:
        self.audit.append("authorization", action=action, target=target, decision="DENY",
                          detail={"reason": reason})
        return Decision(False, reason)
