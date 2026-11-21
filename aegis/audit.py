"""
Tamper-evident audit log.

Every event AEGIS performs - authorization grants, denials, and the result of
each check - is appended here as one JSON line. Each entry carries the SHA-256
hash of the previous entry, forming a chain: changing or deleting any past entry
breaks every hash after it. `verify()` re-derives the chain so counsel can prove
the record is intact.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone

GENESIS = "0" * 64


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(prev_hash: str, body: dict) -> str:
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canon).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str, operator: str = "", engagement_id: str = ""):
        self.path = path
        self.operator = operator
        self.engagement_id = engagement_id
        self._lock = threading.Lock()
        self._last_hash = self._tail_hash()

    def _tail_hash(self) -> str:
        if not os.path.exists(self.path):
            return GENESIS
        last = None
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = line
        if not last:
            return GENESIS
        return json.loads(last)["hash"]

    def append(self, event: str, action: str = "", target: str = "", decision: str = "",
               detail: dict | None = None) -> dict:
        with self._lock:
            seq = self._next_seq()
            body = {
                "seq": seq,
                "ts": _ts(),
                "engagement_id": self.engagement_id,
                "operator": self.operator,
                "event": event,
                "action": action,
                "target": target,
                "decision": decision,
                "detail": detail or {},
                "prev_hash": self._last_hash,
            }
            body["hash"] = _digest(self._last_hash, {k: v for k, v in body.items() if k != "hash"})
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(body, sort_keys=True) + "\n")
            self._last_hash = body["hash"]
            return body

    def _next_seq(self) -> int:
        if self._last_hash == GENESIS and not os.path.exists(self.path):
            return 1
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                count = sum(1 for line in fh if line.strip())
            return count + 1
        except FileNotFoundError:
            return 1

    @staticmethod
    def verify(path: str) -> tuple[bool, str]:
        """Re-derive the hash chain. Returns (ok, message)."""
        prev = GENESIS
        n = 0
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    n += 1
                    entry = json.loads(line)
                    stored = entry.get("hash")
                    if entry.get("prev_hash") != prev:
                        return False, f"chain break at seq {entry.get('seq')} (prev_hash mismatch)"
                    recomputed = _digest(prev, {k: v for k, v in entry.items() if k != "hash"})
                    if recomputed != stored:
                        return False, f"tampered entry at seq {entry.get('seq')} (hash mismatch)"
                    prev = stored
        except FileNotFoundError:
            return False, "audit log not found"
        return True, f"intact: {n} entries verified"
