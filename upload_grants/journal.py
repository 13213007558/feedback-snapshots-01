"""Append-only local signature journal (JSON Lines).

The journal is the "本地签名记录" used to audit what was actually signed.
It records the synthetic access key and the signature/policy material but
never the secret key.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from .model import utcnow

ISSUED = "issued"
REFUSED = "refused"
DENIED = "denied"


class SignatureJournal:
    """JSONL file holding one record per issuance decision or signature."""

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()

    def _next_seq(self) -> int:
        count = 0
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    count += 1
        return count + 1

    def append(self, **entry: object) -> dict:
        record = {
            "seq": self._next_seq(),
            "recorded_at": utcnow().isoformat(),
            **entry,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return record

    def load(self) -> list[dict]:
        records: list[dict] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def query(
            self,
            *,
            request_id: Optional[str] = None,
            event: Optional[str] = None,
            channel: Optional[str] = None,
    ) -> list[dict]:
        result = self.load()
        if request_id is not None:
            result = [r for r in result if r.get("request_id") == request_id]
        if event is not None:
            result = [r for r in result if r.get("event") == event]
        if channel is not None:
            result = [r for r in result if r.get("channel") == channel]
        return result

    def issued_puts(self, request_id: Optional[str] = None) -> list[dict]:
        return self.query(
            request_id=request_id, event=ISSUED, channel="put_url",
        )
