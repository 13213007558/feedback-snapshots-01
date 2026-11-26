"""Canonical ticket store.

The canonical record always keeps the complete materials for internal use,
including internal-only fields and the raw values of withdrawn fields.  The
public preview path never reads those raw values directly; it goes through
:mod:`ticket_preview.gate`.
"""

from __future__ import annotations

import json
from pathlib import Path


class TicketStore:
    def __init__(self, data_file):
        self.data_file = Path(data_file)

    def _load_all(self):
        with self.data_file.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload.get("tickets", [])

    def get(self, ticket_id):
        for ticket in self._load_all():
            if ticket.get("id") == ticket_id:
                return ticket
        return None

    def all_ids(self):
        return [ticket.get("id") for ticket in self._load_all()]

    @staticmethod
    def withdrawn_fields(ticket) -> set:
        withdrawn = ticket.get("withdrawn_fields") or {}
        if isinstance(withdrawn, dict):
            return set(withdrawn.keys())
        return set(withdrawn or [])

    @staticmethod
    def public_field_order(ticket) -> list:
        return list(ticket.get("public_field_order") or [])
