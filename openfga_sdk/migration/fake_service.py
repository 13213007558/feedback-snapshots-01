"""
In-process fake OpenFGA service for migration recovery tests.

The fake speaks the small slice of the OpenFGA HTTP API used by a migration:

* ``POST /stores/{store_id}/write`` - transactional tuple writes/deletes
* ``POST /stores/{store_id}/read``  - tuple reads with simple filtering

It keeps tuples in memory and honours the ``on_duplicate`` / ``on_missing``
conflict flags the SDK sends, so retry behaviour matches a real store.

Fault injection is deliberately stateful. :meth:`lose_next_write_response`
makes the next write request apply (or not, via ``applied``) on the server
but raise a transport error instead of returning a response. This reproduces
the ambiguous "did the batch land?" condition the recovery flow must handle.
"""

import json
import re

from datetime import datetime, timezone

import urllib3

from openfga_sdk import rest
from openfga_sdk.migration.tuple_key import tuple_identity


_WRITE_PATH = re.compile(r"/stores/[^/]+/write$")
_READ_PATH = re.compile(r"/stores/[^/]+/read$")


class LostResponseError(Exception):
    """
    Raised in place of an HTTP response to simulate a dropped connection
    after the server may already have committed the write.
    """


class FakeOpenFgaService:
    """
    Stateful fake server mounted by patching ``RESTClientObject.request``.
    """

    def __init__(self) -> None:
        self._tuples: set[str] = set()
        self._write_log: list[dict] = []
        self._read_log: list[dict] = []
        self._lose_next: dict | None = None
        self._write_sequence = 0

    @property
    def stored_identities(self) -> set[str]:
        return set(self._tuples)

    @property
    def write_requests(self) -> list[dict]:
        return list(self._write_log)

    @property
    def read_requests(self) -> list[dict]:
        return list(self._read_log)

    def seed(self, tuples: list[dict[str, str]]) -> None:
        """Pre-populate the store, e.g. with the legacy role relationships."""
        for item in tuples:
            self._tuples.add(tuple_identity(item))

    def reset(self) -> None:
        self._tuples.clear()
        self._write_log.clear()
        self._read_log.clear()
        self._lose_next = None
        self._write_sequence = 0

    def lose_next_write_response(self, applied: bool = True) -> None:
        """
        Arrange for the next write to lose its response.

        :param applied: When ``True`` the write still mutates the store before
            the error is raised (ambiguous outcome). When ``False`` the store
            is left untouched (pure transport failure before commit).
        """
        self._lose_next = {
            "applied": applied,
            "consumed": False,
            "on_sequence": self._write_sequence,
        }

    def lose_write_response_at(self, sequence: int, applied: bool = True) -> None:
        """
        Arrange for the write at a specific zero-based request sequence to
        lose its response, allowing earlier batches to commit cleanly.
        """
        self._lose_next = {
            "applied": applied,
            "consumed": False,
            "on_sequence": sequence,
        }

    async def handle_request(
        self,
        method,
        url,
        query_params=None,
        headers=None,
        body=None,
        post_params=None,
        _preload_content=True,
        _request_timeout=None,
    ):
        if method != "POST":
            return self._error(405, f"method {method} not supported by fake service")

        if _WRITE_PATH.search(url):
            return await self._handle_write(body)
        if _READ_PATH.search(url):
            return self._handle_read(body)

        return await self._error(404, f"unknown fake service path: {url}")

    async def _handle_write(self, body: dict):
        sequence = self._write_sequence
        self._write_sequence += 1
        self._write_log.append(body)

        writes = (body or {}).get("writes") or {}
        deletes = (body or {}).get("deletes") or {}
        write_keys = writes.get("tuple_keys") or []
        delete_keys = deletes.get("tuple_keys") or []
        on_duplicate = writes.get("on_duplicate", "error")
        on_missing = deletes.get("on_missing", "error")

        write_ids = [tuple_identity(item) for item in write_keys]
        delete_ids = [tuple_identity(item) for item in delete_keys]

        if on_duplicate == "error":
            duplicate = [item for item in write_ids if item in self._tuples]
            if duplicate:
                await self._error(
                    409,
                    "write conflict: tuple already exists: "
                    + ", ".join(sorted(duplicate)),
                )

        if on_missing == "error":
            missing = [item for item in delete_ids if item not in self._tuples]
            if missing:
                await self._error(
                    404,
                    "delete conflict: tuple missing: " + ", ".join(sorted(missing)),
                )

        pending_fault = self._lose_next
        if (
            pending_fault is not None
            and not pending_fault["consumed"]
            and pending_fault["on_sequence"] == sequence
        ):
            pending_fault["consumed"] = True
            self._lose_next = None
            if pending_fault["applied"]:
                self._tuples.difference_update(delete_ids)
                self._tuples.update(write_ids)
            raise LostResponseError("connection reset before response was received")

        self._tuples.difference_update(delete_ids)
        self._tuples.update(write_ids)
        return self._ok({})

    def _handle_read(self, body: dict | None):
        self._read_log.append(body or {})
        filter_key = (body or {}).get("tuple_key") or {}

        wanted_user = filter_key.get("user")
        wanted_relation = filter_key.get("relation")
        wanted_object = filter_key.get("object")

        tuples = []
        for identity in sorted(self._tuples):
            object_, relation, user = self._split(identity)
            if wanted_user and user != wanted_user:
                continue
            if wanted_relation and relation != wanted_relation:
                continue
            if wanted_object and not self._object_matches(object_, wanted_object):
                continue
            tuples.append(
                {
                    "key": {
                        "user": user,
                        "relation": relation,
                        "object": object_,
                    },
                    "timestamp": datetime.now(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                }
            )

        return self._ok({"tuples": tuples, "continuation_token": ""})

    @staticmethod
    def _object_matches(stored_object: str, wanted_object: str) -> bool:
        if wanted_object.endswith(":"):
            return stored_object.startswith(wanted_object)
        return stored_object == wanted_object

    @staticmethod
    def _split(identity: str) -> tuple[str, str, str]:
        object_, remainder = identity.split("#", 1)
        relation, user = remainder.split("@", 1)
        return object_, relation, user

    @staticmethod
    def _ok(payload: dict) -> rest.RESTResponse:
        return _json_response(json.dumps(payload), 200)

    @staticmethod
    async def _error(status: int, message: str) -> rest.RESTResponse:
        response = _json_response(
            json.dumps({"code": str(status), "message": message}), status
        )
        await _raise_for_status(response)
        return response  # pragma: no cover


def _json_response(body: str, status: int) -> rest.RESTResponse:
    headers = urllib3.response.HTTPHeaderDict({"content-type": "application/json"})
    raw = urllib3.HTTPResponse(
        body.encode("utf-8"), headers, status, preload_content=False
    )
    return rest.RESTResponse(raw, raw.data)


async def _raise_for_status(response: rest.RESTResponse) -> None:
    # Reuse the production status-to-exception mapping without constructing a
    # real RESTClientObject (the method itself is stateless regarding self).
    await rest.RESTClientObject.handle_response_exception(None, response)


__all__ = ["FakeOpenFgaService", "LostResponseError"]
