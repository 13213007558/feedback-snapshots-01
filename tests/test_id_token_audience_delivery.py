# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""End-to-end audience delivery tests for derived ID token credentials.

Two service doubles stand in for the local inventory services. Both clients
are derived from the same signing identity but are registered for different
audiences; one refreshes through the IAM generateIdToken endpoint and the
other through the original token exchange endpoint. The doubles interleave
requests and deliberately return the other service's validly-issued token
before the correct one, and the tests record what is actually attached to the
request headers and what remains cached.
"""

import datetime
import http.client as http_client
import json
import os

import pytest  # type: ignore

from google.auth import _helpers
from google.auth import crypt
from google.auth import exceptions
from google.auth import jwt
from google.oauth2 import service_account


DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

with open(os.path.join(DATA_DIR, "privatekey.pem"), "rb") as _fh:
    SIGNER_BYTES = _fh.read()

SERVICE_ACCOUNT_EMAIL = "inventory-signer@example.com"
TOKEN_URI = "https://oauth2.example.com/token"
AUDIENCE_A = "https://inventory-a.example.com"
AUDIENCE_B = "https://inventory-b.example.com"


def _make_id_token(audience, expires_in=500):
    now = _helpers.utcnow()
    payload = {
        "aud": audience,
        "iat": _helpers.datetime_to_secs(now),
        "exp": _helpers.datetime_to_secs(
            now + datetime.timedelta(seconds=expires_in)
        ),
    }
    header = _helpers.unpadded_urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT"}).encode("utf-8")
    )
    body = _helpers.unpadded_urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
    signature = _helpers.unpadded_urlsafe_b64encode(b"signature")
    return b".".join([header, body, signature]).decode("utf-8")


class _FakeResponse:
    def __init__(self, body, status=http_client.OK):
        self.status = status
        self.data = json.dumps(body).encode("utf-8")


class _ServiceDoubles:
    """Serves both token endpoints and records every request it receives."""

    def __init__(self):
        self.requests = []
        self._token_uri_queue = []
        self._iam_queue = []

    def queue_token_uri(self, *tokens):
        self._token_uri_queue.extend(tokens)

    def queue_iam(self, *tokens):
        self._iam_queue.extend(tokens)

    def __call__(self, url, method="GET", body=None, headers=None, **kwargs):
        is_iam = ":generateIdToken" in url
        self.requests.append(
            {"url": url, "path": "iam" if is_iam else "token_uri", "body": body}
        )
        token = (self._iam_queue if is_iam else self._token_uri_queue).pop(0)
        if is_iam:
            return _FakeResponse({"token": token})
        return _FakeResponse({"id_token": token})


def _make_client(audience, use_iam_endpoint):
    signer = crypt.RSASigner.from_string(SIGNER_BYTES, "1")
    credentials = service_account.IDTokenCredentials(
        signer, SERVICE_ACCOUNT_EMAIL, TOKEN_URI, audience
    )
    credentials._use_iam_endpoint = use_iam_endpoint
    return credentials


def _attached_header(credentials):
    headers = {}
    credentials.apply(headers)
    return headers.get("authorization")


def _header_type(authorization):
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    aud = jwt.decode(token, verify=False)["aud"]
    return {"scheme": scheme, "audience": aud}


@pytest.mark.parametrize("use_iam_endpoint", [False, True])
def test_rejected_audience_does_not_poison_other_client(use_iam_endpoint):
    doubles = _ServiceDoubles()
    client_a = _make_client(AUDIENCE_A, use_iam_endpoint=False)
    client_b = _make_client(AUDIENCE_B, use_iam_endpoint=use_iam_endpoint)
    token_a = _make_id_token(AUDIENCE_A)
    token_b = _make_id_token(AUDIENCE_B)
    record = []

    # A warms up on the exchange path and attaches its own ID token.
    doubles.queue_token_uri(token_a)
    client_a.refresh(doubles)
    header_a = _attached_header(client_a)
    record.append(
        {
            "client": "A",
            "path": "token_uri",
            "header": _header_type(header_a),
            "cache": client_a.token == token_a,
            "result": "accepted",
        }
    )

    # B's first approved call receives A's validly-issued token by mistake.
    if use_iam_endpoint:
        doubles.queue_iam(token_a)
    else:
        doubles.queue_token_uri(token_a)
    with pytest.raises(exceptions.RefreshError):
        client_b.refresh(doubles)
    record.append(
        {
            "client": "B",
            "path": "iam" if use_iam_endpoint else "token_uri",
            "header": None,
            "cache": client_b.token is not None,
            "result": "rejected",
        }
    )
    assert client_b.token is None
    assert not client_b.valid

    # B then receives the correct token and attaches it.
    if use_iam_endpoint:
        doubles.queue_iam(token_b)
    else:
        doubles.queue_token_uri(token_b)
    client_b.refresh(doubles)
    header_b = _attached_header(client_b)
    record.append(
        {
            "client": "B",
            "path": "iam" if use_iam_endpoint else "token_uri",
            "header": _header_type(header_b),
            "cache": client_b.token == token_b,
            "result": "accepted",
        }
    )

    # A's cache was not cleared by B's rejection.
    assert client_a.token == token_a
    assert client_a.valid
    assert _attached_header(client_a) == header_a

    assert record[0]["header"] == {"scheme": "Bearer", "audience": AUDIENCE_A}
    assert record[1]["header"] is None
    assert record[1]["cache"] is False
    assert record[2]["header"] == {"scheme": "Bearer", "audience": AUDIENCE_B}
    assert record[2]["cache"] is True
    # Both paths attached an ID token as the Authorization bearer value.
    assert all(
        entry["header"] is None or entry["header"]["scheme"] == "Bearer"
        for entry in record
    )
    # Each client stayed on its own refresh entry point.
    paths = [request["path"] for request in doubles.requests]
    if use_iam_endpoint:
        # A warmed up through the exchange endpoint; B used IAM twice.
        assert paths == ["token_uri", "iam", "iam"]
    else:
        assert paths == ["token_uri", "token_uri", "token_uri"]
