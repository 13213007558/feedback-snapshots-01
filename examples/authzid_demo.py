#!/usr/bin/env python3
"""
Show explicit SASL authorization identities (authzid).

The service account ``svc-backup`` authenticates with its own password and
requests to act as ``alice``.  Whether that request is honored depends on a
trusted server result or an explicit mapping, never on the request alone.

Run with::

    python examples/authzid_demo.py
"""

import asyncio
import os.path
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import aiosasl  # noqa: E402


class RecordingInterface(aiosasl.SASLInterface):
    """Minimal SASL interface which records the first client payload."""

    def __init__(self, outcome, *, refuse_request=False):
        self.outcome = outcome
        self.refuse_request = refuse_request
        self.sent = []

    async def initiate(self, mechanism, payload=None):
        self.sent.append((mechanism, payload))
        if self.refuse_request:
            # A server accepts the authentication identity but declines
            # the authorization request.
            raise aiosasl.SASLFailure(
                "not-authorized",
                text="authorization identity request refused",
            )
        return self.outcome, None

    async def respond(self, payload):
        self.sent.append(("response", payload))
        return aiosasl.SASLState.SUCCESS, None

    async def abort(self):
        return aiosasl.SASLState.FAILURE, None


async def provide_credentials():
    return "svc-backup", "service-secret"


def show_plain_request():
    request = aiosasl.encode_plain_payload(
        "svc-backup",
        "service-secret",
        "alice",
    )
    parsed = aiosasl.parse_plain_client_response(request)
    print("PLAIN payload:", request)
    print("  authcid:", parsed.authcid.decode())
    print("  authzid:", parsed.authzid.decode())
    return parsed


def show_scram_request():
    header = aiosasl.build_gs2_header(b"n", "a,alice=ops")
    print("GS2 header:", header)
    parsed = aiosasl.parse_gs2_header(header)
    print("  decoded authzid:", parsed.authzid.decode())
    return header


def allowed_by_mapping():
    return aiosasl.resolve_authorization(
        "svc-backup",
        "alice",
        mapping={"svc-backup": {"alice"}},
    )


def denied_by_server():
    # The server authenticated the service account but did not grant the
    # requested identity.
    return aiosasl.resolve_authorization(
        "svc-backup",
        "alice",
        server_identity="svc-backup",
    )


def main():
    show_plain_request()
    show_scram_request()

    allowed = allowed_by_mapping()
    print(
        "allowed:",
        allowed.effective_identity,
        "(source: {})".format(allowed.source),
    )

    denied = denied_by_server()
    print(
        "server declined: effective identity is",
        denied.effective_identity,
        "(delegated: {})".format(denied.delegated),
    )

    try:
        aiosasl.resolve_authorization("svc-backup", "alice")
    except aiosasl.AuthorizationFailure as exc:
        print("refused without a grant:", exc)

    loop = asyncio.new_event_loop()
    try:
        interface = RecordingInterface(aiosasl.SASLState.SUCCESS)
        sm = aiosasl.SASLStateMachine(interface)
        loop.run_until_complete(
            aiosasl.PLAIN(
                provide_credentials,
                authzid="alice",
            ).authenticate(sm, "PLAIN")
        )
        print("sent PLAIN payload:", interface.sent[0][1])

        declined = RecordingInterface(
            aiosasl.SASLState.SUCCESS,
            refuse_request=True,
        )
        sm = aiosasl.SASLStateMachine(declined)
        try:
            loop.run_until_complete(
                aiosasl.PLAIN(
                    provide_credentials,
                    authzid="alice",
                ).authenticate(sm, "PLAIN")
            )
        except aiosasl.SASLFailure as exc:
            print(
                "server refused delegation:",
                "authcid authenticated, authzid request denied",
                "({})".format(exc),
            )
        else:
            raise SystemExit("expected the delegation request to be refused")
    finally:
        loop.close()


if __name__ == "__main__":
    main()
