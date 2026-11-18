"""
Regression tests for SecureChannel key renewal on long-lived connections.

Fully encrypted message chunks are fed into SecureConnection.receive_from_header_and_body
to verify that the previous / current / next token receive windows stay separated by
channel id, key generation, sequence number and in-flight request id. A fixed test
certificate pair from examples/ is used; no network or device is involved.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization

from asyncua import ua
from asyncua.common.connection import MessageChunk, SecureConnection, TransportLimits
from asyncua.crypto import uacrypto
from asyncua.crypto.security_policies import (
    Cryptography,
    DecryptorAesCbc,
    EncryptorAesCbc,
    SecurityPolicyAes128Sha256RsaOaep,
    SignerHMac256,
    VerifierHMac256,
)
from asyncua.crypto.uacrypto import InvalidSignature
from asyncua.ua.ua_binary import header_from_binary, struct_from_binary

EXAMPLES = Path(__file__).parent.parent / "examples"
SERVER_CERT_PATH = EXAMPLES / "certificate-example.der"
SERVER_KEY_PATH = EXAMPLES / "private-key-example.pem"
CLIENT_CERT_PATH = EXAMPLES / "certificates" / "peer-certificate-example-1.der"
CLIENT_KEY_PATH = EXAMPLES / "certificates" / "peer-private-key-example-1.pem"

CHANNEL_ID = 7
OTHER_CHANNEL_ID = 8
UNKNOWN_TOKEN_ID = 999
TOKEN_LIFETIME_MS = 60_000
CLIENT_NONCE_1 = bytes(range(1, 33))
CLIENT_NONCE_2 = bytes(range(33, 65))


@dataclass
class KeyUse:
    epoch: int
    slot: str
    verified: bool


@dataclass
class RenewalReport:
    key_usage: list[KeyUse] = field(default_factory=list)
    delivered: list[bytes] = field(default_factory=list)
    rejections: list[tuple[str, str]] = field(default_factory=list)
    counterexamples: list[str] = field(default_factory=list)

    def successful_slots(self) -> list[str]:
        return [f"epoch{use.epoch}:{use.slot}" for use in self.key_usage if use.verified]


class _ChannelIds:
    def get_new_channel_id(self) -> int:
        return CHANNEL_ID


def _load_private_key(path: Path) -> object:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _receiving_crypto(secret: bytes, seed: bytes) -> Cryptography:
    sigkey, key, init_vec = uacrypto.p_sha256(secret, seed, (32, 16, 16))
    crypto = Cryptography(ua.MessageSecurityMode.SignAndEncrypt)
    crypto.Signer = SignerHMac256(sigkey)
    crypto.Verifier = VerifierHMac256(sigkey)
    crypto.Encryptor = EncryptorAesCbc(key, init_vec)
    crypto.Decryptor = DecryptorAesCbc(key, init_vec)
    return crypto


class NaiveTokenIdKeyReceiver:
    """Anti-pattern receiver: receive keys are selected by the numeric token id alone."""

    def __init__(self, keyring: dict[int, Cryptography]) -> None:
        self.keyring = keyring
        self.delivered: list[bytes] = []

    def feed(self, raw: bytes) -> bool:
        buf = ua.utils.Buffer(raw)
        header = header_from_binary(buf)
        token_id = struct_from_binary(ua.SymmetricAlgorithmHeader, buf.copy(4)).TokenId
        crypto = self.keyring.get(token_id)
        if crypto is None:
            return False
        policy = SimpleNamespace(symmetric_cryptography=crypto)
        chunk = MessageChunk.from_header_and_body(policy, header, buf)
        self.delivered.append(chunk.Body)
        return True


class RenewalHarness:
    def __init__(self) -> None:
        mode = ua.MessageSecurityMode.SignAndEncrypt
        server_cert = uacrypto.x509_from_der(SERVER_CERT_PATH.read_bytes())
        client_cert = uacrypto.x509_from_der(CLIENT_CERT_PATH.read_bytes())
        server_key = _load_private_key(SERVER_KEY_PATH)
        client_key = _load_private_key(CLIENT_KEY_PATH)
        self.report = RenewalReport()
        self.receiver = SecureConnection(
            SecurityPolicyAes128Sha256RsaOaep(server_cert, client_cert, client_key, mode), TransportLimits()
        )
        self.sender = SecureConnection(
            SecurityPolicyAes128Sha256RsaOaep(client_cert, server_cert, server_key, mode), TransportLimits()
        )
        self.stale_sender = SecureConnection(
            SecurityPolicyAes128Sha256RsaOaep(client_cert, server_cert, server_key, mode), TransportLimits()
        )
        self.epoch = 0
        self.next_sequence = 1
        self._instrument_receiver()
        self._issue_channel()

    def _instrument_receiver(self) -> None:
        crypto = self.receiver.security_policy.symmetric_cryptography
        original_verify = crypto.verify

        def verify(data: bytes, signature: bytes) -> None:
            slot = "prev" if crypto._use_prev_key else "current"
            try:
                original_verify(data, signature)
            except Exception:
                self.report.key_usage.append(KeyUse(self.epoch, slot, False))
                raise
            self.report.key_usage.append(KeyUse(self.epoch, slot, True))

        crypto.verify = verify
        original_revolve = self.receiver.revolve_tokens

        def revolve_tokens() -> None:
            original_revolve()
            self.epoch += 1

        self.receiver.revolve_tokens = revolve_tokens

    def _issue_channel(self) -> None:
        request = SimpleNamespace(
            ClientNonce=CLIENT_NONCE_1,
            RequestedLifetime=TOKEN_LIFETIME_MS,
            RequestType=ua.SecurityTokenRequestType.Issue,
        )
        result = self.sender.open(request, _ChannelIds())
        self.server_nonce_1 = result.ServerNonce
        self.token_1 = result.SecurityToken.TokenId
        self.receiver.set_channel(result, ua.SecurityTokenRequestType.Issue, CLIENT_NONCE_1)
        self.stale_sender.security_policy.make_local_symmetric_key(CLIENT_NONCE_1, self.server_nonce_1)

    def renew(self) -> None:
        request = SimpleNamespace(
            ClientNonce=CLIENT_NONCE_2,
            RequestedLifetime=TOKEN_LIFETIME_MS,
            RequestType=ua.SecurityTokenRequestType.Renew,
        )
        result = self.sender.open(request, _ChannelIds())
        self.server_nonce_2 = result.ServerNonce
        self.token_2 = result.SecurityToken.TokenId
        self.receiver.set_channel(result, ua.SecurityTokenRequestType.Renew, CLIENT_NONCE_2)
        self.sender.revolve_tokens()

    def expire_prev_token(self) -> None:
        self.receiver.prev_security_token.CreatedAt = datetime.now(UTC) - timedelta(milliseconds=2 * TOKEN_LIFETIME_MS)

    def expected_sequence(self) -> int:
        return (self.receiver._peer_sequence_number or 0) + 1

    def receive_state(self) -> tuple[int | None, int, int]:
        return (
            self.receiver._peer_sequence_number,
            len(self.receiver._incoming_parts),
            self.receiver._incoming_size,
        )

    def emit_chunks(
        self,
        conn: SecureConnection,
        body: bytes,
        *,
        token_id: int,
        request_id: int,
        channel_id: int = CHANNEL_ID,
        sequence: int | None = None,
        max_chunk_size: int = 65536,
    ) -> list[bytes]:
        chunks = MessageChunk.message_to_chunks(
            conn.security_policy,
            body,
            max_chunk_size,
            message_type=ua.MessageType.SecureMessage,
            channel_id=channel_id,
            request_id=request_id,
            token_id=token_id,
        )
        raw_chunks = []
        for chunk in chunks:
            if sequence is None:
                chunk.SequenceHeader.SequenceNumber = self.next_sequence
                self.next_sequence += 1
            else:
                chunk.SequenceHeader.SequenceNumber = sequence
                sequence += 1
            raw_chunks.append(chunk.to_binary())
        return raw_chunks

    def emit(
        self,
        conn: SecureConnection,
        body: bytes,
        *,
        token_id: int,
        request_id: int,
        channel_id: int = CHANNEL_ID,
        sequence: int | None = None,
        max_chunk_size: int = 65536,
    ) -> bytes:
        return b"".join(
            self.emit_chunks(
                conn,
                body,
                token_id=token_id,
                request_id=request_id,
                channel_id=channel_id,
                sequence=sequence,
                max_chunk_size=max_chunk_size,
            )
        )

    def feed(self, raw: bytes) -> ua.Message | None:
        buf = ua.utils.Buffer(raw)
        header = header_from_binary(buf)
        message = self.receiver.receive_from_header_and_body(header, buf)
        if isinstance(message, ua.Message):
            body = message.body()
            self.report.delivered.append(body.read(len(body)))
        return message

    def feed_rejected(self, raw: bytes, label: str, expected: type[Exception], match: str | None = None) -> None:
        state = self.receive_state()
        with pytest.raises(expected, match=match) as excinfo:
            self.feed(raw)
        self.report.rejections.append((label, str(excinfo.value)))
        assert self.receive_state() == state

    def naive_receiver(self) -> NaiveTokenIdKeyReceiver:
        return NaiveTokenIdKeyReceiver(
            {
                self.token_1: _receiving_crypto(CLIENT_NONCE_1, self.server_nonce_1),
                self.token_2: _receiving_crypto(CLIENT_NONCE_2, self.server_nonce_2),
            }
        )

    def drive_through_renewal(self) -> None:
        self.feed(self.emit(self.sender, b"gen1-request", token_id=self.token_1, request_id=1))
        self.renew()
        self.feed(self.emit(self.sender, b"gen2-first", token_id=self.token_2, request_id=2))


def test_current_token_message_is_delivered_before_renewal() -> None:
    h = RenewalHarness()
    raw = h.emit(h.sender, b"first-gen1", token_id=h.token_1, request_id=1)
    assert h.feed(raw) is not None
    assert h.report.delivered == [b"first-gen1"]
    assert h.report.successful_slots() == ["epoch0:current"]


def test_next_token_chunk_triggers_revolve_and_is_delivered() -> None:
    h = RenewalHarness()
    h.feed(h.emit(h.sender, b"m1", token_id=h.token_1, request_id=1))
    h.renew()
    assert h.feed(h.emit(h.sender, b"m2", token_id=h.token_2, request_id=2)) is not None
    assert h.receiver.security_token.TokenId == h.token_2
    assert h.receiver.prev_security_token.TokenId == h.token_1
    assert h.epoch == 1
    assert h.report.delivered == [b"m1", b"m2"]
    assert h.report.successful_slots() == ["epoch0:current", "epoch1:current"]


def test_in_flight_previous_token_packet_is_accepted_within_window() -> None:
    h = RenewalHarness()
    h.drive_through_renewal()
    raw = h.emit(h.stale_sender, b"delayed-old", token_id=h.token_1, request_id=3)
    assert h.feed(raw) is not None
    assert h.report.delivered == [b"gen1-request", b"gen2-first", b"delayed-old"]
    assert h.report.successful_slots() == ["epoch0:current", "epoch1:current", "epoch1:prev"]


def test_expired_previous_token_packet_is_rejected_without_advancing_state() -> None:
    h = RenewalHarness()
    h.drive_through_renewal()
    h.expire_prev_token()
    raw = h.emit(h.stale_sender, b"too-late", token_id=h.token_1, request_id=3, sequence=h.expected_sequence())
    h.feed_rejected(raw, "expired-prev-token", ua.UaError, "timed out")
    assert h.report.delivered == [b"gen1-request", b"gen2-first"]


def test_unknown_token_id_is_rejected() -> None:
    h = RenewalHarness()
    h.drive_through_renewal()
    raw = h.emit(h.sender, b"intruder", token_id=UNKNOWN_TOKEN_ID, request_id=3, sequence=h.expected_sequence())
    h.feed_rejected(raw, "unknown-token", ua.UaError, "Invalid security token id")
    assert h.report.delivered == [b"gen1-request", b"gen2-first"]


def test_other_channel_packet_is_rejected() -> None:
    h = RenewalHarness()
    h.drive_through_renewal()
    raw = h.emit(
        h.sender,
        b"cross-channel",
        token_id=h.token_2,
        request_id=3,
        channel_id=OTHER_CHANNEL_ID,
        sequence=h.expected_sequence(),
    )
    h.feed_rejected(raw, "wrong-channel", ua.UaError, "Wrong channel id")
    assert h.report.delivered == [b"gen1-request", b"gen2-first"]


def test_corrupted_signature_is_rejected_without_advancing_state() -> None:
    h = RenewalHarness()
    h.drive_through_renewal()
    raw = bytearray(h.emit(h.sender, b"tampered", token_id=h.token_2, request_id=3, sequence=h.expected_sequence()))
    raw[-1] ^= 0xFF
    h.feed_rejected(bytes(raw), "bad-signature", InvalidSignature)
    assert h.report.delivered == [b"gen1-request", b"gen2-first"]


def test_token_change_does_not_allow_sequence_reset() -> None:
    h = RenewalHarness()
    h.drive_through_renewal()
    reset = h.emit(h.sender, b"reset", token_id=h.token_2, request_id=3, sequence=1)
    h.feed_rejected(reset, "sequence-reset", ua.UaError, "wrong sequence")
    gap = h.emit(h.sender, b"gap", token_id=h.token_2, request_id=3, sequence=h.expected_sequence() + 5)
    h.feed_rejected(gap, "sequence-gap", ua.UaError, "wrong sequence")
    raw = h.emit(h.sender, b"gen2-next", token_id=h.token_2, request_id=3)
    assert h.feed(raw) is not None
    assert h.report.delivered == [b"gen1-request", b"gen2-first", b"gen2-next"]


def test_in_flight_request_id_mismatch_is_rejected_and_assembly_survives() -> None:
    h = RenewalHarness()
    h.drive_through_renewal()
    parts = h.emit_chunks(h.sender, b"assembled-request-body", token_id=h.token_2, request_id=100, max_chunk_size=64)
    assert len(parts) >= 2
    assert h.feed(parts[0]) is None
    assert h.receive_state()[1] == 1
    intruder = h.emit(h.sender, b"other-request", token_id=h.token_2, request_id=101, sequence=h.expected_sequence())
    h.feed_rejected(intruder, "request-id-mismatch", ua.UaError, "Wrong request id")
    result = None
    for part in parts[1:]:
        result = h.feed(part)
    assert result is not None
    assert h.report.delivered == [b"gen1-request", b"gen2-first", b"assembled-request-body"]


def test_renewal_interleaved_flow_report(tmp_path: Path) -> None:
    h = RenewalHarness()
    h.drive_through_renewal()
    h.feed(h.emit(h.stale_sender, b"in-flight-old", token_id=h.token_1, request_id=3))
    h.feed_rejected(
        h.emit(h.sender, b"bad-token", token_id=UNKNOWN_TOKEN_ID, request_id=4, sequence=h.expected_sequence()),
        "unknown-token",
        ua.UaError,
        "Invalid security token id",
    )
    h.feed_rejected(
        h.emit(
            h.sender,
            b"wrong-channel",
            token_id=h.token_2,
            request_id=4,
            channel_id=OTHER_CHANNEL_ID,
            sequence=h.expected_sequence(),
        ),
        "wrong-channel",
        ua.UaError,
        "Wrong channel id",
    )
    corrupted = bytearray(
        h.emit(h.sender, b"corrupted", token_id=h.token_2, request_id=4, sequence=h.expected_sequence())
    )
    corrupted[-1] ^= 0xFF
    h.feed_rejected(bytes(corrupted), "bad-signature", InvalidSignature)
    h.expire_prev_token()
    h.feed_rejected(
        h.emit(h.stale_sender, b"expired-old", token_id=h.token_1, request_id=4, sequence=h.expected_sequence()),
        "expired-prev-token",
        ua.UaError,
        "timed out",
    )
    h.feed_rejected(
        h.emit(h.sender, b"seq-reset", token_id=h.token_2, request_id=4, sequence=1),
        "sequence-reset",
        ua.UaError,
        "wrong sequence",
    )
    parts = h.emit_chunks(h.sender, b"assembled-request-body", token_id=h.token_2, request_id=100, max_chunk_size=64)
    assert h.feed(parts[0]) is None
    h.feed_rejected(
        h.emit(h.sender, b"other-request", token_id=h.token_2, request_id=101, sequence=h.expected_sequence()),
        "request-id-mismatch",
        ua.UaError,
        "Wrong request id",
    )
    for part in parts[1:]:
        h.feed(part)
    h.feed(h.emit(h.sender, b"gen2-final", token_id=h.token_2, request_id=5))

    assert h.report.delivered == [
        b"gen1-request",
        b"gen2-first",
        b"in-flight-old",
        b"assembled-request-body",
        b"gen2-final",
    ]
    assert [label for label, _ in h.report.rejections] == [
        "unknown-token",
        "wrong-channel",
        "bad-signature",
        "expired-prev-token",
        "sequence-reset",
        "request-id-mismatch",
    ]
    successful = h.report.successful_slots()
    assert successful[0] == "epoch0:current"
    assert successful.count("epoch1:prev") == 1
    assert successful[-1] == "epoch1:current"
    assert h.epoch == 1
    assert all(not slot.startswith("epoch0") for slot in successful[1:])

    artifact = tmp_path / "renewal_report.json"
    artifact.write_text(
        json.dumps(
            {
                "key_usage": [
                    f"epoch{use.epoch}:{use.slot}:{'ok' if use.verified else 'fail'}" for use in h.report.key_usage
                ],
                "delivered": [body.decode() for body in h.report.delivered],
                "rejections": h.report.rejections,
            },
            indent=2,
        )
    )


def test_naive_token_id_key_selection_produces_locatable_counterexample() -> None:
    h = RenewalHarness()
    h.feed(h.emit(h.sender, b"gen1-request", token_id=h.token_1, request_id=1))
    h.renew()
    current = h.emit(h.sender, b"gen2-first", token_id=h.token_2, request_id=2)
    h.feed(current)
    h.expire_prev_token()
    stale = h.emit(
        h.stale_sender, b"expired-in-flight", token_id=h.token_1, request_id=3, sequence=h.expected_sequence()
    )
    h.feed_rejected(stale, "expired-prev-token", ua.UaError, "timed out")

    naive = h.naive_receiver()
    assert naive.feed(current)
    assert naive.feed(stale)
    assert naive.delivered == [b"gen2-first", b"expired-in-flight"]
    assert h.report.delivered == [b"gen1-request", b"gen2-first"]

    h.report.counterexamples.append(
        f"packet 'expired-in-flight' (token {h.token_1}, channel {CHANNEL_ID}): secure receiver rejected it "
        "as timed out, naive token-id key selection delivered it to the application"
    )
    assert h.report.counterexamples == [
        f"packet 'expired-in-flight' (token {h.token_1}, channel {CHANNEL_ID}): secure receiver rejected it "
        "as timed out, naive token-id key selection delivered it to the application"
    ]
