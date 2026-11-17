import asyncio as aio
from contextlib import suppress

import pytest

from ndn import app as ndn_app
from ndn import encoding as enc
from ndn import security as sec
from ndn import types
from ndn.app_support import replay_guard as rg
from ndn.encoding import ndn_format_0_3 as fmt
from ndn.encoding.tlv_model import tlv_encode
from ndn.transport.dummy_face import DummyFace

KEY_A = b'fixed-key-for-signer-a-0123456789'
KEY_B = b'fixed-key-for-signer-b-0123456789'
KEY_NAME_A = '/control/KEY/a'
KEY_NAME_B = '/control/KEY/b'


class Clock:
    def __init__(self, now: int):
        self.now = now

    def __call__(self) -> int:
        return self.now


def make_signed_interest(name: str, key_name: str, key: bytes, *,
                         app_param: bytes = b'do-something',
                         sig_time: int | None = None,
                         sig_seq: int | None = None,
                         sig_nonce: int | None = None,
                         lifetime: int = 4000,
                         signer: sec.HmacSha256Signer | None = None) -> bytes:
    """Build a wire Interest signed by *key*, with explicit freshness fields."""
    if signer is None:
        signer = sec.HmacSha256Signer(key_name, key, with_signature_time=False)
    signer.with_signature_time = False

    value = fmt.InterestPacketValue(
        name=name,
        can_be_prefix=False,
        must_be_fresh=False,
        nonce=1,
        lifetime=lifetime,
        application_parameters=app_param,
    )
    sig_info = fmt.SignatureInfo()
    signer.write_signature_info(sig_info)
    sig_info.signature_time = sig_time
    sig_info.signature_seq_num = sig_seq
    sig_info.signature_nonce = sig_nonce
    value.signature_info = sig_info

    markers = {
        '##signer': signer,
        '##need_digest': value.application_parameters is not None,
        '##_digest_cover_start_field': '_digest_cover_start',
        '##_digest_cover_end_field': '_digest_cover_end',
    }
    encoded = tlv_encode(value, markers=markers)
    vlen = len(encoded)
    if vlen < 253:
        header = bytes([0x05, vlen])
    else:
        header = b'\x05\xfd' + vlen.to_bytes(2, 'big')
    return header + bytes(encoded)


class Harness:
    """In-memory Face harness with fixed keys and a controllable clock."""

    def __init__(self, *, max_age=60_000, retention=None, clock=None,
                 max_entries=4096, max_signers=1024):
        self.face = None
        self.app = None
        self.clock = clock
        self.guard = rg.ReplayGuard(
            max_age=max_age,
            retention=retention,
            clock=clock,
            max_entries=max_entries,
            max_signers=max_signers,
        )
        self.handled = 0
        self.seen = []
        self.raise_in_handler = False
        self.auth_gate: aio.Event | None = None
        self.auth_entered = 0

    async def start(self):
        self.face = DummyFace(lambda _face: aio.Event().wait())
        self.app = ndn_app.NDNApp(self.face)
        self.face.app = self.app

        @self.guard.route(self.app, '/control', self._authenticate)
        def on_control(name, app_param, reply, context):
            self.handled += 1
            self.seen.append((enc.Name.to_str(name),
                              bytes(app_param) if app_param else None))
            if self.raise_in_handler:
                raise RuntimeError('handler failed')
            reply(self.app.make_data(name, b'ok', signer=sec.NullSigner()))

        # Opening the face after route attachment avoids sending a real
        # prefix registration command into the dummy output buffer.
        await self.face.open()

    async def stop(self):
        if self.face:
            self.face.shutdown()

    async def _authenticate(self, name, sig, context):
        if self.auth_gate is not None:
            self.auth_entered += 1
            await self.auth_gate.wait()
        info = sig.signature_info
        if info is None or info.key_locator is None or not info.key_locator.name:
            return types.ValidResult.FAIL
        key_name = enc.Name.to_str(info.key_locator.name)
        if key_name == KEY_NAME_A:
            return await sec.HmacChecker.from_key(KEY_NAME_A, KEY_A)(name, sig, context)
        if key_name == KEY_NAME_B:
            return await sec.HmacChecker.from_key(KEY_NAME_B, KEY_B)(name, sig, context)
        return types.ValidResult.FAIL

    async def inject(self, packet: bytes):
        await self.face.input_packet(packet)

    async def settle(self, rounds: int = 20):
        for _ in range(rounds):
            await aio.sleep(0.002)


def run(coro):
    return aio.run(coro)


async def with_harness(h: Harness, body):
    await h.start()
    try:
        await body()
    finally:
        await h.stop()


def test_original_and_replay_only_enter_handler_once():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock)

    async def body():
        wire = make_signed_interest('/control/do', KEY_NAME_A, KEY_A,
                                    sig_time=clock.now - 1000)
        await h.inject(wire)
        await h.inject(wire)
        await h.settle()

    run(with_harness(h, body))
    assert h.handled == 1
    assert h.guard.record_count == 1


def test_parallel_identical_requests_admit_only_one():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock)

    async def body():
        wire = make_signed_interest('/control/parallel', KEY_NAME_A, KEY_A,
                                    sig_time=clock.now)
        # All copies pass authentication before the first handler runs, so
        # the in-progress reservation is what rejects the duplicates.
        await aio.gather(*[h.inject(wire) for _ in range(8)])
        await h.settle()

    run(with_harness(h, body))
    assert h.handled == 1


def test_in_progress_reservation_blocks_duplicate_and_survives_commit():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock)
    wire = make_signed_interest('/control/do', KEY_NAME_A, KEY_A,
                                sig_time=clock.now, app_param=b'payload')
    name, _, app_param, sig = fmt.parse_interest(wire)

    token = h.guard.reserve(name, sig)
    assert token is not None
    # Another copy arrives after authentication but before the handler returns.
    assert h.guard.reserve(name, sig) is None
    assert token.commit()
    # A completed action stays replay-protected.
    assert h.guard.reserve(name, sig) is None
    assert not token.abort()


def test_aborted_reservation_can_be_retried():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock)
    wire = make_signed_interest('/control/do', KEY_NAME_A, KEY_A,
                                sig_time=clock.now)
    name, _, app_param, sig = fmt.parse_interest(wire)

    token = h.guard.reserve(name, sig)
    assert token is not None
    assert h.guard.reserve(name, sig) is None
    assert token.abort()
    assert h.guard.record_count == 0
    retry = h.guard.reserve(name, sig)
    assert retry is not None
    retry.commit()


def test_expired_signature_time_is_rejected_even_with_new_digest():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock, max_age=10_000)
    # A fresh digest does not replace freshness.
    fresh_payload = make_signed_interest('/control/do', KEY_NAME_A, KEY_A,
                                         app_param=b'never-seen-before',
                                         sig_time=clock.now - 10_001)
    name, _, app_param, sig = fmt.parse_interest(fresh_payload)
    assert app_param == b'never-seen-before'
    assert h.guard.reserve(name, sig) is None


def test_requests_authenticated_in_parallel_admit_one():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock)
    h.auth_gate = aio.Event()

    async def body():
        wire = make_signed_interest('/control/parallel', KEY_NAME_A, KEY_A,
                                    sig_seq=42)
        await aio.gather(*[h.inject(wire) for _ in range(4)])
        async with aio.timeout(1):
            while h.auth_entered < 4:
                await aio.sleep(0.001)
        # Every copy passed the signature check; only one may reserve.
        h.auth_gate.set()
        await h.settle()

    run(with_harness(h, body))
    assert h.handled == 1


def test_two_signers_same_sequence_are_independent():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock)

    async def body():
        a = make_signed_interest('/control/shared', KEY_NAME_A, KEY_A, sig_seq=7)
        b = make_signed_interest('/control/shared', KEY_NAME_B, KEY_B, sig_seq=7)
        await h.inject(a)
        await h.inject(b)
        await h.settle()
        await h.inject(a)
        await h.inject(b)
        await h.settle()

    run(with_harness(h, body))
    assert h.handled == 2
    assert h.guard.record_count == 0  # sequence-only requests use sequence state


def test_sequence_must_strictly_increase():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock)

    async def body():
        for seq in (10, 10, 9, 11):
            await h.inject(make_signed_interest('/control/seq', KEY_NAME_A, KEY_A,
                                                sig_seq=seq))
            await h.settle(5)

    run(with_harness(h, body))
    assert h.handled == 2  # seq 10 once, then seq 11


def test_nonce_is_one_time_per_signer():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock)

    async def body():
        wire = make_signed_interest('/control/nonce', KEY_NAME_A, KEY_A,
                                    sig_nonce=0x1234)
        await h.inject(wire)
        await h.inject(wire)
        # A different request reusing the same nonce is also a replay.
        reused = make_signed_interest('/control/other', KEY_NAME_A, KEY_A,
                                      sig_nonce=0x1234)
        await h.inject(reused)
        await h.settle()

    run(with_harness(h, body))
    assert h.handled == 1


def test_failed_authentication_does_not_consume_freshness():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock)

    async def body():
        # Same signed fields, but signed with the wrong key for the key name.
        bad = make_signed_interest('/control/do', KEY_NAME_A, KEY_B,
                                   sig_time=clock.now)
        await h.inject(bad)
        await h.settle()
        assert h.handled == 0
        assert len(h.guard) == 0

        good = make_signed_interest('/control/do', KEY_NAME_A, KEY_A,
                                    sig_time=clock.now)
        await h.inject(good)
        await h.inject(good)
        await h.settle()

    run(with_harness(h, body))
    assert h.handled == 1


def test_missing_freshness_fields_are_rejected():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock)

    async def body():
        unsigned_freshness = make_signed_interest('/control/do', KEY_NAME_A, KEY_A)
        await h.inject(unsigned_freshness)
        await h.settle()

    run(with_harness(h, body))
    assert h.handled == 0


def test_handler_exception_does_not_record_completion():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock)
    h.raise_in_handler = True

    async def body():
        wire = make_signed_interest('/control/do', KEY_NAME_A, KEY_A,
                                    sig_time=clock.now)
        await h.inject(wire)
        await h.settle()
        assert h.handled == 1
        assert h.guard.record_count == 0
        h.raise_in_handler = False
        await h.inject(wire)
        await h.settle()

    run(with_harness(h, body))
    assert h.handled == 2


def test_cancelled_validation_task_does_not_record_completion():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock)
    wire = make_signed_interest('/control/do', KEY_NAME_A, KEY_A, sig_time=clock.now)
    name, _, _, sig = fmt.parse_interest(wire)
    entered = aio.Event()

    async def start_validation_then_wait():
        validator = h.guard.validator(h._authenticate)
        context = {}
        assert await validator(name, sig, context) is types.ValidResult.PASS
        assert h.guard.record_count == 1
        entered.set()
        await aio.sleep(10)

    async def body():
        task = aio.create_task(start_validation_then_wait())
        await entered.wait()
        task.cancel()
        with suppress(aio.CancelledError):
            await task
        assert h.guard.record_count == 0

    run(with_harness(h, body))


def test_stale_and_future_timestamps_are_rejected():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock, max_age=30_000)

    async def body():
        stale = make_signed_interest('/control/stale', KEY_NAME_A, KEY_A,
                                     sig_time=clock.now - 30_001)
        future = make_signed_interest('/control/future', KEY_NAME_A, KEY_A,
                                      sig_time=clock.now + 60_000)
        edge = make_signed_interest('/control/edge', KEY_NAME_A, KEY_A,
                                    sig_time=clock.now - 30_000)
        await h.inject(stale)
        await h.inject(future)
        await h.inject(edge)
        await h.settle()

    run(with_harness(h, body))
    assert h.handled == 1
    assert h.seen[0][0].startswith('/control/edge')


def test_records_expire_with_the_signature_time():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock, max_age=10_000)

    async def body():
        wire = make_signed_interest('/control/do', KEY_NAME_A, KEY_A,
                                    sig_time=clock.now)
        await h.inject(wire)
        await h.settle()

    run(with_harness(h, body))
    assert h.handled == 1
    clock.now += 10_000
    assert h.guard.record_count == 1
    clock.now += 1
    assert h.guard.record_count == 0  # a replay now fails the freshness check


def test_bounds_reject_rather_than_evict():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock, max_entries=1)

    async def body():
        first = make_signed_interest('/control/a', KEY_NAME_A, KEY_A,
                                     sig_time=clock.now)
        second = make_signed_interest('/control/b', KEY_NAME_A, KEY_A,
                                      sig_time=clock.now)
        await h.inject(first)
        await h.inject(second)
        await h.settle()

    run(with_harness(h, body))
    assert h.handled == 1


def test_same_time_different_requests_are_not_replays():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock)

    async def body():
        # Both share the same signed millisecond from the same signer.  The
        # full name (including its parameter digest) distinguishes them.
        one = make_signed_interest('/control/do', KEY_NAME_A, KEY_A,
                                   app_param=b'payload-1', sig_time=clock.now)
        two = make_signed_interest('/control/do', KEY_NAME_A, KEY_A,
                                   app_param=b'payload-2', sig_time=clock.now)
        await h.inject(one)
        await h.inject(two)
        await h.inject(one)
        await h.settle()

    run(with_harness(h, body))
    assert h.handled == 2


def test_request_digest_is_binding_not_freshness():
    clock = Clock(1_700_000_000_000)
    h = Harness(clock=clock)

    async def body():
        one = make_signed_interest('/control/do', KEY_NAME_A, KEY_A,
                                   app_param=b'payload-1', sig_time=clock.now)
        two = make_signed_interest('/control/do', KEY_NAME_A, KEY_A,
                                   app_param=b'payload-2', sig_time=clock.now)
        await h.inject(one)
        await h.inject(two)
        await h.settle()
        await h.inject(one)
        await h.settle()

    run(with_harness(h, body))
    assert h.handled == 2
    assert sorted(p for _, p in h.seen) == [b'payload-1', b'payload-2']


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-x', '-q']))
