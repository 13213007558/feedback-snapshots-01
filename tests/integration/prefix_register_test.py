import asyncio as aio

import pytest

from ndn import app as ndn_app
from ndn import encoding as enc
from ndn import security as sec
from ndn import types
from ndn.app_support import nfd_mgmt
from ndn.encoding import ndn_format_0_3 as fmt
from ndn.encoding import ndnlp_v2 as ndnlp
from ndn.encoding.tlv_model import tlv_encode, tlv_parse
from ndn.transport.dummy_face import DummyFace
from ndn.transport.nfd_registerer import NfdRegister
from ndn.transport.prefix_registerer import ManagementOutcome


def _decode_command(interest):
    name, _, app_param, sig = fmt.parse_interest(interest)
    assert app_param == b''
    assert sig.signature_info.signature_type == fmt.SignatureType.DIGEST_SHA256
    assert enc.Component.get_type(name[-1]) == enc.Component.TYPE_PARAMETERS_SHA256
    cp = tlv_parse(nfd_mgmt.ControlParameters, enc.Component.get_value(name[4]))
    return name, cp.cp


def _response(data_name, params_name, status_code=200, status_text='OK', body=True):
    params = nfd_mgmt.ControlParametersValue(name=params_name) if body else None
    body = tlv_encode(nfd_mgmt.ControlResponse(
        status_code=status_code, status_text=status_text, body=params))
    content = bytes([0x65, len(body)]) + body
    return bytes(fmt.make_data(data_name, fmt.MetaInfo(), content, signer=sec.NullSigner()))


def _malformed(data_name, content=b'\x66\x00'):
    return bytes(fmt.make_data(data_name, fmt.MetaInfo(), content, signer=sec.NullSigner()))


class FakeLocalMgmt:
    """Fake local NFD management transport driven by a responder callback."""

    def __init__(self, face: DummyFace, responder):
        self.face = face
        self.responder = responder
        self.commands = []
        self._task = None

    async def _read_interest(self):
        async with aio.timeout(1):
            while True:
                buf = self.face.output_buf
                if buf:
                    _, typ_len = enc.parse_tl_num(buf)
                    size, size_len = enc.parse_tl_num(buf, typ_len)
                    total = typ_len + size_len + size
                    if len(buf) >= total:
                        packet, self.face.output_buf = bytes(buf[:total]), buf[total:]
                        return packet
                await aio.sleep(0.001)

    async def serve(self):
        while True:
            interest = await self._read_interest()
            name, params = _decode_command(interest)
            self.commands.append((interest, name, params))
            wire = self.responder(interest, name, params, len(self.commands))
            if wire is not None:
                await self.face.input_packet(wire)

    def start(self):
        self._task = aio.create_task(self.serve())

    async def stop(self):
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except aio.CancelledError:
                pass
            self._task = None


async def _run(responder, body, registerer=None, lifetime=200):
    face = DummyFace(lambda _face: aio.sleep(0))
    app = ndn_app.NDNApp(face, registerer=registerer or NfdRegister(lifetime=lifetime))
    face.callback = app._receive
    await face.open()
    fake = FakeLocalMgmt(face, responder)
    fake.start()
    try:
        return await body(app, fake)
    finally:
        await fake.stop()
        app.shutdown()


def _mode_response(mode):
    def responder(interest, name, params, _index):
        prefix = enc.Name.to_str(params.name)
        if mode == 'ok':
            return _response(name, prefix)
        if mode == 'shared_prefix':
            # A success packet that is only a prefix of this command and
            # describes a different registration.
            return _response(enc.Name.from_str('/localhost/nfd/rib/register'), '/audit/other')
        if mode == 'other_exact':
            other = nfd_mgmt.make_command_v2('rib', 'register', None, name='/audit/other')
            _, other_final = fmt.make_interest(
                other, fmt.InterestParam(lifetime=1000, nonce=1), b'',
                signer=sec.DigestSha256Signer(for_interest=True), need_final_name=True)
            return _response(other_final, '/audit/other')
        if mode == 'other_params':
            return _response(name, '/audit/other')
        if mode == 'rejected':
            return _response(name, prefix, 404, 'Not found')
        if mode == 'unknown':
            return _response(name, prefix, 299, 'Odd')
        if mode == 'no_status':
            return _response(name, prefix, None, None)
        if mode == 'malformed':
            return _malformed(name)
        if mode == 'nack':
            return ndnlp.make_network_nack(interest, ndnlp.NackReason.NO_ROUTE)
        if mode == 'timeout':
            return None
        raise AssertionError(mode)
    return responder


def test_interleaved_commands_keep_their_own_results():
    """Two registrations and one unregistration cannot borrow one another's success."""
    plan = [
        (('register', '/audit/a'), 'shared_prefix'),
        (('register', '/audit/b'), 'other_params'),
        (('unregister', '/audit/a'), 'rejected'),
    ]
    retry = [
        (('register', '/audit/a'), 'ok'),
        (('register', '/audit/b'), 'ok'),
        (('unregister', '/audit/a'), 'ok'),
    ]
    queues = {}
    for key, mode in plan + retry:
        queues.setdefault(key, []).append(mode)
    seen = {}

    def responder(interest, name, params, index):
        action = 'register' if enc.Name.to_str(name).startswith('/localhost/nfd/rib/register/') \
            else 'unregister'
        prefix = enc.Name.to_str(params.name)
        key = (action, prefix)
        mode = queues[key].pop(0)
        seen.setdefault(key, []).append(mode)
        return _mode_response(mode)(interest, name, params, index)

    async def body(app, fake):
        first = [
            aio.create_task(app.register('/audit/a')),
            aio.create_task(app.register('/audit/b')),
            aio.create_task(app.unregister('/audit/a')),
        ]
        r_a, r_b, r_unreg = await aio.gather(*first)

        assert (r_a.outcome, r_a.status_code) == (ManagementOutcome.NAME_MISMATCH, None)
        assert (r_b.outcome, r_b.status_code) == (ManagementOutcome.PARAMETER_MISMATCH, 200)
        assert (r_unreg.outcome, r_unreg.status_code) == (ManagementOutcome.REJECTED, 404)
        assert not r_a and not r_b and not r_unreg

        # Retries start from a clean slate: each is a fresh command and each
        # response is judged on its own.
        r_a2 = await app.register('/audit/a')
        r_b2 = await app.register('/audit/b')
        u_a2 = await app.unregister('/audit/a')
        assert r_a2.confirmed and r_b2.confirmed and u_a2.confirmed
        assert r_a2.status_code == 200 and u_a2.status_code == 200

        assert len(fake.commands) == 6
        assert seen == {
            ('register', '/audit/a'): ['shared_prefix', 'ok'],
            ('register', '/audit/b'): ['other_params', 'ok'],
            ('unregister', '/audit/a'): ['rejected', 'ok'],
        }
        for _, name, _ in fake.commands:
            assert enc.Component.get_type(name[-1]) == enc.Component.TYPE_PARAMETERS_SHA256
        for result in (r_a2, r_b2, u_a2):
            assert result.data_name == result.expected_name
        return r_a2

    result = aio.run(_run(responder, body))
    assert result.request_parameters['name'] == '/audit/a'
    assert result.request_digest is not None and len(result.request_digest) == 64


@pytest.mark.parametrize('mode, outcome', [
    ('shared_prefix', ManagementOutcome.NAME_MISMATCH),
    ('other_exact', ManagementOutcome.NAME_MISMATCH),
    ('other_params', ManagementOutcome.PARAMETER_MISMATCH),
    ('rejected', ManagementOutcome.REJECTED),
    ('unknown', ManagementOutcome.UNKNOWN_STATUS),
    ('no_status', ManagementOutcome.UNKNOWN_STATUS),
    ('malformed', ManagementOutcome.MALFORMED_RESPONSE),
    ('nack', ManagementOutcome.NACKED),
    ('timeout', ManagementOutcome.TIMEOUT),
])
def test_failure_kinds_are_preserved_and_retry_is_fresh(mode, outcome):
    script = [mode, 'ok']

    def responder(interest, name, params, _index):
        return _mode_response(script.pop(0))(interest, name, params, _index)

    async def body(app, fake):
        failed = await app.register('/audit/prefix')
        assert failed.outcome is outcome
        assert failed.command == 'rib/register'
        assert failed.name == '/audit/prefix'
        assert not failed
        if outcome is ManagementOutcome.REJECTED:
            assert failed.status_code == 404
        elif outcome is ManagementOutcome.NACKED:
            assert failed.nack_reason == ndnlp.NackReason.NO_ROUTE
        elif outcome is ManagementOutcome.UNKNOWN_STATUS:
            assert failed.status_code in (299, None)

        ok = await app.register('/audit/prefix')
        assert ok.confirmed and ok.status_code == 200
        assert ok.data_name == ok.expected_name
        assert len(fake.commands) == 2
        # Each attempt is a new signed Interest with a new timestamp.
        first, second = fake.commands
        assert first[1] != second[1]
        return failed

    aio.run(_run(responder, body))


def test_validator_policy_decides_and_is_not_cached():
    calls = []

    async def deny(name, sig, _context):
        calls.append(('deny', enc.Name.to_str(name)))
        return types.ValidResult.FAIL

    async def timeout(name, sig, _context):
        calls.append(('timeout', enc.Name.to_str(name)))
        return types.ValidResult.TIMEOUT

    async def allow(name, sig, _context):
        calls.append(('allow', enc.Name.to_str(name), sig.signature_info.signature_type))
        return types.ValidResult.PASS

    script = ['ok', 'ok', 'ok']

    def responder(interest, name, params, _index):
        return _mode_response(script.pop(0))(interest, name, params, _index)

    async def body(app, fake):
        denied = await app.register('/audit/prefix', validator=deny)
        assert denied.outcome is ManagementOutcome.VALIDATION_FAILED
        assert denied.validation_result is types.ValidResult.FAIL
        assert denied.status_code == 200
        assert not denied

        timed_out = await app.unregister('/audit/prefix', validator=timeout)
        assert timed_out.outcome is ManagementOutcome.VALIDATION_FAILED
        assert timed_out.validation_result is types.ValidResult.TIMEOUT

        allowed = await app.register('/audit/prefix', validator=allow)
        assert allowed.confirmed
        assert calls[-1][2] is fmt.SignatureType.NULL
        return allowed

    aio.run(_run(responder, body))
    assert [call[0] for call in calls] == ['deny', 'timeout', 'allow']


def test_unregister_requires_matching_success():
    script = ['rejected', 'other_params', 'ok']

    def responder(interest, name, params, _index):
        return _mode_response(script.pop(0))(interest, name, params, _index)

    async def body(app, fake):
        rejected = await app.unregister('/audit/prefix')
        assert rejected.command == 'rib/unregister'
        assert rejected.outcome is ManagementOutcome.REJECTED
        assert rejected.status_code == 404

        mismatched = await app.unregister('/audit/prefix')
        assert mismatched.outcome is ManagementOutcome.PARAMETER_MISMATCH
        assert mismatched.status_code == 200

        confirmed = await app.unregister('/audit/prefix')
        assert confirmed.confirmed
        assert confirmed.data_name == confirmed.expected_name
        assert len(fake.commands) == 3
        return confirmed

    aio.run(_run(responder, body))


def test_validator_exception_does_not_confirm():
    async def explode(_name, _sig, _context):
        raise RuntimeError('policy backend unavailable')

    async def body(app, fake):
        result = await app.register('/audit/prefix', validator=explode)
        assert result.outcome is ManagementOutcome.VALIDATION_FAILED
        assert result.validation_result is types.ValidResult.FAIL
        assert not result
        return result

    aio.run(_run(_mode_response('ok'), body))


def test_result_truth_and_comparison_semantics():
    async def body(app, fake):
        result = await app.register('/audit/prefix')
        assert result.confirmed
        assert result == True  # noqa: E712 - compatibility with the bool API
        assert result != False  # noqa: E712
        return result

    aio.run(_run(_mode_response('ok'), body))


def test_face_down_is_not_a_confirmation():
    face = DummyFace(lambda _face: aio.sleep(0))
    app = ndn_app.NDNApp(face, registerer=NfdRegister())
    with pytest.raises(types.NetworkError):
        aio.run(app.register('/audit/prefix'))
