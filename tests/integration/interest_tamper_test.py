import asyncio as aio
from hashlib import sha256

from ndn import app as ndn_app
from ndn import encoding as enc
from ndn import security as sec
from ndn import types
from ndn.encoding import ndn_format_0_3 as fmt
from ndn.transport.dummy_face import DummyFace


# ---------------------------------------------------------------------------
# Independent wire helpers.
#
# These re-implement VAR-NUMBER handling, TLV walking, and the
# ParametersSha256DigestComponent coverage (ApplicationParameters .. end of
# the Interest value, per NDN Packet Format v0.3) from scratch.  They
# deliberately do NOT reuse ndn.encoding parsing helpers: if the library's
# digest-coverage offsets were wrong, the encoder and the receiver would
# still agree with each other, while this independent recomputation would
# catch the discrepancy.
# ---------------------------------------------------------------------------

INTEREST_TLV = 0x05
NAME_TLV = 0x07
PARAMS_SHA256_COMPONENT = 0x02
APP_PARAMS_TLV = 0x24
SIG_INFO_TLV = 0x2C
# Even type number => non-critical per NDN TLV criticality rules; an
# implementation must silently ignore such unknown elements.
NON_CRITICAL_EXT_TLV = 0x80
CRITICAL_EXT_TLV = 0x81


def _read_varnum(buf, offset):
    first = buf[offset]
    if first < 0xFD:
        return first, 1
    if first == 0xFD:
        return int.from_bytes(buf[offset + 1:offset + 3], 'big'), 3
    if first == 0xFE:
        return int.from_bytes(buf[offset + 1:offset + 5], 'big'), 5
    return int.from_bytes(buf[offset + 1:offset + 9], 'big'), 9


def _write_varnum(num):
    if num < 0xFD:
        return bytes([num])
    if num <= 0xFFFF:
        return b'\xFD' + num.to_bytes(2, 'big')
    if num <= 0xFFFFFFFF:
        return b'\xFE' + num.to_bytes(4, 'big')
    return b'\xFF' + num.to_bytes(8, 'big')


def _read_tlv(buf, offset):
    """Return (type, value_start, tlv_end) for the TLV at offset."""
    typ, sz_t = _read_varnum(buf, offset)
    length, sz_l = _read_varnum(buf, offset + sz_t)
    value_start = offset + sz_t + sz_l
    return typ, value_start, value_start + length


def _interest_value_range(wire):
    typ, value_start, value_end = _read_tlv(wire, 0)
    assert typ == INTEREST_TLV
    assert value_end == len(wire)
    return value_start, value_end


def _find_tlv(wire, start, end, wanted):
    offset = start
    while offset < end:
        typ, value_start, tlv_end = _read_tlv(wire, offset)
        if typ == wanted:
            return offset, value_start, tlv_end
        offset = tlv_end
    raise AssertionError(f'TLV type {wanted:#x} not found')


def _name_digest_span(wire):
    """(offset, length) of the ParametersSha256DigestComponent value."""
    start, end = _interest_value_range(wire)
    _, name_value, name_end = _find_tlv(wire, start, end, NAME_TLV)
    offset = name_value
    while offset < name_end:
        typ, value_start, comp_end = _read_tlv(wire, offset)
        if typ == PARAMS_SHA256_COMPONENT:
            assert comp_end - value_start == 32
            return value_start, 32
        offset = comp_end
    raise AssertionError('ParametersSha256DigestComponent not found')


def _independent_params_digest(wire):
    """SHA-256 over ApplicationParameters .. end of the Interest value."""
    start, end = _interest_value_range(wire)
    app_params_btl, _, _ = _find_tlv(wire, start, end, APP_PARAMS_TLV)
    return sha256(bytes(wire[app_params_btl:end])).digest()


def _digest_binding_ok(wire):
    """Independently recompute the name<->AppParams digest binding."""
    offset, length = _name_digest_span(wire)
    return bytes(wire[offset:offset + length]) == _independent_params_digest(wire)


# ---------------------------------------------------------------------------
# Single-field wire mutations.  Each takes a valid encoder-produced wire and
# changes exactly one field, keeping every other byte (and all lengths,
# unless the mutation is the field itself) intact.
# ---------------------------------------------------------------------------

def _flip_byte(wire, offset):
    mutated = bytearray(wire)
    mutated[offset] ^= 0xFF
    return bytes(mutated)


def _tamper_app_params(wire):
    start, end = _interest_value_range(wire)
    _, value_start, value_end = _find_tlv(wire, start, end, APP_PARAMS_TLV)
    assert value_end > value_start
    return _flip_byte(wire, value_start)


def _tamper_digest_component(wire):
    offset, _ = _name_digest_span(wire)
    return _flip_byte(wire, offset)


def _tamper_sig_info(wire):
    start, end = _interest_value_range(wire)
    _, _, value_end = _find_tlv(wire, start, end, SIG_INFO_TLV)
    return _flip_byte(wire, value_end - 1)


def _rewrap(new_value):
    return bytes([INTEREST_TLV]) + _write_varnum(len(new_value)) + new_value


def _append_trailing_tlv(wire, typ=NON_CRITICAL_EXT_TLV):
    start, end = _interest_value_range(wire)
    return _rewrap(bytes(wire[start:end]) + bytes([typ, 0x01, 0xAA]))


def _insert_non_critical_extension(wire):
    """Insert an unknown non-critical TLV right before ApplicationParameters."""
    start, end = _interest_value_range(wire)
    app_params_btl, _, _ = _find_tlv(wire, start, end, APP_PARAMS_TLV)
    ext = bytes([NON_CRITICAL_EXT_TLV, 0x01, 0xBB])
    return _rewrap(bytes(wire[start:app_params_btl]) + ext + bytes(wire[app_params_btl:end]))


# ---------------------------------------------------------------------------
# Positive wires produced by the real encoder.
# ---------------------------------------------------------------------------

def _make_signed(name, app_param):
    param = fmt.InterestParam(nonce=0x01020304, lifetime=4000)
    signer = sec.DigestSha256Signer(for_interest=True)
    return bytes(fmt.make_interest(name, param, app_param=app_param, signer=signer))


def _make_unsigned(name, app_param):
    param = fmt.InterestParam(nonce=0x05060708, lifetime=4000)
    return bytes(fmt.make_interest(name, param, app_param=app_param, signer=None))


# ---------------------------------------------------------------------------
# Receive-chain harness with callback counters.
# ---------------------------------------------------------------------------

class ReceiveHarness:
    """Feeds wires through the real receive chain and counts callbacks."""

    def __init__(self):
        self.face = DummyFace(lambda _face: None)
        self.app = ndn_app.NDNApp(self.face)
        self.handler_calls = []
        self.validator_calls = []

    def attach(self, prefix, with_validator=True):
        def on_interest(name, app_param, _reply, _context):
            self.handler_calls.append(
                (enc.Name.to_str(name),
                 bytes(app_param) if app_param is not None else None))
        validator = self._validator if with_validator else None
        self.app.attach_handler(prefix, on_interest, validator=validator)

    async def _validator(self, name, _sig, _context):
        self.validator_calls.append(enc.Name.to_str(name))
        return types.ValidResult.PASS

    async def feed(self, wire):
        await self.face.input_packet(wire)
        # _on_interest dispatches via aio.create_task; let the task run.
        await aio.sleep(0.05)


def test_independent_digest_recomputation():
    """The independent digest check must accept valid wires, detect every
    single-field tamper, and still accept unknown non-critical extensions."""
    signed = _make_signed('/tamper/signed', b'\x01\x02\x03')
    unsigned = _make_unsigned('/tamper/unsigned', b'\x04\x05\x06')
    empty = _make_signed('/tamper/empty', b'')

    for valid in (signed, unsigned, empty):
        assert _digest_binding_ok(valid)

    for tamper in (_tamper_app_params, _tamper_digest_component,
                   _tamper_sig_info, _append_trailing_tlv):
        assert not _digest_binding_ok(tamper(signed))
    for tamper in (_tamper_app_params, _tamper_digest_component,
                   _append_trailing_tlv):
        assert not _digest_binding_ok(tamper(unsigned))

    # An unknown non-critical extension before ApplicationParameters is
    # outside the digest coverage and must not break the binding.
    assert _digest_binding_ok(_insert_non_critical_extension(signed))
    assert _digest_binding_ok(_insert_non_critical_extension(unsigned))


def test_signed_interest_dispatches():
    async def main():
        harness = ReceiveHarness()
        harness.attach('/tamper/signed')
        wire = _make_signed('/tamper/signed', b'\x01\x02\x03')
        await harness.feed(wire)
        assert harness.validator_calls == ['/tamper/signed/params-sha256='
                                           + _name_digest_span_hex(wire)]
        assert len(harness.handler_calls) == 1
        name, app_param = harness.handler_calls[0]
        assert enc.Name.from_str(name)[:-1] == enc.Name.from_str('/tamper/signed')
        assert app_param == b'\x01\x02\x03'
    aio.run(main())


def _name_digest_span_hex(wire):
    offset, length = _name_digest_span(wire)
    return bytes(wire[offset:offset + length]).hex()


def test_signed_empty_app_params_dispatches():
    """A legitimate empty ApplicationParameters is protocol-valid."""
    async def main():
        harness = ReceiveHarness()
        harness.attach('/tamper/empty')
        await harness.feed(_make_signed('/tamper/empty', b''))
        assert len(harness.handler_calls) == 1
        assert harness.handler_calls[0][1] == b''
    aio.run(main())


def test_unsigned_app_params_dispatches_when_validator_admits():
    """Declared policy: the validator may admit unsigned parameterized
    Interests; the digest binding is still enforced first."""
    async def main():
        harness = ReceiveHarness()
        harness.attach('/tamper/unsigned')
        await harness.feed(_make_unsigned('/tamper/unsigned', b'\x04\x05\x06'))
        assert len(harness.validator_calls) == 1
        assert len(harness.handler_calls) == 1
        assert harness.handler_calls[0][1] == b'\x04\x05\x06'
    aio.run(main())


def test_plain_unsigned_interest_needs_no_validator():
    """Declared policy: Interests without AppParams and SignatureInfo are
    dispatched directly, without a validator."""
    async def main():
        harness = ReceiveHarness()
        harness.attach('/tamper/plain', with_validator=False)
        await harness.feed(_make_unsigned('/tamper/plain', None))
        assert harness.validator_calls == []
        assert harness.handler_calls == [('/tamper/plain', None)]
    aio.run(main())


def test_unknown_non_critical_extension_ignored():
    """Unknown non-critical extensions must be ignored per protocol, not
    blanket-rejected."""
    async def main():
        harness = ReceiveHarness()
        harness.attach('/tamper/ext')
        wire = _insert_non_critical_extension(_make_signed('/tamper/ext', b'\x07'))
        await harness.feed(wire)
        assert len(harness.handler_calls) == 1
        assert harness.handler_calls[0][1] == b'\x07'
    aio.run(main())


def _assert_dropped_then_valid(tampered, valid, expected_param):
    """Feed a tampered wire, prove neither validator nor handler ran, then
    prove the route is still alive by feeding the valid wire."""
    async def main():
        harness = ReceiveHarness()
        harness.attach('/tamper/signed')
        harness.attach('/tamper/unsigned')
        await harness.feed(tampered)
        assert harness.handler_calls == []
        assert harness.validator_calls == []
        await harness.feed(valid)
        assert len(harness.validator_calls) == 1
        assert len(harness.handler_calls) == 1
        assert harness.handler_calls[0][1] == expected_param
    aio.run(main())


def test_signed_tampered_app_params_dropped():
    valid = _make_signed('/tamper/signed', b'\x01\x02\x03')
    _assert_dropped_then_valid(_tamper_app_params(valid), valid, b'\x01\x02\x03')


def test_signed_tampered_digest_component_dropped():
    valid = _make_signed('/tamper/signed', b'\x01\x02\x03')
    _assert_dropped_then_valid(_tamper_digest_component(valid), valid, b'\x01\x02\x03')


def test_signed_tampered_sig_info_dropped():
    valid = _make_signed('/tamper/signed', b'\x01\x02\x03')
    _assert_dropped_then_valid(_tamper_sig_info(valid), valid, b'\x01\x02\x03')


def test_signed_trailing_tlv_dropped():
    valid = _make_signed('/tamper/signed', b'\x01\x02\x03')
    # A non-critical trailer reaches the digest check; a critical one is
    # already rejected at parse time.  Neither may reach the handler.
    async def main():
        harness = ReceiveHarness()
        harness.attach('/tamper/signed')
        await harness.feed(_append_trailing_tlv(valid, NON_CRITICAL_EXT_TLV))
        await harness.feed(_append_trailing_tlv(valid, CRITICAL_EXT_TLV))
        assert harness.handler_calls == []
        assert harness.validator_calls == []
        await harness.feed(valid)
        assert len(harness.handler_calls) == 1
    aio.run(main())


def test_unsigned_tampered_app_params_dropped():
    valid = _make_unsigned('/tamper/unsigned', b'\x04\x05\x06')
    _assert_dropped_then_valid(_tamper_app_params(valid), valid, b'\x04\x05\x06')


def test_unsigned_tampered_digest_component_dropped():
    valid = _make_unsigned('/tamper/unsigned', b'\x04\x05\x06')
    _assert_dropped_then_valid(_tamper_digest_component(valid), valid, b'\x04\x05\x06')


def test_unsigned_trailing_tlv_dropped():
    valid = _make_unsigned('/tamper/unsigned', b'\x04\x05\x06')
    _assert_dropped_then_valid(_append_trailing_tlv(valid), valid, b'\x04\x05\x06')


def test_signed_interest_without_validator_dropped():
    """Declared policy: signed Interests are dropped when the route has no
    validator, even if the digest binding is intact."""
    async def main():
        harness = ReceiveHarness()
        harness.attach('/tamper/novalidator', with_validator=False)
        await harness.feed(_make_signed('/tamper/novalidator', b'\x01'))
        assert harness.handler_calls == []
        # The same route still accepts plain unsigned Interests.
        await harness.feed(_make_unsigned('/tamper/novalidator', None))
        assert harness.handler_calls == [('/tamper/novalidator', None)]
    aio.run(main())


def test_unsigned_app_params_without_validator_dropped():
    """Declared policy: unsigned Interests with AppParams require a
    validator; without one they are dropped."""
    async def main():
        harness = ReceiveHarness()
        harness.attach('/tamper/novalidator', with_validator=False)
        await harness.feed(_make_unsigned('/tamper/novalidator', b'\x01'))
        assert harness.handler_calls == []
        await harness.feed(_make_unsigned('/tamper/novalidator', None))
        assert harness.handler_calls == [('/tamper/novalidator', None)]
    aio.run(main())
