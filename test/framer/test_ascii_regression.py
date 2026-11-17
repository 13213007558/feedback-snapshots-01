"""Independent regression tests for the Modbus ASCII framer.

This suite is self-contained: frames are handcrafted byte strings and the
LRC is recomputed with an independent implementation, so parsing, discard
and remaining-buffer behavior is verified without trusting the framer's
own helpers.

Covered contract:
    * frames start with ":" and end with the configurable delimiter
    * hexadecimal payload may be upper or lower case, encoding is upper
    * an odd number of hex nibbles rejects the frame
    * the LRC must match an independent two's-complement calculation
    * switching the delimiter changes encoding and decoding together
    * consecutive frames are consumed one by one, in order
    * a frame with an invalid character is rejected wholesale; the
      character is never silently ignored to recover another valid
      write request, and each rejection reports the exact number of
      consumed bytes (its position in the buffer)
"""

import pytest

from pymodbus.framer import FramerAscii
from pymodbus.pdu import DecodePDU
from pymodbus.pdu.device import ModbusControlBlock


def reference_lrc(data: bytes) -> int:
    """Independent LRC: two's complement of the plain byte sum."""
    return (-sum(data)) & 0xFF


def make_frame(body: bytes, *, lrc=None, end=b"\r\n", upper=True) -> bytes:
    """Handcraft an ASCII frame without using the framer implementation."""
    hex_body = body.hex()
    if upper:
        hex_body = hex_body.upper()
    check = reference_lrc(body) if lrc is None else lrc
    hex_lrc = f"{check:02X}" if upper else f"{check:02x}"
    return b":" + hex_body.encode() + hex_lrc.encode() + end


# Handcrafted write-single-register request: dev 1, func 6, address 0, value 10.
WRITE_BODY = bytes([0x01, 0x06, 0x00, 0x00, 0x00, 0x0A])
WRITE_PAYLOAD = WRITE_BODY[1:]
WRITE_FRAME = make_frame(WRITE_BODY)
# Handcrafted read-holding-registers request: dev 2, func 3, address 0x73, count 6.
READ_BODY = bytes([0x02, 0x03, 0x00, 0x73, 0x00, 0x06])
READ_PAYLOAD = READ_BODY[1:]
READ_FRAME = make_frame(READ_BODY)


@pytest.fixture(autouse=True)
def restore_delimiter():
    """Restore the global ASCII delimiter after every test."""
    yield
    ModbusControlBlock().Delimiter = b"\n"


@pytest.fixture(name="framer")
def prepare_framer():
    """Return a server-side ASCII framer."""
    return FramerAscii(DecodePDU(True))


class TestAsciiLRC:
    """LRC verified against an independent calculation."""

    @pytest.mark.parametrize(
        "body",
        [
            WRITE_BODY,
            READ_BODY,
            bytes([0x00]),
            bytes([0xFF]),
            bytes([0x12, 0x34, 0x23, 0x45, 0x34, 0x56, 0x45, 0x67]),
        ],
    )
    def test_compute_lrc_matches_reference(self, body):
        """Framer LRC equals the independent two's-complement sum."""
        assert FramerAscii.compute_LRC(body) == reference_lrc(body)

    def test_check_lrc_accepts_and_rejects(self):
        """check_LRC agrees with the reference value, off-by-one fails."""
        assert FramerAscii.check_LRC(WRITE_BODY, reference_lrc(WRITE_BODY))
        assert not FramerAscii.check_LRC(WRITE_BODY, (reference_lrc(WRITE_BODY) + 1) & 0xFF)


class TestAsciiEncode:
    """Encoding contract: colon start, upper-case hex, configured delimiter."""

    def test_encode_matches_handcrafted_frame(self, framer):
        """encode() produces exactly the handcrafted frame."""
        assert framer.encode(WRITE_PAYLOAD, 1, 0) == WRITE_FRAME

    def test_encode_is_uppercase(self, framer):
        """encode() emits upper-case hexadecimal only."""
        frame = framer.encode(WRITE_PAYLOAD, 1, 0)
        assert frame == frame.upper()
        assert frame.startswith(b":")
        assert frame.endswith(b"\r\n")

    @pytest.mark.parametrize(
        ("delimiter", "expected_end"),
        [
            (b"\n", b"\r\n"),
            (b"=", b"\r="),
            (b";", b"\r;"),
        ],
    )
    def test_encode_uses_configured_delimiter(self, framer, delimiter, expected_end):
        """Switching the delimiter changes the emitted end-of-frame."""
        ModbusControlBlock().Delimiter = delimiter
        frame = framer.encode(WRITE_PAYLOAD, 1, 0)
        assert frame.endswith(expected_end)
        assert frame == b":" + WRITE_BODY.hex().upper().encode() + b"EF" + expected_end


class TestAsciiDecode:
    """Decoding of handcrafted frames, including rejection positions."""

    def test_decode_valid_frame(self, framer):
        """A handcrafted valid frame decodes fully, nothing remains."""
        used_len, dev_id, tid, payload = framer.decode(WRITE_FRAME)
        assert used_len == len(WRITE_FRAME)
        assert (dev_id, tid) == (1, 0)
        assert payload == WRITE_PAYLOAD

    def test_decode_lowercase_hex(self, framer):
        """Lower-case hexadecimal decodes to the same payload."""
        frame = make_frame(WRITE_BODY, upper=False)
        used_len, dev_id, _, payload = framer.decode(frame)
        assert used_len == len(frame)
        assert dev_id == 1
        assert payload == WRITE_PAYLOAD

    def test_decode_mixed_case_hex(self, framer):
        """Mixed-case hexadecimal decodes to the same payload."""
        frame = b":01060000000aeF\r\n"
        used_len, dev_id, _, payload = framer.decode(frame)
        assert used_len == len(frame)
        assert dev_id == 1
        assert payload == WRITE_PAYLOAD

    def test_odd_nibble_count_rejected(self, framer):
        """An odd number of hex nibbles rejects the frame at its end."""
        frame = b":" + WRITE_BODY.hex().upper().encode()[:-1] + b"EF\r\n"
        used_len, _, _, payload = framer.decode(frame)
        assert payload == b"", "odd-nibble frame must not yield a payload"
        assert used_len == len(frame), "rejection consumes the corrupt frame"
        assert frame[used_len:] == b"", "no buffer remains after rejection"

    def test_wrong_lrc_rejected(self, framer):
        """A bad LRC rejects the frame, consuming exactly its length."""
        frame = make_frame(WRITE_BODY, lrc=(reference_lrc(WRITE_BODY) + 1) & 0xFF)
        used_len, _, _, payload = framer.decode(frame)
        assert payload == b""
        assert used_len == len(frame)

    def test_wrong_lrc_then_valid_frame(self, framer):
        """After an LRC rejection, parsing resumes at the next frame."""
        bad = make_frame(WRITE_BODY, lrc=(reference_lrc(WRITE_BODY) + 1) & 0xFF)
        used_len, dev_id, _, payload = framer.decode(bad + WRITE_FRAME)
        assert used_len == len(bad) + len(WRITE_FRAME)
        assert dev_id == 1
        assert payload == WRITE_PAYLOAD

    def test_missing_colon_consumes_garbage(self, framer):
        """Data without a colon is discarded up to the buffer end."""
        garbage = bytes(range(1, 10))
        used_len, dev_id, _, payload = framer.decode(garbage)
        assert used_len == len(garbage), "rejection position is the buffer end"
        assert (dev_id, payload) == (0, b"")

    def test_garbage_before_colon_skipped(self, framer):
        """Garbage in front of a valid frame is skipped byte-exactly."""
        garbage = b"\x00\x01junk"
        used_len, dev_id, _, payload = framer.decode(garbage + WRITE_FRAME)
        assert used_len == len(garbage) + len(WRITE_FRAME)
        assert dev_id == 1
        assert payload == WRITE_PAYLOAD

    def test_partial_frame_waits_for_more_data(self, framer):
        """An incomplete frame consumes nothing and waits."""
        used_len, dev_id, tid, payload = framer.decode(WRITE_FRAME[:9])
        assert (used_len, dev_id, tid, payload) == (0, 0, 0, b"")

    def test_missing_end_marker_waits(self, framer):
        """A frame without the end marker consumes nothing and waits."""
        used_len, _, _, payload = framer.decode(WRITE_FRAME[:-2])
        assert used_len == 0
        assert payload == b""


class TestAsciiConsecutiveFrames:
    """Consecutive frames are consumed one by one, in order."""

    def test_chained_decode(self, framer):
        """decode() stops at the first frame end, leaving the rest."""
        stream = WRITE_FRAME + READ_FRAME
        used_len, dev_id, _, payload = framer.decode(stream)
        assert used_len == len(WRITE_FRAME)
        assert (dev_id, payload) == (1, WRITE_PAYLOAD)
        used_len2, dev_id2, _, payload2 = framer.decode(stream[used_len:])
        assert used_len2 == len(READ_FRAME)
        assert (dev_id2, payload2) == (2, READ_PAYLOAD)
        assert used_len + used_len2 == len(stream)

    def test_handle_frame_processes_in_order(self, framer):
        """handleFrame() returns the PDUs of a stream one at a time."""
        stream = WRITE_FRAME + READ_FRAME
        used_len, pdu = framer.handleFrame(stream, 0, 0)
        assert used_len == len(WRITE_FRAME)
        assert pdu.function_code == 6
        assert pdu.dev_id == 1
        used_len2, pdu2 = framer.handleFrame(stream[used_len:], 0, 0)
        assert used_len2 == len(READ_FRAME)
        assert pdu2.function_code == 3
        assert pdu2.dev_id == 2


class TestAsciiDelimiterContract:
    """After switching the delimiter, encode and decode share one contract."""

    @pytest.mark.parametrize("delimiter", [b"=", b";"])
    def test_custom_delimiter_roundtrip(self, framer, delimiter):
        """A frame encoded with the new delimiter decodes with it."""
        ModbusControlBlock().Delimiter = delimiter
        frame = framer.encode(WRITE_PAYLOAD, 1, 0)
        assert frame.endswith(b"\r" + delimiter)
        used_len, dev_id, _, payload = framer.decode(frame)
        assert used_len == len(frame)
        assert (dev_id, payload) == (1, WRITE_PAYLOAD)

    def test_standard_frame_waits_with_custom_delimiter(self, framer):
        """A CRLF frame is not accepted once the delimiter changed."""
        ModbusControlBlock().Delimiter = b"="
        used_len, _, _, payload = framer.decode(WRITE_FRAME)
        assert (used_len, payload) == (0, b""), "old contract must not parse"

    def test_custom_frame_waits_with_standard_delimiter(self, framer):
        """A frame with a custom delimiter is not accepted by default."""
        frame = make_frame(WRITE_BODY, end=b"\r=")
        used_len, _, _, payload = framer.decode(frame)
        assert (used_len, payload) == (0, b""), "foreign delimiter must not parse"


class TestAsciiInvalidCharacterRejection:
    """Security: invalid characters are never silently ignored.

    Inserting one invalid character into a legal write request must not
    recover into another valid write request by skipping that character.
    """

    @pytest.mark.parametrize("bad_char", [b"G", b" ", b"!", b"\x00", b"\t", b":"])
    @pytest.mark.parametrize(
        "position",
        [1, 5, len(WRITE_FRAME) - 4],
        ids=["device-id", "data", "before-lrc"],
    )
    def test_injected_char_rejects_frame(self, framer, bad_char, position):
        """One invalid character anywhere in the body rejects the frame."""
        injected = WRITE_FRAME[:position] + bad_char + WRITE_FRAME[position:]
        used_len, _, _, payload = framer.decode(injected)
        assert payload == b"", "invalid character must not be ignored"
        assert used_len == len(injected), (
            "rejection consumes the corrupt frame, position reported by used_len"
        )

    @pytest.mark.parametrize("bad_char", [b"G", b" ", b"\x00"])
    def test_injected_char_recovers_no_write_request(self, framer, bad_char):
        """handleFrame() yields no PDU for a corrupted write request."""
        injected = WRITE_FRAME[:5] + bad_char + WRITE_FRAME[5:]
        used_len, pdu = framer.handleFrame(injected, 0, 0)
        assert pdu is None, "corrupted frame must not become a write request"
        assert used_len == len(injected)

    def test_valid_write_request_control(self, framer):
        """Control: the untouched write request decodes to a func-6 PDU."""
        used_len, pdu = framer.handleFrame(WRITE_FRAME, 0, 0)
        assert used_len == len(WRITE_FRAME)
        assert pdu.function_code == 6
        assert pdu.dev_id == 1

    def test_injected_frame_blocks_resync_to_next_frame(self, framer):
        """A corrupt frame does not resynchronize into a trailing valid frame."""
        injected = WRITE_FRAME[:5] + b"G" + WRITE_FRAME[5:]
        used_len, _, _, payload = framer.decode(injected + WRITE_FRAME)
        assert payload == b""
        assert used_len == len(injected) + len(WRITE_FRAME), (
            "rejection position is the buffer end: no hidden resync"
        )
