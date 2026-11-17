"""Regression tests for malformed write requests.

The tests drive raw TCP (MBAP) and RTU frames through the real framer,
``DecodePDU`` and the request ``datastore_update`` service path. A recording
datastore backed by the real simulator context observes every get/set call,
so assertions prove that an inconsistent frame never produces a partial write:
a mere "decode raises" check would be insufficient because some frames decode
fine and only fail validation inside ``datastore_update``, potentially after
part of the data had been written.
"""

from __future__ import annotations

import logging

import pytest

from pymodbus.constants import ExcCodes
from pymodbus.datastore import ModbusServerContext, ModbusSimulatorContext
from pymodbus.exceptions import ModbusIOException
from pymodbus.framer import FramerRTU, FramerSocket
from pymodbus.pdu import DecodePDU, ExceptionResponse


# ---------------------------------------------------------------------------#
# Recording datastore
# ---------------------------------------------------------------------------#


class RecordingServerContext(ModbusServerContext):
    """A real datastore that records every get/set interaction."""

    def __init__(self) -> None:
        """Build a writable simulator and an empty call record."""
        config = {
            "setup": {
                "co size": 32,
                "di size": 32,
                "hr size": 32,
                "ir size": 32,
                "shared blocks": False,
                "type exception": False,
                "defaults": {
                    "value": {
                        "bits": 0,
                        "uint16": 0,
                        "uint32": 0,
                        "float32": 0,
                        "float64": 0,
                        "string": " ",
                    },
                    "action": {
                        "bits": None,
                        "uint16": None,
                        "uint32": None,
                        "float32": None,
                        "float64": None,
                        "string": None,
                    },
                },
            },
            "invalid": [],
            "write": [[0, 127]],
            "bits": [[0, 31]],
            "uint16": [[32, 127]],
            "repeat": [],
        }
        logging.disable(logging.CRITICAL)
        simulator = ModbusSimulatorContext(config, None)
        logging.disable(logging.NOTSET)
        super().__init__(devices=simulator, single=False)
        self.simulator = simulator
        self.set_calls: list[tuple[int, int, int, list]] = []
        self.get_calls: list[tuple[int, int, int, int]] = []

    async def async_getValues(self, device_id, func_code, address, count=1):
        """Record reads and delegate to the real simulator."""
        self.get_calls.append((device_id, func_code, address, count))
        return await super().async_getValues(device_id, func_code, address, count)

    async def async_setValues(self, device_id, func_code, address, values):
        """Record writes and delegate to the real simulator."""
        self.set_calls.append(
            (device_id, func_code, address, list(values))
        )
        return await super().async_setValues(device_id, func_code, address, values)

    def snapshot(self) -> list[int]:
        """Return the raw cell values of all four blocks."""
        return [cell.value for cell in self.simulator.registers]

    def coil_values(self, address: int, count: int) -> list[bool]:
        """Read coils straight from the simulator cells."""
        block_start = self.simulator.fc_offset[15]
        word_index = block_start + address // 16
        bit_index = address % 16
        result: list[bool] = []
        while len(result) < count:
            word = self.simulator.registers[word_index].value
            for offset in range(bit_index, 16):
                if len(result) == count:
                    break
                result.append(bool(word & (2**offset)))
            word_index += 1
            bit_index = 0
        return result

    def register_values(self, func_code: int, address: int, count: int) -> list[int]:
        """Read holding registers straight from the simulator cells."""
        block_start = self.simulator.fc_offset[func_code]
        return [
            self.simulator.registers[block_start + address + idx].value
            for idx in range(count)
        ]


@pytest.fixture(name="recorder")
def prepare_recorder():
    """Return a fresh recording datastore."""
    return RecordingServerContext()


# ---------------------------------------------------------------------------#
# Raw frame helpers
# ---------------------------------------------------------------------------#

DEVICE_ID = 1
TRANSACTION_ID = 7


def _tcp_frame(pdu: bytes, tid: int = TRANSACTION_ID) -> bytes:
    """Wrap a PDU in a Modbus TCP (MBAP) frame."""
    return FramerSocket(DecodePDU(True)).encode(pdu, DEVICE_ID, tid)


def _rtu_frame(pdu: bytes) -> bytes:
    """Wrap a PDU in a Modbus RTU frame (with valid CRC)."""
    return FramerRTU(DecodePDU(True)).encode(pdu, DEVICE_ID, 0)


def _assert_no_write_side_effects(
    recorder: RecordingServerContext, before: list[int]
) -> None:
    """Assert no set call happened and no cell changed."""
    assert recorder.set_calls == []
    assert recorder.snapshot() == before


# ---------------------------------------------------------------------------#
# Correct write control cases
# ---------------------------------------------------------------------------#


class TestValidWriteControls:
    """Confirm well-formed writes reach the datastore and change its state."""

    async def test_tcp_write_multiple_registers_control(self, recorder):
        """A consistent fc16 TCP frame writes exactly the declared registers."""
        before = recorder.snapshot()
        frame = _tcp_frame(b"\x10\x00\x00\x00\x03\x06\x00\x0a\x00\x0b\x00\x0c")

        framer = FramerSocket(DecodePDU(True))
        used_len, request = framer.handleFrame(frame, 0, 0)
        assert used_len == len(frame)
        response = await request.datastore_update(recorder, DEVICE_ID)

        assert not isinstance(response, ExceptionResponse)
        assert response.function_code == 0x10
        assert response.address == 0
        assert response.count == 3
        assert recorder.register_values(16, 0, 3) == [0x0A, 0x0B, 0x0C]
        assert recorder.set_calls == [
            (DEVICE_ID, 16, 0, [0x0A, 0x0B, 0x0C])
        ]
        assert recorder.snapshot() != before

    async def test_tcp_write_multiple_coils_padding_is_not_data(self, recorder):
        """Padding bits are accepted but never written as real coils."""
        # 9 real coils need 2 bytes; the upper 7 bits of byte 2 are padding.
        # Setting a padding bit (0x0100) must not create a 10th coil write.
        frame = _tcp_frame(b"\x0f\x00\x00\x00\x09\x02\xff\x01")

        _, request = FramerSocket(DecodePDU(True)).handleFrame(frame, 0, 0)
        response = await request.datastore_update(recorder, DEVICE_ID)

        assert not isinstance(response, ExceptionResponse)
        assert request.count == 9
        assert len(request.bits) == 9
        assert recorder.set_calls == [
            (DEVICE_ID, 15, 0, [True] * 9)
        ]
        assert recorder.coil_values(0, 10) == [True] * 9 + [False]
        assert recorder.register_values(16, 0, 1) == [0]

    async def test_rtu_write_multiple_registers_control(self, recorder):
        """A consistent fc16 RTU frame writes through the real RTU framer."""
        frame = _rtu_frame(b"\x10\x00\x05\x00\x02\x04\x12\x34\x56\x78")

        used_len, request = FramerRTU(DecodePDU(True)).handleFrame(frame, 0, 0)
        assert used_len == len(frame)
        assert request.dev_id == DEVICE_ID
        response = await request.datastore_update(recorder, DEVICE_ID)

        assert not isinstance(response, ExceptionResponse)
        assert recorder.register_values(16, 5, 2) == [0x1234, 0x5678]
        assert recorder.set_calls == [
            (DEVICE_ID, 16, 5, [0x1234, 0x5678])
        ]

    async def test_tcp_readwrite_multiple_registers_control(self, recorder):
        """A consistent fc23 frame writes then reads, both against the store."""
        frame = _tcp_frame(
            b"\x17\x00\x00\x00\x02\x00\x0a\x00\x02\x04\x11\x11\x22\x22"
        )

        _, request = FramerSocket(DecodePDU(True)).handleFrame(frame, 0, 0)
        response = await request.datastore_update(recorder, DEVICE_ID)

        assert not isinstance(response, ExceptionResponse)
        assert recorder.register_values(16, 10, 2) == [0x1111, 0x2222]
        assert recorder.set_calls == [
            (DEVICE_ID, 23, 10, [0x1111, 0x2222])
        ]
        assert recorder.get_calls == [(DEVICE_ID, 23, 0, 2)]


# ---------------------------------------------------------------------------#
# fc15 write multiple coils: bit packing / byte_count / count mismatch
# ---------------------------------------------------------------------------#

FC15_MALFORMED = [
    pytest.param(
        b"\x0f\x00\x00\x00\x08\x02\xff\x01",
        "count 8 needs 1 byte but byte_count says 2",
        id="coils_byte_count_too_large",
    ),
    pytest.param(
        b"\x0f\x00\x00\x00\x10\x01\xff",
        "count 16 needs 2 bytes but byte_count says 1",
        id="coils_byte_count_too_small",
    ),
    pytest.param(
        b"\x0f\x00\x00\x00\x08\x01\xff\x00",
        "frame carries one data byte more than declared",
        id="coils_payload_longer_than_byte_count",
    ),
    pytest.param(
        b"\x0f\x00\x00\x00\x08\x01",
        "frame truncated before the single data byte",
        id="coils_payload_shorter_than_byte_count",
    ),
]


class TestMalformedWriteMultipleCoils:
    """Inconsistent fc15 frames must answer ILLEGAL_VALUE without writing."""

    @pytest.mark.parametrize("pdu, reason", FC15_MALFORMED)
    async def test_tcp_rejects_and_does_not_write(self, recorder, pdu, reason):
        """Each malformed fc15 TCP frame leaves every cell untouched."""
        before = recorder.snapshot()
        frame = _tcp_frame(pdu)

        _, request = FramerSocket(DecodePDU(True)).handleFrame(frame, 0, 0)
        response = await request.datastore_update(recorder, DEVICE_ID)

        assert isinstance(response, ExceptionResponse), reason
        assert response.exception_code == ExcCodes.ILLEGAL_VALUE
        _assert_no_write_side_effects(recorder, before)

    async def test_tcp_header_truncated_raises_without_side_effect(
        self, recorder
    ):
        """A frame cut before byte_count fails decoding and never writes."""
        before = recorder.snapshot()
        frame = _tcp_frame(b"\x0f\x00\x00\x00\x08")

        with pytest.raises(ModbusIOException):
            FramerSocket(DecodePDU(True)).handleFrame(frame, 0, 0)
        _assert_no_write_side_effects(recorder, before)

    @pytest.mark.parametrize(
        "pdu, reason",
        [
            pytest.param(
                b"\x0f\x00\x00\x00\x08\x02\xff\x01",
                "coil byte_count mismatch over RTU",
                id="rtu_coils_byte_count_mismatch",
            ),
        ],
    )
    async def test_rtu_service_rejects_and_does_not_write(
        self, recorder, pdu, reason
    ):
        """CRC-valid malformed RTU frames are rejected at the service layer."""
        before = recorder.snapshot()
        frame = _rtu_frame(pdu)

        _, request = FramerRTU(DecodePDU(True)).handleFrame(frame, 0, 0)
        assert request is not None
        response = await request.datastore_update(recorder, DEVICE_ID)

        assert isinstance(response, ExceptionResponse), reason
        assert response.exception_code == ExcCodes.ILLEGAL_VALUE
        _assert_no_write_side_effects(recorder, before)

    @pytest.mark.parametrize(
        "pdu, reason",
        [
            pytest.param(
                b"\x0f\x00\x00\x00\x08\x01\xff\x00",
                "coil extra payload byte over RTU",
                id="rtu_coils_extra_payload",
            ),
        ],
    )
    async def test_rtu_crc_rejects_extra_bytes_without_side_effect(
        self, recorder, pdu, reason
    ):
        """Extra payload bytes shift the CRC, so the framer drops the frame.

        RTU framing derives the frame length from the declared byte_count and
        checks the CRC at that boundary: bytes hidden behind a too-small
        declared length break the CRC and the request is never delivered.
        """
        before = recorder.snapshot()
        frame = _rtu_frame(pdu)

        _, request = FramerRTU(DecodePDU(True)).handleFrame(frame, 0, 0)
        assert request is None, reason
        _assert_no_write_side_effects(recorder, before)

    async def test_tcp_padding_bits_distinguished_from_real_coils(
        self, recorder
    ):
        """A padding bit set in a malformed frame never reaches a coil."""
        before = recorder.snapshot()
        # count=8 (1 byte) but 2 bytes present: the extra byte is rejected,
        # not applied to the following coils.
        frame = _tcp_frame(b"\x0f\x00\x00\x00\x08\x02\xff\x80")

        _, request = FramerSocket(DecodePDU(True)).handleFrame(frame, 0, 0)
        response = await request.datastore_update(recorder, DEVICE_ID)

        assert isinstance(response, ExceptionResponse)
        assert response.exception_code == ExcCodes.ILLEGAL_VALUE
        _assert_no_write_side_effects(recorder, before)
        assert recorder.coil_values(0, 16) == [False] * 16


# ---------------------------------------------------------------------------#
# fc16 write multiple registers: count / byte_count / payload mismatch
# ---------------------------------------------------------------------------#

FC16_MALFORMED = [
    pytest.param(
        b"\x10\x00\x00\x00\x02\x02\x00\x0a\x00\x0b",
        "byte_count 2 but count 2 needs 4 bytes",
        id="registers_byte_count_too_small",
    ),
    pytest.param(
        b"\x10\x00\x00\x00\x02\x06\x00\x0a\x00\x0b",
        "byte_count 6 but only 4 payload bytes present",
        id="registers_byte_count_too_large",
    ),
    pytest.param(
        b"\x10\x00\x00\x00\x02\x04\x00\x0a",
        "truncated payload: one register missing",
        id="registers_payload_truncated",
    ),
    pytest.param(
        b"\x10\x00\x00\x00\x02\x04\x00\x0a\x00\x0b\x00\x0c",
        "payload carries one register more than declared",
        id="registers_payload_with_extra_register",
    ),
    pytest.param(
        b"\x10\x00\x00\x00\x00\x00",
        "zero quantity is illegal",
        id="registers_zero_count",
    ),
]


class TestMalformedWriteMultipleRegisters:
    """Inconsistent fc16 frames must answer ILLEGAL_VALUE without writing."""

    @pytest.mark.parametrize("pdu, reason", FC16_MALFORMED)
    async def test_tcp_rejects_and_does_not_write(self, recorder, pdu, reason):
        """No register may be updated even when decode itself succeeds."""
        before = recorder.snapshot()
        frame = _tcp_frame(pdu)

        _, request = FramerSocket(DecodePDU(True)).handleFrame(frame, 0, 0)
        response = await request.datastore_update(recorder, DEVICE_ID)

        assert isinstance(response, ExceptionResponse), reason
        assert response.exception_code == ExcCodes.ILLEGAL_VALUE
        _assert_no_write_side_effects(recorder, before)

    async def test_rtu_small_byte_count_breaks_crc_without_side_effect(
        self, recorder
    ):
        """A hidden trailing register shifts the RTU CRC and drops the frame."""
        before = recorder.snapshot()
        frame = _rtu_frame(b"\x10\x00\x00\x00\x02\x02\x00\x0a\x00\x0b")

        _, request = FramerRTU(DecodePDU(True)).handleFrame(frame, 0, 0)
        assert request is None
        _assert_no_write_side_effects(recorder, before)

    async def test_rtu_oversized_byte_count_waits_without_side_effect(
        self, recorder
    ):
        """An oversized byte_count makes the framer wait past the CRC."""
        before = recorder.snapshot()
        # Declared 6 bytes -> frame size 15, but only 4 payload bytes plus CRC
        # are present, so the framer keeps waiting and never delivers a PDU.
        frame = _rtu_frame(b"\x10\x00\x00\x00\x02\x06\x00\x0a\x00\x0b")

        _, request = FramerRTU(DecodePDU(True)).handleFrame(frame, 0, 0)
        assert request is None
        _assert_no_write_side_effects(recorder, before)

    async def test_decode_failure_also_has_no_side_effect(self, recorder):
        """A frame that cannot even decode must not touch the datastore."""
        before = recorder.snapshot()
        decoder = DecodePDU(True)
        # quantity 2001 exceeds the fc15 maximum and is rejected at decode time.
        with pytest.raises(ModbusIOException):
            decoder.decode(b"\x0f\x00\x00\x07\xd1\x01\xff")
        _assert_no_write_side_effects(recorder, before)
        assert recorder.get_calls == []


# ---------------------------------------------------------------------------#
# fc23 read/write multiple registers combined
# ---------------------------------------------------------------------------#

FC23_MALFORMED = [
    pytest.param(
        b"\x17\x00\x00\x00\x02\x00\x0a\x00\x02\x02\x00\x0a\x00\x0b",
        "write_byte_count 2 but write_count 2 needs 4",
        id="rw_byte_count_too_small",
    ),
    pytest.param(
        b"\x17\x00\x00\x00\x02\x00\x0a\x00\x02\x06\x00\x0a\x00\x0b",
        "write_byte_count 6 but only 4 payload bytes present",
        id="rw_byte_count_too_large",
    ),
    pytest.param(
        b"\x17\x00\x00\x00\x02\x00\x0a\x00\x02\x04\x00\x0a",
        "write payload truncated mid register",
        id="rw_payload_truncated",
    ),
    pytest.param(
        b"\x17\x00\x00\x00\x00\x00\x0a\x00\x02\x04\x00\x0a\x00\x0b",
        "read quantity zero is illegal",
        id="rw_zero_read_count",
    ),
]


class TestMalformedReadWriteMultipleRegisters:
    """Malformed fc23 frames must neither write nor perform the trailing read."""

    @pytest.mark.parametrize("pdu, reason", FC23_MALFORMED)
    async def test_tcp_rejects_without_write_or_read(
        self, recorder, pdu, reason
    ):
        """Validation happens before setValues and before getValues."""
        before = recorder.snapshot()
        frame = _tcp_frame(pdu)

        _, request = FramerSocket(DecodePDU(True)).handleFrame(frame, 0, 0)
        response = await request.datastore_update(recorder, DEVICE_ID)

        assert isinstance(response, ExceptionResponse), reason
        assert response.exception_code == ExcCodes.ILLEGAL_VALUE
        _assert_no_write_side_effects(recorder, before)
        assert recorder.get_calls == []


# ---------------------------------------------------------------------------#
# Truncated frames: framer must wait for more data, never partial processing
# ---------------------------------------------------------------------------#


class TestTruncatedFrames:
    """A cut-off frame must not yield a PDU nor any datastore interaction."""

    @pytest.mark.parametrize(
        "full_pdu",
        [
            b"\x10\x00\x00\x00\x02\x04\x00\x0a\x00\x0b",
            b"\x0f\x00\x00\x00\x09\x02\xff\x01",
        ],
    )
    async def test_tcp_truncated_waits_and_does_not_write(
        self, recorder, full_pdu
    ):
        """Every prefix shorter than the MBAP length returns no request."""
        frame = _tcp_frame(full_pdu)
        framer = FramerSocket(DecodePDU(True))
        before = recorder.snapshot()

        for size in range(1, len(frame)):
            used_len, request = framer.handleFrame(frame[:size], 0, 0)
            assert used_len == 0
            assert request is None

        _assert_no_write_side_effects(recorder, before)

    @pytest.mark.parametrize(
        "full_pdu",
        [
            b"\x10\x00\x00\x00\x02\x04\x00\x0a\x00\x0b",
            b"\x0f\x00\x00\x00\x09\x02\xff\x01",
        ],
    )
    async def test_rtu_truncated_waits_and_does_not_write(
        self, recorder, full_pdu
    ):
        """Every prefix shorter than the declared RTU frame returns no request."""
        frame = _rtu_frame(full_pdu)
        framer = FramerRTU(DecodePDU(True))
        before = recorder.snapshot()

        for size in range(1, len(frame)):
            used_len, request = framer.handleFrame(frame[:size], 0, 0)
            assert used_len == 0
            assert request is None

        _assert_no_write_side_effects(recorder, before)


# ---------------------------------------------------------------------------#
# Short counter-example: small declared quantity with another request trailing
# ---------------------------------------------------------------------------#


class TestTrailingRequestBoundary:
    """Bytes of a second request must never be consumed by the first."""

    async def test_tcp_small_byte_count_keeps_trailing_request_boundary(
        self, recorder
    ):
        """The malformed first frame is rejected; the trailing frame is whole."""
        before = recorder.snapshot()
        # fc16 declares byte_count=2 (one register) while carrying 4 bytes,
        # immediately followed by an independent, valid fc6 frame.
        first = _tcp_frame(
            b"\x10\x00\x00\x00\x02\x02\x00\x0a\x00\x0b", tid=11
        )
        second = _tcp_frame(b"\x06\x00\x09\x12\x34", tid=12)
        stream = first + second

        framer = FramerSocket(DecodePDU(True))
        used_len, first_request = framer.handleFrame(stream, 0, 0)
        assert used_len == len(first)
        first_response = await first_request.datastore_update(
            recorder, DEVICE_ID
        )
        assert isinstance(first_response, ExceptionResponse)
        assert first_response.exception_code == ExcCodes.ILLEGAL_VALUE
        _assert_no_write_side_effects(recorder, before)

        # The second MBAP frame is decoded independently with its own TID.
        remaining = stream[used_len:]
        second_used, second_request = framer.handleFrame(remaining, 0, 0)
        assert second_used == len(second)
        assert second_request.transaction_id == 12
        second_response = await second_request.datastore_update(
            recorder, DEVICE_ID
        )
        assert not isinstance(second_response, ExceptionResponse)
        assert recorder.register_values(16, 9, 1) == [0x1234]
        assert recorder.set_calls == [(DEVICE_ID, 6, 9, [0x1234])]

    async def test_rtu_small_byte_count_does_not_swallow_trailing_request(
        self, recorder
    ):
        """A hidden trailing request breaks the CRC and is never merged.

        RTU framing sizes the frame from the declared byte_count. With a
        too-small declared length, the bytes of the trailing request shift the
        CRC position, the CRC fails and no PDU is delivered at all: the two
        requests can never be interpreted as one combined write.
        """
        before = recorder.snapshot()
        first = _rtu_frame(b"\x10\x00\x00\x00\x02\x02\x00\x0a\x00\x0b")
        second = _rtu_frame(b"\x06\x00\x09\x12\x34")
        stream = first + second

        framer = FramerRTU(DecodePDU(True))
        _, swallowed = framer.handleFrame(stream, 0, 0)
        assert swallowed is None
        _assert_no_write_side_effects(recorder, before)

        # When delivered on its own, the trailing request remains intact and
        # performs exactly its own single-register write.
        framer_two = FramerRTU(DecodePDU(True))
        _, trailing_request = framer_two.handleFrame(second, 0, 0)
        assert trailing_request is not None
        assert trailing_request.function_code == 6
        assert trailing_request.address == 9
        assert trailing_request.registers == [0x1234]
        response = await trailing_request.datastore_update(recorder, DEVICE_ID)
        assert not isinstance(response, ExceptionResponse)
        assert recorder.register_values(16, 9, 1) == [0x1234]
        assert recorder.set_calls == [(DEVICE_ID, 6, 9, [0x1234])]
