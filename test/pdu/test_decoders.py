"""Test decoders."""

import copy

import pytest

from pymodbus.exceptions import MessageRegisterException, ModbusIOException
from pymodbus.pdu import ModbusPDU
from pymodbus.pdu.bit_message import ReadCoilsResponse
from pymodbus.pdu.decoders import DecodePDU


class TestModbusPDU:
    """Test ModbusPDU."""

    client = DecodePDU(False)
    server = DecodePDU(True)
    requests = (
        (0x01, b"\x01\x00\x01\x00\x01"),  # read coils
        (0x02, b"\x02\x00\x01\x00\x01"),  # read discrete inputs
        (0x03, b"\x03\x00\x01\x00\x01"),  # read holding registers
        (0x04, b"\x04\x00\x01\x00\x01"),  # read input registers
        (0x05, b"\x05\x00\x01\x00\x01"),  # write single coil
        (0x06, b"\x06\x00\x01\x00\x01"),  # write single register
        (0x07, b"\x07"),  # read exception status
        (0x08, b"\x08\x00\x00\x00\x00"),  # read diagnostic
        (0x0B, b"\x0b"),  # get comm event counters
        (0x0C, b"\x0c"),  # get comm event log
        (0x0F, b"\x0f\x00\x01\x00\x08\x01\x00\xff"),  # write multiple coils
        (0x10, b"\x10\x00\x01\x00\x02\x04\0xff\xff"),  # write multiple registers
        (0x11, b"\x11"),  # report device id
        (
            0x14,
            b"\x14\x0e\x06\x00\x04\x00\x01\x00\x02\x06\x00\x03\x00\x09\x00\x02",
        ),  # read file record
        (
            0x15,
            b"\x15\x0d\x06\x00\x04\x00\x07\x00\x03\x06\xaf\x04\xbe\x10\x0d",
        ),  # write file record
        (0x16, b"\x16\x00\x01\x00\xff\xff\x00"),  # mask write register
        (
            0x17,
            b"\x17\x00\x01\x00\x01\x00\x01\x00\x01\x02\x12\x34",
        ),  # r/w multiple regs
        (0x18, b"\x18\x00\x01"),  # read fifo queue
        (0x2B, b"\x2b\x0e\x01\x00"),  # read device identification
    )

    responses = (
        (0x01, b"\x01\x01\x01"),  # read coils
        (0x02, b"\x02\x01\x01"),  # read discrete inputs
        (0x03, b"\x03\x02\x01\x01"),  # read holding registers
        (0x04, b"\x04\x02\x01\x01"),  # read input registers
        (0x05, b"\x05\x00\x01\x00\x01"),  # write single coil
        (0x06, b"\x06\x00\x01\x00\x01"),  # write single register
        (0x07, b"\x07\x00"),  # read exception status
        (0x08, b"\x08\x00\x00\x00\x00"),  # read diagnostic
        (0x0B, b"\x0b\x00\x00\x00\x00"),  # get comm event counters
        (0x0C, b"\x0c\x08\x00\x00\x01\x08\x01\x21\x20\x00"),  # get comm event log
        (0x0F, b"\x0f\x00\x01\x00\x08"),  # write multiple coils
        (0x10, b"\x10\x00\x01\x00\x02"),  # write multiple registers
        (0x11, b"\x11\x03\x05\x01\x54"),  # report device id (device specific)
        (
            0x14,
            b"\x14\x0c\x05\x06\x0d\xfe\x00\x20\x05\x06\x33\xcd\x00\x40",
        ),  # read file record
        (
            0x15,
            b"\x15\x0d\x06\x00\x04\x00\x07\x00\x03\x06\xaf\x04\xbe\x10\x0d",
        ),  # write file record
        (0x16, b"\x16\x00\x01\x00\xff\xff\x00"),  # mask write register
        (0x17, b"\x17\x02\x12\x34"),  # read/write multiple registers
        (0x18, b"\x18\x00\x01\x00\x01\x00\x00"),  # read fifo queue
        (
            0x2B,
            b"\x2b\x0e\x01\x01\x00\x00\x01\x00\x01\x77",
        ),  # read device identification
    )

    exceptions = (
        (0x81, b"\x81\x01\xd0\x50"),  # illegal function exception
        (0x82, b"\x82\x02\x90\xa1"),  # illegal data address exception
        (0x83, b"\x83\x03\x50\xf1"),  # illegal data value exception
        (0x84, b"\x84\x04\x13\x03"),  # skave device failure exception
        (0x85, b"\x85\x05\xd3\x53"),  # acknowledge exception
        (0x86, b"\x86\x06\x93\xa2"),  # device busy exception
        (0x87, b"\x87\x08\x53\xf2"),  # memory parity exception
        (0x88, b"\x88\x0a\x16\x06"),  # gateway path unavailable exception
        (0x89, b"\x89\x0b\xd6\x56"),  # gateway target failed exception
    )

    bad = (
        (0x80, b"\x80\x00\x00\x00"),  # Unknown Function
        (0x81, b"\x81\x00\x00\x00"),  # error message
    )

    @pytest.mark.parametrize(("code", "frame"), list(responses) + list(exceptions))
    def test_client_lookup(self, code, frame):
        """Test lookup for responses."""
        data = b"\x01" + frame
        pdu = self.client._lookupPduClass(data)
        assert pdu
        if not code & 0x80:
            assert pdu.function_code == code

    def test_client_lookup_no_fc(self):
        """Test lookup for responses."""
        data = b"\x01\x70"
        pdu = self.client._lookupPduClass(data)
        assert not pdu

    def test_list_function_codes(self):
        """Test lookup for responses."""
        fc_list = self.client.list_function_codes()
        assert fc_list

    @pytest.mark.parametrize(("code", "frame"), list(requests))
    def test_server_lookup(self, code, frame):
        """Test lookup for requests."""
        data = b"\x01" + frame
        pdu = self.client._lookupPduClass(data)
        assert pdu
        assert pdu.function_code == code

    @pytest.mark.parametrize(("code", "frame"), list(responses) + list(exceptions))
    def test_client_decode(self, code, frame):
        """Test lookup for responses."""
        pdu = self.client.decode(frame)
        assert pdu
        assert pdu.function_code == code

    @pytest.mark.parametrize(("code", "frame"), list(requests))
    def test_server_decode(self, code, frame):
        """Test lookup for requests."""
        pdu = self.server.decode(frame)
        assert pdu
        assert pdu.function_code == code

    @pytest.mark.parametrize(("code", "frame"), list(exceptions))
    def test_server_decode_reserved_function_code(self, code, frame):
        """A request may not use a function code reserved for exception responses."""
        with pytest.raises(ModbusIOException) as exc:
            self.server.decode(frame)
        assert exc.value.fcode == code

    @pytest.mark.parametrize(("frame"), [b"", b"NO FRAME"])
    @pytest.mark.parametrize(("decoder"), [server, client])
    def test_decode_bad_frame(self, decoder, frame):
        """Test lookup bad frames."""
        with pytest.raises(ModbusIOException):
            decoder.decode(frame)

    @pytest.mark.parametrize(
        ("decoder", "frame"),
        [
            (server, b"\x14\x10"),  # read file record, byte count past the frame
            (server, b"\x15\x10"),  # write file record, byte count past the frame
            (client, b"\x18\x00\x06\x00\x05\x00\x01"),  # fifo count past the frame
        ],
    )
    def test_decode_bad_file_record_frame(self, decoder, frame):
        """Test bad file record frames fail like other undecodable frames."""
        with pytest.raises(ModbusIOException):
            decoder.decode(frame)

    def test_decode_unknown_sub(self):
        """Test for unknown sub code."""
        with pytest.raises(ModbusIOException):
            self.client.decode(b"\x08\x00\xf0\xf0\x00")

    @pytest.mark.parametrize("is_server", [True, False])
    def test_register_custom_request(self, is_server, mockPDU):
        """A custom PDU is decoded only by the decoder it was registered on."""

        class NoCustomRequestResponse:
            """Custom request."""

            function_code = 0x70

            def x_encode(self):
                """Encode."""

            def x_decode(self, _data):
                """Decode."""

        decoder = DecodePDU(is_server)
        other = DecodePDU(is_server)
        decoder.register(mockPDU)
        data = b"\x01" + mockPDU().x_encode()
        assert decoder._lookupPduClass(data) is mockPDU
        # Isolation: another decoder keeps its own interpretation.
        assert other._lookupPduClass(data) is None

        mockPDU.sub_function_code = 0xF7
        decoder.register(mockPDU)
        mockPDU.sub_function_code = 0xF4
        decoder.register(mockPDU)
        data = b"\x01" + mockPDU().x_encode()
        assert decoder._lookupPduClass(data) is mockPDU
        assert other._lookupPduClass(data) is None
        with pytest.raises(MessageRegisterException):
            decoder.register(NoCustomRequestResponse)

    def test_register_isolation_between_decoders(self):
        """Same custom function code on two decoders maps to distinct PDUs."""
        class VendorA(ModbusPDU):
            """Vendor A interpretation of function code 0x65."""

            function_code = 0x65

            def x_encode(self):
                """Encode."""
                return b"\x65A"

            def x_decode(self, _data):
                """Decode."""

            @classmethod
            def x_calculateRtuFrameSize(cls, _data):
                """Calculate frame size."""
                return 3

        class VendorB(ModbusPDU):
            """Vendor B interpretation of the same function code."""

            function_code = 0x65

            def x_encode(self):
                """Encode."""
                return b"\x65B"

            def x_decode(self, _data):
                """Decode."""

            @classmethod
            def x_calculateRtuFrameSize(cls, _data):
                """Calculate frame size."""
                return 3

        decoder_a = DecodePDU(False)
        decoder_b = DecodePDU(False)
        decoder_a.register(VendorA)
        decoder_b.register(VendorB)
        frame = b"\x65\x00"

        assert decoder_a._lookupPduClass(b"\x01" + frame) is VendorA
        assert decoder_b._lookupPduClass(b"\x01" + frame) is VendorB
        assert decoder_a.decode(frame).__class__ is VendorA
        assert decoder_b.decode(frame).__class__ is VendorB

    def test_register_standard_function_protected(self):
        """Standard function codes cannot be silently overwritten."""
        class HijackReadCoils(ModbusPDU):
            """Attempt to take over a standard function code."""

            function_code = 0x01

            def x_encode(self):
                """Encode."""
                return b""

            def x_decode(self, _data):
                """Decode."""

        decoder = DecodePDU(False)
        standard = decoder.pdu_table[0x01]
        # Re-registering the already active standard class is a harmless no-op.
        decoder.register(ReadCoilsResponse)
        assert decoder.pdu_table[0x01] == standard
        # A different class on a standard code is rejected, mapping unchanged.
        with pytest.raises(MessageRegisterException):
            decoder.register(HijackReadCoils)
        assert decoder.pdu_table[0x01] == standard
        assert decoder.decode(b"\x01\x01\x01").__class__ is ReadCoilsResponse

    def test_failed_register_keeps_mapping(self):
        """A rejected registration must not mutate the existing mapping."""
        class FirstCustom(ModbusPDU):
            """First occupant of function code 0x66."""

            function_code = 0x66

            def x_encode(self):
                """Encode."""
                return b""

            def x_decode(self, _data):
                """Decode."""

        class SecondCustom(ModbusPDU):
            """Conflicting occupant of function code 0x66."""

            function_code = 0x66

            def x_encode(self):
                """Encode."""
                return b""

            def x_decode(self, _data):
                """Decode."""

        class NotAPdu:
            """Not derived from ModbusPDU."""

            function_code = 0x67

        decoder = DecodePDU(False)
        decoder.register(FirstCustom)
        before = decoder.pdu_table[0x66]
        with pytest.raises(MessageRegisterException):
            decoder.register(SecondCustom)
        with pytest.raises(MessageRegisterException):
            decoder.register(NotAPdu)
        assert decoder.pdu_table[0x66] == before
        assert 0x67 not in decoder.pdu_table

    def test_sub_function_dispatch_isolated(self):
        """Custom sub function dispatch stays local to one decoder."""
        class CustomDiag(ModbusPDU):
            """Custom diagnostic sub function."""

            function_code = 0x08
            sub_function_code = 0xFF01

            @classmethod
            def decode_sub_function_code(cls, data):
                """Decode sub function code (2 bytes)."""
                return int.from_bytes(data[2:4], "big")

            def x_encode(self):
                """Encode."""
                return b"\x08\xff\x01"

            def x_decode(self, _data):
                """Decode."""

            @classmethod
            def x_calculateRtuFrameSize(cls, _data):
                """Calculate frame size."""
                return 8

        decoder = DecodePDU(False)
        other = DecodePDU(False)
        decoder.register(CustomDiag)
        frame = b"\x00\x08\xff\x01\x00\x00"
        assert decoder._lookupPduClass(frame) is CustomDiag
        # The other decoder does not know this sub function and returns None.
        assert other._lookupPduClass(frame) is None
        # Standard sub functions remain available on both decoders.
        standard_frame = b"\x00\x08\x00\x00\x00\x00"
        assert decoder._lookupPduClass(standard_frame) is not None
        assert other._lookupPduClass(standard_frame) is not None

    def test_snapshot_unaffected_by_class_table_mutation(self):
        """Existing decoders keep working when class defaults are mutated."""
        decoder = DecodePDU(False)
        standard_entry = decoder.pdu_table[0x03]
        saved_table = copy.deepcopy(DecodePDU.pdu_table)
        saved_sub_table = copy.deepcopy(DecodePDU.pdu_sub_table)
        try:
            DecodePDU.pdu_table.clear()
            DecodePDU.pdu_sub_table.clear()
            assert decoder.pdu_table[0x03] == standard_entry
            assert decoder.decode(b"\x03\x02\x01\x01").function_code == 0x03
            # A decoder created later would miss defaults; restore first.
        finally:
            DecodePDU.pdu_table.clear()
            DecodePDU.pdu_table.update(saved_table)
            DecodePDU.pdu_sub_table.clear()
            DecodePDU.pdu_sub_table.update(saved_sub_table)
        # Restored defaults remain available to new decoders.
        assert DecodePDU(False).pdu_table[0x03] == standard_entry

    def test_decoders_have_independent_table_objects(self):
        """Each decoder owns distinct, detached mapping objects."""
        decoder_a = DecodePDU(False)
        decoder_b = DecodePDU(False)
        assert decoder_a.pdu_table is not decoder_b.pdu_table
        assert decoder_a.pdu_sub_table is not decoder_b.pdu_sub_table
        assert decoder_a.pdu_table is not DecodePDU.pdu_table
        decoder_a.pdu_table[0x71] = (None, None)
        assert 0x71 not in decoder_b.pdu_table
        assert 0x71 not in DecodePDU.pdu_table
