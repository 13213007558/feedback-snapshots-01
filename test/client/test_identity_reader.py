"""Tests for the bounded, integrity-reporting device identity reader.

The transport is replaced by a scripted double so the reader can be driven
with well-formed multi-page replies as well as hostile ones (never-ending
``More Follows``, non-advancing object ids, changing access levels). The
double records every request, which lets the tests assert the actual number
of Modbus exchanges the bounded reader performed.
"""

import pytest

from pymodbus.client.identity import (
    DeviceIdentityResult,
    IdentityConflictCode,
    IdentityReadLimits,
    read_device_identity,
    read_device_identity_sync,
)
from pymodbus.constants import DeviceInformation, MoreData
from pymodbus.pdu import ExceptionResponse, ModbusPDU
from pymodbus.pdu.mei_message import (
    ReadDeviceInformationRequest,
    ReadDeviceInformationResponse,
)


def _make_response(
    objects: dict[int, bytes | list[bytes]],
    *,
    read_code: int = DeviceInformation.BASIC,
    more_follows: int = MoreData.NOTHING,
    next_object_id: int = 0,
    declared_count: int | None = None,
) -> ReadDeviceInformationResponse:
    """Build a response from raw wire bytes to keep full header control."""
    count = sum(len(v) if isinstance(v, list) else 1 for v in objects.values())
    body = b""
    for object_id, value in objects.items():
        values = value if isinstance(value, list) else [value]
        for item in values:
            body += bytes([object_id, len(item)]) + item
    header = bytes(
        [
            ReadDeviceInformationResponse.sub_function_code,
            read_code,
            0x83,  # conformity
            more_follows,
            next_object_id,
            count if declared_count is None else declared_count,
        ]
    )
    response = ReadDeviceInformationResponse(read_code=0, information={})
    response.x_decode(header + body)
    return response


class ScriptedIdentityTransport:
    """Transport double returning scripted responses and logging requests."""

    def __init__(self, responses: list[ModbusPDU]) -> None:
        """Queue the scripted responses."""
        self._responses = list(responses)
        self.requests: list[ReadDeviceInformationRequest] = []
        self.request_count = 0

    async def __call__(self, request: ModbusPDU) -> ModbusPDU:
        """Serve one request and record it."""
        self.request_count += 1
        assert isinstance(request, ReadDeviceInformationRequest)
        self.requests.append(request)
        if not self._responses:
            raise AssertionError("transport called more times than scripted")
        return self._responses.pop(0)

    @property
    def requested_object_ids(self) -> list[int]:
        """Object ids the reader asked for, in request order."""
        return [request.object_id for request in self.requests]


class SyncScriptedIdentityTransport:
    """Synchronous transport double."""

    def __init__(self, responses: list[ModbusPDU]) -> None:
        """Queue the scripted responses."""
        self._responses = list(responses)
        self.request_count = 0

    def __call__(self, request: ModbusPDU) -> ModbusPDU:
        """Serve one request and record it."""
        self.request_count += 1
        assert isinstance(request, ReadDeviceInformationRequest)
        if not self._responses:
            raise AssertionError("transport called more times than scripted")
        return self._responses.pop(0)


class TestIdentityReader:
    """Bounded device identity read behavior."""

    async def test_normal_multi_page_is_complete(self):
        """A clean two-page read verifies the chain and reports complete."""
        page1 = _make_response(
            {0x00: b"Vendor", 0x01: b"Product"},
            more_follows=MoreData.KEEP_READING,
            next_object_id=0x02,
        )
        page2 = _make_response({0x02: b"1.0", 0x03: b"url"})
        transport = ScriptedIdentityTransport([page1, page2])

        result = await read_device_identity(
            transport, read_code=DeviceInformation.BASIC
        )

        assert isinstance(result, DeviceIdentityResult)
        assert result.complete is True
        assert result.conflicts == []
        assert result.pages_requested == 2
        assert transport.request_count == 2
        # The second request must follow the endpoint's next object id.
        assert transport.requested_object_ids == [0x00, 0x02]
        assert result.information == {
            0x00: b"Vendor",
            0x01: b"Product",
            0x02: b"1.0",
            0x03: b"url",
        }
        # Every declared object matched the parsed objects on both pages.
        assert all(
            evidence.claimed_object_count == evidence.object_count
            and evidence.locally_verified_continuation
            for evidence in result.page_evidence
        )
        # Endpoint claim and local proof agree for a clean chain.
        assert result.claimed_more_follows == MoreData.NOTHING

    async def test_endless_more_follows_is_bounded_and_partial(self):
        """An endpoint that never clears More Follows is stopped by the cap.

        The hostile endpoint keeps returning fresh, advancing object ids while
        asserting More Follows forever, so only the caller's page cap can stop
        it. No overlap occurs; the cap alone must bound the exchanges.
        """
        endless_pages = [
            _make_response(
                {oid: f"obj{oid}".encode()},
                more_follows=MoreData.KEEP_READING,
                next_object_id=oid + 1,
            )
            for oid in range(10)
        ]
        transport = ScriptedIdentityTransport(endless_pages)
        limits = IdentityReadLimits(max_pages=3, max_identity_bytes=4096)

        result = await read_device_identity(
            transport, read_code=DeviceInformation.BASIC, limits=limits
        )

        assert result.complete is False
        assert result.limit_reached is True
        assert transport.request_count == 3
        assert result.pages_requested == 3
        conflict_codes = {conflict.code for conflict in result.conflicts}
        assert conflict_codes == {IdentityConflictCode.PAGE_LIMIT_REACHED}
        # The advancing chain itself was locally valid up to the forced stop.
        assert all(
            evidence.locally_verified_continuation for evidence in result.page_evidence
        )
        # The three already fetched objects are retained, never presented whole.
        assert sorted(result.information) == [0, 1, 2]

    async def test_no_progress_stops_without_hitting_page_cap(self):
        """A repeated next object id terminates the loop early, bounded."""
        page1 = _make_response(
            {0x00: b"Vendor"},
            more_follows=MoreData.KEEP_READING,
            next_object_id=0x00,
        )
        page2 = _make_response(
            {0x00: b"Vendor"},
            more_follows=MoreData.KEEP_READING,
            next_object_id=0x00,
        )
        transport = ScriptedIdentityTransport([page1, page2])
        limits = IdentityReadLimits(max_pages=8, max_identity_bytes=4096)

        result = await read_device_identity(
            transport, read_code=DeviceInformation.BASIC, limits=limits
        )

        assert result.complete is False
        # The reader detected the loop after the overlapping page instead of
        # burning through all eight permitted pages.
        assert transport.request_count == 2
        assert result.pages_requested == 2
        assert result.limit_reached is False
        assert IdentityConflictCode.NO_PROGRESS in {
            conflict.code for conflict in result.conflicts
        }

    async def test_non_monotonic_id_within_page_is_no_progress(self):
        """Distinct ids that decrease inside one page fail monotonicity."""
        # Object id 0x02 arrives before 0x01 on the same page.
        page = _make_response({0x00: b"Vendor", 0x02: b"rev", 0x01: b"Product"})
        transport = ScriptedIdentityTransport([page])

        result = await read_device_identity(
            transport, read_code=DeviceInformation.BASIC
        )

        assert result.complete is False
        conflict = next(
            conflict
            for conflict in result.conflicts
            if conflict.code == IdentityConflictCode.NO_PROGRESS
        )
        assert conflict.object_id == 0x01
        assert result.page_evidence[0].locally_verified_continuation is False

    async def test_repeated_id_on_one_page_is_kept_not_conflicted(self):
        """Repeated values for one id on the same page are legal and retained."""
        page = _make_response(
            {0x81: [b"first", b"second"]}, read_code=DeviceInformation.EXTENDED
        )
        transport = ScriptedIdentityTransport([page])

        result = await read_device_identity(
            transport, read_code=DeviceInformation.EXTENDED
        )

        assert result.complete is True
        assert result.information[0x81] == [b"first", b"second"]
        assert result.conflicts == []

    async def test_access_level_change_is_flagged(self):
        """A response that changes read code is recorded as a conflict."""
        page1 = _make_response(
            {0x00: b"Vendor"},
            read_code=DeviceInformation.BASIC,
            more_follows=MoreData.KEEP_READING,
            next_object_id=0x01,
        )
        page2 = _make_response({0x01: b"Product"}, read_code=DeviceInformation.EXTENDED)
        transport = ScriptedIdentityTransport([page1, page2])

        result = await read_device_identity(
            transport, read_code=DeviceInformation.BASIC
        )

        assert result.complete is False
        conflict = next(
            conflict
            for conflict in result.conflicts
            if conflict.code == IdentityConflictCode.ACCESS_LEVEL_CHANGED
        )
        assert conflict.page == 2
        # The objects are still collected, but the profile is not trusted whole.
        assert result.information[0x00] == b"Vendor"
        assert result.information[0x01] == b"Product"

    async def test_object_count_mismatch_is_reported(self):
        """A declared object count that disagrees with the frame is a conflict."""
        lying = _make_response({0x00: b"Vendor"}, declared_count=9)
        transport = ScriptedIdentityTransport([lying])

        result = await read_device_identity(
            transport, read_code=DeviceInformation.BASIC
        )

        assert result.complete is False
        assert IdentityConflictCode.OBJECT_COUNT_MISMATCH in {
            conflict.code for conflict in result.conflicts
        }
        evidence = result.page_evidence[0]
        assert evidence.claimed_object_count == 9
        assert evidence.object_count == 1

    async def test_byte_cap_returns_partial_identity(self):
        """Reaching the byte bound keeps collected objects but is partial."""
        page1 = _make_response(
            {0x00: b"abcdefghij"},
            more_follows=MoreData.KEEP_READING,
            next_object_id=0x01,
        )
        page2 = _make_response({0x01: b"klmnopqrst"})
        transport = ScriptedIdentityTransport([page1, page2])
        limits = IdentityReadLimits(max_pages=8, max_identity_bytes=15)

        result = await read_device_identity(
            transport, read_code=DeviceInformation.BASIC, limits=limits
        )

        assert result.complete is False
        assert result.identity_bytes == 20
        assert result.limit_reached is True
        assert IdentityConflictCode.BYTE_LIMIT_REACHED in {
            conflict.code for conflict in result.conflicts
        }
        assert 0x00 in result.information

    async def test_exception_response_is_partial(self):
        """A Modbus exception response ends the read as a conflict."""
        transport = ScriptedIdentityTransport(
            [ExceptionResponse(function_code=0x2B, exception_code=0x02)]
        )

        result = await read_device_identity(
            transport, read_code=DeviceInformation.BASIC
        )

        assert result.complete is False
        assert transport.request_count == 1
        assert result.conflicts[0].code == IdentityConflictCode.EXCEPTION_RESPONSE

    async def test_claim_vs_local_evidence_are_distinct(self):
        """Endpoint headers are stored separately from locally proven links."""
        page1 = _make_response(
            {0x00: b"Vendor", 0x01: b"Product"},
            more_follows=MoreData.KEEP_READING,
            next_object_id=0x02,
        )
        page2 = _make_response({0x02: b"1.0"})
        transport = ScriptedIdentityTransport([page1, page2])

        result = await read_device_identity(
            transport, read_code=DeviceInformation.BASIC
        )

        assert result.complete is True
        page1_evidence, page2_evidence = result.page_evidence
        # What the endpoint claimed on each response header.
        assert page1_evidence.claimed_more_follows == MoreData.KEEP_READING
        assert page1_evidence.claimed_next_object_id == 0x02
        assert page2_evidence.claimed_more_follows == MoreData.NOTHING
        # What local validation proved about the page-to-page relationship.
        assert page1_evidence.locally_verified_continuation is True
        assert page2_evidence.locally_verified_continuation is True

    def test_invalid_limits_are_rejected(self):
        """Caller bounds must be positive."""
        with pytest.raises(ValueError, match="max_pages"):
            IdentityReadLimits(max_pages=0)
        with pytest.raises(ValueError, match="max_identity_bytes"):
            IdentityReadLimits(max_identity_bytes=0)

    def test_sync_transport_records_request_count(self):
        """The synchronous entry runs the same bounded state machine."""
        page1 = _make_response(
            {0x00: b"Vendor"},
            more_follows=MoreData.KEEP_READING,
            next_object_id=0x01,
        )
        page2 = _make_response({0x01: b"Product"})
        transport = SyncScriptedIdentityTransport([page1, page2])

        result = read_device_identity_sync(transport, read_code=DeviceInformation.BASIC)

        assert result.complete is True
        assert transport.request_count == 2
        assert result.pages_requested == 2

    async def test_plugs_into_real_client_execute(self):
        """A real client's execute coroutine can be wrapped as the transport."""

        class FakeClient:
            """Minimal stand-in exposing the async client execute signature."""

            def __init__(self, responses: list[ModbusPDU]) -> None:
                self._responses = list(responses)
                self.sent: list[ModbusPDU] = []

            async def execute(
                self, no_response_expected: bool, request: ModbusPDU
            ) -> ModbusPDU:
                assert no_response_expected is False
                self.sent.append(request)
                return self._responses.pop(0)

        client = FakeClient(
            [
                _make_response(
                    {0x00: b"Vendor"},
                    more_follows=MoreData.KEEP_READING,
                    next_object_id=0x01,
                ),
                _make_response({0x01: b"Product"}),
            ]
        )

        async def transport(request: ModbusPDU) -> ModbusPDU:
            return await client.execute(False, request)

        result = await read_device_identity(
            transport, read_code=DeviceInformation.BASIC
        )

        assert result.complete is True
        assert len(client.sent) == 2
        assert all(
            isinstance(sent, ReadDeviceInformationRequest) for sent in client.sent
        )
        assert [sent.object_id for sent in client.sent] == [0x00, 0x01]
