import asyncio
from collections.abc import AsyncIterator

import pytest

from asyncua import Server, ua
from asyncua.common.node import Node
from asyncua.crypto.permission_rules import User, UserRole
from asyncua.server.address_space import AddressSpace
from asyncua.server.internal_session import InternalSession
from asyncua.server.ranged_write import RangedWriteGateway, parse_numeric_range


class SlowGateway(RangedWriteGateway):
    def __init__(self, aspace: AddressSpace, delay: float) -> None:
        super().__init__(aspace)
        self._delay = delay

    async def _before_write_back(self, nodeid: ua.NodeId) -> None:
        await asyncio.sleep(self._delay)


@pytest.fixture
async def gateway_server() -> AsyncIterator[tuple[Server, RangedWriteGateway, Node, Node, Node]]:
    server = Server()
    await server.init()
    idx = await server.register_namespace("urn:example:matrix")
    vector = await server.nodes.objects.add_variable(idx, "Vector", [0] * 6, ua.VariantType.Int32)
    await vector.write_value_rank(ua.ValueRank.OneDimension)
    await vector.write_attribute(ua.AttributeIds.ArrayDimensions, ua.DataValue(ua.Variant([6], ua.VariantType.UInt32)))
    await vector.set_writable(True)
    matrix = await server.nodes.objects.add_variable(idx, "Matrix", [0] * 12, ua.VariantType.Int32)
    await matrix.write_value_rank(ua.ValueRank.TwoDimensions)
    await matrix.write_attribute(
        ua.AttributeIds.ArrayDimensions, ua.DataValue(ua.Variant([3, 4], ua.VariantType.UInt32))
    )
    await matrix.set_writable(True)
    plain = await server.nodes.objects.add_variable(idx, "Plain", [0] * 4, ua.VariantType.Int32)
    await plain.write_value_rank(ua.ValueRank.OneDimension)
    await plain.write_attribute(ua.AttributeIds.ArrayDimensions, ua.DataValue(ua.Variant([4], ua.VariantType.UInt32)))
    await plain.set_writable(True)
    gateway = RangedWriteGateway(server.iserver.aspace)
    yield server, gateway, vector, matrix, plain
    await server.stop()


def make_session(server: Server, name: str) -> InternalSession:
    return server.iserver.create_session(name, user=User(role=UserRole.User, name=name))


async def write_region(
    session: InternalSession,
    node: Node,
    index_range: str | None,
    values: object,
    varianttype: ua.VariantType = ua.VariantType.Int32,
) -> ua.StatusCode:
    wv = ua.WriteValue()
    wv.NodeId = node.nodeid
    wv.AttributeId = ua.AttributeIds.Value
    wv.IndexRange = index_range
    wv.Value = ua.DataValue(ua.Variant(values, varianttype))
    params = ua.WriteParameters()
    params.NodesToWrite = [wv]
    results = await session.write(params)
    return results[0]


def test_parse_numeric_range() -> None:
    assert parse_numeric_range("3") == [(3, 3)]
    assert parse_numeric_range("1:4") == [(1, 4)]
    assert parse_numeric_range("0:1,2:3") == [(0, 1), (2, 3)]
    assert parse_numeric_range(" 2 , 5:6 ") == [(2, 2), (5, 6)]
    for bad in ("", "  ", "a", "1:x", "1:2:3", "3:1", "-1:2", "1,,2", ","):
        with pytest.raises(ValueError):
            parse_numeric_range(bad)


async def test_grant_requires_fixed_size_matrix(gateway_server) -> None:
    server, gateway, vector, matrix, _ = gateway_server
    scalar = await server.nodes.objects.add_variable(2, "Scalar", 1, ua.VariantType.Int32)
    with pytest.raises(ValueError):
        gateway.grant(scalar.nodeid, "alice", ["0:0"])
    with pytest.raises(ValueError):
        gateway.grant(matrix.nodeid, "alice", ["0:1,0:1,0:1"])
    with pytest.raises(ValueError):
        gateway.grant(matrix.nodeid, "alice", ["0:2,0:4"])
    with pytest.raises(ValueError):
        gateway.grant(vector.nodeid, "alice", ["0:6"])
    gateway.grant(vector.nodeid, "alice", ["0:5"])
    assert gateway.is_managed(vector.nodeid)
    gateway.revoke(vector.nodeid, "alice")
    assert not gateway.is_managed(vector.nodeid)


async def test_partial_write_1d(gateway_server) -> None:
    server, gateway, vector, _, _ = gateway_server
    gateway.grant(vector.nodeid, "alice", ["1:2"])
    session = make_session(server, "alice")
    status = await write_region(session, vector, "1:2", [7, 9])
    assert status.is_good()
    assert await vector.read_value() == [0, 7, 9, 0, 0, 0]


async def test_partial_write_2d_preserves_neighbours(gateway_server) -> None:
    server, gateway, _, matrix, _ = gateway_server
    gateway.grant(matrix.nodeid, "alice", ["0:1,1:2"])
    session = make_session(server, "alice")
    status = await write_region(session, matrix, "0:1,1:2", [11, 12, 15, 16])
    assert status.is_good()
    assert await matrix.read_value() == [0, 11, 12, 0, 0, 15, 16, 0, 0, 0, 0, 0]


async def test_single_element_range(gateway_server) -> None:
    server, gateway, _, matrix, _ = gateway_server
    gateway.grant(matrix.nodeid, "alice", ["2:2,3:3"])
    session = make_session(server, "alice")
    status = await write_region(session, matrix, "2:2,3:3", [99])
    assert status.is_good()
    values = await matrix.read_value()
    assert values[11] == 99
    assert sum(1 for v in values if v != 0) == 1


async def test_unauthorized_user_and_range(gateway_server) -> None:
    server, gateway, _, matrix, _ = gateway_server
    gateway.grant(matrix.nodeid, "alice", ["0:0,0:3"])
    bob = make_session(server, "bob")
    status = await write_region(bob, matrix, "0:0,0:1", [1, 2])
    assert status.value == ua.StatusCodes.BadUserAccessDenied
    alice = make_session(server, "alice")
    status = await write_region(alice, matrix, "1:1,0:3", [1, 2, 3, 4])
    assert status.value == ua.StatusCodes.BadUserAccessDenied
    assert await matrix.read_value() == [0] * 12


async def test_empty_and_missing_index_range(gateway_server) -> None:
    server, gateway, _, matrix, _ = gateway_server
    gateway.grant(matrix.nodeid, "alice", ["0:2,0:3"])
    session = make_session(server, "alice")
    for index_range in (None, ""):
        status = await write_region(session, matrix, index_range, [1] * 12)
        assert status.value == ua.StatusCodes.BadIndexRangeInvalid
    assert await matrix.read_value() == [0] * 12


async def test_dimension_count_mismatch(gateway_server) -> None:
    server, gateway, _, matrix, _ = gateway_server
    gateway.grant(matrix.nodeid, "alice", ["0:2,0:3"])
    session = make_session(server, "alice")
    status = await write_region(session, matrix, "0:1,0:1,0:1", [1, 2, 3, 4, 5, 6, 7, 8])
    assert status.value == ua.StatusCodes.BadIndexRangeInvalid
    status = await write_region(session, matrix, "0:1", [1, 2])
    assert status.value == ua.StatusCodes.BadIndexRangeInvalid
    assert await matrix.read_value() == [0] * 12


async def test_out_of_bounds(gateway_server) -> None:
    server, gateway, _, matrix, _ = gateway_server
    gateway.grant(matrix.nodeid, "alice", ["0:2,0:3"])
    session = make_session(server, "alice")
    status = await write_region(session, matrix, "0:2,0:4", [1] * 15)
    assert status.value == ua.StatusCodes.BadIndexRangeInvalid
    status = await write_region(session, matrix, "3:3,0:0", [1])
    assert status.value == ua.StatusCodes.BadIndexRangeInvalid
    assert await matrix.read_value() == [0] * 12


async def test_forged_shape(gateway_server) -> None:
    server, gateway, _, matrix, _ = gateway_server
    gateway.grant(matrix.nodeid, "alice", ["0:1,0:1"])
    session = make_session(server, "alice")
    status = await write_region(session, matrix, "0:1,0:1", [1, 2, 3])
    assert status.value == ua.StatusCodes.BadIndexRangeDataMismatch
    status = await write_region(session, matrix, "0:1,0:1", [1, 2, 3, 4, 5])
    assert status.value == ua.StatusCodes.BadIndexRangeDataMismatch
    status = await write_region(session, matrix, "0:1,0:1", 5)
    assert status.value == ua.StatusCodes.BadIndexRangeDataMismatch
    status = await write_region(session, matrix, "0:1,0:1", [1.0, 2.0, 3.0, 4.0], ua.VariantType.Double)
    assert status.value == ua.StatusCodes.BadTypeMismatch
    assert await matrix.read_value() == [0] * 12


async def test_index_range_on_unmanaged_node(gateway_server) -> None:
    server, gateway, _, _, plain = gateway_server
    session = make_session(server, "alice")
    status = await write_region(session, plain, "0:1", [1, 2])
    assert status.value == ua.StatusCodes.BadWriteNotSupported
    assert await plain.read_value() == [0] * 4


async def test_admin_whole_value_write_still_works(gateway_server) -> None:
    server, gateway, _, matrix, _ = gateway_server
    gateway.grant(matrix.nodeid, "alice", ["0:0,0:3"])
    await matrix.write_value(list(range(12)), ua.VariantType.Int32)
    assert await matrix.read_value() == list(range(12))


async def test_concurrent_disjoint_writes(gateway_server) -> None:
    server, _, _, matrix, _ = gateway_server
    slow = SlowGateway(server.iserver.aspace, delay=0.05)
    slow.grant(matrix.nodeid, "alice", ["0:0,0:3"])
    slow.grant(matrix.nodeid, "bob", ["2:2,0:3"])
    alice = make_session(server, "alice")
    bob = make_session(server, "bob")
    status_a, status_b = await asyncio.gather(
        write_region(alice, matrix, "0:0,0:3", [101, 102, 103, 104]),
        write_region(bob, matrix, "2:2,0:3", [201, 202, 203, 204]),
    )
    assert status_a.is_good()
    assert status_b.is_good()
    assert await matrix.read_value() == [101, 102, 103, 104, 0, 0, 0, 0, 201, 202, 203, 204]


async def test_write_back_failure_leaves_value_unchanged(gateway_server) -> None:
    server, gateway, _, matrix, _ = gateway_server
    gateway.grant(matrix.nodeid, "alice", ["0:0,0:1"])

    def broken_setter(node, attr, value) -> None:
        raise RuntimeError("device callback failed")

    server.iserver.aspace.set_attribute_value_setter(matrix.nodeid, ua.AttributeIds.Value, broken_setter)
    session = make_session(server, "alice")
    status = await write_region(session, matrix, "0:0,0:1", [5, 6])
    assert status.value == ua.StatusCodes.BadInternalError
    assert await matrix.read_value() == [0] * 12
