"""
Explicit limited-range write access for matrix variables.

A `RangedWriteGateway` lets a server operator delegate writes to selected
regions of one- or two-dimensional fixed-size array variables to named
maintenance accounts, without handing those accounts whole-value writes.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import math
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from asyncua import ua
from asyncua.crypto.permission_rules import User, UserRole

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .address_space import AddressSpace

_logger = logging.getLogger(__name__)

IndexBox = tuple[tuple[int, int], ...]


def parse_numeric_range(text: str) -> list[tuple[int, int]]:
    """
    Parse an OPC UA NumericRange string ("2", "1:3", "0:1,2:3") into
    inclusive (low, high) bounds per dimension.
    """
    if not text or not text.strip():
        raise ValueError("index range is empty")
    bounds = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            raise ValueError(f"empty dimension in index range {text!r}")
        low_text, sep, high_text = part.partition(":")
        low = int(low_text)
        high = int(high_text) if sep else low
        if low < 0 or high < 0:
            raise ValueError(f"negative index in index range {text!r}")
        if low > high:
            raise ValueError(f"inverted bounds in index range {text!r}")
        bounds.append((low, high))
    return bounds


def _box_contains(outer: IndexBox, inner: IndexBox) -> bool:
    return len(outer) == len(inner) and all(
        outer_low <= inner_low and inner_high <= outer_high
        for (outer_low, outer_high), (inner_low, inner_high) in zip(outer, inner, strict=True)
    )


class RangedWriteGateway:
    """
    Grants named accounts write access to explicit regions of managed matrix
    variables and applies those writes as atomic read-modify-write cycles, so
    concurrent partial updates cannot clobber each other and regions outside
    the grant are preserved.

    Only one- and two-dimensional fixed-size arrays (ValueRank 1 or 2 with
    matching non-zero ArrayDimensions) can be managed. A write to a managed
    node by a non-admin user must carry an explicit, bounded IndexRange that
    is contained in one of the account's granted regions; anything else is
    rejected before the current value is read or modified.
    """

    def __init__(self, aspace: AddressSpace) -> None:
        self._aspace = aspace
        self._grants: dict[ua.NodeId, dict[str, list[IndexBox]]] = {}
        self._locks: dict[ua.NodeId, asyncio.Lock] = {}
        aspace.ranged_write_gateway = self

    def grant(self, nodeid: ua.NodeId, username: str, ranges: Iterable[str]) -> None:
        shape = self._node_shape(nodeid)
        if shape is None:
            raise ValueError(f"node {nodeid} is not a one- or two-dimensional fixed-size array")
        rank, dims = shape
        boxes = []
        for text in ranges:
            box = tuple(parse_numeric_range(text))
            self._check_box(nodeid, box, rank, dims)
            boxes.append(box)
        self._grants.setdefault(nodeid, {})[username] = boxes

    def revoke(self, nodeid: ua.NodeId, username: str | None = None) -> None:
        if username is None:
            self._grants.pop(nodeid, None)
        elif nodeid in self._grants:
            self._grants[nodeid].pop(username, None)
            if not self._grants[nodeid]:
                del self._grants[nodeid]

    def is_managed(self, nodeid: ua.NodeId) -> bool:
        return nodeid in self._grants

    async def try_write(self, writevalue: ua.WriteValue, user: User) -> ua.StatusCode | None:
        """
        Handle a Value write targeting a managed node from a non-admin user.
        Return None to let the default write path process the request.
        """
        node_grants = self._grants.get(writevalue.NodeId)
        if node_grants is None or user.role == UserRole.Admin:
            return None
        return await self._write_region(writevalue, node_grants, user)

    async def _write_region(
        self, writevalue: ua.WriteValue, node_grants: dict[str, list[IndexBox]], user: User
    ) -> ua.StatusCode:
        nodeid = writevalue.NodeId
        granted = node_grants.get(user.name) if user.name else None
        if not granted:
            return ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)
        try:
            box = tuple(parse_numeric_range(writevalue.IndexRange or ""))
        except ValueError:
            return ua.StatusCode(ua.StatusCodes.BadIndexRangeInvalid)
        shape = self._node_shape(nodeid)
        if shape is None:
            return ua.StatusCode(ua.StatusCodes.BadWriteNotSupported)
        rank, dims = shape
        if len(box) != rank or any(high >= dim for (_, high), dim in zip(box, dims, strict=True)):
            return ua.StatusCode(ua.StatusCodes.BadIndexRangeInvalid)
        if not any(_box_contains(outer, box) for outer in granted):
            return ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)
        variant = writevalue.Value.Value
        count = math.prod(high - low + 1 for low, high in box)
        if variant is None or not isinstance(variant.Value, list) or len(variant.Value) != count:
            return ua.StatusCode(ua.StatusCodes.BadIndexRangeDataMismatch)
        async with self._locks.setdefault(nodeid, asyncio.Lock()):
            return await self._merge_and_write(nodeid, writevalue, box, dims, variant)

    async def _merge_and_write(
        self,
        nodeid: ua.NodeId,
        writevalue: ua.WriteValue,
        box: IndexBox,
        dims: list[int],
        variant: ua.Variant,
    ) -> ua.StatusCode:
        current = self._aspace.read_attribute_value(nodeid, ua.AttributeIds.Value)
        if current.StatusCode is not None and current.StatusCode.is_bad():
            return current.StatusCode
        current_variant = current.Value
        if current_variant is None or not isinstance(current_variant.Value, list):
            return ua.StatusCode(ua.StatusCodes.BadIndexRangeNoData)
        merged = list(current_variant.Value)
        if len(merged) != math.prod(dims):
            return ua.StatusCode(ua.StatusCodes.BadIndexRangeNoData)
        if variant.VariantType != current_variant.VariantType:
            return ua.StatusCode(ua.StatusCodes.BadTypeMismatch)
        if len(box) == 1:
            (low, high) = box[0]
            merged[low : high + 1] = variant.Value
        else:
            (row_low, row_high), (col_low, col_high) = box
            columns = dims[1]
            offset = 0
            for row in range(row_low, row_high + 1):
                start = row * columns + col_low
                width = col_high - col_low + 1
                merged[start : start + width] = variant.Value[offset : offset + width]
                offset += width
        dv = writevalue.Value
        if self._aspace.force_server_timestamp:
            dv = dataclasses.replace(dv, ServerTimestamp=datetime.now(UTC), ServerPicoseconds=None)
        dv = dataclasses.replace(dv, Value=ua.Variant(merged, current_variant.VariantType))
        await self._before_write_back(nodeid)
        try:
            return await self._aspace.write_attribute_value(nodeid, ua.AttributeIds.Value, dv)
        except Exception:
            _logger.exception("write-back of merged region failed for node %s; stored value left unchanged", nodeid)
            return ua.StatusCode(ua.StatusCodes.BadInternalError)

    async def _before_write_back(self, nodeid: ua.NodeId) -> None:
        """
        Extension point invoked with the per-node lock held, after the merged
        matrix has been computed and before it is written back.
        """

    @staticmethod
    def _check_box(nodeid: ua.NodeId, box: IndexBox, rank: int, dims: list[int]) -> None:
        if len(box) != rank:
            raise ValueError(f"range for node {nodeid} has {len(box)} dimensions, expected {rank}")
        if any(high >= dim for (_, high), dim in zip(box, dims, strict=True)):
            raise ValueError(f"range for node {nodeid} exceeds array dimensions {dims}")

    def _node_shape(self, nodeid: ua.NodeId) -> tuple[int, list[int]] | None:
        rank_dv = self._aspace.read_attribute_value(nodeid, ua.AttributeIds.ValueRank)
        dims_dv = self._aspace.read_attribute_value(nodeid, ua.AttributeIds.ArrayDimensions)
        if rank_dv.Value is None or dims_dv.Value is None:
            return None
        rank = rank_dv.Value.Value
        dims = dims_dv.Value.Value
        if rank not in (ua.ValueRank.OneDimension, ua.ValueRank.TwoDimensions):
            return None
        if not isinstance(dims, list) or len(dims) != rank or any(not isinstance(d, int) or d <= 0 for d in dims):
            return None
        return int(rank), dims
