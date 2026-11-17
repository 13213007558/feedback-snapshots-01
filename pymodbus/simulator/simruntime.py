"""Simulator runtime implementation.

**REMARK** This class is internal to the server/simulator,.
"""

from __future__ import annotations

import asyncio
from typing import cast

from ..constants import ExcCodes
from .simdevice import SimDevice
from .simutils import DataType, SimUtils


class SimRuntime:
    """Memory setup for device.

    **Batch write contract**

    The memory datastore treats one call to :meth:`async_setValues` as one
    indivisible batch:

    * ``values`` is the complete payload; its length is the write count.
    * The complete target range is checked before memory is changed. This
      includes the registers used by a bit write that crosses a register
      boundary and undefined ("sparse") register holes.
    * A batch that covers an undefined, sparse, or read-only register is
      rejected as a whole with :attr:`ExcCodes.ILLEGAL_ADDRESS`.
    * The optional ``SimDevice.action`` callback runs against a private
      staging copy of the registers and of ``set_values``. Its changes are
      committed only when it returns ``None`` and does not change the
      number of values.
    * A callback returning an :class:`ExcCodes` member, or raising an
      exception, leaves the memory unchanged. Exceptions are propagated,
      not converted into a successful write.
    * An empty payload is invalid; it is not treated as a read or a no-op.

    This guarantee applies to this in-memory implementation only. An
    adapter that forwards writes to external hardware must not claim this
    guarantee: if the hardware cannot roll back a partially applied batch,
    the adapter must return :attr:`ExcCodes.DEVICE_FAILURE` (exception code
    ``0x04``) and must not report success or a precise address error that
    would imply that nothing was written.
    """

    #: Adapter capability flag; the PDU layer uses it for combined read/write.
    supports_atomic_set_and_get = True

    _fx_mapper = {2: "d", 4: "i"}  # Discrete input and Input registers
    _fx_mapper.update(
        [
            (i, "h")  # Holding registers
            for i in (3, 6, 16, 22, 23)
        ]
    )
    _fx_mapper.update(
        [
            (i, "c")  # Coils
            for i in (1, 5, 15)
        ]
    )

    def __init__(self, device: SimDevice):
        """Build device memory."""
        self.action = device.action
        self.use_bit_addressing = device.use_bit_addressing
        self._lock = asyncio.Lock()
        build = device.build_device()
        self.block: dict[str, tuple[int, int, list[int], list[int]]] = {}
        if not isinstance(build, dict):
            self.block["x"] = (
                build[0],
                len(build[2]),
                build[1],
                build[2],
            )
            return
        for i in ("c", "d", "h", "i"):
            self.block[i] = (build[i][0], len(build[i][1]), build[i][1], build[i][2])

    def __resolve_block(self, func_code: int) -> tuple[str, bool]:
        """Return the block id and whether the function code addresses bits."""
        if (fc_block := self._fx_mapper.get(func_code, "z")) == "z":
            raise AttributeError("Datastore, not supported function code")
        block_id = "x" if "x" in self.block else fc_block
        return block_id, fc_block in {"c", "d"}

    def __preflight(
        self,
        block_id: str,
        count: int,
        offset: int,
        is_write: bool,
    ) -> ExcCodes | None:
        """Check a complete range without changing memory."""
        _, _, __, flags = self.block[block_id]
        for i in range(count):
            flag = flags[offset + i]
            if flag & SimUtils.RunTimeFlag_TYPE == DataType.INVALID:
                return ExcCodes.ILLEGAL_ADDRESS
            if is_write and flag & SimUtils.RunTimeFlag_READONLY:
                return ExcCodes.ILLEGAL_ADDRESS
        return None

    async def __run_action(
        self,
        func_code: int,
        start_address: int,
        address: int,
        count: int,
        registers: list[int],
        values: list[int] | list[bool] | None,
        value_count: int | None = None,
    ) -> ExcCodes | None:
        """Run the optional callback on the supplied staging registers."""
        if not self.action:
            return None
        if result := await self.action(
            func_code, start_address, address, count, registers, values
        ):
            return result
        if values is not None:
            expected = count if value_count is None else value_count
            if not isinstance(values, list) or len(values) != expected:
                return ExcCodes.ILLEGAL_VALUE
        return None

    async def __write_batch(
        self,
        func_code: int,
        address: int,
        values: list[int] | list[bool],
        read_address: int | None = None,
        read_count: int = 0,
    ) -> list[int] | list[bool] | ExcCodes:
        """Apply one batch and optionally read from the committed view.

        This is the single commit point for writes and combined
        write/read requests. The preflight covers the write range and,
        when requested, the read range, before any register is changed.
        The callback runs against a private copy, so a callback failure
        leaves both the memory and the returned read values untouched.

        Without a read range, the values that were committed are returned.
        """
        if not isinstance(values, list) or not values:
            return ExcCodes.ILLEGAL_VALUE
        block_id, is_bits = self.__resolve_block(func_code)
        start_address, register_count, registers, _ = self.block[block_id]
        count = len(values)
        if is_bits:
            offset = (
                int(address / 16) if self.use_bit_addressing else address
            ) - start_address
            bit_offset = address % 16
            reg_count = (bit_offset + count + 15) // 16
            if offset < 0 or offset + reg_count > register_count:
                return ExcCodes.ILLEGAL_ADDRESS
            action_count = reg_count
        else:
            offset = address - start_address
            if offset < 0 or offset + count > register_count:
                return ExcCodes.ILLEGAL_ADDRESS
            action_count = count
        if read_address is not None:
            read_offset = read_address - start_address
            if read_count < 1 or read_offset < 0 or (
                read_offset + read_count > register_count
            ):
                return ExcCodes.ILLEGAL_ADDRESS
        if result := self.__preflight(block_id, action_count, offset, True):
            return result
        if read_address is not None:
            if result := self.__preflight(block_id, read_count, read_offset, False):
                return result

        staged_registers = list(registers)
        staged_values: list[int] | list[bool] = list(values)
        if result := await self.__run_action(
            func_code,
            start_address,
            address,
            action_count,
            staged_registers,
            staged_values,
            count,
        ):
            return result
        if is_bits:
            list_bools = SimUtils.registersToBits(
                staged_registers[offset : offset + reg_count]
            )
            list_bools[bit_offset : bit_offset + count] = staged_values
            staged_registers[offset : offset + reg_count] = SimUtils.bitsToRegisters(
                list_bools
            )
            written_values = list_bools[bit_offset : bit_offset + count]
        else:
            staged_registers[offset : offset + count] = staged_values
            written_values = staged_values
        if read_address is not None and self.action:
            if result := await self.action(
                func_code,
                start_address,
                read_address,
                read_count,
                staged_registers,
                None,
            ):
                return result
        if read_address is not None:
            result_values = staged_registers[read_offset : read_offset + read_count]
        else:
            result_values = written_values
        registers[:] = staged_registers
        return result_values

    async def get_bit_block(
        self,
        block_id: str,
        func_code: int,
        address: int,
        count: int,
        values: list[bool] | None,
    ) -> list[bool] | ExcCodes:
        """Handle coils and discrete input."""
        start_address, register_count, registers, _ = self.block[block_id]
        if values is not None:
            return ExcCodes.ILLEGAL_FUNCTION
        if count < 1:
            return ExcCodes.ILLEGAL_VALUE
        offset = (
            int(address / 16) if self.use_bit_addressing else address
        ) - start_address
        bit_offset = address % 16
        reg_count = (bit_offset + count + 15) // 16
        if offset < 0 or offset + reg_count > register_count:
            return ExcCodes.ILLEGAL_ADDRESS
        if result := self.__preflight(block_id, reg_count, offset, False):
            return result
        if not self.action:
            list_bools = SimUtils.registersToBits(
                registers[offset : offset + reg_count]
            )
            return list_bools[bit_offset : bit_offset + count]
        staged_registers = list(registers)
        if result := await self.__run_action(
            func_code, start_address, address, reg_count, staged_registers, None
        ):
            return result
        list_bools = SimUtils.registersToBits(
            staged_registers[offset : offset + reg_count]
        )
        registers[:] = staged_registers
        return list_bools[bit_offset : bit_offset + count]

    async def get_reg_block(
        self,
        block_id: str,
        func_code: int,
        address: int,
        count: int,
        values: list[int] | None,
    ) -> list[int] | ExcCodes:
        """Handle holding registers and input registers."""
        start_address, register_count, registers, _ = self.block[block_id]
        if values is not None:
            return ExcCodes.ILLEGAL_FUNCTION
        if count < 1:
            return ExcCodes.ILLEGAL_VALUE
        offset = address - start_address
        if offset < 0 or offset + count > register_count:
            return ExcCodes.ILLEGAL_ADDRESS
        if result := self.__preflight(block_id, count, offset, False):
            return result
        if not self.action:
            return registers[offset : offset + count]
        staged_registers = list(registers)
        if result := await self.__run_action(
            func_code, start_address, address, count, staged_registers, None
        ):
            return result
        result_values = staged_registers[offset : offset + count]
        registers[:] = staged_registers
        return result_values

    async def get_block(
        self,
        func_code: int,
        address: int,
        count: int,
        values: list[int] | list[bool] | None,
    ) -> list[int] | list[bool] | ExcCodes:
        """Calculate offset and run the request under the batch lock."""
        block_id, is_bits = self.__resolve_block(func_code)
        if values is not None:
            values = list(values)
            if not values or len(values) != count:
                return ExcCodes.ILLEGAL_VALUE
            return await self.__write_batch(func_code, address, values)
        async with self._lock:
            if is_bits:
                return await self.get_bit_block(
                    block_id, func_code, address, count, cast(list[bool], values)
                )
            return await self.get_reg_block(
                block_id, func_code, address, count, cast(list[int], values)
            )

    async def async_getValues(
        self, func_code: int, address: int, count: int
    ) -> list[int] | list[bool] | ExcCodes:
        """Get `count` values from datastore."""
        return await self.get_block(func_code, address, count, None)

    async def async_setValues(
        self, func_code: int, address: int, values: list[int] | list[bool]
    ) -> ExcCodes | None:
        """Set the datastore with the supplied values as one atomic batch."""
        async with self._lock:
            result = await self.__write_batch(func_code, address, values)
        return result if isinstance(result, ExcCodes) else None

    async def async_setgetValues(
        self,
        func_code: int,
        write_address: int,
        values: list[int] | list[bool],
        read_address: int,
        read_count: int,
    ) -> list[int] | list[bool] | ExcCodes:
        """Write a batch and read from the same committed view."""
        async with self._lock:
            return await self.__write_batch(
                func_code, write_address, values, read_address, read_count
            )
