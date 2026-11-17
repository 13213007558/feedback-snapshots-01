"""Test SimCore."""

import pytest

from pymodbus.constants import ExcCodes
from pymodbus.simulator import DataType, SimData, SimDevice
from pymodbus.simulator.simruntime import SimRuntime


class TestSimRuntime:
    """Test simulator runtime component."""

    async def my_action(
        self,
        function_code,
        _start_address,
        _address,
        _count,
        current_registers,
        set_values,
    ):
        """Run action."""
        if function_code in {1, 3}:
            current_registers[1] = 17
        if function_code in {2, 4}:
            return ExcCodes.ILLEGAL_ADDRESS
        elif function_code == 15:
            set_values[0] = False
        elif function_code == 16:
            set_values[0] = 17

    sd_block = (
        [
            SimData(0, values=[14], datatype=DataType.BITS),
            SimData(16, values=[15], readonly=True, datatype=DataType.BITS),
            SimData(32, values=[16], datatype=DataType.BITS),
        ],
        [
            SimData(0, values=[14], datatype=DataType.BITS),
            SimData(16, values=[15], readonly=True, datatype=DataType.BITS),
            SimData(32, values=[16], datatype=DataType.BITS),
        ],
        [
            SimData(0, values=[14], datatype=DataType.REGISTERS),
            SimData(1, values=[15], readonly=True, datatype=DataType.REGISTERS),
            SimData(2, values=[16], datatype=DataType.REGISTERS),
        ],
        [
            SimData(0, values=[14], datatype=DataType.REGISTERS),
            SimData(1, values=[15], readonly=True, datatype=DataType.REGISTERS),
            SimData(2, values=[16], datatype=DataType.REGISTERS),
        ],
    )
    sd_shared = [
        SimData(0, datatype=DataType.REGISTERS, values=[14]),
        SimData(1, readonly=True, datatype=DataType.REGISTERS, values=[15]),
        SimData(2, datatype=DataType.REGISTERS, values=[16]),
    ]
    block_ids = {1: "c", 2: "d", 3: "h", 4: "i", 15: "c", 16: "h"}

    def test_simruntime_instanciate(self):
        """Test that simdata can be objects."""
        SimRuntime(SimDevice(0, self.sd_block))
        SimRuntime(SimDevice(0, self.sd_shared))

    @pytest.mark.parametrize("block", [False, True])
    @pytest.mark.parametrize("fc", range(1, 25))
    async def test_simruntime_fc(self, fc, block):
        """Test that simdata can be objects."""
        sd = SimDevice(1, simdata=(self.sd_block if block else self.sd_shared))
        rt = SimRuntime(sd)
        if fc in (1, 2, 3, 4, 5, 6, 15, 16, 22, 23):
            ret = await rt.get_block(fc, 1, 1, None)
            assert not isinstance(ret, ExcCodes)
        else:
            with pytest.raises(AttributeError):
                await rt.get_block(fc, 1, 1, None)

    @pytest.mark.parametrize("block", [True, False])
    @pytest.mark.parametrize(
        ("fc", "values", "expect"),
        [
            (1, None, [14, 17, 16, 0]),
            (3, None, [14, 17, 16, 0]),
            (4, None, -1),
            (2, None, -1),
            (15, [True, False], [12, 15, 16, 0]),
            (16, [12], [17, 15, 16, 0]),
        ],
    )
    async def test_simruntime_action(self, block, fc, values, expect):
        """Test that simdata can be objects."""
        rt = SimRuntime(
            SimDevice(
                1,
                action=self.my_action,
                simdata=(self.sd_block if block else self.sd_shared),
            )
        )
        block_id = self.block_ids[fc] if block else "x"
        count = len(values) if values else 2
        ret = await rt.get_block(fc, 0, count, values)
        if expect == -1:
            assert ret == ExcCodes.ILLEGAL_ADDRESS
        else:
            assert rt.block[block_id][2] == expect

    @pytest.mark.parametrize("block", [True, False])
    @pytest.mark.parametrize(
        ("fc", "addr", "count", "values", "expect"),
        [
            (1, 0, 2, None, [False, True]),
            (1, 0, 17, None, [False] + [True] * 3 + [False] * 12 + [True]),
            (2, 0, 2, None, [False, True]),
            (3, 0, 2, None, [14, 15]),
            (4, 0, 2, None, [14, 15]),
            (15, 0, 2, [True, False], [True, False]),
            (16, 0, 1, [12], [12]),
            (99, 0, 2, None, AttributeError),
            (3, 15, 2, None, ExcCodes.ILLEGAL_ADDRESS),
            (3, 2, 2, None, ExcCodes.ILLEGAL_ADDRESS),
            (16, 2, 2, [12, 12], ExcCodes.ILLEGAL_ADDRESS),
            (16, 1, 1, [12], ExcCodes.ILLEGAL_ADDRESS),
            (1, 64, 2, None, ExcCodes.ILLEGAL_ADDRESS),
            (15, 48, 17, [True] * 17, ExcCodes.ILLEGAL_ADDRESS),
        ],
    )
    async def test_simruntime_block(self, block, fc, addr, count, values, expect):
        """Test that simdata can be objects."""
        rt = SimRuntime(
            SimDevice(1, simdata=(self.sd_block if block else self.sd_shared))
        )
        if not isinstance(expect, list) and expect in {AttributeError}:
            with pytest.raises(expect):
                await rt.get_block(fc, addr, count, values)
        else:
            ret = await rt.get_block(fc, addr, count, values)
            assert ret == expect

    async def test_simruntime_getValues(self):
        """Test that simdata can be objects."""
        sd = SimDevice(0, simdata=SimData(10, values=15, datatype=DataType.REGISTERS))
        rt = SimRuntime(sd)
        result = await rt.async_getValues(0x03, 10, 1)
        assert result == [15]
        result = await rt.async_getValues(0x03, 8, 1)
        assert isinstance(result, ExcCodes)
        result = await rt.async_getValues(0x03, 9, 1)
        assert isinstance(result, ExcCodes)
        result = await rt.async_getValues(0x03, 11, 1)
        assert isinstance(result, ExcCodes)
        result = await rt.async_getValues(0x03, 12, 1)
        assert isinstance(result, ExcCodes)
        result = await rt.async_getValues(0x03, 15, 1)
        assert isinstance(result, ExcCodes)

    async def test_simruntime_setValues(self):
        """Test that simdata can be objects."""
        sd = SimDevice(0, simdata=SimData(10, values=15, datatype=DataType.REGISTERS))
        rt = SimRuntime(sd)
        result = await rt.async_setValues(0x03, 10, [1])
        assert not result
        result2 = await rt.async_getValues(0x03, 10, 1)
        assert result2 == [1]
        result3 = await rt.async_setValues(0x03, 15, [1])
        assert isinstance(result3, ExcCodes)


class TestSimRuntimeBatchContract:
    """Batch write contract of the in-memory datastore."""

    @staticmethod
    def make_runtime(action=None):
        """Two safe adjacent thresholds followed by a read-only guard."""
        return SimRuntime(
            SimDevice(
                1,
                simdata=[
                    SimData(10, values=10, datatype=DataType.REGISTERS),
                    SimData(11, values=20, datatype=DataType.REGISTERS),
                    SimData(12, values=30, readonly=True, datatype=DataType.REGISTERS),
                ],
                action=action,
            )
        )

    async def test_batch_at_threshold_commits_both_registers(self):
        """A batch ending at the last writable register is committed."""
        rt = self.make_runtime()
        assert await rt.async_setValues(0x10, 10, [11, 21]) is None
        assert await rt.async_getValues(0x03, 10, 2) == [11, 21]

    async def test_batch_crossing_threshold_leaves_original_values(self):
        """A batch crossing into the read-only guard is rejected as a whole."""
        rt = self.make_runtime()
        assert await rt.async_setValues(0x10, 10, [11, 21, 31]) == (
            ExcCodes.ILLEGAL_ADDRESS
        )
        assert await rt.async_getValues(0x03, 10, 3) == [10, 20, 30]

    async def test_sparse_hole_rejects_whole_batch(self):
        """A sparse gap in the middle leaves the earlier values untouched."""
        rt = SimRuntime(
            SimDevice(
                1,
                simdata=[
                    SimData(10, values=10, datatype=DataType.REGISTERS),
                    SimData(12, values=30, datatype=DataType.REGISTERS),
                ],
            )
        )
        assert await rt.async_setValues(0x10, 10, [11, 21, 31]) == (
            ExcCodes.ILLEGAL_ADDRESS
        )
        assert await rt.async_getValues(0x03, 10, 1) == [10]
        assert await rt.async_getValues(0x03, 12, 1) == [30]

    async def test_value_count_mismatch_is_rejected(self):
        """The payload length must match the requested write count."""
        rt = self.make_runtime()
        assert await rt.get_block(0x10, 10, 2, [11]) == ExcCodes.ILLEGAL_VALUE
        assert await rt.async_getValues(0x03, 10, 2) == [10, 20]

    async def test_empty_batch_is_invalid(self):
        """An empty write is invalid, not a silent success."""
        rt = self.make_runtime()
        assert await rt.async_setValues(0x10, 10, []) == ExcCodes.ILLEGAL_VALUE

    async def test_callback_error_leaves_both_values(self):
        """A callback error after staging must not change memory."""

        async def action(
            _fc, _start, _addr, _count, registers, set_values
        ):
            if set_values:
                registers[0] = 99
                set_values[0] = 99
                return ExcCodes.DEVICE_FAILURE
            return None

        rt = self.make_runtime(action)
        assert await rt.async_setValues(0x10, 10, [11, 21]) == (
            ExcCodes.DEVICE_FAILURE
        )
        assert await rt.async_getValues(0x03, 10, 2) == [10, 20]

    async def test_callback_exception_leaves_original_values(self):
        """An exception from the callback propagates and does not commit."""

        async def action(
            _fc, _start, _addr, _count, _registers, set_values
        ):
            if set_values:
                raise RuntimeError("hardware fault")
            return None

        rt = self.make_runtime(action)
        with pytest.raises(RuntimeError):
            await rt.async_setValues(0x10, 10, [11, 21])
        assert await rt.async_getValues(0x03, 10, 2) == [10, 20]

    async def test_callback_can_veto_values_without_commit(self):
        """A callback may rewrite set_values; only the staged copy commits."""

        async def action(
            _fc, _start, _addr, _count, _registers, set_values
        ):
            if set_values:
                set_values[0] = 42
            return None

        rt = self.make_runtime(action)
        assert await rt.async_setValues(0x10, 10, [11, 21]) is None
        assert await rt.async_getValues(0x03, 10, 2) == [42, 21]

    async def test_callback_value_count_change_rejected(self):
        """A callback that changes the value count is rejected."""

        async def action(
            _fc, _start, _addr, _count, _registers, set_values
        ):
            if set_values:
                set_values.pop()
            return None

        rt = self.make_runtime(action)
        assert await rt.async_setValues(0x10, 10, [11, 21]) == (
            ExcCodes.ILLEGAL_VALUE
        )
        assert await rt.async_getValues(0x03, 10, 2) == [10, 20]

    async def test_setget_reads_committed_values(self):
        """A combined write/read sees the committed write."""
        rt = self.make_runtime()
        result = await rt.async_setgetValues(0x17, 10, [11, 21], 10, 2)
        assert result == [11, 21]
        assert await rt.async_getValues(0x03, 10, 2) == [11, 21]

    async def test_setget_read_failure_does_not_write(self):
        """If the read half is invalid, the write half is not applied."""
        rt = self.make_runtime()
        assert await rt.async_setgetValues(0x17, 10, [11, 21], 11, 3) == (
            ExcCodes.ILLEGAL_ADDRESS
        )
        assert await rt.async_getValues(0x03, 10, 2) == [10, 20]

    async def test_setget_callback_failure_does_not_write(self):
        """A callback failure in a combined request leaves memory unchanged."""

        async def action(
            _fc, _start, _addr, _count, _registers, set_values
        ):
            if set_values is not None:
                return ExcCodes.DEVICE_FAILURE
            return None

        rt = self.make_runtime(action)
        assert await rt.async_setgetValues(0x17, 10, [11, 21], 10, 2) == (
            ExcCodes.DEVICE_FAILURE
        )
        assert await rt.async_getValues(0x03, 10, 2) == [10, 20]

    async def test_bit_write_batch_rejects_readonly_register(self):
        """A coil batch crossing into a read-only register writes nothing."""
        rt = SimRuntime(
            SimDevice(
                1,
                simdata=[
                    SimData(0, values=[True] * 16, datatype=DataType.BITS),
                    SimData(
                        1,
                        values=[False] * 16,
                        readonly=True,
                        datatype=DataType.BITS,
                    ),
                ],
                use_bit_addressing=True,
            )
        )
        assert await rt.async_setValues(0x0F, 14, [False] * 4) == (
            ExcCodes.ILLEGAL_ADDRESS
        )
        assert await rt.async_getValues(0x01, 14, 4) == [True, True, False, False]
