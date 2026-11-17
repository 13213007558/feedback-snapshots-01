"""Simulator data model implementation.

**REMARK** This class is internal to the server/simulator,.
"""

from __future__ import annotations

from ..constants import ExcCodes
from ..exceptions import NoSuchIdException
from .simdevice import SimDevice
from .simruntime import SimRuntime


class SimCore:
    """Handler for the simulator/server."""

    #: The in-memory runtime provides an atomic write/read view.
    supports_atomic_set_and_get = True

    def __init__(self, devices: SimDevice | list[SimDevice]) -> None:
        """Build datastore."""
        if not isinstance(devices, list):
            if not isinstance(devices, SimDevice):
                raise TypeError(
                    "devices= is not a SimDevice or list of SimDevice entry"
                )
            devices = [devices]
        self.devices: dict[int, SimRuntime] = {}
        for inx, device in enumerate(devices):
            if not isinstance(device, SimDevice):
                raise TypeError(f"devices=list[{inx}] is not a SimDevice entry")
            if device.id in self.devices:
                raise TypeError(
                    f"devices= device_id: {device.id} in multiple SimDevice entries"
                )
            self.devices[device.id] = SimRuntime(device)

    def __get_device(self, device_id: int) -> SimRuntime:
        """Return device object, device 0 serves ids not defined."""
        if device_id in self.devices:
            return self.devices[device_id]
        if 0 in self.devices:
            return self.devices[0]
        raise NoSuchIdException(
            f"device_id - {device_id} does not exist, or is out of range"
        )

    def device_ids(self) -> list[int]:
        """Return list of device ids."""
        dev_ids: list[int] = []
        for dev_id in self.devices:
            dev_ids.append(dev_id)
        return dev_ids

    async def async_getValues(
        self, device_id: int, func_code: int, address: int, count: int = 1
    ) -> list[int] | list[bool] | ExcCodes:
        """Get `count` values from datastore."""
        return await self.__get_device(device_id).async_getValues(
            func_code, address, count
        )

    async def async_setValues(
        self,
        device_id: int,
        func_code: int,
        address: int,
        values: list[int] | list[bool],
    ) -> ExcCodes | None:
        """Set the datastore with the supplied values."""
        return await self.__get_device(device_id).async_setValues(
            func_code, address, values
        )

    async def async_setgetValues(
        self,
        device_id: int,
        func_code: int,
        write_address: int,
        values: list[int] | list[bool],
        read_address: int,
        read_count: int,
    ) -> list[int] | list[bool] | ExcCodes:
        """Write a batch and read from the same committed view."""
        return await self.__get_device(device_id).async_setgetValues(
            func_code, write_address, values, read_address, read_count
        )
