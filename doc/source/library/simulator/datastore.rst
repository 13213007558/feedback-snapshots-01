Simulator datastore
===================

The simulator datastore is an advanced datastore.
The simulator allows to simulate the registers of a real life modbus device by adding a simple dict (definition see :ref:`Device entries`).

The simulator datastore allows to add actions (functions) to a register, and thus allows a low level automation.

Documentation :class:`pymodbus.datastore.ModbusSimulatorContext`

Batch write contract
--------------------

A single ``async_setValues`` / ``async_setgetValues`` call is one batch.
The value list is the complete payload, so the write count is
``len(values)``; an empty payload is invalid.

The in-memory datastore applies all-or-nothing semantics:

- the complete target range is checked before memory changes, including
  registers covered by a coil write that crosses a register boundary;
- an undefined (sparse) or read-only register rejects the whole batch with
  ``ILLEGAL_ADDRESS``;
- the optional action callback runs against a private staging copy and is
  committed only when it returns ``None`` and keeps the value count
  unchanged. A returned exception code, an exception, or a changed value
  count leaves the original registers untouched;
- ``async_setgetValues`` (used by function code 23) preflights both the
  write and the read range and returns the read from the same committed
  view, so a failed read cannot leave a successful write behind.

This guarantee belongs to the memory implementation only. An adapter that
forwards writes to external hardware must not advertise
``supports_atomic_set_and_get`` unless the hardware can provide the same
view. If a batch may have been partially applied and the hardware cannot
roll it back, the adapter must report ``DEVICE_FAILURE`` (exception code
``0x04``); it must not report success, and it must not report a precise
address error that would imply nothing was written.
