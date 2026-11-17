"""Explicit request policies for Modbus servers."""

from __future__ import annotations

from ..pdu import ModbusPDU


class ReadOnlyRequestPolicy:
    """Allow-list policy admitting only side-effect-free read requests.

    The policy is decided on the decoded PDU *before* any datastore or
    device callback is invoked. Anything that is not a confirmed pure
    read is denied, in particular:

    - all write function codes (single/multiple coils and registers),
    - read/write combos such as Read/Write Multiple Registers (0x17),
      which only look like reads,
    - Mask Write Register (0x16) and Write File Record (0x15),
    - state-changing diagnostics (restart communications, change
      delimiter, force listen-only, clear counters/statistics),
    - custom or otherwise unknown function codes, whose side effects
      cannot be confirmed.
    """

    #: Function codes that only ever read data.
    READ_FUNCTION_CODES = frozenset(
        {
            0x01,  # Read Coils
            0x02,  # Read Discrete Inputs
            0x03,  # Read Holding Registers
            0x04,  # Read Input Registers
            0x07,  # Read Exception Status
            0x0B,  # Get Comm Event Counter
            0x0C,  # Get Comm Event Log
            0x11,  # Report Device Id
            0x14,  # Read File Record
            0x18,  # Read FIFO Queue
        }
    )

    DIAGNOSTICS_FUNCTION_CODE = 0x08
    ENCAPSULATED_INTERFACE_FUNCTION_CODE = 0x2B

    #: Diagnostic sub-functions that only read data. State-changing
    #: sub-functions (restart, change delimiter, listen-only, clear
    #: counters/statistics) are deliberately excluded.
    READ_DIAGNOSTIC_SUB_FUNCTION_CODES = frozenset(
        {
            0x0000,  # Return Query Data
            0x0002,  # Return Diagnostic Register
            0x000B,  # Return Bus Message Count
            0x000C,  # Return Bus Communication Error Count
            0x000D,  # Return Bus Exception Error Count
            0x000E,  # Return Device Message Count
            0x000F,  # Return Device No Response Count
            0x0010,  # Return Device NAK Count
            0x0011,  # Return Device Busy Count
            0x0012,  # Return Device Bus Character Overrun Count
            0x0013,  # Return IOP Overrun Count
        }
    )

    #: MEI sub-functions that only read data.
    READ_MEI_SUB_FUNCTION_CODES = frozenset(
        {
            0x0E,  # Read Device Information
        }
    )

    def allows(self, pdu: ModbusPDU) -> bool:
        """Return True only if the request is a confirmed pure read."""
        if pdu.function_code in self.READ_FUNCTION_CODES:
            return True
        if pdu.function_code == self.DIAGNOSTICS_FUNCTION_CODE:
            return pdu.sub_function_code in self.READ_DIAGNOSTIC_SUB_FUNCTION_CODES
        if pdu.function_code == self.ENCAPSULATED_INTERFACE_FUNCTION_CODE:
            return pdu.sub_function_code in self.READ_MEI_SUB_FUNCTION_CODES
        return False
