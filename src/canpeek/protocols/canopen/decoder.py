"""
CANopen protocol decoder.

Decodes CANopen messages based on COB-ID (CAN Object Identifier).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

from canpeek.core.types import CANFrame


class CANopenFunction(IntEnum):
    """CANopen function codes (upper bits of COB-ID)."""
    NMT = 0x000
    SYNC = 0x080
    EMCY = 0x080  # + NodeID (0x081-0x0FF)
    TIME = 0x100
    TPDO1 = 0x180
    RPDO1 = 0x200
    TPDO2 = 0x280
    RPDO2 = 0x300
    TPDO3 = 0x380
    RPDO3 = 0x400
    TPDO4 = 0x480
    RPDO4 = 0x500
    TSDO = 0x580  # SDO response (server -> client)
    RSDO = 0x600  # SDO request (client -> server)
    HEARTBEAT = 0x700  # Also Node Guarding


class NMTCommand(IntEnum):
    """NMT command specifiers."""
    START_REMOTE_NODE = 0x01
    STOP_REMOTE_NODE = 0x02
    ENTER_PRE_OPERATIONAL = 0x80
    RESET_NODE = 0x81
    RESET_COMMUNICATION = 0x82


class NMTState(IntEnum):
    """NMT node states (from Heartbeat)."""
    BOOT_UP = 0x00
    STOPPED = 0x04
    OPERATIONAL = 0x05
    PRE_OPERATIONAL = 0x7F


class SDOCommand(IntEnum):
    """SDO command specifiers (first 3 bits of first byte)."""
    DOWNLOAD_SEGMENT = 0  # Client -> Server segment
    INITIATE_DOWNLOAD = 1  # Client -> Server initiate
    UPLOAD_SEGMENT = 2  # Server -> Client segment
    INITIATE_UPLOAD = 3  # Server -> Client initiate (response) or Client request
    ABORT = 4  # Abort transfer
    BLOCK_UPLOAD = 5
    BLOCK_DOWNLOAD = 6


@dataclass
class CANopenMessage:
    """Decoded CANopen message."""
    function: str  # Human-readable function name
    node_id: Optional[int]  # Node ID (1-127), None for broadcast
    details: str  # Decoded details
    raw_frame: CANFrame

    # For specific message types
    nmt_state: Optional[NMTState] = None
    sdo_index: Optional[int] = None
    sdo_subindex: Optional[int] = None

    @property
    def function_short(self) -> str:
        """Short function code for display."""
        return self.function.split()[0] if self.function else ""


# COB-ID ranges for each function
COB_ID_RANGES = [
    (0x000, 0x000, "NMT"),
    (0x080, 0x080, "SYNC"),
    (0x081, 0x0FF, "EMCY"),
    (0x100, 0x100, "TIME"),
    (0x180, 0x1FF, "TPDO1"),
    (0x200, 0x27F, "RPDO1"),
    (0x280, 0x2FF, "TPDO2"),
    (0x300, 0x37F, "RPDO2"),
    (0x380, 0x3FF, "TPDO3"),
    (0x400, 0x47F, "RPDO3"),
    (0x480, 0x4FF, "TPDO4"),
    (0x500, 0x57F, "RPDO4"),
    (0x580, 0x5FF, "TSDO"),
    (0x600, 0x67F, "RSDO"),
    (0x700, 0x77F, "HEARTBEAT"),
]


def get_node_id(cob_id: int) -> Optional[int]:
    """
    Extract node ID from COB-ID.

    Returns None for broadcast messages (NMT, SYNC, TIME).
    """
    if cob_id == 0x000:  # NMT
        return None
    if cob_id == 0x080:  # SYNC
        return None
    if cob_id == 0x100:  # TIME
        return None

    # For all other messages, node ID is in lower 7 bits
    node_id = cob_id & 0x7F
    if 1 <= node_id <= 127:
        return node_id
    return None


def get_function_code(cob_id: int) -> Optional[str]:
    """Get function name from COB-ID."""
    for start, end, name in COB_ID_RANGES:
        if start <= cob_id <= end:
            return name
    return None


def is_canopen_frame(frame: CANFrame) -> bool:
    """Check if frame could be a CANopen message."""
    # CANopen uses 11-bit standard IDs only
    if frame.is_extended_id:
        return False

    # Check if COB-ID is in CANopen range
    return get_function_code(frame.arbitration_id) is not None


def decode_nmt(frame: CANFrame) -> CANopenMessage:
    """Decode NMT message."""
    if len(frame.data) >= 2:
        command = frame.data[0]
        target_node = frame.data[1]

        cmd_names = {
            NMTCommand.START_REMOTE_NODE: "Start",
            NMTCommand.STOP_REMOTE_NODE: "Stop",
            NMTCommand.ENTER_PRE_OPERATIONAL: "Pre-Op",
            NMTCommand.RESET_NODE: "Reset Node",
            NMTCommand.RESET_COMMUNICATION: "Reset Comm",
        }
        cmd_name = cmd_names.get(command, f"Cmd 0x{command:02X}")

        if target_node == 0:
            details = f"{cmd_name} (all nodes)"
        else:
            details = f"{cmd_name} -> Node {target_node}"
    else:
        details = "Invalid NMT"

    return CANopenMessage(
        function="NMT",
        node_id=None,
        details=details,
        raw_frame=frame,
    )


def decode_sync(frame: CANFrame) -> CANopenMessage:
    """Decode SYNC message."""
    if len(frame.data) > 0:
        counter = frame.data[0]
        details = f"Counter: {counter}"
    else:
        details = ""

    return CANopenMessage(
        function="SYNC",
        node_id=None,
        details=details,
        raw_frame=frame,
    )


def decode_time(frame: CANFrame) -> CANopenMessage:
    """Decode TIME message."""
    if len(frame.data) >= 6:
        # TIME_OF_DAY format
        ms = int.from_bytes(frame.data[0:4], 'little') & 0x0FFFFFFF
        days = int.from_bytes(frame.data[4:6], 'little')
        details = f"Days: {days}, ms: {ms}"
    else:
        details = frame.data.hex(' ').upper()

    return CANopenMessage(
        function="TIME",
        node_id=None,
        details=details,
        raw_frame=frame,
    )


def decode_emergency(frame: CANFrame, node_id: int) -> CANopenMessage:
    """Decode Emergency message."""
    if len(frame.data) >= 8:
        error_code = int.from_bytes(frame.data[0:2], 'little')
        error_register = frame.data[2]
        vendor_specific = frame.data[3:8].hex(' ').upper()

        # Common error codes
        error_names = {
            0x0000: "No error",
            0x1000: "Generic error",
            0x2000: "Current error",
            0x3000: "Voltage error",
            0x4000: "Temperature error",
            0x5000: "Device hardware error",
            0x6000: "Device software error",
            0x7000: "Additional modules error",
            0x8000: "Monitoring error",
            0x9000: "External error",
            0xF000: "Additional functions error",
            0xFF00: "Device specific error",
        }

        # Find matching error category
        error_name = None
        for code, name in error_names.items():
            if error_code & 0xFF00 == code:
                error_name = name
                break

        if error_name:
            details = f"{error_name} (0x{error_code:04X}) Reg:0x{error_register:02X}"
        else:
            details = f"Error 0x{error_code:04X} Reg:0x{error_register:02X}"
    else:
        details = frame.data.hex(' ').upper()

    return CANopenMessage(
        function="EMCY",
        node_id=node_id,
        details=details,
        raw_frame=frame,
    )


def decode_heartbeat(frame: CANFrame, node_id: int) -> CANopenMessage:
    """Decode Heartbeat/Node Guarding message."""
    nmt_state = None

    if len(frame.data) >= 1:
        state_byte = frame.data[0] & 0x7F  # Bit 7 is toggle for node guarding

        state_names = {
            NMTState.BOOT_UP: "Boot-up",
            NMTState.STOPPED: "Stopped",
            NMTState.OPERATIONAL: "Operational",
            NMTState.PRE_OPERATIONAL: "Pre-operational",
        }

        try:
            nmt_state = NMTState(state_byte)
            state_name = state_names.get(nmt_state, f"State 0x{state_byte:02X}")
        except ValueError:
            state_name = f"State 0x{state_byte:02X}"

        details = state_name
    else:
        details = "RTR" if frame.is_remote_frame else "Empty"

    return CANopenMessage(
        function="HEARTBEAT",
        node_id=node_id,
        details=details,
        raw_frame=frame,
        nmt_state=nmt_state,
    )


def decode_sdo(frame: CANFrame, node_id: int, is_request: bool) -> CANopenMessage:
    """Decode SDO message."""
    function = "RSDO" if is_request else "TSDO"
    sdo_index = None
    sdo_subindex = None

    if len(frame.data) >= 1:
        cmd_byte = frame.data[0]
        cmd_specifier = (cmd_byte >> 5) & 0x07

        if cmd_specifier == SDOCommand.ABORT:
            # Abort transfer
            if len(frame.data) >= 8:
                index = int.from_bytes(frame.data[1:3], 'little')
                subindex = frame.data[3]
                abort_code = int.from_bytes(frame.data[4:8], 'little')
                details = f"ABORT [{index:04X}:{subindex:02X}] Code:0x{abort_code:08X}"
                sdo_index = index
                sdo_subindex = subindex
            else:
                details = "ABORT"

        elif cmd_specifier == SDOCommand.INITIATE_DOWNLOAD:
            # Initiate download (write)
            if len(frame.data) >= 4:
                index = int.from_bytes(frame.data[1:3], 'little')
                subindex = frame.data[3]
                expedited = bool(cmd_byte & 0x02)
                size_indicated = bool(cmd_byte & 0x01)

                sdo_index = index
                sdo_subindex = subindex

                if expedited and len(frame.data) >= 8:
                    n = (cmd_byte >> 2) & 0x03 if size_indicated else 0
                    data_len = 4 - n
                    data = frame.data[4:4+data_len]
                    details = f"WRITE [{index:04X}:{subindex:02X}] = {data.hex(' ').upper()}"
                else:
                    details = f"WRITE [{index:04X}:{subindex:02X}] (segmented)"
            else:
                details = "WRITE (invalid)"

        elif cmd_specifier == SDOCommand.INITIATE_UPLOAD:
            # Initiate upload (read request or response)
            if len(frame.data) >= 4:
                index = int.from_bytes(frame.data[1:3], 'little')
                subindex = frame.data[3]

                sdo_index = index
                sdo_subindex = subindex

                if is_request:
                    details = f"READ [{index:04X}:{subindex:02X}]"
                else:
                    expedited = bool(cmd_byte & 0x02)
                    if expedited and len(frame.data) >= 8:
                        size_indicated = bool(cmd_byte & 0x01)
                        n = (cmd_byte >> 2) & 0x03 if size_indicated else 0
                        data_len = 4 - n
                        data = frame.data[4:4+data_len]
                        details = f"RESP [{index:04X}:{subindex:02X}] = {data.hex(' ').upper()}"
                    else:
                        details = f"RESP [{index:04X}:{subindex:02X}] (segmented)"
            else:
                details = "READ (invalid)"

        elif cmd_specifier in (SDOCommand.DOWNLOAD_SEGMENT, SDOCommand.UPLOAD_SEGMENT):
            # Segment transfer
            toggle = bool(cmd_byte & 0x10)
            details = f"SEGMENT t={int(toggle)}"

        else:
            details = f"Cmd 0x{cmd_byte:02X}"
    else:
        details = "Empty"

    return CANopenMessage(
        function=function,
        node_id=node_id,
        details=details,
        raw_frame=frame,
        sdo_index=sdo_index,
        sdo_subindex=sdo_subindex,
    )


def decode_pdo(frame: CANFrame, node_id: int, pdo_type: str) -> CANopenMessage:
    """Decode PDO message."""
    # PDO content depends on mapping, just show raw data
    data_str = frame.data.hex(' ').upper() if frame.data else "Empty"

    return CANopenMessage(
        function=pdo_type,
        node_id=node_id,
        details=data_str,
        raw_frame=frame,
    )


def decode_frame(frame: CANFrame) -> Optional[CANopenMessage]:
    """
    Decode a CAN frame as CANopen message.

    Returns None if frame is not a valid CANopen message.
    """
    if frame.is_extended_id:
        return None

    cob_id = frame.arbitration_id
    func = get_function_code(cob_id)

    if func is None:
        return None

    node_id = get_node_id(cob_id)

    # Decode based on function
    if func == "NMT":
        return decode_nmt(frame)
    elif func == "SYNC":
        return decode_sync(frame)
    elif func == "TIME":
        return decode_time(frame)
    elif func == "EMCY":
        return decode_emergency(frame, node_id)
    elif func == "HEARTBEAT":
        return decode_heartbeat(frame, node_id)
    elif func == "RSDO":
        return decode_sdo(frame, node_id, is_request=True)
    elif func == "TSDO":
        return decode_sdo(frame, node_id, is_request=False)
    elif func.startswith("TPDO") or func.startswith("RPDO"):
        return decode_pdo(frame, node_id, func)

    # Unknown function
    return CANopenMessage(
        function=func,
        node_id=node_id,
        details=frame.data.hex(' ').upper() if frame.data else "",
        raw_frame=frame,
    )


def format_canopen_short(msg: CANopenMessage) -> str:
    """Format CANopen message for short display."""
    if msg.node_id is not None:
        return f"{msg.function}[{msg.node_id}]"
    return msg.function


def format_canopen_full(msg: CANopenMessage) -> str:
    """Format CANopen message for full display."""
    if msg.node_id is not None:
        return f"{msg.function} Node {msg.node_id}: {msg.details}"
    return f"{msg.function}: {msg.details}"
