"""
Core types for CAN frame handling.

This module defines the fundamental data structures used throughout CANPeek,
optimized for memory efficiency and performance.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag, auto
from typing import Optional
from uuid import UUID, uuid4


# --- Frame Flag Constants ---
# These flags are stored as a single byte for memory efficiency

FLAG_EXTENDED_ID = 1 << 0       # 29-bit extended identifier
FLAG_FD_FRAME = 1 << 1          # CAN FD frame
FLAG_BITRATE_SWITCH = 1 << 2    # Bitrate switching enabled (FD)
FLAG_ERROR_STATE_IND = 1 << 3   # Error State Indicator (FD)
FLAG_REMOTE_FRAME = 1 << 4      # Remote Transmission Request
FLAG_ERROR_FRAME = 1 << 5       # Error frame
FLAG_IS_RX = 1 << 6             # Received frame (vs transmitted)


class FrameDirection(IntEnum):
    """Direction of CAN frame."""
    TX = 0
    RX = 1


class FrameType(IntEnum):
    """Type of CAN frame."""
    DATA = 0
    REMOTE = 1
    ERROR = 2
    OVERLOAD = 3


class BusState(IntEnum):
    """CAN bus state according to CAN specification."""
    UNKNOWN = 0
    ERROR_ACTIVE = 1      # TEC/REC < 128
    ERROR_WARNING = 2     # TEC/REC >= 96
    ERROR_PASSIVE = 3     # TEC/REC >= 128
    BUS_OFF = 4           # TEC >= 256
    STOPPED = 5           # Interface stopped
    SLEEPING = 6          # Bus in sleep mode


# CAN FD DLC to actual data length mapping
FD_DLC_TO_LEN = {
    0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8,
    9: 12, 10: 16, 11: 20, 12: 24, 13: 32, 14: 48, 15: 64
}

FD_LEN_TO_DLC = {v: k for k, v in FD_DLC_TO_LEN.items()}


def dlc_to_len(dlc: int, is_fd: bool = False) -> int:
    """Convert DLC to actual data length."""
    if is_fd:
        return FD_DLC_TO_LEN.get(dlc, 8)
    return min(dlc, 8)


def len_to_dlc(length: int, is_fd: bool = False) -> int:
    """Convert data length to DLC."""
    if is_fd:
        # Find smallest DLC that can fit the data
        for dlc, max_len in sorted(FD_DLC_TO_LEN.items()):
            if max_len >= length:
                return dlc
        return 15  # Maximum
    return min(length, 8)


@dataclass(slots=True)
class CANFrame:
    """
    High-performance CAN frame representation.

    Uses __slots__ for memory efficiency and fast attribute access.
    Immutable-style design (create new instances rather than modifying).

    Attributes:
        timestamp_ns: Timestamp in nanoseconds (monotonic or epoch)
        arbitration_id: CAN identifier (11-bit or 29-bit)
        data: Frame payload (up to 64 bytes for CAN FD)
        dlc: Data Length Code
        flags: Bit flags for frame properties
        bus_id: Bus identifier (index into bus list)
        bus_name: Human-readable bus name
        connection_id: UUID of the connection this frame belongs to
    """
    timestamp_ns: int
    arbitration_id: int
    data: bytes
    dlc: int
    flags: int = 0
    bus_id: int = 0
    bus_name: str = ""
    connection_id: Optional[UUID] = None

    # --- Property accessors for flags ---

    @property
    def is_extended_id(self) -> bool:
        """True if frame uses 29-bit extended identifier."""
        return bool(self.flags & FLAG_EXTENDED_ID)

    @property
    def is_fd(self) -> bool:
        """True if this is a CAN FD frame."""
        return bool(self.flags & FLAG_FD_FRAME)

    @property
    def is_brs(self) -> bool:
        """True if bitrate switching is enabled (CAN FD only)."""
        return bool(self.flags & FLAG_BITRATE_SWITCH)

    @property
    def is_esi(self) -> bool:
        """True if Error State Indicator is set (CAN FD only)."""
        return bool(self.flags & FLAG_ERROR_STATE_IND)

    @property
    def is_remote_frame(self) -> bool:
        """True if this is a Remote Transmission Request."""
        return bool(self.flags & FLAG_REMOTE_FRAME)

    @property
    def is_error_frame(self) -> bool:
        """True if this is an error frame."""
        return bool(self.flags & FLAG_ERROR_FRAME)

    @property
    def is_rx(self) -> bool:
        """True if frame was received (False if transmitted)."""
        return bool(self.flags & FLAG_IS_RX)

    @property
    def direction(self) -> FrameDirection:
        """Frame direction (RX or TX)."""
        return FrameDirection.RX if self.is_rx else FrameDirection.TX

    @property
    def timestamp(self) -> float:
        """Timestamp in seconds (float, for compatibility)."""
        return self.timestamp_ns / 1_000_000_000

    @property
    def data_length(self) -> int:
        """Actual data length in bytes."""
        return len(self.data)

    @property
    def frame_type(self) -> FrameType:
        """Get the frame type."""
        if self.is_error_frame:
            return FrameType.ERROR
        if self.is_remote_frame:
            return FrameType.REMOTE
        return FrameType.DATA

    # --- Factory methods ---

    @classmethod
    def from_python_can(cls, msg, bus_id: int = 0, bus_name: str = "",
                        connection_id: Optional[UUID] = None) -> CANFrame:
        """
        Create CANFrame from python-can Message object.

        Args:
            msg: python-can Message object
            bus_id: Numeric bus identifier
            bus_name: Human-readable bus name
            connection_id: UUID of the connection

        Returns:
            New CANFrame instance
        """
        flags = 0
        if msg.is_extended_id:
            flags |= FLAG_EXTENDED_ID
        if getattr(msg, 'is_fd', False):
            flags |= FLAG_FD_FRAME
        if getattr(msg, 'bitrate_switch', False):
            flags |= FLAG_BITRATE_SWITCH
        if getattr(msg, 'error_state_indicator', False):
            flags |= FLAG_ERROR_STATE_IND
        if msg.is_remote_frame:
            flags |= FLAG_REMOTE_FRAME
        if msg.is_error_frame:
            flags |= FLAG_ERROR_FRAME
        if getattr(msg, 'is_rx', True):
            flags |= FLAG_IS_RX

        # Convert timestamp to nanoseconds
        timestamp_ns = int(msg.timestamp * 1_000_000_000)

        return cls(
            timestamp_ns=timestamp_ns,
            arbitration_id=msg.arbitration_id,
            data=bytes(msg.data),
            dlc=msg.dlc,
            flags=flags,
            bus_id=bus_id,
            bus_name=bus_name,
            connection_id=connection_id,
        )

    @classmethod
    def create(
        cls,
        arbitration_id: int,
        data: bytes,
        *,
        is_extended_id: bool = False,
        is_fd: bool = False,
        is_brs: bool = False,
        is_remote_frame: bool = False,
        is_rx: bool = True,
        bus_id: int = 0,
        bus_name: str = "",
        connection_id: Optional[UUID] = None,
        timestamp_ns: Optional[int] = None,
    ) -> CANFrame:
        """
        Create a new CANFrame with explicit parameters.

        Args:
            arbitration_id: CAN identifier
            data: Frame payload
            is_extended_id: Use 29-bit identifier
            is_fd: CAN FD frame
            is_brs: Enable bitrate switching
            is_remote_frame: Remote Transmission Request
            is_rx: Received frame
            bus_id: Bus identifier
            bus_name: Bus name
            connection_id: Connection UUID
            timestamp_ns: Timestamp (uses current time if None)

        Returns:
            New CANFrame instance
        """
        flags = 0
        if is_extended_id:
            flags |= FLAG_EXTENDED_ID
        if is_fd:
            flags |= FLAG_FD_FRAME
        if is_brs:
            flags |= FLAG_BITRATE_SWITCH
        if is_remote_frame:
            flags |= FLAG_REMOTE_FRAME
        if is_rx:
            flags |= FLAG_IS_RX

        if timestamp_ns is None:
            timestamp_ns = time.time_ns()

        dlc = len_to_dlc(len(data), is_fd)

        return cls(
            timestamp_ns=timestamp_ns,
            arbitration_id=arbitration_id,
            data=data,
            dlc=dlc,
            flags=flags,
            bus_id=bus_id,
            bus_name=bus_name,
            connection_id=connection_id,
        )

    # --- Serialization ---

    def to_bytes(self) -> bytes:
        """
        Serialize frame to bytes for storage/transmission.

        Format (28 bytes header + data):
            - timestamp_ns: 8 bytes (uint64)
            - arbitration_id: 4 bytes (uint32)
            - dlc: 1 byte (uint8)
            - flags: 1 byte (uint8)
            - bus_id: 1 byte (uint8)
            - data_len: 1 byte (uint8)
            - reserved: 12 bytes
            - data: variable length
        """
        header = struct.pack(
            '<QIBBBBxxxxxxxxxxxx',  # 28 bytes header
            self.timestamp_ns,
            self.arbitration_id,
            self.dlc,
            self.flags,
            self.bus_id,
            len(self.data),
        )
        return header + self.data

    @classmethod
    def from_bytes(cls, raw: bytes) -> CANFrame:
        """Deserialize frame from bytes."""
        ts, arb_id, dlc, flags, bus_id, data_len = struct.unpack(
            '<QIBBBBxxxxxxxxxxxx', raw[:28]
        )
        data = raw[28:28 + data_len]
        return cls(
            timestamp_ns=ts,
            arbitration_id=arb_id,
            data=data,
            dlc=dlc,
            flags=flags,
            bus_id=bus_id,
        )

    # --- Display methods ---

    def id_str(self) -> str:
        """Get CAN ID as hex string."""
        if self.is_extended_id:
            return f"0x{self.arbitration_id:08X}"
        return f"0x{self.arbitration_id:03X}"

    def data_str(self) -> str:
        """Get data as hex string with spaces."""
        return self.data.hex(' ').upper()

    def type_str(self) -> str:
        """Get frame type as string."""
        parts = []
        if self.is_extended_id:
            parts.append("Ext")
        else:
            parts.append("Std")
        if self.is_fd:
            parts.append("FD")
            if self.is_brs:
                parts.append("BRS")
        if self.is_remote_frame:
            parts.append("RTR")
        if self.is_error_frame:
            parts.append("ERR")
        return " ".join(parts)

    def __repr__(self) -> str:
        return (
            f"CANFrame(id={self.id_str()}, "
            f"data=[{self.data_str()}], "
            f"type={self.type_str()}, "
            f"bus={self.bus_name or self.bus_id})"
        )


@dataclass(slots=True)
class BusStatistics:
    """Statistics for a CAN bus."""
    bus_id: int
    bus_name: str

    # Counters
    rx_frames: int = 0
    tx_frames: int = 0
    rx_bytes: int = 0
    tx_bytes: int = 0
    error_frames: int = 0

    # Timing
    first_timestamp_ns: int = 0
    last_timestamp_ns: int = 0

    # Bus state
    state: BusState = BusState.UNKNOWN
    tx_error_counter: int = 0
    rx_error_counter: int = 0

    # Performance
    frames_per_second: float = 0.0
    bus_load_percent: float = 0.0
    buffer_overflow_count: int = 0

    def update(self, frame: CANFrame) -> None:
        """Update statistics with a new frame."""
        if frame.is_rx:
            self.rx_frames += 1
            self.rx_bytes += len(frame.data)
        else:
            self.tx_frames += 1
            self.tx_bytes += len(frame.data)

        if frame.is_error_frame:
            self.error_frames += 1

        if self.first_timestamp_ns == 0:
            self.first_timestamp_ns = frame.timestamp_ns
        self.last_timestamp_ns = frame.timestamp_ns


@dataclass
class Connection:
    """Represents a CAN bus connection configuration."""
    id: UUID = field(default_factory=uuid4)
    name: str = ""
    interface: str = "socketcan"  # python-can interface name
    channel: str = ""  # e.g., "can0", "PCAN_USBBUS1"
    bitrate: int = 500000
    data_bitrate: int = 2000000  # For CAN FD
    fd: bool = False
    enabled: bool = True

    # Additional config passed to python-can
    extra_config: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.name:
            self.name = self.channel or f"Connection-{str(self.id)[:8]}"

    def to_python_can_config(self) -> dict:
        """Get configuration dict for python-can Bus()."""
        config = {
            'interface': self.interface,
            'channel': self.channel,
            'bitrate': self.bitrate,
        }
        if self.fd:
            config['fd'] = True
            config['data_bitrate'] = self.data_bitrate
        config.update(self.extra_config)
        return config
