"""
SocketCAN integration module.

Provides advanced SocketCAN management including:
- Interface discovery and status
- Bus up/down control (requires sudo)
- Bitrate and CAN FD configuration
- Error detection and statistics
"""

from canpeek.socketcan.manager import (
    SocketCANManager,
    CANInterfaceInfo,
    CANInterfaceStats,
    InterfaceState,
)

__all__ = [
    "SocketCANManager",
    "CANInterfaceInfo",
    "CANInterfaceStats",
    "InterfaceState",
]
