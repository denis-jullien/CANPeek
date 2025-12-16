"""
Core module - High-performance CAN frame handling and processing.
"""

from canpeek.core.types import (
    CANFrame,
    BusState,
    FrameDirection,
    FrameType,
    FLAG_EXTENDED_ID,
    FLAG_FD_FRAME,
    FLAG_BITRATE_SWITCH,
    FLAG_ERROR_STATE_IND,
    FLAG_REMOTE_FRAME,
    FLAG_ERROR_FRAME,
    FLAG_IS_RX,
)
from canpeek.core.buffer import RingBuffer

__all__ = [
    "CANFrame",
    "BusState",
    "FrameDirection",
    "FrameType",
    "RingBuffer",
    "FLAG_EXTENDED_ID",
    "FLAG_FD_FRAME",
    "FLAG_BITRATE_SWITCH",
    "FLAG_ERROR_STATE_IND",
    "FLAG_REMOTE_FRAME",
    "FLAG_ERROR_FRAME",
    "FLAG_IS_RX",
]
