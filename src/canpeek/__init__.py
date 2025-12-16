"""
CANPeek v2 - High-Performance CAN/CAN FD Bus Analyzer

A professional-grade CAN bus analyzer with multi-bus support,
inspired by PCAN-Explorer's UI layout.
"""

__version__ = "2.0.0-dev"
__author__ = "Denis Jullien"

from canpeek.core.types import CANFrame, BusState, FrameDirection

__all__ = [
    "CANFrame",
    "BusState",
    "FrameDirection",
    "__version__",
]
