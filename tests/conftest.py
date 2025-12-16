"""
Pytest configuration and fixtures.
"""

import pytest


@pytest.fixture
def sample_frame():
    """Create a sample CAN frame for testing."""
    from canpeek.core.types import CANFrame

    return CANFrame.create(
        arbitration_id=0x100,
        data=bytes([0x12, 0x34, 0x56, 0x78]),
        is_rx=True,
        bus_name="test",
    )


@pytest.fixture
def sample_fd_frame():
    """Create a sample CAN FD frame for testing."""
    from canpeek.core.types import CANFrame

    return CANFrame.create(
        arbitration_id=0x200,
        data=bytes(range(64)),
        is_fd=True,
        is_brs=True,
        is_rx=True,
        bus_name="test_fd",
    )
