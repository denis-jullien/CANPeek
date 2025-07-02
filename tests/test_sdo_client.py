import asyncio
import pytest
import uuid
import struct
from unittest.mock import MagicMock

import can
from canpeek.co.sdo_client import SdoClient, SdoAbortedError

# Mark all tests in this file as asyncio
pytestmark = pytest.mark.asyncio

NODE_ID = 0x42
CONNECTION_ID = uuid.uuid4()


@pytest.fixture
def mock_send_callback():
    """Fixture for the mock send callback."""
    return MagicMock()


@pytest.fixture
def sdo_client(mock_send_callback):
    """Fixture for the SdoClient."""
    return SdoClient(NODE_ID, CONNECTION_ID, mock_send_callback)


async def queue_response(client: SdoClient, data: bytes, delay: float = 0):
    """Helper to queue a response frame on the client's queue."""
    await asyncio.sleep(delay)
    await client.on_frame_rx(can.Message(arbitration_id=0x580 + NODE_ID, data=data))


# --- Read Tests ---


async def test_read_expedited(sdo_client: SdoClient, mock_send_callback: MagicMock):
    """Test a successful expedited SDO read."""
    index, subindex = 0x1008, 0x00
    test_data = b"test"
    response_payload = bytearray(test_data)
    response_payload.extend(b"\x00" * (4 - len(test_data)))

    # CS = 0x43 (4 bytes, expedited, size indicated)
    response_cs = 0x43
    response = bytearray(
        struct.pack("<B H B 4s", response_cs, index, subindex, response_payload)
    )

    # Create a task for the read operation and a task to queue the response
    read_task = asyncio.create_task(sdo_client.read(index, subindex))
    asyncio.create_task(queue_response(sdo_client, response))

    # Wait for the read operation to complete
    result = await read_task

    assert result == test_data
    mock_send_callback.assert_called_once()
    sent_msg = mock_send_callback.call_args[0][0]
    assert sent_msg.arbitration_id == 0x600 + NODE_ID
    assert sent_msg.data[0] == 0x40  # REQUEST_UPLOAD


async def test_read_segmented(sdo_client: SdoClient, mock_send_callback: MagicMock):
    """Test a successful segmented SDO read."""
    index, subindex = 0x1009, 0x00
    long_data = b"this is a long data string for testing"

    # --- Server Responses ---
    # 1. Initiation response
    init_response_cs = 0x41  # Segmented, size indicated
    init_response = bytearray(
        struct.pack("<B H B L", init_response_cs, index, subindex, len(long_data))
    )

    # 2. Segment responses
    segment_responses = []
    toggle = 0
    bytes_sent = 0
    while bytes_sent < len(long_data):
        chunk = long_data[bytes_sent : bytes_sent + 7]
        bytes_in_segment = len(chunk)
        bytes_sent += bytes_in_segment
        is_last = 1 if bytes_sent >= len(long_data) else 0

        seg_cs = (toggle << 4) | ((7 - bytes_in_segment) << 1) | is_last
        payload = bytearray(chunk)
        payload.extend(b"\x00" * (7 - len(chunk)))
        segment_responses.append(bytearray([seg_cs]) + payload)
        toggle ^= 1

    # --- Test Execution ---
    read_task = asyncio.create_task(sdo_client.read(index, subindex))

    # Queue the responses
    await queue_response(sdo_client, init_response, delay=0.01)
    for resp in segment_responses:
        await queue_response(sdo_client, resp, delay=0.01)

    result = await read_task

    assert result == long_data
    # Check that the correct number of requests were sent (1 initiate + num_segments)
    assert mock_send_callback.call_count == 1 + len(segment_responses)


# --- Write Tests ---


async def test_write_expedited(sdo_client: SdoClient, mock_send_callback: MagicMock):
    """Test a successful expedited SDO write."""
    index, subindex = 0x2000, 0x01
    data_to_write = b"OK"

    # Server response: success
    response_cs = 0x60  # download success
    response = bytearray(struct.pack("<B H B L", response_cs, index, subindex, 0))

    write_task = asyncio.create_task(sdo_client.write(index, subindex, data_to_write))
    await queue_response(sdo_client, response, delay=0.01)

    await write_task  # Should complete without error

    mock_send_callback.assert_called_once()
    sent_msg = mock_send_callback.call_args[0][0]
    assert sent_msg.arbitration_id == 0x600 + NODE_ID
    # Check for expedited download request CS
    assert sent_msg.data[0] & 0xF3 == 0x23


# --- Error Handling Tests ---


async def test_sdo_abort(sdo_client: SdoClient):
    """Test that SdoAbortedError is raised on abort."""
    index, subindex = 0x1010, 0x00
    abort_code = 0x06090011  # Object does not exist

    response = bytearray(struct.pack("<B H B L", 0x80, index, subindex, abort_code))

    read_task = asyncio.create_task(sdo_client.read(index, subindex))
    await queue_response(sdo_client, response, delay=0.01)

    with pytest.raises(SdoAbortedError) as excinfo:
        await read_task
    assert excinfo.value.code == abort_code


async def test_sdo_timeout(sdo_client: SdoClient):
    """Test that asyncio.TimeoutError is raised on timeout."""
    with pytest.raises(asyncio.TimeoutError):
        await sdo_client.read(0x1018, 0x01)
