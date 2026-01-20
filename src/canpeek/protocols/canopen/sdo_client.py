"""
SDO (Service Data Object) client for CANopen communication.

Provides async read/write access to CANopen object dictionary entries.
"""

import asyncio
import struct
from typing import Callable, Optional
from uuid import UUID

import can

# SDO abort codes with descriptions
SDO_ABORT_CODES = {
    0x05030000: "Toggle bit not alternated",
    0x05040000: "SDO protocol timed out",
    0x05040001: "Client/server command specifier not valid",
    0x05040002: "Invalid block size",
    0x05040003: "Invalid sequence number",
    0x05040004: "CRC error",
    0x05040005: "Out of memory",
    0x06010000: "Unsupported access to an object",
    0x06010001: "Attempt to read a write-only object",
    0x06010002: "Attempt to write a read-only object",
    0x06020000: "Object does not exist in the object dictionary",
    0x06040041: "Object cannot be mapped to the PDO",
    0x06040042: "Number and length of objects would exceed PDO length",
    0x06040043: "General parameter incompatibility reason",
    0x06040047: "General internal incompatibility in the device",
    0x06060000: "Access failed due to hardware error",
    0x06070010: "Data type does not match, length does not match",
    0x06070012: "Data type does not match, length too high",
    0x06070013: "Data type does not match, length too low",
    0x06090011: "Sub-index does not exist",
    0x06090030: "Invalid value for parameter",
    0x06090031: "Value too high",
    0x06090032: "Value too low",
    0x06090036: "Maximum value is less than minimum value",
    0x060A0023: "Resource not available: SDO connection",
    0x08000000: "General error",
    0x08000020: "Data cannot be transferred or stored to the application",
    0x08000021: "Data cannot be transferred due to local control",
    0x08000022: "Data cannot be transferred due to device state",
    0x08000023: "Object dictionary dynamic generation fails",
    0x08000024: "No data available",
}


class SdoAbortError(Exception):
    """Exception raised when an SDO transfer is aborted."""

    def __init__(self, code: int):
        self.code = code
        self.message = SDO_ABORT_CODES.get(code, f"Unknown error (0x{code:08X})")
        super().__init__(f"SDO Abort 0x{code:08X}: {self.message}")


class SdoTimeoutError(Exception):
    """Exception raised when an SDO operation times out."""

    pass


class SdoProtocolError(Exception):
    """Exception raised for SDO protocol violations."""

    pass


class SdoClient:
    """
    Async SDO client for reading/writing CANopen object dictionary entries.

    Usage:
        client = SdoClient(node_id=1, connection_id=uuid, send_callback=send_frame)

        # In frame receive handler:
        client.on_frame_received(frame)

        # To read:
        data = await client.read(0x1000, 0)

        # To write:
        await client.write(0x6040, 0, struct.pack('<H', 0x0006))
    """

    # SDO command specifiers
    INITIATE_DOWNLOAD_REQUEST = 0x20  # Write request
    INITIATE_UPLOAD_REQUEST = 0x40  # Read request
    SEGMENT_DOWNLOAD_REQUEST = 0x00
    SEGMENT_UPLOAD_REQUEST = 0x60
    ABORT_TRANSFER = 0x80

    def __init__(
        self,
        node_id: int,
        connection_id: UUID,
        send_callback: Callable[[can.Message, UUID], None],
        timeout: float = 2.0,
    ):
        """
        Initialize the SDO client.

        Args:
            node_id: CANopen node ID (1-127)
            connection_id: UUID of the CAN connection
            send_callback: Function to send CAN frames (frame, connection_id)
            timeout: Timeout for SDO operations in seconds
        """
        self.node_id = node_id
        self.connection_id = connection_id
        self._send = send_callback
        self._timeout = timeout
        self._response_queue: asyncio.Queue = asyncio.Queue(maxsize=16)
        self._abort_event = asyncio.Event()

    @property
    def tx_cob_id(self) -> int:
        """SDO request COB-ID (client -> server)."""
        return 0x600 + self.node_id

    @property
    def rx_cob_id(self) -> int:
        """SDO response COB-ID (server -> client)."""
        return 0x580 + self.node_id

    def on_frame_received(self, frame: can.Message) -> bool:
        """
        Process a received CAN frame.

        Call this from the main frame receive handler for all frames.
        Returns True if the frame was an SDO response for this client.
        """
        if frame.arbitration_id != self.rx_cob_id:
            return False

        try:
            self._response_queue.put_nowait(frame)
            return True
        except asyncio.QueueFull:
            # Queue full - old responses will be discarded
            return True

    def abort(self) -> None:
        """Abort any ongoing transfer."""
        self._abort_event.set()

    async def read(self, index: int, subindex: int) -> bytes:
        """
        Read a value from the object dictionary (SDO upload).

        Args:
            index: Object dictionary index (0x0000-0xFFFF)
            subindex: Sub-index (0-255)

        Returns:
            Raw bytes of the read value

        Raises:
            SdoAbortError: If the device aborts the transfer
            SdoTimeoutError: If no response within timeout
            SdoProtocolError: If protocol error occurs
        """
        self._abort_event.clear()
        self._clear_queue()

        # Build initiate upload request
        request = bytearray(8)
        struct.pack_into("<B H B", request, 0, self.INITIATE_UPLOAD_REQUEST, index, subindex)

        self._send_frame(request)

        # Wait for response
        response = await self._wait_response()
        cs = response.data[0]

        # Check for abort
        if cs == self.ABORT_TRANSFER:
            abort_code = struct.unpack_from("<L", response.data, 4)[0]
            raise SdoAbortError(abort_code)

        # Verify index/subindex match
        res_index, res_subindex = struct.unpack_from("<H B", response.data, 1)
        if res_index != index or res_subindex != subindex:
            raise SdoProtocolError(
                f"Response index mismatch: expected {index:04X}:{subindex}, "
                f"got {res_index:04X}:{res_subindex}"
            )

        # Check transfer type
        if cs & 0x02:  # Expedited transfer (e bit set)
            # Size indicated in cs bits 2-3
            if cs & 0x01:  # Size indicated
                size = 4 - ((cs >> 2) & 0x03)
            else:
                size = 4
            return bytes(response.data[4 : 4 + size])

        elif cs & 0x01:  # Normal transfer with size indicated
            # Segmented transfer
            total_size = struct.unpack_from("<L", response.data, 4)[0]
            return await self._read_segmented(total_size)

        else:
            # Normal transfer without size - read until end
            return await self._read_segmented(None)

    async def _read_segmented(self, total_size: Optional[int]) -> bytes:
        """Read data using segmented transfer."""
        data = bytearray()
        toggle = 0

        while True:
            if self._abort_event.is_set():
                raise asyncio.CancelledError("Transfer aborted")

            # Request next segment
            request = bytearray(8)
            request[0] = self.SEGMENT_UPLOAD_REQUEST | (toggle << 4)
            self._send_frame(request)

            response = await self._wait_response()
            cs = response.data[0]

            # Check for abort
            if cs == self.ABORT_TRANSFER:
                abort_code = struct.unpack_from("<L", response.data, 4)[0]
                raise SdoAbortError(abort_code)

            # Verify toggle bit
            if ((cs >> 4) & 0x01) != toggle:
                raise SdoProtocolError("Toggle bit mismatch")

            # Extract data (7 bytes max per segment)
            n = (cs >> 1) & 0x07  # Number of unused bytes
            segment_data = response.data[1 : 8 - n]
            data.extend(segment_data)

            # Check for last segment
            if cs & 0x01:
                break

            toggle ^= 1

            # Safety check
            if total_size and len(data) >= total_size:
                break

        return bytes(data)

    async def write(self, index: int, subindex: int, data: bytes) -> None:
        """
        Write a value to the object dictionary (SDO download).

        Args:
            index: Object dictionary index (0x0000-0xFFFF)
            subindex: Sub-index (0-255)
            data: Data to write

        Raises:
            SdoAbortError: If the device aborts the transfer
            SdoTimeoutError: If no response within timeout
            SdoProtocolError: If protocol error occurs
        """
        self._abort_event.clear()
        self._clear_queue()

        size = len(data)

        if size <= 4:
            # Expedited transfer
            await self._write_expedited(index, subindex, data)
        else:
            # Segmented transfer
            await self._write_segmented(index, subindex, data)

    async def _write_expedited(self, index: int, subindex: int, data: bytes) -> None:
        """Write using expedited transfer (≤4 bytes)."""
        size = len(data)
        # Build command specifier: expedited, size indicated
        cs = 0x23 | ((4 - size) << 2)

        request = bytearray(8)
        struct.pack_into("<B H B", request, 0, cs, index, subindex)
        request[4 : 4 + size] = data

        self._send_frame(request)

        response = await self._wait_response()
        self._check_download_response(response)

    async def _write_segmented(self, index: int, subindex: int, data: bytes) -> None:
        """Write using segmented transfer (>4 bytes)."""
        size = len(data)

        # Initiate download
        request = bytearray(8)
        cs = 0x21  # Download, size indicated, not expedited
        struct.pack_into("<B H B L", request, 0, cs, index, subindex, size)

        self._send_frame(request)

        response = await self._wait_response()
        self._check_download_response(response)

        # Send segments
        toggle = 0
        offset = 0

        while offset < size:
            if self._abort_event.is_set():
                raise asyncio.CancelledError("Transfer aborted")

            chunk = data[offset : offset + 7]
            chunk_size = len(chunk)
            offset += chunk_size

            is_last = offset >= size
            unused = 7 - chunk_size

            cs = (toggle << 4) | (unused << 1) | (1 if is_last else 0)

            request = bytearray(8)
            request[0] = cs
            request[1 : 1 + chunk_size] = chunk

            self._send_frame(request)

            response = await self._wait_response()
            resp_cs = response.data[0]

            if resp_cs == self.ABORT_TRANSFER:
                abort_code = struct.unpack_from("<L", response.data, 4)[0]
                raise SdoAbortError(abort_code)

            # Verify toggle bit in response
            if ((resp_cs >> 4) & 0x01) != toggle:
                raise SdoProtocolError("Toggle bit mismatch in download response")

            toggle ^= 1

    def _check_download_response(self, response: can.Message) -> None:
        """Check the response to a download initiation."""
        cs = response.data[0]

        if cs == self.ABORT_TRANSFER:
            abort_code = struct.unpack_from("<L", response.data, 4)[0]
            raise SdoAbortError(abort_code)

        if cs != 0x60:
            raise SdoProtocolError(f"Unexpected download response: 0x{cs:02X}")

    def _send_frame(self, data: bytes) -> None:
        """Send an SDO request frame."""
        frame = can.Message(
            arbitration_id=self.tx_cob_id,
            is_extended_id=False,
            dlc=8,
            data=bytes(data),
        )
        self._send(frame, self.connection_id)

    async def _wait_response(self) -> can.Message:
        """Wait for an SDO response with timeout."""
        try:
            return await asyncio.wait_for(
                self._response_queue.get(), timeout=self._timeout
            )
        except asyncio.TimeoutError:
            raise SdoTimeoutError(f"SDO timeout after {self._timeout}s")

    def _clear_queue(self) -> None:
        """Clear any pending responses."""
        while not self._response_queue.empty():
            try:
                self._response_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
