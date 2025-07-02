"""
A standalone SDO client for handling SDO communication.
"""

import asyncio
import struct
import uuid

import can
import canopen


class SdoAbortedError(Exception):
    """Raised when an SDO transfer is aborted by the server."""

    def __init__(self, code):
        self.code = code
        super().__init__(f"SDO Abort Code: 0x{code:08X}")


class SdoClient:
    """A client for handling SDO communication."""

    def __init__(self, node_id: int, connection_id: uuid.UUID, frame_to_send_callback):
        self.node_id = node_id
        self.connection_id = connection_id
        self.frame_to_send_callback = frame_to_send_callback
        self.response_queue = asyncio.Queue(maxsize=127)
        self.transfer_abort_event = asyncio.Event()

    async def on_frame_rx(self, frame: can.Message):
        """Handle received SDO frames by placing them in the response queue."""
        if frame.arbitration_id != (0x580 + self.node_id):
            return

        try:
            self.response_queue.put_nowait(frame)
        except asyncio.QueueFull:
            print("SDO response queue is full, dropping frame.")

    async def read(self, index: int, subindex: int) -> bytes:
        """Read a value from the object dictionary."""
        self.transfer_abort_event.clear()
        while not self.response_queue.empty():
            self.response_queue.get_nowait()

        request = bytearray(8)
        command_specifier = canopen.sdo.constants.REQUEST_UPLOAD
        struct.pack_into("<B H B", request, 0, command_specifier, index, subindex)

        self.frame_to_send_callback(
            can.Message(
                arbitration_id=0x600 + self.node_id,
                is_extended_id=False,
                dlc=8,
                data=request,
            ),
            self.connection_id,
        )

        response_frame = await asyncio.wait_for(self.response_queue.get(), timeout=2.0)
        cs, res_index, res_subindex, payload = struct.unpack_from(
            "<B H B 4s", response_frame.data
        )

        if cs == 0x80:
            abort_code = struct.unpack_from("<L", payload)[0]
            raise SdoAbortedError(abort_code)

        if res_index != index or res_subindex != subindex:
            raise ValueError("Received SDO response for a different object.")

        if cs & 0x02:  # Expedited transfer
            size_indicated = (cs >> 2) & 0x03
            num_bytes = 4 - size_indicated
            return payload[:num_bytes]

        if cs & 0x01:  # Segmented transfer initiated
            total_size = struct.unpack_from("<L", payload)[0]
            received_data = bytearray()
            toggle_bit = 0

            while len(received_data) < total_size:
                if self.transfer_abort_event.is_set():
                    raise asyncio.CancelledError("Transfer aborted by user")

                segment_req_cs = 0x60 | (toggle_bit << 4)
                self.frame_to_send_callback(
                    can.Message(
                        arbitration_id=0x600 + self.node_id,
                        is_extended_id=False,
                        dlc=8,
                        data=bytes([segment_req_cs, 0, 0, 0, 0, 0, 0, 0]),
                    ),
                    self.connection_id,
                )

                segment_frame = await asyncio.wait_for(
                    self.response_queue.get(), timeout=2.0
                )
                seg_cs = segment_frame.data[0]
                seg_payload = segment_frame.data[1:]

                if seg_cs == 0x80:
                    abort_code = struct.unpack_from("<L", segment_frame.data[4:])[0]
                    raise SdoAbortedError(abort_code)

                if (seg_cs >> 4) & 1 != toggle_bit:
                    raise ValueError("SDO protocol error: toggle bit mismatch.")

                bytes_in_segment = 7 - ((seg_cs >> 1) & 0x7)
                received_data.extend(seg_payload[:bytes_in_segment])

                if seg_cs & 0x01:
                    break

                toggle_bit ^= 1
            return received_data

        raise ValueError(f"Invalid SDO initiation response (CS=0x{cs:02X})")

    async def write(self, index: int, subindex: int, data: bytes):
        """Write a value to the object dictionary."""
        self.transfer_abort_event.clear()
        while not self.response_queue.empty():
            self.response_queue.get_nowait()

        total_size = len(data)
        init_request = bytearray(8)

        if total_size <= 4:
            cs = 0x23 | ((4 - total_size) << 2)
            payload = bytearray(data)
            payload.extend(b"\x00" * (4 - total_size))
            struct.pack_into("<B H B 4s", init_request, 0, cs, index, subindex, payload)
        else:
            cs = 0x21
            struct.pack_into(
                "<B H B L", init_request, 0, cs, index, subindex, total_size
            )

        self.frame_to_send_callback(
            can.Message(
                arbitration_id=0x600 + self.node_id,
                is_extended_id=False,
                dlc=8,
                data=init_request,
            ),
            self.connection_id,
        )

        response_frame = await asyncio.wait_for(self.response_queue.get(), timeout=2.0)
        cs, res_index, res_subindex, _ = struct.unpack_from(
            "<B H B 4s", response_frame.data
        )

        if cs == 0x80:
            abort_code = struct.unpack_from("<L", response_frame.data[4:])[0]
            raise SdoAbortedError(abort_code)

        if cs != 0x60:
            raise ValueError(f"Invalid SDO initiation response (CS=0x{cs:02X})")

        if total_size > 4:
            toggle_bit = 0
            bytes_sent = 0
            while bytes_sent < total_size:
                if self.transfer_abort_event.is_set():
                    raise asyncio.CancelledError("Transfer aborted by user")

                chunk = data[bytes_sent : bytes_sent + 7]
                bytes_in_segment = len(chunk)
                bytes_sent += bytes_in_segment

                is_last_segment = 1 if bytes_sent >= total_size else 0
                num_unused_bytes = 7 - bytes_in_segment

                seg_cs = (toggle_bit << 4) | (num_unused_bytes << 1) | is_last_segment

                seg_payload = bytearray(chunk)
                seg_payload.extend(b"\x00" * num_unused_bytes)

                seg_request = bytearray([seg_cs]) + seg_payload

                self.frame_to_send_callback(
                    can.Message(
                        arbitration_id=0x600 + self.node_id,
                        dlc=8,
                        data=seg_request,
                    ),
                    self.connection_id,
                )

                seg_resp_frame = await asyncio.wait_for(
                    self.response_queue.get(), timeout=2.0
                )
                ack_cs = seg_resp_frame.data[0]

                if ack_cs == 0x80:
                    abort_code = struct.unpack_from("<L", seg_resp_frame.data[4:])[0]
                    raise SdoAbortedError(abort_code)

                if (ack_cs & 0x10) != (toggle_bit << 4):
                    raise ValueError("SDO protocol error: toggle bit mismatch.")

                toggle_bit ^= 1
