"""
High-performance CAN bus reader with multi-bus support.

This module provides threaded CAN frame reception with:
- Per-bus reader threads
- Lock-free buffer communication
- Error handling and bus state monitoring
- Clean shutdown handling
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional, Callable
from uuid import UUID

import can
from can import Bus, Message, Notifier, Listener
from can.exceptions import CanOperationError

from canpeek.core.types import CANFrame, BusState, Connection, BusStatistics
from canpeek.core.buffer import RingBuffer


@dataclass
class ReaderConfig:
    """Configuration for CAN reader."""
    buffer_capacity: int = 100_000
    receive_own_messages: bool = True
    error_frames: bool = True
    poll_timeout: float = 0.1  # Seconds


class BusStateError(Exception):
    """Raised when bus enters error state."""
    pass


class CANBusReader(Listener):
    """
    Thread-safe CAN bus reader using python-can.

    Runs frame reception in a dedicated thread, pushing frames
    to a ring buffer for consumption by the main application.

    Features:
        - Threaded reception for non-blocking operation
        - Lock-free buffer for high throughput
        - Bus state monitoring
        - Error frame handling
        - Clean shutdown

    Example:
        >>> reader = CANBusReader(connection, buffer)
        >>> reader.on_state_change = lambda s: print(f"State: {s}")
        >>> reader.on_error = lambda e: print(f"Error: {e}")
        >>> reader.start()
        >>> # ... frames are pushed to buffer ...
        >>> reader.stop()
    """

    def __init__(
        self,
        connection: Connection,
        buffer: RingBuffer[CANFrame],
        config: Optional[ReaderConfig] = None,
    ):
        """
        Initialize CAN bus reader.

        Args:
            connection: Connection configuration
            buffer: Ring buffer to push frames to
            config: Reader configuration
        """
        super().__init__()
        self.connection = connection
        self.buffer = buffer
        self.config = config or ReaderConfig()

        self._bus: Optional[Bus] = None
        self._notifier: Optional[Notifier] = None
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self._stop_event = threading.Event()

        # Statistics
        self.statistics = BusStatistics(
            bus_id=0,
            bus_name=connection.name,
        )

        # Callbacks
        self.on_state_change: Optional[Callable[[BusState], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None
        self.on_started: Optional[Callable[[], None]] = None
        self.on_stopped: Optional[Callable[[], None]] = None

        self._last_state = BusState.UNKNOWN

    @property
    def is_running(self) -> bool:
        """Check if reader is running."""
        return self._running.is_set()

    @property
    def bus_state(self) -> BusState:
        """Get current bus state."""
        if self._bus is None:
            return BusState.UNKNOWN

        try:
            state = self._bus.state
            if state == can.BusState.ACTIVE:
                return BusState.ERROR_ACTIVE
            elif state == can.BusState.PASSIVE:
                return BusState.ERROR_PASSIVE
            elif state == can.BusState.ERROR:
                return BusState.BUS_OFF
        except Exception:
            pass

        return BusState.UNKNOWN

    def start(self) -> bool:
        """
        Start the CAN bus reader.

        Returns:
            True if started successfully

        Raises:
            Exception: If bus cannot be opened
        """
        if self._running.is_set():
            return True

        try:
            # Build bus configuration
            bus_config = self.connection.to_python_can_config()
            bus_config['receive_own_messages'] = self.config.receive_own_messages

            # Open bus
            self._bus = Bus(**bus_config)

            # Start notifier (uses internal threading)
            self._notifier = Notifier(
                self._bus,
                [self],
                timeout=self.config.poll_timeout
            )

            self._running.set()
            self._stop_event.clear()

            # Notify
            if self.on_started:
                self.on_started()

            # Check initial state
            self._check_state()

            return True

        except Exception as e:
            self._cleanup()
            if self.on_error:
                self.on_error(f"Failed to start: {e}")
            raise

    def stop(self) -> None:
        """Stop the CAN bus reader."""
        if not self._running.is_set():
            return

        self._stop_event.set()
        self._running.clear()

        self._cleanup()

        if self.on_stopped:
            self.on_stopped()

    def _cleanup(self) -> None:
        """Clean up resources."""
        if self._notifier:
            try:
                self._notifier.stop()
            except Exception:
                pass
            self._notifier = None

        if self._bus:
            try:
                self._bus.shutdown()
            except Exception:
                pass
            self._bus = None

    def on_message_received(self, msg: Message) -> None:
        """
        Called by python-can Notifier when a message is received.

        This is called from the Notifier's internal thread.
        """
        if self._stop_event.is_set():
            return

        # Handle error frames
        if msg.is_error_frame:
            self.statistics.error_frames += 1
            self._check_state()

            if not self.config.error_frames:
                return

        # Convert to CANFrame
        frame = CANFrame.from_python_can(
            msg,
            bus_id=0,  # Will be set by bus manager
            bus_name=self.connection.name,
            connection_id=self.connection.id,
        )

        # Update statistics
        self.statistics.update(frame)

        # Push to buffer
        self.buffer.push(frame)

    def on_error(self, exc: Exception) -> None:
        """Called by python-can Notifier on error."""
        if isinstance(exc, CanOperationError):
            self._check_state()
            if self.on_error:
                self.on_error(f"CAN error: {exc}")
        else:
            if self.on_error:
                self.on_error(f"Error: {exc}")

    def _check_state(self) -> None:
        """Check bus state and notify if changed."""
        new_state = self.bus_state
        if new_state != self._last_state:
            self._last_state = new_state
            self.statistics.state = new_state
            if self.on_state_change:
                self.on_state_change(new_state)

    def send(self, frame: CANFrame) -> bool:
        """
        Send a CAN frame.

        Args:
            frame: Frame to send

        Returns:
            True if sent successfully
        """
        if not self._running.is_set() or self._bus is None:
            return False

        try:
            msg = Message(
                arbitration_id=frame.arbitration_id,
                data=frame.data,
                is_extended_id=frame.is_extended_id,
                is_fd=frame.is_fd,
                bitrate_switch=frame.is_brs,
                is_remote_frame=frame.is_remote_frame,
            )
            self._bus.send(msg)

            # Update TX statistics
            self.statistics.tx_frames += 1
            self.statistics.tx_bytes += len(frame.data)

            return True

        except Exception as e:
            if self.on_error:
                self.on_error(f"Send error: {e}")
            return False

    def send_message(
        self,
        arbitration_id: int,
        data: bytes,
        is_extended_id: bool = False,
        is_fd: bool = False,
        is_brs: bool = False,
        is_remote_frame: bool = False,
    ) -> bool:
        """
        Send a CAN message with explicit parameters.

        Returns:
            True if sent successfully
        """
        frame = CANFrame.create(
            arbitration_id=arbitration_id,
            data=data,
            is_extended_id=is_extended_id,
            is_fd=is_fd,
            is_brs=is_brs,
            is_remote_frame=is_remote_frame,
            is_rx=False,
            connection_id=self.connection.id,
        )
        return self.send(frame)


class BusManager:
    """
    Manages multiple CAN bus readers.

    Provides a unified interface for working with multiple CAN buses,
    including starting/stopping all buses, sending frames, and
    collecting frames from all buses.

    Example:
        >>> manager = BusManager()
        >>> manager.add_connection(connection1)
        >>> manager.add_connection(connection2)
        >>> manager.start_all()
        >>> frames = manager.get_all_frames()
        >>> manager.stop_all()
    """

    def __init__(self, buffer_capacity: int = 100_000):
        """
        Initialize bus manager.

        Args:
            buffer_capacity: Capacity for each bus's ring buffer
        """
        self.buffer_capacity = buffer_capacity

        self._readers: dict[UUID, CANBusReader] = {}
        self._buffers: dict[UUID, RingBuffer[CANFrame]] = {}
        self._connections: dict[UUID, Connection] = {}
        self._lock = threading.Lock()

        # Callbacks
        self.on_frame_received: Optional[Callable[[CANFrame], None]] = None
        self.on_bus_state_change: Optional[Callable[[UUID, BusState], None]] = None
        self.on_bus_error: Optional[Callable[[UUID, str], None]] = None

    def add_connection(self, connection: Connection) -> None:
        """Add a connection configuration."""
        with self._lock:
            self._connections[connection.id] = connection

    def remove_connection(self, connection_id: UUID) -> None:
        """Remove a connection (stops reader if running)."""
        self.stop_reader(connection_id)
        with self._lock:
            self._connections.pop(connection_id, None)
            self._buffers.pop(connection_id, None)

    def get_connection(self, connection_id: UUID) -> Optional[Connection]:
        """Get connection by ID."""
        with self._lock:
            return self._connections.get(connection_id)

    def get_all_connections(self) -> list[Connection]:
        """Get all connections."""
        with self._lock:
            return list(self._connections.values())

    def start_reader(self, connection_id: UUID) -> bool:
        """
        Start reader for a specific connection.

        Returns:
            True if started successfully
        """
        with self._lock:
            if connection_id in self._readers:
                return self._readers[connection_id].is_running

            connection = self._connections.get(connection_id)
            if not connection or not connection.enabled:
                return False

            # Create buffer
            buffer = RingBuffer[CANFrame](capacity=self.buffer_capacity)
            self._buffers[connection_id] = buffer

            # Create reader
            reader = CANBusReader(connection, buffer)

            # Set up callbacks
            def on_state(state: BusState, cid=connection_id):
                if self.on_bus_state_change:
                    self.on_bus_state_change(cid, state)

            def on_error(msg: str, cid=connection_id):
                if self.on_bus_error:
                    self.on_bus_error(cid, msg)

            reader.on_state_change = on_state
            reader.on_error = on_error

            self._readers[connection_id] = reader

        # Start outside lock
        try:
            return reader.start()
        except Exception as e:
            with self._lock:
                self._readers.pop(connection_id, None)
                self._buffers.pop(connection_id, None)
            if self.on_bus_error:
                self.on_bus_error(connection_id, str(e))
            return False

    def stop_reader(self, connection_id: UUID) -> None:
        """Stop reader for a specific connection."""
        with self._lock:
            reader = self._readers.pop(connection_id, None)

        if reader:
            reader.stop()

    def start_all(self) -> dict[UUID, bool]:
        """
        Start all enabled connections.

        Returns:
            Dict mapping connection ID to success status
        """
        results = {}
        with self._lock:
            connection_ids = [
                cid for cid, conn in self._connections.items()
                if conn.enabled
            ]

        for cid in connection_ids:
            results[cid] = self.start_reader(cid)

        return results

    def stop_all(self) -> None:
        """Stop all readers."""
        with self._lock:
            reader_ids = list(self._readers.keys())

        for cid in reader_ids:
            self.stop_reader(cid)

    def is_running(self, connection_id: UUID) -> bool:
        """Check if a reader is running."""
        with self._lock:
            reader = self._readers.get(connection_id)
            return reader.is_running if reader else False

    def get_any_running(self) -> bool:
        """Check if any reader is running."""
        with self._lock:
            return any(r.is_running for r in self._readers.values())

    def get_frames(self, connection_id: UUID, max_count: int = 10000) -> list[CANFrame]:
        """
        Get frames from a specific bus.

        Args:
            connection_id: Connection ID
            max_count: Maximum frames to return

        Returns:
            List of frames
        """
        with self._lock:
            buffer = self._buffers.get(connection_id)

        if buffer:
            return buffer.pop_batch(max_count)
        return []

    def get_all_frames(self, max_per_bus: int = 10000) -> list[CANFrame]:
        """
        Get frames from all buses, sorted by timestamp.

        Args:
            max_per_bus: Maximum frames per bus

        Returns:
            Merged list of frames sorted by timestamp
        """
        all_frames: list[CANFrame] = []

        with self._lock:
            buffers = list(self._buffers.values())

        for buffer in buffers:
            all_frames.extend(buffer.pop_batch(max_per_bus))

        # Sort by timestamp
        all_frames.sort(key=lambda f: f.timestamp_ns)
        return all_frames

    def send_frame(self, connection_id: UUID, frame: CANFrame) -> bool:
        """
        Send a frame on a specific bus.

        Returns:
            True if sent successfully
        """
        with self._lock:
            reader = self._readers.get(connection_id)

        if reader:
            return reader.send(frame)
        return False

    def get_statistics(self, connection_id: UUID) -> Optional[BusStatistics]:
        """Get statistics for a bus."""
        with self._lock:
            reader = self._readers.get(connection_id)
            return reader.statistics if reader else None

    def get_all_statistics(self) -> dict[UUID, BusStatistics]:
        """Get statistics for all buses."""
        with self._lock:
            return {
                cid: reader.statistics
                for cid, reader in self._readers.items()
            }

    def get_bus_state(self, connection_id: UUID) -> BusState:
        """Get bus state for a connection."""
        with self._lock:
            reader = self._readers.get(connection_id)
            return reader.bus_state if reader else BusState.UNKNOWN
