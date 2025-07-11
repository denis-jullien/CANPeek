from PySide6.QtCore import (
    Signal,
    QObject,
)
import can
from .data_utils import Connection, CANFrame
import threading
import time
from queue import Queue
from multiprocessing import Process, Queue as MPQueue, Event as MPEvent
import signal


# A "safe" notifier that won't crash on network errors
class SafeNotifier(can.Notifier):
    def _on_message_available(self, bus: can.BusABC) -> None:
        try:
            if msg := bus.recv(0):
                self._on_message_received(msg)
        except can.CanOperationError as e:
            if self._loop is not None:
                self._loop.call_soon_threadsafe(self._on_error, e)
            else:
                self._on_error(e)


# Metaclass to resolve conflict between QObject and can.Listener
class QObjectListenerMeta(type(QObject), type(can.Listener)):
    pass


def can_worker_process(
    connection_dict: dict,
    frame_queue: MPQueue,
    control_queue: MPQueue,
    send_queue: MPQueue,
    stop_event: MPEvent,
):
    """
    Worker process function for CAN reading/sending - runs in separate process to avoid GIL

    Args:
        connection_dict: Serialized Connection object as dict
        frame_queue: Multiprocessing queue for sending frames to main process
        control_queue: Queue for control messages (errors, state changes)
        send_queue: Queue for receiving messages to send from main process
        stop_event: Event to signal process shutdown
    """
    # Reconstruct connection from dict
    connection = Connection(
        id=connection_dict["id"],
        name=connection_dict["name"],
        interface=connection_dict["interface"],
        config=connection_dict["config"],
    )

    bus = None

    # Handle graceful shutdown on SIGTERM
    def signal_handler(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Create CAN bus
        bus = can.Bus(
            interface=connection.interface,
            receive_own_messages=True,
            **connection.config,
        )

        print(f"Opened multiprocess CAN bus '{connection.name}', State: {bus.state}")

        # Send initial state
        control_queue.put(("bus_state", bus.state))

        # Main reading/sending loop
        while not stop_event.is_set():
            try:
                # Check for outgoing messages to send
                try:
                    while not send_queue.empty():
                        # Get message to send (non-blocking)
                        msg_dict = send_queue.get_nowait()

                        # Reconstruct can.Message from dict
                        msg = can.Message(
                            arbitration_id=msg_dict["arbitration_id"],
                            data=msg_dict["data"],
                            is_extended_id=msg_dict.get("is_extended_id", False),
                            is_remote_frame=msg_dict.get("is_remote_frame", False),
                            is_error_frame=msg_dict.get("is_error_frame", False),
                            dlc=msg_dict.get("dlc", len(msg_dict["data"])),
                        )

                        # Send the message
                        bus.send(msg)
                        print(f"Sent message on {connection.name}: {msg}")

                except Exception as e:
                    # Continue even if send fails
                    control_queue.put(
                        ("error", f"Send error on {connection.name}: {e}")
                    )

                # Non-blocking read with timeout
                msg = bus.recv(
                    timeout=0.01
                )  # 10ms timeout (faster for send responsiveness)

                if msg is not None:
                    if msg.is_error_frame:
                        if bus:
                            control_queue.put(("bus_state", bus.state))
                        continue

                    # Create CANFrame - must be pickleable for multiprocessing
                    frame = CANFrame(
                        msg.timestamp,
                        msg.arbitration_id,
                        msg.data,
                        msg.dlc,
                        msg.is_extended_id,
                        msg.is_error_frame,
                        msg.is_remote_frame,
                        bus=connection.name,
                        connection_id=connection.id,
                        is_rx=msg.is_rx,
                    )

                    try:
                        # Send frame to main process (non-blocking)
                        frame_queue.put_nowait(frame)
                    except Exception as e:
                        # Queue full - drop frame and report
                        control_queue.put(
                            ("error", f"Frame queue full, dropping message: {e}")
                        )

            except can.CanTimeoutError:
                # Timeout is expected, continue
                continue
            except can.CanOperationError as e:
                # Emit error but continue trying
                control_queue.put(
                    ("error", f"CAN operation error on {connection.name}: {e}")
                )
                time.sleep(0.1)  # Brief pause before retrying
                continue
            except Exception as e:
                # Unexpected error
                control_queue.put(
                    (
                        "error",
                        f"Unexpected error in CAN worker process {connection.name}: {e}",
                    )
                )
                break

    except Exception as e:
        control_queue.put(
            ("error", f"Failed to start CAN worker process for {connection.name}: {e}")
        )
    finally:
        if bus:
            try:
                bus.shutdown()
                print(f"CAN bus {connection.name} shutdown complete in worker process")
            except Exception as e:
                print(
                    f"Error shutting down CAN bus {connection.name} in worker process: {e}"
                )


# Multiprocessing-based CAN reader (GIL-free)
class CANMultiprocessReader(QObject):
    frame_received = Signal(object)
    error_occurred = Signal(str)
    bus_state_changed = Signal(object)

    def __init__(self, connection: Connection, frame_queues: list[Queue] = None):
        super().__init__()
        self.connection = connection
        self.running = False
        self.worker_process = None
        self.bridge_thread = None
        self._stop_event = None

        # Multiprocessing queues
        self.frame_queue = None
        self.control_queue = None
        self.send_queue = None

        # Support both queue-based and signal-based operation
        self.frame_queues = frame_queues or []

    def start_reading(self):
        """Start multiprocess CAN reading"""
        if self.running:
            return True

        try:
            # Create multiprocessing queues and events
            self.frame_queue = MPQueue(maxsize=10000)  # Large queue to prevent blocking
            self.control_queue = MPQueue(maxsize=1000)
            self.send_queue = MPQueue(maxsize=100)  # Queue for outgoing messages
            self._stop_event = MPEvent()

            # Convert connection to dict for serialization
            connection_dict = {
                "id": self.connection.id,
                "name": self.connection.name,
                "interface": self.connection.interface,
                "config": self.connection.config,
            }

            # Start worker process
            self.worker_process = Process(
                target=can_worker_process,
                args=(
                    connection_dict,
                    self.frame_queue,
                    self.control_queue,
                    self.send_queue,
                    self._stop_event,
                ),
                name=f"CAN-{self.connection.name}",
                daemon=True,
            )

            # Start bridge thread to convert multiprocessing events to Qt signals
            self.bridge_thread = threading.Thread(
                target=self._bridge_thread,
                name=f"CANBridge-{self.connection.name}",
                daemon=True,
            )

            self.running = True
            self.worker_process.start()
            self.bridge_thread.start()

            print(f"CAN multiprocess reader started for {self.connection.name}")
            return True

        except Exception as e:
            self.error_occurred.emit(
                f"Failed to start multiprocess CAN reading on {self.connection.name}: {e}"
            )
            return False

    def _bridge_thread(self):
        """Thread function to bridge multiprocessing events to Qt signals"""
        print(f"CAN bridge thread running for {self.connection.name}")

        try:
            while self.running:
                try:
                    # Poll frame queue
                    while not self.frame_queue.empty():
                        try:
                            frame = self.frame_queue.get_nowait()
                            self._process_frame(frame)
                        except Exception:
                            break

                    # Poll control queue
                    while not self.control_queue.empty():
                        try:
                            msg_type, data = self.control_queue.get_nowait()
                            if msg_type == "error":
                                self.error_occurred.emit(data)
                            elif msg_type == "bus_state":
                                self.bus_state_changed.emit(data)
                        except Exception:
                            break

                    # Small sleep to prevent busy waiting
                    time.sleep(0.001)  # 1ms

                except Exception as e:
                    self.error_occurred.emit(
                        f"Error in bridge thread for {self.connection.name}: {e}"
                    )
                    break

        except Exception as e:
            self.error_occurred.emit(
                f"Bridge thread crashed for {self.connection.name}: {e}"
            )
        finally:
            print(f"CAN bridge thread stopped for {self.connection.name}")

    def _process_frame(self, frame: CANFrame):
        """Process a received CAN frame from worker process"""
        try:
            frames_dropped = 0
            # Write directly to queue if available
            for queue in self.frame_queues:
                if queue is not None and isinstance(queue, Queue):
                    try:
                        queue.put_nowait(frame)
                    except Exception:
                        frames_dropped += 1

            if frames_dropped > 0:
                print(
                    f"Warning: {frames_dropped} frames dropped for {self.connection.name}"
                )

            # Emit signal (thread-safe Qt signal)
            self.frame_received.emit(frame)

        except Exception as e:
            self.error_occurred.emit(
                f"Error processing frame in {self.connection.name}: {e}"
            )

    def send_frame(self, message: can.Message):
        """Send a CAN frame using the shared bus connection in worker process"""
        if not self.running:
            raise RuntimeError(
                f"Cannot send frame - CAN reader {self.connection.name} is not running"
            )

        if not self.send_queue:
            raise RuntimeError(f"Send queue not available for {self.connection.name}")

        try:
            # Convert can.Message to dict for multiprocessing serialization
            msg_dict = {
                "arbitration_id": message.arbitration_id,
                "data": list(
                    message.data
                ),  # Convert bytes to list for JSON serialization
                "is_extended_id": message.is_extended_id,
                "is_remote_frame": message.is_remote_frame,
                "is_error_frame": message.is_error_frame,
                "dlc": message.dlc,
            }

            # Send to worker process via queue (non-blocking)
            self.send_queue.put_nowait(msg_dict)
            print(f"Queued frame for sending on {self.connection.name}: {message}")

        except Exception as e:
            error_msg = (
                f"Failed to queue frame for sending on {self.connection.name}: {e}"
            )
            print(error_msg)
            self.error_occurred.emit(error_msg)
            raise

    def stop_reading(self):
        """Stop multiprocess CAN reading"""
        print(f"Stopping CAN multiprocess reader for {self.connection.name}")

        self.running = False

        # Stop worker process
        if self._stop_event:
            self._stop_event.set()

        if self.worker_process and self.worker_process.is_alive():
            # Wait for process to finish
            self.worker_process.join(timeout=2.0)
            if self.worker_process.is_alive():
                print(
                    f"Warning: Terminating CAN worker process for {self.connection.name}"
                )
                self.worker_process.terminate()
                self.worker_process.join(timeout=1.0)
                if self.worker_process.is_alive():
                    print(
                        f"Warning: Killing CAN worker process for {self.connection.name}"
                    )
                    self.worker_process.kill()

        # Stop bridge thread
        if self.bridge_thread and self.bridge_thread.is_alive():
            self.bridge_thread.join(timeout=2.0)
            if self.bridge_thread.is_alive():
                print(
                    f"Warning: Bridge thread for {self.connection.name} did not stop cleanly"
                )

        # Clean up queues
        if self.frame_queue:
            try:
                while not self.frame_queue.empty():
                    self.frame_queue.get_nowait()
            except Exception:
                pass

        if self.control_queue:
            try:
                while not self.control_queue.empty():
                    self.control_queue.get_nowait()
            except Exception:
                pass

        if self.send_queue:
            try:
                while not self.send_queue.empty():
                    self.send_queue.get_nowait()
            except Exception:
                pass

        print(f"CAN multiprocess reader stopped for {self.connection.name}")

    # Implement required Listener methods for compatibility
    def on_message_received(self, msg: can.Message) -> None:
        """Not used in multiprocess mode"""
        pass

    def on_error(self, exc: Exception):
        """Not used in multiprocess mode"""
        pass
