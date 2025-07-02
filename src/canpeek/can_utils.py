from PySide6.QtCore import (
    Signal,
    QObject,
)
import can
from .data_utils import Connection, CANFrame
import asyncio


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


# Replace the CANReaderThread class (around line 850)
class CANAsyncReader(QObject, can.Listener, metaclass=QObjectListenerMeta):
    frame_received = Signal(object)
    error_occurred = Signal(str)
    bus_state_changed = Signal(object)

    def __init__(self, connection: Connection):
        QObject.__init__(self)
        can.Listener.__init__(self)
        self.connection = connection
        self.running = False
        self.bus = None
        self.notifier = None
        self.reader = None
        self.read_task = None

    async def start_reading(self):
        """Start async CAN reading"""
        try:
            self.bus = can.Bus(
                interface=self.connection.interface,
                receive_own_messages=True,
                **self.connection.config,
            )

            print(
                f"Opened Bus '{self.connection.name}', State : {self.bus.state}, Info : {self.bus.channel_info}"
            )

            loop = asyncio.get_running_loop()
            self.notifier = SafeNotifier(self.bus, [self], loop=loop)
            self.running = True
            self.bus_state_changed.emit(self.bus.state)
            return True

        except Exception as e:
            self.error_occurred.emit(
                f"Failed to start CAN reading on {self.connection.name}: {e}"
            )
            return False

    def on_message_received(self, msg: can.Message) -> None:
        """Regular callback function. Can also be a coroutine."""
        if msg.is_error_frame:
            if self.bus:
                self.bus_state_changed.emit(self.bus.state)
            return

        frame = CANFrame(
            msg.timestamp,
            msg.arbitration_id,
            msg.data,
            msg.dlc,
            msg.is_extended_id,
            msg.is_error_frame,
            msg.is_remote_frame,
            bus=self.connection.name,
            connection_id=self.connection.id,
            is_rx=msg.is_rx,
        )
        self.frame_received.emit(frame)

    def on_error(self, exc: Exception):
        """Handle errors from the Notifier."""
        if isinstance(exc, can.CanOperationError):
            self.error_occurred.emit(f"CAN error on {self.connection.name}: {exc}")

    def stop_reading(self):
        """Stop async CAN reading"""
        self.running = False

        if self.read_task and not self.read_task.done():
            self.read_task.cancel()

        if self.notifier:
            self.notifier.stop()
            self.notifier = None

        if self.bus:
            try:
                self.bus.shutdown()
            except Exception as e:
                print(f"Error shutting down CAN bus on {self.connection.name}: {e}")
            finally:
                self.bus = None

        self.reader = None
        self.read_task = None

    def send_frame(self, message: can.Message):
        """Send a CAN frame"""
        if self.bus and self.running:
            try:
                self.bus.send(message)
            except Exception as e:
                self.error_occurred.emit(f"Send error on {self.connection.name}: {e}")
