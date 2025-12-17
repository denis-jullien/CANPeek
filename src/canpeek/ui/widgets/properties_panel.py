"""
Properties panel for displaying details about selected items.

Shows detailed information about:
- Selected CAN message (ID, signals, statistics)
- Selected connection (interface, bitrate, state)
- Selected database message definition
- Selected CANopen node
"""

from __future__ import annotations

from typing import Optional, Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QFormLayout,
    QLabel,
    QScrollArea,
    QGroupBox,
    QFrame,
)

from canpeek.core.types import Connection, BusState, CANFrame


class PropertiesPanel(QWidget):
    """
    Properties panel showing details of selected items.

    Displays contextual information based on what is selected in
    the project tree or receive/trace views.
    """

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._setup_ui()
        self._current_item = None

    def _setup_ui(self) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Scroll area for content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        layout.addWidget(scroll)

        # Content widget
        self._content = QWidget()
        self._content_layout = QVBoxLayout(self._content)
        self._content_layout.setAlignment(Qt.AlignTop)
        scroll.setWidget(self._content)

        # Title label
        self._title = QLabel("No Selection")
        self._title.setStyleSheet("font-weight: bold; font-size: 14px;")
        self._content_layout.addWidget(self._title)

        # Properties form
        self._form_group = QGroupBox("Properties")
        self._form = QFormLayout(self._form_group)
        self._content_layout.addWidget(self._form_group)

        # Signals group (for messages)
        self._signals_group = QGroupBox("Signals")
        self._signals_layout = QFormLayout(self._signals_group)
        self._signals_group.setVisible(False)
        self._content_layout.addWidget(self._signals_group)

        # Statistics group
        self._stats_group = QGroupBox("Statistics")
        self._stats_layout = QFormLayout(self._stats_group)
        self._stats_group.setVisible(False)
        self._content_layout.addWidget(self._stats_group)

        self._content_layout.addStretch()

    def clear(self) -> None:
        """Clear all displayed properties."""
        self._title.setText("No Selection")
        self._clear_form(self._form)
        self._clear_form(self._signals_layout)
        self._clear_form(self._stats_layout)
        self._signals_group.setVisible(False)
        self._stats_group.setVisible(False)
        self._current_item = None

    def _clear_form(self, form: QFormLayout) -> None:
        """Clear all rows from a form layout."""
        while form.rowCount() > 0:
            form.removeRow(0)

    def _add_row(self, form: QFormLayout, label: str, value: Any) -> None:
        """Add a row to a form layout."""
        value_label = QLabel(str(value))
        value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        value_label.setWordWrap(True)
        form.addRow(f"{label}:", value_label)

    def show_connection(self, connection: Connection, state: BusState = BusState.UNKNOWN) -> None:
        """Display connection properties."""
        self.clear()
        self._current_item = connection
        self._title.setText(f"Connection: {connection.name}")

        self._add_row(self._form, "Interface", connection.interface)
        self._add_row(self._form, "Channel", connection.channel)
        self._add_row(self._form, "Bitrate", f"{connection.bitrate:,} bps")

        if connection.fd:
            self._add_row(self._form, "Data Bitrate", f"{connection.data_bitrate:,} bps")
            self._add_row(self._form, "CAN FD", "Enabled")
        else:
            self._add_row(self._form, "CAN FD", "Disabled")

        self._add_row(self._form, "State", state.name)
        self._add_row(self._form, "Enabled", "Yes" if connection.enabled else "No")

        if connection.extra_config:
            self._add_row(self._form, "Extra Config", str(connection.extra_config))

    def show_frame(self, frame: CANFrame, decoded: Optional[dict] = None,
                   message_name: str = "", cycle_time: Optional[float] = None,
                   count: int = 0) -> None:
        """Display CAN frame properties."""
        self.clear()
        self._current_item = frame
        self._title.setText(f"Message: {frame.id_str()}")

        if message_name:
            self._add_row(self._form, "Name", message_name)

        self._add_row(self._form, "CAN ID", frame.id_str())
        self._add_row(self._form, "Type", frame.type_str())
        self._add_row(self._form, "DLC", frame.dlc)
        self._add_row(self._form, "Data Length", f"{len(frame.data)} bytes")
        self._add_row(self._form, "Data", frame.data_str())
        self._add_row(self._form, "Bus", frame.bus_name or str(frame.bus_id))
        self._add_row(self._form, "Direction", "RX" if frame.is_rx else "TX")
        self._add_row(self._form, "Timestamp", f"{frame.timestamp:.6f} s")

        # Show decoded signals
        if decoded:
            self._signals_group.setVisible(True)
            for name, value in decoded.items():
                if isinstance(value, float):
                    self._add_row(self._signals_layout, name, f"{value:.3f}")
                else:
                    self._add_row(self._signals_layout, name, value)

        # Show statistics if available
        if count > 0 or cycle_time is not None:
            self._stats_group.setVisible(True)
            self._add_row(self._stats_layout, "Count", f"{count:,}")
            if cycle_time is not None:
                self._add_row(self._stats_layout, "Cycle Time", f"{cycle_time:.1f} ms")

    def show_database_message(self, msg_info: dict) -> None:
        """Display database message definition."""
        self.clear()
        self._current_item = msg_info
        self._title.setText(f"Message: {msg_info.get('name', 'Unknown')}")

        self._add_row(self._form, "Name", msg_info.get("name", ""))
        self._add_row(self._form, "ID", f"0x{msg_info.get('id', 0):X}")
        self._add_row(self._form, "Length", f"{msg_info.get('length', 0)} bytes")
        self._add_row(self._form, "Extended ID", "Yes" if msg_info.get("is_extended_id") else "No")

        comment = msg_info.get("comment", "")
        if comment:
            self._add_row(self._form, "Comment", comment)

        # Show signal names
        signals = msg_info.get("signals", [])
        if signals:
            self._signals_group.setVisible(True)
            for i, sig_name in enumerate(signals):
                self._add_row(self._signals_layout, f"Signal {i+1}", sig_name)

    def show_signal(self, signal_info: dict) -> None:
        """Display signal definition."""
        self.clear()
        self._current_item = signal_info
        self._title.setText(f"Signal: {signal_info.get('name', 'Unknown')}")

        self._add_row(self._form, "Name", signal_info.get("name", ""))
        self._add_row(self._form, "Start Bit", signal_info.get("start_bit", 0))
        self._add_row(self._form, "Length", f"{signal_info.get('length', 0)} bits")
        self._add_row(self._form, "Byte Order", signal_info.get("byte_order", ""))
        self._add_row(self._form, "Signed", "Yes" if signal_info.get("is_signed") else "No")
        self._add_row(self._form, "Scale", signal_info.get("scale", 1))
        self._add_row(self._form, "Offset", signal_info.get("offset", 0))

        unit = signal_info.get("unit", "")
        if unit:
            self._add_row(self._form, "Unit", unit)

        minimum = signal_info.get("minimum")
        maximum = signal_info.get("maximum")
        if minimum is not None or maximum is not None:
            range_str = f"{minimum if minimum is not None else '-inf'} to {maximum if maximum is not None else 'inf'}"
            self._add_row(self._form, "Range", range_str)

        choices = signal_info.get("choices")
        if choices:
            self._signals_group.setVisible(True)
            self._signals_group.setTitle("Value Choices")
            for value, name in choices.items():
                self._add_row(self._signals_layout, str(value), name)

    def show_canopen_node(self, node) -> None:
        """Display CANopen node properties."""
        self.clear()
        self._current_item = node
        self._title.setText(f"CANopen Node: {node.node_id}")

        self._add_row(self._form, "Node ID", node.node_id)
        self._add_row(self._form, "State", node.state_name)

        if node.device_name:
            self._add_row(self._form, "Device Name", node.device_name)

        if node.vendor_id:
            self._add_row(self._form, "Vendor ID", f"0x{node.vendor_id:08X}")

        if node.product_code:
            self._add_row(self._form, "Product Code", f"0x{node.product_code:08X}")

        # Statistics
        self._stats_group.setVisible(True)
        self._add_row(self._stats_layout, "Messages", f"{node.message_count:,}")

        if node.heartbeat_interval_ms:
            self._add_row(self._stats_layout, "Heartbeat", f"{node.heartbeat_interval_ms:.0f} ms")

        if node.error_count > 0:
            self._add_row(self._stats_layout, "Errors", f"{node.error_count:,}")
