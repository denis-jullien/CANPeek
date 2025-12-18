"""
Editable properties panel for connections, filters, and messages.

Provides inline editing with auto-save for:
- Connections (name, interface, channel, bitrate)
- Filters (name, ID range, bus filter)
- Message info (read-only with actions)
"""

from __future__ import annotations

from typing import Optional, Any
from uuid import UUID

from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QLabel,
    QLineEdit,
    QComboBox,
    QCheckBox,
    QPushButton,
    QScrollArea,
    QFrame,
    QSpinBox,
    QGroupBox,
    QStackedWidget,
)
from PySide6.QtGui import QIntValidator

from canpeek.core.types import Connection, BusState
from canpeek.core.types import CANFrame
from canpeek.project import FilterConfig


# Available CAN interfaces
INTERFACES = [
    ("socketcan", "SocketCAN (Linux)"),
    ("virtual", "Virtual Bus"),
    ("pcan", "PEAK PCAN"),
    ("kvaser", "Kvaser"),
    ("vector", "Vector"),
    ("ixxat", "IXXAT"),
    ("nixnet", "NI-XNET"),
    ("neovi", "Intrepid neoVI"),
    ("slcan", "SLCAN (Serial)"),
]

# Common bitrates
BITRATES = [
    (125000, "125 kbit/s"),
    (250000, "250 kbit/s"),
    (500000, "500 kbit/s"),
    (800000, "800 kbit/s"),
    (1000000, "1 Mbit/s"),
]

DATA_BITRATES = [
    (1000000, "1 Mbit/s"),
    (2000000, "2 Mbit/s"),
    (4000000, "4 Mbit/s"),
    (5000000, "5 Mbit/s"),
    (8000000, "8 Mbit/s"),
]


class ConnectionEditor(QWidget):
    """Editor widget for Connection properties."""

    changed = Signal(object)  # Emits Connection when changed
    connect_requested = Signal(object)  # Request to connect
    disconnect_requested = Signal(object)  # Request to disconnect
    delete_requested = Signal(object)  # Request to delete

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._connection: Optional[Connection] = None
        self._is_connected = False
        self._updating = False  # Prevent recursive updates
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(300)  # 300ms debounce
        self._save_timer.timeout.connect(self._emit_changed)

        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Form layout
        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)

        # Name
        self._name_edit = QLineEdit()
        self._name_edit.textChanged.connect(self._on_field_changed)
        form.addRow("Name:", self._name_edit)

        # Interface
        self._interface_combo = QComboBox()
        for value, label in INTERFACES:
            self._interface_combo.addItem(label, value)
        self._interface_combo.currentIndexChanged.connect(self._on_field_changed)
        form.addRow("Interface:", self._interface_combo)

        # Channel
        self._channel_edit = QLineEdit()
        self._channel_edit.setPlaceholderText("e.g., can0, PCAN_USBBUS1")
        self._channel_edit.textChanged.connect(self._on_field_changed)
        form.addRow("Channel:", self._channel_edit)

        # Bitrate
        self._bitrate_combo = QComboBox()
        self._bitrate_combo.setEditable(True)
        for value, label in BITRATES:
            self._bitrate_combo.addItem(label, value)
        self._bitrate_combo.currentIndexChanged.connect(self._on_field_changed)
        self._bitrate_combo.lineEdit().editingFinished.connect(self._on_field_changed)
        form.addRow("Bitrate:", self._bitrate_combo)

        # CAN FD
        self._fd_check = QCheckBox("Enable CAN FD")
        self._fd_check.toggled.connect(self._on_fd_toggled)
        form.addRow("", self._fd_check)

        # Data Bitrate (FD only)
        self._data_bitrate_combo = QComboBox()
        self._data_bitrate_combo.setEditable(True)
        for value, label in DATA_BITRATES:
            self._data_bitrate_combo.addItem(label, value)
        self._data_bitrate_combo.currentIndexChanged.connect(self._on_field_changed)
        self._data_bitrate_label = QLabel("Data Bitrate:")
        form.addRow(self._data_bitrate_label, self._data_bitrate_combo)

        layout.addLayout(form)

        # Buttons
        btn_layout = QHBoxLayout()

        self._connect_btn = QPushButton("Connect")
        self._connect_btn.clicked.connect(self._on_connect_clicked)
        btn_layout.addWidget(self._connect_btn)

        self._disconnect_btn = QPushButton("Disconnect")
        self._disconnect_btn.clicked.connect(self._on_disconnect_clicked)
        btn_layout.addWidget(self._disconnect_btn)

        btn_layout.addStretch()

        self._delete_btn = QPushButton("Delete")
        self._delete_btn.setStyleSheet("color: #F44336;")
        self._delete_btn.clicked.connect(self._on_delete_clicked)
        btn_layout.addWidget(self._delete_btn)

        layout.addLayout(btn_layout)
        layout.addStretch()

        # Initial state
        self._update_fd_visibility()
        self._update_button_state()

    def set_connection(self, connection: Optional[Connection], is_connected: bool = False) -> None:
        """Set the connection to edit."""
        self._updating = True
        self._connection = connection
        self._is_connected = is_connected

        if connection:
            self._name_edit.setText(connection.name)

            # Set interface
            idx = self._interface_combo.findData(connection.interface)
            if idx >= 0:
                self._interface_combo.setCurrentIndex(idx)

            self._channel_edit.setText(connection.channel)

            # Set bitrate
            idx = self._bitrate_combo.findData(connection.bitrate)
            if idx >= 0:
                self._bitrate_combo.setCurrentIndex(idx)
            else:
                self._bitrate_combo.setCurrentText(str(connection.bitrate))

            self._fd_check.setChecked(connection.fd)

            # Set data bitrate
            idx = self._data_bitrate_combo.findData(connection.data_bitrate)
            if idx >= 0:
                self._data_bitrate_combo.setCurrentIndex(idx)
            else:
                self._data_bitrate_combo.setCurrentText(str(connection.data_bitrate))

        self._update_fd_visibility()
        self._update_button_state()
        self._updating = False

    def set_connected_state(self, is_connected: bool) -> None:
        """Update the connected state."""
        self._is_connected = is_connected
        self._update_button_state()

    def _update_fd_visibility(self) -> None:
        """Show/hide FD fields."""
        is_fd = self._fd_check.isChecked()
        self._data_bitrate_combo.setVisible(is_fd)
        self._data_bitrate_label.setVisible(is_fd)

    def _update_button_state(self) -> None:
        """Update connect/disconnect button state."""
        self._connect_btn.setEnabled(not self._is_connected and self._connection is not None)
        self._disconnect_btn.setEnabled(self._is_connected)

    def _on_fd_toggled(self, checked: bool) -> None:
        self._update_fd_visibility()
        self._on_field_changed()

    def _on_field_changed(self) -> None:
        """Handle any field change - schedule auto-save."""
        if self._updating or not self._connection:
            return
        self._save_timer.start()

    def _emit_changed(self) -> None:
        """Apply changes to connection and emit signal."""
        if not self._connection:
            return

        self._connection.name = self._name_edit.text()
        self._connection.interface = self._interface_combo.currentData() or "socketcan"
        self._connection.channel = self._channel_edit.text()

        # Parse bitrate
        bitrate = self._bitrate_combo.currentData()
        if bitrate is None:
            try:
                bitrate = int(self._bitrate_combo.currentText().replace(" ", "").replace("kbit/s", "000").replace("Mbit/s", "000000"))
            except ValueError:
                bitrate = 500000
        self._connection.bitrate = bitrate

        self._connection.fd = self._fd_check.isChecked()

        # Parse data bitrate
        data_bitrate = self._data_bitrate_combo.currentData()
        if data_bitrate is None:
            try:
                data_bitrate = int(self._data_bitrate_combo.currentText().replace(" ", "").replace("Mbit/s", "000000"))
            except ValueError:
                data_bitrate = 2000000
        self._connection.data_bitrate = data_bitrate

        self.changed.emit(self._connection)

    def _on_connect_clicked(self) -> None:
        if self._connection:
            self.connect_requested.emit(self._connection)

    def _on_disconnect_clicked(self) -> None:
        if self._connection:
            self.disconnect_requested.emit(self._connection)

    def _on_delete_clicked(self) -> None:
        if self._connection:
            self.delete_requested.emit(self._connection)


class FilterEditor(QWidget):
    """Editor widget for Filter properties."""

    changed = Signal(object)  # Emits FilterConfig when changed
    delete_requested = Signal(object)  # Request to delete

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._filter: Optional[FilterConfig] = None
        self._updating = False
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(300)
        self._save_timer.timeout.connect(self._emit_changed)

        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)

        # Name
        self._name_edit = QLineEdit()
        self._name_edit.textChanged.connect(self._on_field_changed)
        form.addRow("Name:", self._name_edit)

        # Enabled
        self._enabled_check = QCheckBox("Enabled")
        self._enabled_check.toggled.connect(self._on_field_changed)
        form.addRow("", self._enabled_check)

        # Min ID
        self._min_id_edit = QLineEdit()
        self._min_id_edit.setPlaceholderText("0x000 (leave empty for no min)")
        self._min_id_edit.textChanged.connect(self._on_field_changed)
        form.addRow("Min ID:", self._min_id_edit)

        # Max ID
        self._max_id_edit = QLineEdit()
        self._max_id_edit.setPlaceholderText("0x7FF (leave empty for no max)")
        self._max_id_edit.textChanged.connect(self._on_field_changed)
        form.addRow("Max ID:", self._max_id_edit)

        # Bus filter
        self._bus_edit = QLineEdit()
        self._bus_edit.setPlaceholderText("Leave empty for all buses")
        self._bus_edit.textChanged.connect(self._on_field_changed)
        form.addRow("Bus:", self._bus_edit)

        # Pattern
        self._pattern_edit = QLineEdit()
        self._pattern_edit.setPlaceholderText("ID or name pattern")
        self._pattern_edit.textChanged.connect(self._on_field_changed)
        form.addRow("Pattern:", self._pattern_edit)

        layout.addLayout(form)

        # Delete button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self._delete_btn = QPushButton("Delete Filter")
        self._delete_btn.setStyleSheet("color: #F44336;")
        self._delete_btn.clicked.connect(self._on_delete_clicked)
        btn_layout.addWidget(self._delete_btn)

        layout.addLayout(btn_layout)
        layout.addStretch()

    def set_filter(self, filter_config: Optional[FilterConfig]) -> None:
        """Set the filter to edit."""
        self._updating = True
        self._filter = filter_config

        if filter_config:
            self._name_edit.setText(filter_config.name)
            self._enabled_check.setChecked(filter_config.enabled)
            self._min_id_edit.setText(f"0x{filter_config.min_id:X}" if filter_config.min_id is not None else "")
            self._max_id_edit.setText(f"0x{filter_config.max_id:X}" if filter_config.max_id is not None else "")
            self._bus_edit.setText(filter_config.bus_filter or "")
            self._pattern_edit.setText(filter_config.id_pattern or "")

        self._updating = False

    def _on_field_changed(self) -> None:
        if self._updating or not self._filter:
            return
        self._save_timer.start()

    def _emit_changed(self) -> None:
        if not self._filter:
            return

        self._filter.name = self._name_edit.text()
        self._filter.enabled = self._enabled_check.isChecked()

        # Parse min ID
        min_text = self._min_id_edit.text().strip()
        if min_text:
            try:
                self._filter.min_id = int(min_text, 16) if min_text.startswith("0x") else int(min_text)
            except ValueError:
                self._filter.min_id = None
        else:
            self._filter.min_id = None

        # Parse max ID
        max_text = self._max_id_edit.text().strip()
        if max_text:
            try:
                self._filter.max_id = int(max_text, 16) if max_text.startswith("0x") else int(max_text)
            except ValueError:
                self._filter.max_id = None
        else:
            self._filter.max_id = None

        self._filter.bus_filter = self._bus_edit.text().strip() or None
        self._filter.id_pattern = self._pattern_edit.text().strip()

        self.changed.emit(self._filter)

    def _on_delete_clicked(self) -> None:
        if self._filter:
            self.delete_requested.emit(self._filter)


class MessageInfoPanel(QWidget):
    """Read-only panel showing message info with action buttons."""

    add_to_transmit = Signal(object)  # Emit CANFrame
    create_filter = Signal(int, str)  # Emit (arbitration_id, bus_name)

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._frame: Optional[CANFrame] = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        form = QFormLayout()

        self._id_label = QLabel()
        self._id_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        form.addRow("ID:", self._id_label)

        self._name_label = QLabel()
        self._name_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        form.addRow("Name:", self._name_label)

        self._bus_label = QLabel()
        form.addRow("Bus:", self._bus_label)

        self._type_label = QLabel()
        form.addRow("Type:", self._type_label)

        self._dlc_label = QLabel()
        form.addRow("DLC:", self._dlc_label)

        self._data_label = QLabel()
        self._data_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._data_label.setWordWrap(True)
        form.addRow("Data:", self._data_label)

        self._count_label = QLabel()
        form.addRow("Count:", self._count_label)

        self._cycle_label = QLabel()
        form.addRow("Cycle:", self._cycle_label)

        layout.addLayout(form)

        # Signals group
        self._signals_group = QGroupBox("Decoded Signals")
        self._signals_layout = QFormLayout(self._signals_group)
        self._signals_group.setVisible(False)
        layout.addWidget(self._signals_group)

        # Action buttons
        btn_layout = QHBoxLayout()

        self._transmit_btn = QPushButton("Add to Transmit")
        self._transmit_btn.clicked.connect(self._on_add_to_transmit)
        btn_layout.addWidget(self._transmit_btn)

        self._filter_btn = QPushButton("Create Filter")
        self._filter_btn.clicked.connect(self._on_create_filter)
        btn_layout.addWidget(self._filter_btn)

        btn_layout.addStretch()

        layout.addLayout(btn_layout)
        layout.addStretch()

    def set_message(self, frame: CANFrame, decoded: Optional[dict] = None,
                   message_name: str = "", cycle_time: Optional[float] = None,
                   count: int = 0) -> None:
        """Display message info."""
        self._frame = frame

        self._id_label.setText(frame.id_str())
        self._name_label.setText(message_name or "-")
        self._bus_label.setText(frame.bus_name or str(frame.bus_id))
        self._type_label.setText(frame.type_str())
        self._dlc_label.setText(str(frame.dlc))
        self._data_label.setText(frame.data_str())
        self._count_label.setText(f"{count:,}")
        self._cycle_label.setText(f"{cycle_time:.1f} ms" if cycle_time else "-")

        # Clear and populate signals
        while self._signals_layout.rowCount() > 0:
            self._signals_layout.removeRow(0)

        if decoded:
            self._signals_group.setVisible(True)
            for name, value in decoded.items():
                label = QLabel(str(value))
                label.setTextInteractionFlags(Qt.TextSelectableByMouse)
                self._signals_layout.addRow(f"{name}:", label)
        else:
            self._signals_group.setVisible(False)

    def _on_add_to_transmit(self) -> None:
        if self._frame:
            self.add_to_transmit.emit(self._frame)

    def _on_create_filter(self) -> None:
        if self._frame:
            self.create_filter.emit(self._frame.arbitration_id, self._frame.bus_name or "")


class CANopenNodePanel(QWidget):
    """Panel showing CANopen node info with NMT actions."""

    send_nmt = Signal(int, str)  # node_id, command

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._node = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        form = QFormLayout()

        self._node_id_label = QLabel()
        form.addRow("Node ID:", self._node_id_label)

        self._state_label = QLabel()
        form.addRow("State:", self._state_label)

        self._device_label = QLabel()
        form.addRow("Device:", self._device_label)

        self._heartbeat_label = QLabel()
        form.addRow("Heartbeat:", self._heartbeat_label)

        self._messages_label = QLabel()
        form.addRow("Messages:", self._messages_label)

        layout.addLayout(form)

        # NMT commands
        nmt_group = QGroupBox("NMT Commands")
        nmt_layout = QHBoxLayout(nmt_group)

        self._start_btn = QPushButton("Start")
        self._start_btn.clicked.connect(lambda: self._send_nmt("start"))
        nmt_layout.addWidget(self._start_btn)

        self._stop_btn = QPushButton("Stop")
        self._stop_btn.clicked.connect(lambda: self._send_nmt("stop"))
        nmt_layout.addWidget(self._stop_btn)

        self._reset_btn = QPushButton("Reset")
        self._reset_btn.clicked.connect(lambda: self._send_nmt("reset"))
        nmt_layout.addWidget(self._reset_btn)

        layout.addWidget(nmt_group)
        layout.addStretch()

    def set_node(self, node) -> None:
        """Display node info."""
        self._node = node

        self._node_id_label.setText(str(node.node_id))
        self._state_label.setText(node.state_name)
        self._device_label.setText(node.device_name or "-")
        self._heartbeat_label.setText(f"{node.heartbeat_interval_ms:.0f} ms" if node.heartbeat_interval_ms else "-")
        self._messages_label.setText(f"{node.message_count:,}")

    def _send_nmt(self, command: str) -> None:
        if self._node:
            self.send_nmt.emit(self._node.node_id, command)


class PropertiesPanel(QWidget):
    """
    Editable properties panel with auto-save.

    Shows different editors based on selection:
    - Connection: editable form
    - Filter: editable form
    - Message: read-only info with actions
    - CANopen node: info with NMT commands
    """

    # Signals for changes
    connection_changed = Signal(object)  # Connection
    connection_connect = Signal(object)
    connection_disconnect = Signal(object)
    connection_delete = Signal(object)
    filter_changed = Signal(object)  # FilterConfig
    filter_delete = Signal(object)
    add_to_transmit = Signal(object)  # CANFrame
    create_filter_for_id = Signal(int, str)  # arbitration_id, bus_name
    send_nmt_command = Signal(int, str)  # node_id, command

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Title
        self._title = QLabel("No Selection")
        self._title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(self._title)

        # Stacked widget for different editors
        self._stack = QStackedWidget()

        # Empty panel
        self._empty_panel = QWidget()
        empty_layout = QVBoxLayout(self._empty_panel)
        empty_layout.addWidget(QLabel("Select an item to view properties"))
        empty_layout.addStretch()
        self._stack.addWidget(self._empty_panel)

        # Connection editor
        self._connection_editor = ConnectionEditor()
        self._stack.addWidget(self._connection_editor)

        # Filter editor
        self._filter_editor = FilterEditor()
        self._stack.addWidget(self._filter_editor)

        # Message info panel
        self._message_panel = MessageInfoPanel()
        self._stack.addWidget(self._message_panel)

        # CANopen node panel
        self._canopen_panel = CANopenNodePanel()
        self._stack.addWidget(self._canopen_panel)

        layout.addWidget(self._stack)

    def _connect_signals(self) -> None:
        # Connection editor signals
        self._connection_editor.changed.connect(self.connection_changed)
        self._connection_editor.connect_requested.connect(self.connection_connect)
        self._connection_editor.disconnect_requested.connect(self.connection_disconnect)
        self._connection_editor.delete_requested.connect(self.connection_delete)

        # Filter editor signals
        self._filter_editor.changed.connect(self.filter_changed)
        self._filter_editor.delete_requested.connect(self.filter_delete)

        # Message panel signals
        self._message_panel.add_to_transmit.connect(self.add_to_transmit)
        self._message_panel.create_filter.connect(self.create_filter_for_id)

        # CANopen panel signals
        self._canopen_panel.send_nmt.connect(self.send_nmt_command)

    def clear(self) -> None:
        """Clear and show empty panel."""
        self._title.setText("No Selection")
        self._stack.setCurrentWidget(self._empty_panel)

    def show_connection(self, connection: Connection, is_connected: bool = False) -> None:
        """Show connection editor."""
        self._title.setText(f"Connection: {connection.name}")
        self._connection_editor.set_connection(connection, is_connected)
        self._stack.setCurrentWidget(self._connection_editor)

    def update_connection_state(self, connection_id: UUID, is_connected: bool) -> None:
        """Update connected state if showing this connection."""
        if (self._stack.currentWidget() == self._connection_editor and
            self._connection_editor._connection is not None and
            self._connection_editor._connection.id == connection_id):
            self._connection_editor.set_connected_state(is_connected)

    def show_filter(self, filter_config: FilterConfig) -> None:
        """Show filter editor."""
        self._title.setText(f"Filter: {filter_config.name}")
        self._filter_editor.set_filter(filter_config)
        self._stack.setCurrentWidget(self._filter_editor)

    def show_frame(self, frame: CANFrame, decoded: Optional[dict] = None,
                   message_name: str = "", cycle_time: Optional[float] = None,
                   count: int = 0) -> None:
        """Show message info panel."""
        self._title.setText(f"Message: {frame.id_str()}")
        self._message_panel.set_message(frame, decoded, message_name, cycle_time, count)
        self._stack.setCurrentWidget(self._message_panel)

    def show_canopen_node(self, node) -> None:
        """Show CANopen node panel."""
        self._title.setText(f"CANopen Node: {node.node_id}")
        self._canopen_panel.set_node(node)
        self._stack.setCurrentWidget(self._canopen_panel)

    def show_database(self, path: str, message_count: int = 0) -> None:
        """Show database info (read-only for now)."""
        self._title.setText(f"Database: {path.split('/')[-1]}")
        # Could add more database info here
        self._stack.setCurrentWidget(self._empty_panel)
