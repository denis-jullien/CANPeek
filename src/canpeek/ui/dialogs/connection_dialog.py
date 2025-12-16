"""
Connection configuration dialog.

Allows users to add or edit CAN bus connections.
"""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QGroupBox,
    QLineEdit,
    QComboBox,
    QSpinBox,
    QCheckBox,
    QPushButton,
    QDialogButtonBox,
    QLabel,
    QWidget,
)

from canpeek.core.types import Connection


# Common CAN bitrates
STANDARD_BITRATES = [
    10000, 20000, 50000, 100000, 125000, 250000, 500000, 800000, 1000000
]

# Common CAN FD data bitrates
FD_DATA_BITRATES = [
    500000, 1000000, 2000000, 4000000, 5000000, 8000000
]

# Interface types supported by python-can
INTERFACE_TYPES = [
    ("socketcan", "SocketCAN (Linux)"),
    ("virtual", "Virtual Bus"),
    ("pcan", "PEAK PCAN"),
    ("kvaser", "Kvaser"),
    ("vector", "Vector"),
    ("ixxat", "IXXAT"),
    ("nican", "NI-CAN"),
    ("neovi", "Intrepid neoVI"),
    ("slcan", "Serial/SLCAN"),
    ("usb2can", "USB2CAN"),
    ("gs_usb", "Geschwister Schneider USB/CAN"),
    ("cantact", "CANtact"),
    ("canalystii", "Canalyst-II"),
]


class ConnectionDialog(QDialog):
    """Dialog for creating or editing a CAN connection."""

    def __init__(
        self,
        parent: Optional[QWidget] = None,
        connection: Optional[Connection] = None,
    ):
        super().__init__(parent)
        self._connection = connection
        self._is_edit = connection is not None

        self.setWindowTitle("Edit Connection" if self._is_edit else "New Connection")
        self.setMinimumWidth(400)

        self._setup_ui()
        self._connect_signals()

        if self._is_edit:
            self._load_connection(connection)

    def _setup_ui(self) -> None:
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)

        # Basic settings
        basic_group = QGroupBox("Connection")
        basic_layout = QFormLayout(basic_group)

        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText("e.g., Vehicle CAN")
        basic_layout.addRow("Name:", self._name_edit)

        self._interface_combo = QComboBox()
        for iface_id, iface_name in INTERFACE_TYPES:
            self._interface_combo.addItem(iface_name, iface_id)
        basic_layout.addRow("Interface:", self._interface_combo)

        self._channel_edit = QLineEdit()
        self._channel_edit.setPlaceholderText("e.g., can0, vcan0, PCAN_USBBUS1")
        basic_layout.addRow("Channel:", self._channel_edit)

        layout.addWidget(basic_group)

        # Bitrate settings
        bitrate_group = QGroupBox("Bitrate")
        bitrate_layout = QFormLayout(bitrate_group)

        self._bitrate_combo = QComboBox()
        self._bitrate_combo.setEditable(True)
        for bitrate in STANDARD_BITRATES:
            self._bitrate_combo.addItem(f"{bitrate // 1000} kbit/s", bitrate)
        self._bitrate_combo.setCurrentIndex(6)  # 500 kbit/s default
        bitrate_layout.addRow("Bitrate:", self._bitrate_combo)

        self._fd_checkbox = QCheckBox("Enable CAN FD")
        bitrate_layout.addRow("", self._fd_checkbox)

        self._data_bitrate_combo = QComboBox()
        self._data_bitrate_combo.setEditable(True)
        self._data_bitrate_combo.setEnabled(False)
        for bitrate in FD_DATA_BITRATES:
            self._data_bitrate_combo.addItem(f"{bitrate // 1000000} Mbit/s", bitrate)
        self._data_bitrate_combo.setCurrentIndex(2)  # 2 Mbit/s default
        bitrate_layout.addRow("Data Bitrate:", self._data_bitrate_combo)

        layout.addWidget(bitrate_group)

        # SocketCAN-specific options
        self._socketcan_group = QGroupBox("SocketCAN Options")
        socketcan_layout = QFormLayout(self._socketcan_group)

        self._auto_config_checkbox = QCheckBox("Auto-configure interface (requires sudo)")
        self._auto_config_checkbox.setToolTip(
            "Automatically bring up the interface and set bitrate.\n"
            "Requires sudo privileges."
        )
        socketcan_layout.addRow("", self._auto_config_checkbox)

        layout.addWidget(self._socketcan_group)

        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        # Initial state
        self._update_interface_options()

    def _connect_signals(self) -> None:
        """Connect widget signals."""
        self._fd_checkbox.toggled.connect(self._data_bitrate_combo.setEnabled)
        self._interface_combo.currentIndexChanged.connect(self._update_interface_options)
        self._channel_edit.textChanged.connect(self._update_name_placeholder)

    def _update_interface_options(self) -> None:
        """Update options based on selected interface."""
        interface = self._interface_combo.currentData()
        is_socketcan = interface == "socketcan"
        self._socketcan_group.setVisible(is_socketcan)

        # Update channel placeholder
        placeholders = {
            "socketcan": "can0, vcan0",
            "virtual": "test",
            "pcan": "PCAN_USBBUS1",
            "kvaser": "0",
            "vector": "0",
            "slcan": "/dev/ttyUSB0",
        }
        self._channel_edit.setPlaceholderText(
            placeholders.get(interface, "channel")
        )

    def _update_name_placeholder(self, channel: str) -> None:
        """Update name placeholder based on channel."""
        if not self._name_edit.text():
            self._name_edit.setPlaceholderText(channel or "Connection name")

    def _load_connection(self, conn: Connection) -> None:
        """Load connection data into the form."""
        self._name_edit.setText(conn.name)

        # Find interface in combo
        for i in range(self._interface_combo.count()):
            if self._interface_combo.itemData(i) == conn.interface:
                self._interface_combo.setCurrentIndex(i)
                break

        self._channel_edit.setText(conn.channel)

        # Find bitrate in combo
        for i in range(self._bitrate_combo.count()):
            if self._bitrate_combo.itemData(i) == conn.bitrate:
                self._bitrate_combo.setCurrentIndex(i)
                break

        self._fd_checkbox.setChecked(conn.fd)

        # Find data bitrate in combo
        for i in range(self._data_bitrate_combo.count()):
            if self._data_bitrate_combo.itemData(i) == conn.data_bitrate:
                self._data_bitrate_combo.setCurrentIndex(i)
                break

    def get_connection(self) -> Connection:
        """Get the configured connection."""
        # Get bitrate value (handle custom input)
        bitrate_data = self._bitrate_combo.currentData()
        if bitrate_data:
            bitrate = bitrate_data
        else:
            try:
                bitrate = int(self._bitrate_combo.currentText().replace(" kbit/s", "")) * 1000
            except ValueError:
                bitrate = 500000

        # Get data bitrate value
        data_bitrate_data = self._data_bitrate_combo.currentData()
        if data_bitrate_data:
            data_bitrate = data_bitrate_data
        else:
            try:
                data_bitrate = int(self._data_bitrate_combo.currentText().replace(" Mbit/s", "")) * 1000000
            except ValueError:
                data_bitrate = 2000000

        # Build extra config
        extra_config = {}
        if self._auto_config_checkbox.isChecked():
            extra_config["auto_config"] = True

        # Create or update connection
        if self._is_edit and self._connection:
            conn_id = self._connection.id
        else:
            conn_id = None

        name = self._name_edit.text() or self._channel_edit.text()

        conn = Connection(
            name=name,
            interface=self._interface_combo.currentData(),
            channel=self._channel_edit.text(),
            bitrate=bitrate,
            data_bitrate=data_bitrate,
            fd=self._fd_checkbox.isChecked(),
            extra_config=extra_config,
        )

        if conn_id:
            conn.id = conn_id

        return conn

    @property
    def auto_configure(self) -> bool:
        """Check if auto-configure is requested."""
        return self._auto_config_checkbox.isChecked()
