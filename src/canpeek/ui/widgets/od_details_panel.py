"""
Object Dictionary details panel showing entry properties and SDO operations.
"""

from typing import Optional

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from canpeek.protocols.canopen.object_dictionary import ODEntry, ODIndex


class ODDetailsPanel(QWidget):
    """Panel showing details of selected OD entry with SDO operations."""

    # Signals
    read_requested = Signal(int, int)  # index, subindex
    write_requested = Signal(int, int, bytes)  # index, subindex, data
    read_all_requested = Signal()  # Read all entries in current index

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_entry: Optional[ODEntry] = None
        self._current_index: Optional[ODIndex] = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Header section
        header_layout = QVBoxLayout()

        self._name_label = QLabel()
        self._name_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        header_layout.addWidget(self._name_label)

        self._index_label = QLabel()
        self._index_label.setStyleSheet("color: #666;")
        header_layout.addWidget(self._index_label)

        layout.addLayout(header_layout)

        # Tab widget for different info sections
        self._tabs = QTabWidget()

        # General tab
        general_tab = QWidget()
        general_layout = QFormLayout(general_tab)
        general_layout.setContentsMargins(8, 8, 8, 8)

        self._object_type_label = QLabel()
        general_layout.addRow("Object Type:", self._object_type_label)

        self._data_type_label = QLabel()
        general_layout.addRow("Data Type:", self._data_type_label)

        self._access_label = QLabel()
        general_layout.addRow("Access:", self._access_label)

        self._unit_label = QLabel()
        general_layout.addRow("Unit:", self._unit_label)

        self._description_text = QTextEdit()
        self._description_text.setReadOnly(True)
        self._description_text.setMaximumHeight(80)
        general_layout.addRow("Description:", self._description_text)

        self._tabs.addTab(general_tab, "General")

        # Values tab
        values_tab = QWidget()
        values_layout = QFormLayout(values_tab)
        values_layout.setContentsMargins(8, 8, 8, 8)

        self._default_label = QLabel()
        values_layout.addRow("Default:", self._default_label)

        self._min_label = QLabel()
        values_layout.addRow("Min:", self._min_label)

        self._max_label = QLabel()
        values_layout.addRow("Max:", self._max_label)

        # Current value with read/write controls
        value_group = QGroupBox("Current Value")
        value_layout = QVBoxLayout(value_group)

        self._current_value_edit = QLineEdit()
        self._current_value_edit.setPlaceholderText("No value read yet")
        value_layout.addWidget(self._current_value_edit)

        # Raw hex display
        self._raw_value_label = QLabel()
        self._raw_value_label.setStyleSheet("color: #666; font-family: monospace;")
        value_layout.addWidget(self._raw_value_label)

        # Read/Write buttons
        btn_layout = QHBoxLayout()

        self._read_btn = QPushButton("Read")
        self._read_btn.clicked.connect(self._on_read_clicked)
        btn_layout.addWidget(self._read_btn)

        self._write_btn = QPushButton("Write")
        self._write_btn.clicked.connect(self._on_write_clicked)
        btn_layout.addWidget(self._write_btn)

        value_layout.addLayout(btn_layout)
        values_layout.addRow(value_group)

        self._tabs.addTab(values_tab, "Values")

        layout.addWidget(self._tabs)

        # Status bar
        self._status_label = QLabel()
        self._status_label.setStyleSheet("padding: 4px;")
        layout.addWidget(self._status_label)

        layout.addStretch()

        # Initial state
        self.clear()

    def show_entry(self, entry: ODEntry) -> None:
        """Display an OD entry."""
        self._current_entry = entry
        self._current_index = None

        self._name_label.setText(entry.name)
        self._index_label.setText(f"Index: 0x{entry.index:04X}:{entry.subindex:02X}")

        # General tab
        self._object_type_label.setText("VAR")
        self._data_type_label.setText(entry.data_type_name)
        self._access_label.setText(entry.access_type.upper())
        self._unit_label.setText(entry.unit or "-")
        self._description_text.setText(entry.description or "")

        # Values tab
        self._default_label.setText(str(entry.default) if entry.default is not None else "-")
        self._min_label.setText(str(entry.min_value) if entry.min_value is not None else "-")
        self._max_label.setText(str(entry.max_value) if entry.max_value is not None else "-")

        # Current value
        if entry.current_value is not None:
            self._current_value_edit.setText(str(entry.current_value))
        else:
            self._current_value_edit.clear()

        # Update button states based on access
        self._read_btn.setEnabled("r" in entry.access_type or entry.access_type == "const")
        self._write_btn.setEnabled("w" in entry.access_type and entry.access_type != "ro")

        self._clear_status()

    def show_index(self, od_index: ODIndex) -> None:
        """Display an OD index (parent entry)."""
        self._current_entry = None
        self._current_index = od_index

        self._name_label.setText(od_index.name)
        self._index_label.setText(f"Index: 0x{od_index.index:04X}")

        # General tab
        self._object_type_label.setText(od_index.object_type_name)
        self._data_type_label.setText("-")
        self._access_label.setText("-")
        self._unit_label.setText("-")
        self._description_text.setText(od_index.description or "")

        # Values tab - clear for index-level
        self._default_label.setText("-")
        self._min_label.setText("-")
        self._max_label.setText("-")
        self._current_value_edit.clear()
        self._raw_value_label.clear()

        # Disable read/write for index-level selection
        self._read_btn.setEnabled(False)
        self._write_btn.setEnabled(False)

        self._clear_status()

    def clear(self) -> None:
        """Clear the panel."""
        self._current_entry = None
        self._current_index = None

        self._name_label.setText("No selection")
        self._index_label.setText("")
        self._object_type_label.setText("-")
        self._data_type_label.setText("-")
        self._access_label.setText("-")
        self._unit_label.setText("-")
        self._description_text.clear()

        self._default_label.setText("-")
        self._min_label.setText("-")
        self._max_label.setText("-")
        self._current_value_edit.clear()
        self._raw_value_label.clear()

        self._read_btn.setEnabled(False)
        self._write_btn.setEnabled(False)

        self._clear_status()

    def set_value(self, value: str, raw_hex: str = "") -> None:
        """Set the current value display."""
        self._current_value_edit.setText(value)
        if raw_hex:
            self._raw_value_label.setText(f"Raw: {raw_hex}")
        else:
            self._raw_value_label.clear()

    def set_status(self, message: str, is_error: bool = False) -> None:
        """Display a status message."""
        color = "#c00" if is_error else "#060"
        self._status_label.setStyleSheet(f"color: {color}; padding: 4px;")
        self._status_label.setText(message)

    def _clear_status(self) -> None:
        """Clear the status message."""
        self._status_label.clear()

    def _on_read_clicked(self) -> None:
        """Handle read button click."""
        if self._current_entry:
            self.read_requested.emit(
                self._current_entry.index, self._current_entry.subindex
            )

    def _on_write_clicked(self) -> None:
        """Handle write button click."""
        if self._current_entry:
            # Get value from input
            value_text = self._current_value_edit.text().strip()
            if not value_text:
                self.set_status("Enter a value to write", is_error=True)
                return

            # Convert to bytes based on data type
            try:
                data = self._encode_value(value_text, self._current_entry)
                self.write_requested.emit(
                    self._current_entry.index, self._current_entry.subindex, data
                )
            except ValueError as e:
                self.set_status(f"Invalid value: {e}", is_error=True)

    def _encode_value(self, value_text: str, entry: ODEntry) -> bytes:
        """Encode a value string to bytes based on the entry's data type."""
        import struct

        # Determine the packing format based on data type name
        dt = entry.data_type_name.upper()

        # Handle hex input
        if value_text.startswith("0x") or value_text.startswith("0X"):
            int_val = int(value_text, 16)
        else:
            try:
                int_val = int(value_text)
            except ValueError:
                int_val = None

        if "UNSIGNED8" in dt or "BOOLEAN" in dt:
            return struct.pack("<B", int_val)
        elif "UNSIGNED16" in dt:
            return struct.pack("<H", int_val)
        elif "UNSIGNED32" in dt:
            return struct.pack("<L", int_val)
        elif "UNSIGNED64" in dt:
            return struct.pack("<Q", int_val)
        elif "INTEGER8" in dt:
            return struct.pack("<b", int_val)
        elif "INTEGER16" in dt:
            return struct.pack("<h", int_val)
        elif "INTEGER32" in dt:
            return struct.pack("<l", int_val)
        elif "INTEGER64" in dt:
            return struct.pack("<q", int_val)
        elif "REAL32" in dt:
            return struct.pack("<f", float(value_text))
        elif "REAL64" in dt:
            return struct.pack("<d", float(value_text))
        elif "STRING" in dt:
            return value_text.encode("utf-8")
        else:
            # Try to encode as raw hex bytes
            if value_text.startswith("0x"):
                hex_str = value_text[2:]
                return bytes.fromhex(hex_str)
            raise ValueError(f"Cannot encode for type {dt}")
