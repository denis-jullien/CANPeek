"""
Transmit panel for sending CAN messages.

Allows users to define, edit, and send CAN messages manually
or on a periodic cycle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any, Callable
from uuid import UUID, uuid4
import time

from PySide6.QtCore import Qt, QTimer, QAbstractTableModel, QModelIndex, QPersistentModelIndex, Signal
from PySide6.QtGui import QColor, QFontDatabase, QAction
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableView,
    QHeaderView,
    QPushButton,
    QToolBar,
    QComboBox,
    QLabel,
    QStyle,
    QSpinBox,
    QLineEdit,
    QStyledItemDelegate,
    QMenu,
)

from canpeek.core.types import CANFrame, Connection


@dataclass
class TransmitMessage:
    """Configuration for a message to transmit."""
    id: UUID = field(default_factory=uuid4)
    arbitration_id: int = 0x100
    data: bytearray = field(default_factory=lambda: bytearray(8))
    dlc: int = 8
    is_extended_id: bool = False
    is_fd: bool = False
    is_brs: bool = False
    name: str = ""

    # Transmission settings
    enabled: bool = False  # For cyclic transmission
    cycle_ms: int = 100  # Cycle time in milliseconds
    connection_id: Optional[UUID] = None  # Target bus

    # Statistics
    sent_count: int = 0
    last_sent_time: float = 0.0

    def to_frame(self) -> CANFrame:
        """Convert to CANFrame for transmission."""
        return CANFrame.create(
            arbitration_id=self.arbitration_id,
            data=bytes(self.data[:self.dlc]),
            is_extended_id=self.is_extended_id,
            is_fd=self.is_fd,
            is_brs=self.is_brs,
            is_rx=False,
            connection_id=self.connection_id,
        )

    @classmethod
    def from_frame(cls, frame: CANFrame) -> TransmitMessage:
        """Create from a received frame."""
        return cls(
            arbitration_id=frame.arbitration_id,
            data=bytearray(frame.data),
            dlc=frame.dlc,
            is_extended_id=frame.is_extended_id,
            is_fd=frame.is_fd,
            is_brs=frame.is_brs,
            connection_id=frame.connection_id,
        )


class TransmitColumn:
    """Column indices for transmit table."""
    ENABLED = 0
    ID = 1
    NAME = 2
    DLC = 3
    DATA = 4
    CYCLE = 5
    SEND = 6
    COUNT = 7


TRANSMIT_HEADERS = {
    TransmitColumn.ENABLED: "On",
    TransmitColumn.ID: "ID",
    TransmitColumn.NAME: "Name",
    TransmitColumn.DLC: "DLC",
    TransmitColumn.DATA: "Data",
    TransmitColumn.CYCLE: "Cycle (ms)",
    TransmitColumn.SEND: "Send",
    TransmitColumn.COUNT: "Sent",
}


class HexDataDelegate(QStyledItemDelegate):
    """Delegate for editing hex data."""

    def createEditor(self, parent, option, index):
        editor = QLineEdit(parent)
        editor.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        return editor

    def setEditorData(self, editor, index):
        data = index.data(Qt.EditRole)
        if isinstance(data, (bytes, bytearray)):
            editor.setText(data.hex(' ').upper())
        else:
            editor.setText(str(data) if data else "")

    def setModelData(self, editor, model, index):
        text = editor.text().replace(' ', '').strip()
        try:
            data = bytes.fromhex(text)
            model.setData(index, data, Qt.EditRole)
        except ValueError:
            pass  # Invalid hex, don't update


class TransmitModel(QAbstractTableModel):
    """Model for transmit message table."""

    send_requested = Signal(object)  # TransmitMessage

    def __init__(self, parent=None):
        super().__init__(parent)
        self._messages: list[TransmitMessage] = []

    def add_message(self, msg: Optional[TransmitMessage] = None) -> int:
        """Add a new message, returns row index."""
        if msg is None:
            msg = TransmitMessage()

        row = len(self._messages)
        self.beginInsertRows(QModelIndex(), row, row)
        self._messages.append(msg)
        self.endInsertRows()
        return row

    def remove_message(self, row: int) -> None:
        """Remove message at row."""
        if 0 <= row < len(self._messages):
            self.beginRemoveRows(QModelIndex(), row, row)
            del self._messages[row]
            self.endRemoveRows()

    def get_message(self, row: int) -> Optional[TransmitMessage]:
        """Get message at row."""
        if 0 <= row < len(self._messages):
            return self._messages[row]
        return None

    def get_enabled_messages(self) -> list[TransmitMessage]:
        """Get all enabled messages for cyclic transmission."""
        return [m for m in self._messages if m.enabled]

    def update_sent_count(self, msg: TransmitMessage) -> None:
        """Update sent count display for a message."""
        try:
            row = self._messages.index(msg)
            index = self.index(row, TransmitColumn.COUNT)
            self.dataChanged.emit(index, index)
        except ValueError:
            pass

    def clear(self) -> None:
        """Remove all messages."""
        if self._messages:
            self.beginResetModel()
            self._messages.clear()
            self.endResetModel()

    # --- QAbstractTableModel implementation ---

    def rowCount(self, parent=QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._messages)

    def columnCount(self, parent=QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(TRANSMIT_HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return TRANSMIT_HEADERS.get(section, "")
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        row = index.row()
        col = index.column()

        if row < 0 or row >= len(self._messages):
            return None

        msg = self._messages[row]

        if role == Qt.DisplayRole:
            if col == TransmitColumn.ENABLED:
                return ""  # Checkbox handled by flags
            elif col == TransmitColumn.ID:
                if msg.is_extended_id:
                    return f"0x{msg.arbitration_id:08X}"
                return f"0x{msg.arbitration_id:03X}"
            elif col == TransmitColumn.NAME:
                return msg.name
            elif col == TransmitColumn.DLC:
                return str(msg.dlc)
            elif col == TransmitColumn.DATA:
                return msg.data[:msg.dlc].hex(' ').upper()
            elif col == TransmitColumn.CYCLE:
                return str(msg.cycle_ms)
            elif col == TransmitColumn.SEND:
                return "Send"
            elif col == TransmitColumn.COUNT:
                return str(msg.sent_count)

        elif role == Qt.EditRole:
            if col == TransmitColumn.ID:
                return msg.arbitration_id
            elif col == TransmitColumn.NAME:
                return msg.name
            elif col == TransmitColumn.DLC:
                return msg.dlc
            elif col == TransmitColumn.DATA:
                return msg.data[:msg.dlc]
            elif col == TransmitColumn.CYCLE:
                return msg.cycle_ms

        elif role == Qt.CheckStateRole:
            if col == TransmitColumn.ENABLED:
                return Qt.Checked if msg.enabled else Qt.Unchecked

        elif role == Qt.TextAlignmentRole:
            if col in (TransmitColumn.ID, TransmitColumn.DLC, TransmitColumn.CYCLE, TransmitColumn.COUNT):
                return Qt.AlignRight | Qt.AlignVCenter
            if col == TransmitColumn.SEND:
                return Qt.AlignCenter | Qt.AlignVCenter

        elif role == Qt.ForegroundRole:
            if col == TransmitColumn.SEND:
                return QColor("#2196F3")

        return None

    def setData(self, index, value, role=Qt.EditRole) -> bool:
        if not index.isValid():
            return False

        row = index.row()
        col = index.column()

        if row < 0 or row >= len(self._messages):
            return False

        msg = self._messages[row]

        if role == Qt.CheckStateRole and col == TransmitColumn.ENABLED:
            msg.enabled = value == Qt.Checked
            self.dataChanged.emit(index, index)
            return True

        if role == Qt.EditRole:
            if col == TransmitColumn.ID:
                try:
                    if isinstance(value, str):
                        value = int(value.replace('0x', ''), 16)
                    msg.arbitration_id = int(value)
                    self.dataChanged.emit(index, index)
                    return True
                except (ValueError, TypeError):
                    return False

            elif col == TransmitColumn.NAME:
                msg.name = str(value)
                self.dataChanged.emit(index, index)
                return True

            elif col == TransmitColumn.DLC:
                try:
                    msg.dlc = max(0, min(64 if msg.is_fd else 8, int(value)))
                    self.dataChanged.emit(index, index)
                    return True
                except (ValueError, TypeError):
                    return False

            elif col == TransmitColumn.DATA:
                if isinstance(value, (bytes, bytearray)):
                    msg.data = bytearray(value)
                    if len(msg.data) < 64:
                        msg.data.extend(b'\x00' * (64 - len(msg.data)))
                    self.dataChanged.emit(index, index)
                    return True

            elif col == TransmitColumn.CYCLE:
                try:
                    msg.cycle_ms = max(1, int(value))
                    self.dataChanged.emit(index, index)
                    return True
                except (ValueError, TypeError):
                    return False

        return False

    def flags(self, index) -> Qt.ItemFlag:
        if not index.isValid():
            return Qt.NoItemFlags

        flags = Qt.ItemIsEnabled | Qt.ItemIsSelectable
        col = index.column()

        if col == TransmitColumn.ENABLED:
            flags |= Qt.ItemIsUserCheckable
        elif col in (TransmitColumn.ID, TransmitColumn.NAME, TransmitColumn.DLC,
                     TransmitColumn.DATA, TransmitColumn.CYCLE):
            flags |= Qt.ItemIsEditable

        return flags


class TransmitPanel(QWidget):
    """
    Panel for defining and sending CAN messages.

    Features:
        - Add/remove transmit messages
        - Edit message ID, data, cycle time
        - Manual single send
        - Cyclic transmission with configurable period
        - Copy from received messages

    Signals:
        send_frame: Emitted when a frame should be sent (connection_id, CANFrame)
    """

    send_frame = Signal(object, object)  # connection_id, CANFrame

    def __init__(self, parent=None):
        super().__init__(parent)

        self._model = TransmitModel()
        self._connections: list[Connection] = []
        self._cyclic_timer = QTimer(self)
        self._cyclic_timer.timeout.connect(self._on_cyclic_timer)

        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Toolbar
        toolbar = self._create_toolbar()
        layout.addWidget(toolbar)

        # Table view
        self._table = QTableView()
        self._table.setModel(self._model)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableView.SelectRows)
        self._table.setSelectionMode(QTableView.SingleSelection)
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)

        # Set monospace font
        mono_font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        self._table.setFont(mono_font)

        # Set delegate for data column
        self._table.setItemDelegateForColumn(TransmitColumn.DATA, HexDataDelegate(self))

        # Configure header
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(TransmitColumn.ENABLED, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(TransmitColumn.ID, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(TransmitColumn.NAME, QHeaderView.Stretch)
        header.setSectionResizeMode(TransmitColumn.DLC, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(TransmitColumn.DATA, QHeaderView.Stretch)
        header.setSectionResizeMode(TransmitColumn.CYCLE, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(TransmitColumn.SEND, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(TransmitColumn.COUNT, QHeaderView.ResizeToContents)

        layout.addWidget(self._table)

    def _create_toolbar(self) -> QToolBar:
        """Create the toolbar."""
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFloatable(False)

        style = self.style()

        # Add message button
        add_action = QAction(
            style.standardIcon(QStyle.SP_FileDialogNewFolder),
            "Add Message",
            self
        )
        add_action.triggered.connect(self._add_message)
        toolbar.addAction(add_action)

        # Remove message button
        remove_action = QAction(
            style.standardIcon(QStyle.SP_TrashIcon),
            "Remove",
            self
        )
        remove_action.triggered.connect(self._remove_selected)
        toolbar.addAction(remove_action)

        toolbar.addSeparator()

        # Bus selector
        toolbar.addWidget(QLabel(" Bus: "))
        self._bus_combo = QComboBox()
        self._bus_combo.setMinimumWidth(120)
        self._bus_combo.addItem("All", None)
        toolbar.addWidget(self._bus_combo)

        toolbar.addSeparator()

        # Start/Stop cyclic
        self._start_cyclic_action = QAction(
            style.standardIcon(QStyle.SP_MediaPlay),
            "Start Cyclic",
            self
        )
        self._start_cyclic_action.setCheckable(True)
        self._start_cyclic_action.toggled.connect(self._toggle_cyclic)
        toolbar.addAction(self._start_cyclic_action)

        # Send all once
        send_all_action = QAction(
            style.standardIcon(QStyle.SP_CommandLink),
            "Send All Once",
            self
        )
        send_all_action.triggered.connect(self._send_all_once)
        toolbar.addAction(send_all_action)

        toolbar.addSeparator()

        # Clear button
        clear_action = QAction(
            style.standardIcon(QStyle.SP_DialogResetButton),
            "Clear",
            self
        )
        clear_action.triggered.connect(self._model.clear)
        toolbar.addAction(clear_action)

        return toolbar

    def _connect_signals(self) -> None:
        """Connect internal signals."""
        self._table.clicked.connect(self._on_cell_clicked)
        self._table.customContextMenuRequested.connect(self._show_context_menu)

    def set_connections(self, connections: list[Connection]) -> None:
        """Update available connections."""
        self._connections = connections

        # Update combo
        self._bus_combo.clear()
        self._bus_combo.addItem("All", None)
        for conn in connections:
            self._bus_combo.addItem(conn.name, conn.id)

    def add_from_frame(self, frame: CANFrame) -> None:
        """Add a transmit message from a received frame."""
        msg = TransmitMessage.from_frame(frame)
        self._model.add_message(msg)

    def _add_message(self) -> None:
        """Add a new empty message."""
        msg = TransmitMessage()
        # Set default connection
        conn_id = self._bus_combo.currentData()
        if conn_id:
            msg.connection_id = conn_id
        self._model.add_message(msg)

    def _remove_selected(self) -> None:
        """Remove selected message."""
        indexes = self._table.selectionModel().selectedRows()
        if indexes:
            self._model.remove_message(indexes[0].row())

    def _on_cell_clicked(self, index: QModelIndex) -> None:
        """Handle cell click."""
        if index.column() == TransmitColumn.SEND:
            msg = self._model.get_message(index.row())
            if msg:
                self._send_message(msg)

    def _send_message(self, msg: TransmitMessage) -> None:
        """Send a single message."""
        frame = msg.to_frame()

        # Use selected bus or message's connection
        conn_id = self._bus_combo.currentData() or msg.connection_id

        if conn_id or self._connections:
            # If no specific bus, use first connection
            if not conn_id and self._connections:
                conn_id = self._connections[0].id

            self.send_frame.emit(conn_id, frame)
            msg.sent_count += 1
            msg.last_sent_time = time.time()
            self._model.update_sent_count(msg)

    def _send_all_once(self) -> None:
        """Send all messages once."""
        for row in range(self._model.rowCount()):
            msg = self._model.get_message(row)
            if msg:
                self._send_message(msg)

    def _toggle_cyclic(self, checked: bool) -> None:
        """Toggle cyclic transmission."""
        if checked:
            self._cyclic_timer.start(1)  # 1ms resolution
            self._start_cyclic_action.setText("Stop Cyclic")
        else:
            self._cyclic_timer.stop()
            self._start_cyclic_action.setText("Start Cyclic")

    def _on_cyclic_timer(self) -> None:
        """Handle cyclic timer - send enabled messages at their cycle time."""
        now = time.time()

        for msg in self._model.get_enabled_messages():
            elapsed_ms = (now - msg.last_sent_time) * 1000
            if elapsed_ms >= msg.cycle_ms:
                self._send_message(msg)

    def _show_context_menu(self, pos) -> None:
        """Show context menu."""
        index = self._table.indexAt(pos)

        menu = QMenu(self)

        add_action = menu.addAction("Add Message")
        add_action.triggered.connect(self._add_message)

        if index.isValid():
            menu.addSeparator()

            send_action = menu.addAction("Send")
            send_action.triggered.connect(
                lambda: self._send_message(self._model.get_message(index.row()))
            )

            remove_action = menu.addAction("Remove")
            remove_action.triggered.connect(
                lambda: self._model.remove_message(index.row())
            )

            menu.addSeparator()

            duplicate_action = menu.addAction("Duplicate")
            duplicate_action.triggered.connect(
                lambda: self._duplicate_message(index.row())
            )

        menu.exec(self._table.viewport().mapToGlobal(pos))

    def _duplicate_message(self, row: int) -> None:
        """Duplicate a message."""
        msg = self._model.get_message(row)
        if msg:
            new_msg = TransmitMessage(
                arbitration_id=msg.arbitration_id,
                data=bytearray(msg.data),
                dlc=msg.dlc,
                is_extended_id=msg.is_extended_id,
                is_fd=msg.is_fd,
                name=msg.name + " (copy)",
                cycle_ms=msg.cycle_ms,
                connection_id=msg.connection_id,
            )
            self._model.add_message(new_msg)

    @property
    def model(self) -> TransmitModel:
        """Get the transmit model."""
        return self._model

    def stop_cyclic(self) -> None:
        """Stop cyclic transmission."""
        self._cyclic_timer.stop()
        self._start_cyclic_action.setChecked(False)
