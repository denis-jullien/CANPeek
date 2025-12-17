"""
High-performance grouped model for displaying CAN frames by ID.

This model provides a tree view where messages are grouped by CAN ID
with expandable signals decoded from DBC files.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional
from uuid import UUID

from PySide6.QtCore import (
    Qt,
    QAbstractItemModel,
    QModelIndex,
    QPersistentModelIndex,
    QSortFilterProxyModel,
)

from canpeek.core.types import CANFrame
from canpeek.protocols.canopen import decode_frame as decode_canopen, format_canopen_short


class GroupedColumn(IntEnum):
    """Column definitions for grouped view."""
    ID = 0
    BUS = 1
    SYMBOL = 2
    DLC = 3
    DATA = 4
    CYCLE = 5
    COUNT = 6


# Column headers
GROUPED_HEADERS = {
    GroupedColumn.ID: "ID",
    GroupedColumn.BUS: "Bus",
    GroupedColumn.SYMBOL: "Symbol",
    GroupedColumn.DLC: "DLC",
    GroupedColumn.DATA: "Data / Value",
    GroupedColumn.CYCLE: "Cycle (ms)",
    GroupedColumn.COUNT: "Count",
}


@dataclass
class SignalItem:
    """Represents a decoded signal (child of MessageItem)."""
    name: str
    value: Any
    unit: str = ""
    min_value: Optional[float] = None
    max_value: Optional[float] = None


@dataclass
class MessageItem:
    """Represents a CAN message (top-level item)."""
    arbitration_id: int
    bus_id: int
    bus_name: str
    connection_id: Optional[UUID]

    # Current data
    frame: Optional[CANFrame] = None
    dlc: int = 0
    data: bytes = b""

    # Statistics
    count: int = 0
    timestamps: deque = field(default_factory=lambda: deque(maxlen=10))

    # Decoding
    message_name: str = ""
    signals: list[SignalItem] = field(default_factory=list)
    signals_loaded: bool = False

    # Row tracking
    row_index: int = 0

    def update(self, frame: CANFrame) -> None:
        """Update with a new frame."""
        self.frame = frame
        self.dlc = frame.dlc
        self.data = frame.data
        self.count += 1
        self.timestamps.append(frame.timestamp)

        # Invalidate signals for re-decode
        self.signals_loaded = False

    def get_cycle_time_ms(self) -> Optional[float]:
        """Calculate average cycle time in milliseconds."""
        if len(self.timestamps) < 2:
            return None

        deltas = [
            self.timestamps[i] - self.timestamps[i - 1]
            for i in range(1, len(self.timestamps))
        ]
        avg_seconds = sum(deltas) / len(deltas)
        return avg_seconds * 1000

    @property
    def key(self) -> tuple:
        """Unique key for this message."""
        return (self.connection_id, self.arbitration_id)


class GroupedModel(QAbstractItemModel):
    """
    Tree model for CAN frames grouped by ID.

    Features:
        - Messages grouped by CAN ID
        - Expandable signals from DBC decoding
        - Real-time cycle time calculation
        - Frame count tracking
        - Lazy signal loading

    Structure:
        - Top level: MessageItem (one per unique CAN ID)
        - Children: SignalItem (decoded signals)

    Example:
        >>> model = GroupedModel()
        >>> view.setModel(model)
        >>> model.update_frames(new_frames)
    """

    def __init__(self, parent: Optional[Any] = None):
        super().__init__(parent)

        # Message storage - keyed by (connection_id, arbitration_id)
        self._messages: dict[tuple, MessageItem] = {}
        self._message_list: list[MessageItem] = []  # Ordered list for row indexing

        # Decoder for signal decoding
        self._decoder = None

    @property
    def message_count(self) -> int:
        """Get number of unique messages."""
        return len(self._message_list)

    def set_decoder(self, decoder) -> None:
        """Set DBC decoder for signal decoding."""
        self._decoder = decoder
        # Invalidate all signals for re-decode
        for msg in self._message_list:
            msg.signals_loaded = False
        # Refresh view
        self.layoutChanged.emit()

    def clear(self) -> None:
        """Remove all messages."""
        if self._message_list:
            self.beginResetModel()
            self._messages.clear()
            self._message_list.clear()
            self.endResetModel()

    def update_frame(self, frame: CANFrame) -> None:
        """Update with a single frame."""
        self.update_frames([frame])

    def update_frames(self, frames: list[CANFrame]) -> None:
        """
        Update with multiple frames.

        This is the main method for adding new CAN frames.
        Messages are grouped by (connection_id, arbitration_id).
        """
        if not frames:
            return

        new_messages: list[MessageItem] = []
        updated_rows: set[int] = set()

        for frame in frames:
            key = (frame.connection_id, frame.arbitration_id)

            if key not in self._messages:
                # New message
                msg = MessageItem(
                    arbitration_id=frame.arbitration_id,
                    bus_id=frame.bus_id,
                    bus_name=frame.bus_name,
                    connection_id=frame.connection_id,
                    row_index=len(self._message_list) + len(new_messages),
                )
                msg.update(frame)

                self._messages[key] = msg
                new_messages.append(msg)
            else:
                # Existing message - update
                msg = self._messages[key]
                msg.update(frame)
                updated_rows.add(msg.row_index)

        # Insert new messages
        if new_messages:
            start_row = len(self._message_list)
            self.beginInsertRows(QModelIndex(), start_row, start_row + len(new_messages) - 1)
            self._message_list.extend(new_messages)
            self.endInsertRows()

        # Notify about updated existing messages
        if updated_rows:
            for row in updated_rows:
                # Emit dataChanged for all columns of this row
                top_left = self.index(row, 0)
                bottom_right = self.index(row, len(GroupedColumn) - 1)
                self.dataChanged.emit(top_left, bottom_right)

                # Also update children if expanded
                msg = self._message_list[row]
                if msg.signals_loaded and msg.signals:
                    msg.signals_loaded = False  # Force re-decode
                    # Notify that children may have changed
                    parent_idx = self.index(row, 0)
                    child_top = self.index(0, 0, parent_idx)
                    child_bottom = self.index(len(msg.signals) - 1, len(GroupedColumn) - 1, parent_idx)
                    self.dataChanged.emit(child_top, child_bottom)

    def get_message(self, row: int) -> Optional[MessageItem]:
        """Get message at row index."""
        if 0 <= row < len(self._message_list):
            return self._message_list[row]
        return None

    def get_frame(self, row: int) -> Optional[CANFrame]:
        """Get the latest frame for a message."""
        msg = self.get_message(row)
        return msg.frame if msg else None

    # --- QAbstractItemModel implementation ---

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        if not parent.isValid():
            # Top level - message count
            return len(self._message_list)

        # Child level - check if parent is a message
        if parent.internalPointer() is None:
            return 0

        item = parent.internalPointer()
        if isinstance(item, MessageItem):
            # Load signals if needed
            self._ensure_signals_loaded(item)
            return len(item.signals)

        return 0

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        return len(GroupedColumn)

    def index(
        self,
        row: int,
        column: int,
        parent: QModelIndex | QPersistentModelIndex = QModelIndex()
    ) -> QModelIndex:
        if not self.hasIndex(row, column, parent):
            return QModelIndex()

        if not parent.isValid():
            # Top level - message
            if 0 <= row < len(self._message_list):
                return self.createIndex(row, column, self._message_list[row])
            return QModelIndex()

        # Child level - signal
        parent_item = parent.internalPointer()
        if isinstance(parent_item, MessageItem):
            self._ensure_signals_loaded(parent_item)
            if 0 <= row < len(parent_item.signals):
                return self.createIndex(row, column, parent_item.signals[row])

        return QModelIndex()

    def parent(self, index: QModelIndex | QPersistentModelIndex) -> QModelIndex:
        if not index.isValid():
            return QModelIndex()

        item = index.internalPointer()

        if isinstance(item, MessageItem):
            # Messages are top-level
            return QModelIndex()

        if isinstance(item, SignalItem):
            # Find parent message
            for msg in self._message_list:
                if item in msg.signals:
                    return self.createIndex(msg.row_index, 0, msg)

        return QModelIndex()

    def hasChildren(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> bool:
        if not parent.isValid():
            return len(self._message_list) > 0

        item = parent.internalPointer()
        if isinstance(item, MessageItem):
            # Check if we can decode signals
            if self._decoder:
                return True  # Assume we might have signals
            return False

        return False

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.DisplayRole
    ) -> Any:
        if role != Qt.DisplayRole:
            return None

        if orientation == Qt.Horizontal:
            try:
                col = GroupedColumn(section)
                return GROUPED_HEADERS.get(col, "")
            except ValueError:
                return None

        return None

    def data(
        self,
        index: QModelIndex | QPersistentModelIndex,
        role: int = Qt.DisplayRole
    ) -> Any:
        if not index.isValid():
            return None

        item = index.internalPointer()
        col = index.column()

        if isinstance(item, MessageItem):
            return self._get_message_data(item, col, role)
        elif isinstance(item, SignalItem):
            return self._get_signal_data(item, col, role)

        return None

    def _get_message_data(self, msg: MessageItem, col: int, role: int) -> Any:
        """Get data for a message row."""
        try:
            column = GroupedColumn(col)
        except ValueError:
            return None

        if role == Qt.DisplayRole:
            if column == GroupedColumn.ID:
                if msg.frame and msg.frame.is_extended_id:
                    return f"0x{msg.arbitration_id:08X}"
                return f"0x{msg.arbitration_id:03X}"

            if column == GroupedColumn.BUS:
                return msg.bus_name or str(msg.bus_id)

            if column == GroupedColumn.SYMBOL:
                if msg.message_name:
                    return msg.message_name
                # Try CANopen decoding for symbol
                if msg.frame:
                    canopen_msg = decode_canopen(msg.frame)
                    if canopen_msg:
                        return format_canopen_short(canopen_msg)
                return ""

            if column == GroupedColumn.DLC:
                return str(msg.dlc)

            if column == GroupedColumn.DATA:
                return msg.data.hex(' ').upper()

            if column == GroupedColumn.CYCLE:
                cycle = msg.get_cycle_time_ms()
                if cycle is not None:
                    return f"{cycle:.1f}"
                return "-"

            if column == GroupedColumn.COUNT:
                return str(msg.count)

        elif role == Qt.UserRole:
            # For sorting
            if column == GroupedColumn.ID:
                return msg.arbitration_id
            if column == GroupedColumn.COUNT:
                return msg.count
            if column == GroupedColumn.CYCLE:
                return msg.get_cycle_time_ms() or 0

        elif role == Qt.TextAlignmentRole:
            if column in (GroupedColumn.ID, GroupedColumn.DLC, GroupedColumn.COUNT):
                return Qt.AlignRight | Qt.AlignVCenter
            if column == GroupedColumn.CYCLE:
                return Qt.AlignRight | Qt.AlignVCenter

        return None

    def _get_signal_data(self, signal: SignalItem, col: int, role: int) -> Any:
        """Get data for a signal row."""
        try:
            column = GroupedColumn(col)
        except ValueError:
            return None

        if role == Qt.DisplayRole:
            if column == GroupedColumn.ID:
                return f"  └ {signal.name}"

            if column == GroupedColumn.SYMBOL:
                return signal.unit

            if column == GroupedColumn.DATA:
                # Format value appropriately
                if isinstance(signal.value, float):
                    return f"{signal.value:.3f}"
                return str(signal.value)

        elif role == Qt.ForegroundRole:
            # Subtle color for signal rows
            from PySide6.QtGui import QColor
            return QColor("#888888")

        return None

    def _ensure_signals_loaded(self, msg: MessageItem) -> None:
        """Ensure signals are loaded for a message."""
        if msg.signals_loaded:
            return

        msg.signals.clear()
        msg.signals_loaded = True

        if not self._decoder or not msg.frame:
            return

        try:
            # Get message name
            msg_info = self._decoder.get_message_info(msg.arbitration_id)
            if msg_info:
                msg.message_name = msg_info.get("name", "")

            # Decode signals
            decoded = self._decoder.decode(msg.frame)
            if decoded:
                for name, value in decoded.items():
                    signal_info = self._decoder.get_signal_info(
                        msg.arbitration_id, name
                    )
                    unit = signal_info.get("unit", "") if signal_info else ""
                    msg.signals.append(SignalItem(
                        name=name,
                        value=value,
                        unit=unit,
                    ))
        except Exception:
            pass

    def flags(self, index: QModelIndex | QPersistentModelIndex) -> Qt.ItemFlag:
        if not index.isValid():
            return Qt.NoItemFlags
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable


class MessageFilterProxyModel(QSortFilterProxyModel):
    """
    Proxy model for filtering grouped messages.

    Supports filtering by:
    - CAN ID range (min_id, max_id)
    - Bus/connection name
    - Message name pattern (regex)
    - ID pattern (hex string)
    """

    def __init__(self, parent: Optional[Any] = None):
        super().__init__(parent)
        self._min_id: Optional[int] = None
        self._max_id: Optional[int] = None
        self._bus_filter: Optional[str] = None
        self._id_pattern: str = ""

        # Use UserRole for sorting (raw values)
        self.setSortRole(Qt.UserRole)

    def set_id_range(self, min_id: Optional[int], max_id: Optional[int]) -> None:
        """Set CAN ID range filter."""
        self._min_id = min_id
        self._max_id = max_id
        self.invalidateFilter()

    def set_bus_filter(self, bus_name: Optional[str]) -> None:
        """Set bus name filter."""
        self._bus_filter = bus_name
        self.invalidateFilter()

    def set_id_pattern(self, pattern: str) -> None:
        """Set ID pattern filter (hex string like '0x1' or '1A')."""
        self._id_pattern = pattern.strip().upper()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        """Check if row should be shown."""
        # Only filter top-level items (messages)
        if source_parent.isValid():
            return True

        source_model = self.sourceModel()
        if not isinstance(source_model, GroupedModel):
            return True

        msg = source_model.get_message(source_row)
        if msg is None:
            return True

        # ID range filter
        if self._min_id is not None and msg.arbitration_id < self._min_id:
            return False
        if self._max_id is not None and msg.arbitration_id > self._max_id:
            return False

        # Bus filter
        if self._bus_filter:
            if msg.bus_name != self._bus_filter:
                return False

        # ID pattern filter (hex string matching)
        if self._id_pattern:
            id_hex = f"{msg.arbitration_id:X}"
            pattern = self._id_pattern.lstrip("0X")
            if pattern and pattern not in id_hex:
                # Also check message name if available
                if msg.message_name:
                    if self._id_pattern.upper() not in msg.message_name.upper():
                        return False
                else:
                    return False

        return True
