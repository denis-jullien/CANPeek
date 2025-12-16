"""
High-performance trace model for displaying CAN frames.

This model provides efficient display of large numbers of CAN frames
with incremental updates and virtual scrolling support.
"""

from __future__ import annotations

from collections import deque
from enum import IntEnum
from typing import Any, Optional

from PySide6.QtCore import (
    Qt,
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
)

from canpeek.core.types import CANFrame
from canpeek.protocols.canopen import decode_frame as decode_canopen, format_canopen_full


class TraceColumn(IntEnum):
    """Column definitions for trace view."""
    INDEX = 0
    TIMESTAMP = 1
    BUS = 2
    DIRECTION = 3
    ID = 4
    TYPE = 5
    DLC = 6
    DATA = 7
    DECODED = 8


# Column headers
TRACE_HEADERS = {
    TraceColumn.INDEX: "#",
    TraceColumn.TIMESTAMP: "Time",
    TraceColumn.BUS: "Bus",
    TraceColumn.DIRECTION: "Dir",
    TraceColumn.ID: "ID",
    TraceColumn.TYPE: "Type",
    TraceColumn.DLC: "DLC",
    TraceColumn.DATA: "Data",
    TraceColumn.DECODED: "Decoded",
}


class TraceModel(QAbstractTableModel):
    """
    High-performance table model for CAN frame trace view.

    Features:
        - Efficient circular buffer storage
        - Incremental updates (no full model reset)
        - Virtual scrolling support
        - Configurable maximum capacity

    Example:
        >>> model = TraceModel(max_frames=50000)
        >>> view.setModel(model)
        >>> model.add_frames(new_frames)
    """

    def __init__(
        self,
        max_frames: int = 50_000,
        parent: Optional[Any] = None,
    ):
        """
        Initialize trace model.

        Args:
            max_frames: Maximum frames to keep in buffer
            parent: Parent QObject
        """
        super().__init__(parent)

        self._max_frames = max_frames
        self._frames: deque[CANFrame] = deque(maxlen=max_frames)
        self._first_timestamp: Optional[float] = None
        self._show_relative_time = True
        self._show_decoded = True

        # Decoding support (set externally)
        self._decoder = None

    @property
    def frame_count(self) -> int:
        """Get current number of frames."""
        return len(self._frames)

    @property
    def max_frames(self) -> int:
        """Get maximum frame capacity."""
        return self._max_frames

    def set_decoder(self, decoder) -> None:
        """Set DBC decoder for signal decoding."""
        self._decoder = decoder
        # Refresh decoded column
        if self._frames:
            top_left = self.index(0, TraceColumn.DECODED)
            bottom_right = self.index(len(self._frames) - 1, TraceColumn.DECODED)
            self.dataChanged.emit(top_left, bottom_right)

    def set_relative_time(self, relative: bool) -> None:
        """Set whether to show relative or absolute timestamps."""
        if self._show_relative_time != relative:
            self._show_relative_time = relative
            # Refresh timestamp column
            if self._frames:
                top_left = self.index(0, TraceColumn.TIMESTAMP)
                bottom_right = self.index(len(self._frames) - 1, TraceColumn.TIMESTAMP)
                self.dataChanged.emit(top_left, bottom_right)

    def clear(self) -> None:
        """Remove all frames."""
        if self._frames:
            self.beginResetModel()
            self._frames.clear()
            self._first_timestamp = None
            self.endResetModel()

    def add_frame(self, frame: CANFrame) -> None:
        """
        Add a single frame.

        For bulk additions, use add_frames() for better performance.
        """
        self.add_frames([frame])

    def add_frames(self, frames: list[CANFrame]) -> None:
        """
        Add multiple frames efficiently.

        Uses incremental updates when possible to avoid
        full model reset.
        """
        if not frames:
            return

        # Track first timestamp for relative time
        if self._first_timestamp is None and frames:
            self._first_timestamp = frames[0].timestamp

        current_count = len(self._frames)
        new_count = len(frames)
        total = current_count + new_count

        if total <= self._max_frames:
            # Simple append - no overflow
            self.beginInsertRows(
                QModelIndex(),
                current_count,
                current_count + new_count - 1
            )
            self._frames.extend(frames)
            self.endInsertRows()
        else:
            # Overflow case - need to handle removed rows
            overflow = total - self._max_frames

            if overflow >= current_count:
                # Complete replacement - reset model
                self.beginResetModel()
                self._frames.extend(frames)
                self.endResetModel()
            else:
                # Partial overflow - remove from beginning, add to end
                # This is more complex but provides smoother UI updates

                # First, remove overflowed rows from the beginning
                self.beginRemoveRows(QModelIndex(), 0, overflow - 1)
                # deque with maxlen handles this automatically when we extend
                self.endRemoveRows()

                # Then insert new rows at the end
                new_start = len(self._frames)  # After removal
                self.beginInsertRows(
                    QModelIndex(),
                    new_start,
                    new_start + new_count - 1
                )
                self._frames.extend(frames)
                self.endInsertRows()

    def set_frames(self, frames: list[CANFrame]) -> None:
        """
        Replace all frames.

        Use this for loading saved traces.
        """
        self.beginResetModel()
        self._frames.clear()
        self._first_timestamp = frames[0].timestamp if frames else None
        self._frames.extend(frames[-self._max_frames:])  # Limit to max
        self.endResetModel()

    def get_frame(self, row: int) -> Optional[CANFrame]:
        """Get frame at row index."""
        if 0 <= row < len(self._frames):
            return self._frames[row]
        return None

    def get_all_frames(self) -> list[CANFrame]:
        """Get all frames as a list."""
        return list(self._frames)

    # --- QAbstractTableModel implementation ---

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._frames)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(TraceColumn)

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
                col = TraceColumn(section)
                return TRACE_HEADERS.get(col, "")
            except ValueError:
                return None

        # Vertical header (row numbers)
        return str(section + 1)

    def data(
        self,
        index: QModelIndex | QPersistentModelIndex,
        role: int = Qt.DisplayRole
    ) -> Any:
        if not index.isValid():
            return None

        row = index.row()
        col = index.column()

        if row < 0 or row >= len(self._frames):
            return None

        frame = self._frames[row]

        # Display role
        if role == Qt.DisplayRole:
            return self._get_display_data(frame, col, row)

        # Alignment role
        if role == Qt.TextAlignmentRole:
            if col in (TraceColumn.ID, TraceColumn.DLC, TraceColumn.INDEX):
                return Qt.AlignRight | Qt.AlignVCenter
            if col == TraceColumn.DATA:
                return Qt.AlignLeft | Qt.AlignVCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        # Foreground color for direction
        if role == Qt.ForegroundRole:
            if col == TraceColumn.DIRECTION:
                from PySide6.QtGui import QColor
                if frame.is_rx:
                    return QColor("#4CAF50")  # Green for RX
                else:
                    return QColor("#2196F3")  # Blue for TX

        # User role for sorting (return raw values)
        if role == Qt.UserRole:
            return self._get_sort_data(frame, col, row)

        return None

    def _get_display_data(self, frame: CANFrame, col: int, row: int) -> str:
        """Get display string for a cell."""
        try:
            column = TraceColumn(col)
        except ValueError:
            return ""

        if column == TraceColumn.INDEX:
            return str(row + 1)

        if column == TraceColumn.TIMESTAMP:
            if self._show_relative_time and self._first_timestamp is not None:
                rel_time = frame.timestamp - self._first_timestamp
                return f"{rel_time:.6f}"
            return f"{frame.timestamp:.6f}"

        if column == TraceColumn.BUS:
            return frame.bus_name or str(frame.bus_id)

        if column == TraceColumn.DIRECTION:
            return "RX" if frame.is_rx else "TX"

        if column == TraceColumn.ID:
            return frame.id_str()

        if column == TraceColumn.TYPE:
            return frame.type_str()

        if column == TraceColumn.DLC:
            return str(frame.dlc)

        if column == TraceColumn.DATA:
            return frame.data_str()

        if column == TraceColumn.DECODED:
            if self._decoder and self._show_decoded:
                return self._decode_frame(frame)
            return ""

        return ""

    def _get_sort_data(self, frame: CANFrame, col: int, row: int) -> Any:
        """Get sortable value for a cell."""
        try:
            column = TraceColumn(col)
        except ValueError:
            return None

        if column == TraceColumn.INDEX:
            return row

        if column == TraceColumn.TIMESTAMP:
            return frame.timestamp_ns

        if column == TraceColumn.ID:
            return frame.arbitration_id

        if column == TraceColumn.DLC:
            return frame.dlc

        return self._get_display_data(frame, col, row)

    def _decode_frame(self, frame: CANFrame) -> str:
        """Decode frame using DBC decoder or CANopen."""
        # Try DBC decoder first
        if self._decoder:
            try:
                result = self._decoder.decode(frame)
                if result:
                    # Format as "SignalName=Value SignalName2=Value2"
                    parts = [f"{k}={v}" for k, v in result.items()]
                    return " ".join(parts)
            except Exception:
                pass

        # Try CANopen decoding
        canopen_msg = decode_canopen(frame)
        if canopen_msg:
            return format_canopen_full(canopen_msg)

        return ""

    def flags(self, index: QModelIndex | QPersistentModelIndex) -> Qt.ItemFlag:
        if not index.isValid():
            return Qt.NoItemFlags
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable
