from datetime import datetime
import threading
import queue

import numpy as np
import polars as pl
from typing import Dict, Optional
import enum
import numba as nb

# import duckdb
from PySide6.QtCore import QAbstractTableModel, Qt, QTimer, QRect
from PySide6.QtWidgets import QLineEdit, QHeaderView
from PySide6.QtGui import QPainter

from src.canpeek.data_utils import CANFrame
from src.canpeek.view.decoders import CachedDBCDecoder

CAN_DTYPE = np.dtype(
    [
        ("timestamp", "f8"),
        ("bus", "U10"),  # encoded bus index (e.g., can0=0)
        ("direction", "bool"),
        ("id", "U8"),  # id as hex string, up to 29bit
        ("is_extended", "bool"),
        ("is_rtr", "bool"),
        ("dlc", "u1"),
        ("data", "U23"),  # array of 64 bytes as string = 16 + 7 spaces (CAN FD = 64)
    ]
)


class Trace2ViewColumn(enum.IntEnum):
    """Defines the columns for the CANTraceModel."""

    TIMESTAMP = 0
    BUS = 1
    DIRECTION = 2
    ID = 3
    TYPE = 4
    DLC = 5
    DATA = 6
    DECODED = 7


@nb.njit
def my_cond_nb(x, k=10):
    return x < k


@nb.njit
def filter2_nb(arr, cond_nb, count):
    result = np.empty(count, dtype=arr.dtype)
    j = 0
    for i in range(arr.size):
        if cond_nb(arr[i]):
            result[j] = arr[i]
            j += 1
            if j >= count:
                break
    return result


class CANBuffer:
    def __init__(self, trace_queue: queue.Queue, size=2_000_000):
        # Keep NumPy buffer for high-performance circular buffer
        self.buffer = np.zeros(size, dtype=CAN_DTYPE)
        self.size = size
        self.index = 0
        self.lock = threading.Lock()

        # Add Polars DataFrame for filtering
        self._polars_data = pl.DataFrame()
        self._polars_lock = threading.Lock()
        self._needs_polars_update = False

        self.frame_queue = trace_queue
        self.running = False

        # DBC decoder with caching
        self.dbc_decoder = CachedDBCDecoder()

    def push(self, frame):
        with self.lock:
            i = self.index % self.size
            self.buffer[i] = frame
            self.index += 1
            self._needs_polars_update = True

    def push_message(self, msg: CANFrame):
        frame = (
            msg.timestamp,
            msg.bus,
            msg.is_rx,
            format(msg.arbitration_id, "X"),
            msg.is_extended,
            msg.is_remote,
            msg.dlc,
            msg.data.hex(" ").upper(),
        )
        self.push(frame)

    def clear(self):
        with self.lock:
            self.index = 0
            self._needs_polars_update = True

    def latest(self, count):
        with self.lock:
            start = max(0, self.index - count)
            indices = np.arange(start, start + count) % self.size
            return self.buffer[indices]

    def get_polars_data(self, count: int) -> pl.DataFrame:
        """Get latest data as Polars DataFrame for filtering"""
        with self._polars_lock:
            if self._needs_polars_update:
                self._update_polars_data(count)
                self._needs_polars_update = False
            return self._polars_data

    def _update_polars_data(self, count: int):
        """Update Polars DataFrame from NumPy buffer"""
        numpy_data = self.latest(min(count, self.index))

        # # Convert to Polars DataFrame
        # data_rows = []
        # for frame in numpy_data:
        #     if frame["timestamp"] > 0:  # Skip empty frames
        #         data_hex = " ".join(f"{b:02X}" for b in frame["data"][: frame["dlc"]])
        #         data_rows.append(
        #             {
        #                 "timestamp": frame["timestamp"],
        #                 "bus": f"can{frame['bus']}",
        #                 "direction" : frame['direction'],
        #                 "id": int(frame["id"]),
        #                 "dlc": int(frame["dlc"]),
        #                 "data": data_hex,
        #             }
        #         )

        self._polars_data = pl.from_numpy(numpy_data)

    def start(self):
        self.running = True
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        """Main thread execution for trace processing"""
        print("Trace2 worker thread started")

        while self.running:
            try:
                frame = self.frame_queue.get(timeout=0.1)
                self.push_message(frame)

            except queue.Empty:
                continue

        print("Trace2 worker thread stopped")

    def decode_frame_from_numpy(self, frame_data: np.ndarray) -> str:
        """Decode a frame from NumPy array data and return formatted string."""
        try:
            # Convert numpy frame data to CANFrame
            frame = CANFrame(
                timestamp=frame_data["timestamp"],
                arbitration_id=int(frame_data["id"], 16),
                data=bytes.fromhex(frame_data["data"].replace(" ", "")),
                dlc=int(frame_data["dlc"]),
                is_extended=frame_data["is_extended"],
                is_remote=frame_data["is_rtr"],
                bus=frame_data["bus"],
                connection_id=None,  # Will be handled by DBC connection filtering
                is_rx=frame_data["direction"],
            )

            # Decode using cached decoder
            decoding_results = self.dbc_decoder.decode_frame(frame)

            # Format results for display
            if decoding_results:
                formatted_results = []
                for result in decoding_results:
                    signals_str = ", ".join(
                        [f"{sig.name}={sig.value}" for sig in result.signals]
                    )
                    formatted_results.append(
                        f"{result.source}:{result.name}({signals_str})"
                    )
                return " | ".join(formatted_results)
            else:
                return ""

        except Exception as e:
            return f"Error: {str(e)}"


class Trace2FilterHeaderView(QHeaderView):
    """Custom header view with inline filter boxes for trace2 view columns"""

    def __init__(self, orientation, parent=None):
        super().__init__(orientation, parent)
        self.filter_boxes = {}
        self.filter_height = 25
        self.setDefaultSectionSize(120)
        self.setMinimumSectionSize(80)
        self.setSectionsMovable(
            False
        )  # Prevent moving sections to avoid positioning issues

    def set_model(self, model):
        """Set the model and create filter boxes"""
        if hasattr(self, "model") and self.model:
            # Clear existing filter boxes
            for filter_box in self.filter_boxes.values():
                filter_box.deleteLater()
            self.filter_boxes.clear()

        self.model = model

        # Create filter boxes for each column
        for column in Trace2ViewColumn:
            filter_box = QLineEdit(self)
            filter_box.setPlaceholderText("Filter... (* ? supported)")

            # Ensure the filter box can receive focus and input
            filter_box.setFocusPolicy(Qt.StrongFocus)
            filter_box.setAttribute(Qt.WA_InputMethodEnabled, True)
            filter_box.setEnabled(True)

            filter_box.setStyleSheet("""
                QLineEdit {
                    border: 1px solid #ccc;
                    border-radius: 3px;
                    padding: 2px;
                    font-size: 10px;
                    background-color: #f9f9f9;
                }
                QLineEdit:focus {
                    border: 2px solid #4CAF50;
                    background-color: white;
                }
            """)

            # Connect to model filter
            filter_box.textChanged.connect(
                lambda text, col=column: self._on_filter_changed(col, text)
            )

            # Add clear functionality (Escape key) - use installEventFilter instead
            filter_box.installEventFilter(self)

            self.filter_boxes[column] = filter_box

        # Force initial positioning of filter boxes
        self._update_filter_positions()

    def _on_filter_changed(self, column, text):
        """Handle filter text change"""
        if hasattr(self, "model") and self.model:
            # Pass the column index to the CANTableModel
            column_int = int(column) if hasattr(column, "value") else column
            self.model.set_column_filter(column_int, text)

    # def eventFilter(self, watched, event):
    #     """Handle events for filter boxes"""
    #     if event.type() == QEvent.KeyPress:
    #         if event.key() == Qt.Key_Escape:
    #             # Clear the filter box on Escape
    #             if isinstance(watched, QLineEdit):
    #                 watched.clear()
    #                 return True
    #
    #     # Let the event pass through normally
    #     return super().eventFilter(watched, event)

    # def mousePressEvent(self, event):
    #     """Handle mouse press events - check if clicking on filter boxes"""
    #     for filter_box in self.filter_boxes.values():
    #         if filter_box.geometry().contains(event.pos()):
    #             # Click is on a filter box, let it handle the event
    #             filter_box.setFocus()
    #             return

    # # Normal header click handling
    # super().mousePressEvent(event)

    def sizeHint(self):
        """Return size hint including filter boxes"""
        size = super().sizeHint()
        size.setHeight(size.height() + self.filter_height)
        return size

    def paintSection(self, painter: QPainter, rect: QRect, logical_index: int):
        """Paint section with space for filter boxes"""
        # Reduce section height to make room for filter boxes
        header_rect = QRect(
            rect.x(), rect.y(), rect.width(), rect.height() - self.filter_height
        )
        super().paintSection(painter, header_rect, logical_index)

        # Position the filter box
        try:
            column = Trace2ViewColumn(logical_index)
            if column in self.filter_boxes:
                filter_box = self.filter_boxes[column]
                filter_rect = QRect(
                    rect.x() + 2,
                    rect.y() + rect.height() - self.filter_height + 2,
                    rect.width() - 4,
                    self.filter_height - 4,
                )
                filter_box.setGeometry(filter_rect)
                filter_box.show()
        except (ValueError, KeyError):
            pass

    def resizeEvent(self, event):
        """Handle resize to reposition filter boxes"""
        super().resizeEvent(event)
        self._update_filter_positions()

    def _update_filter_positions(self):
        """Update positions of all filter boxes"""
        if not hasattr(self, "model") or not self.model:
            return

        for column in Trace2ViewColumn:
            if column in self.filter_boxes:
                logical_index = column.value
                # Calculate section position manually
                section_start = self.sectionViewportPosition(logical_index)
                section_size = self.sectionSize(logical_index)

                filter_box = self.filter_boxes[column]
                if section_start >= 0 and section_size > 0:  # Section is visible
                    # Calculate filter box geometry
                    filter_rect = QRect(
                        section_start + 2,
                        self.height() - self.filter_height + 2,
                        section_size - 4,
                        self.filter_height - 4,
                    )
                    filter_box.setGeometry(filter_rect)
                    filter_box.show()
                    filter_box.raise_()  # Ensure filter box is on top
                else:
                    # Hide filter box if section is not visible
                    filter_box.hide()


class CANTableModel(QAbstractTableModel):
    """Enhanced CANTableModel with Polars-based filtering support"""

    def __init__(self, buffer: CANBuffer, view_size=100000, parent=None):
        super().__init__(parent)
        self.buffer = buffer
        self.view_size = view_size

        # Column headers
        # Programmatically create headers from the Enum
        self.headers = [col.name.replace("_", " ").title() for col in Trace2ViewColumn]
        self.headers[Trace2ViewColumn.DIRECTION] = "Rx/Tx"  # Custom header name
        self.headers[Trace2ViewColumn.ID] = "ID (hex)"  # Custom header name

        # Filter state
        self.column_filters: Dict[int, str] = {}
        self.filtered_data: Optional[pl.DataFrame] = None

        # Performance monitoring
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_data)
        self.refresh_timer.start(100)  # 100ms refresh rate

    def set_column_filter(self, column: int, filter_text: str):
        """Set filter text for a specific column (called by FilterHeaderView)"""
        if filter_text.strip():
            self.column_filters[column] = filter_text.strip()
        else:
            self.column_filters.pop(column, None)

        # Refresh data with new filters
        self.refresh_data()

    def refresh_data(self):
        """Refresh the filtered data"""
        try:
            # Get raw data from buffer
            raw_data = self.buffer.get_polars_data(self.view_size)

            # Apply filters if any
            if self.column_filters:
                self.filtered_data = self._apply_filters(raw_data)
            else:
                self.filtered_data = raw_data

            # Notify views of data change
            self.beginResetModel()
            self.endResetModel()

        except Exception as e:
            print(f"Error refreshing trace data: {e}")

    def _apply_filters(self, data: pl.DataFrame) -> pl.DataFrame:
        """Apply column filters to the data using Polars expressions"""
        if data.is_empty():
            return data

        filtered_data = data

        for column, filter_text in self.column_filters.items():
            if column == Trace2ViewColumn.TIMESTAMP:  # Timestamp
                filtered_data = self._filter_timestamp(filtered_data, filter_text)
            elif column == Trace2ViewColumn.BUS:  # Bus
                filtered_data = self._filter_bus(filtered_data, filter_text)
            elif column == Trace2ViewColumn.ID:  # ID
                filtered_data = self._filter_id(filtered_data, filter_text)
            elif column == Trace2ViewColumn.DLC:  # DLC
                filtered_data = self._filter_dlc(filtered_data, filter_text)
            elif column == Trace2ViewColumn.DATA:  # Data
                filtered_data = self._filter_data(filtered_data, filter_text)

        return filtered_data

    def _filter_timestamp(self, data: pl.DataFrame, filter_text: str) -> pl.DataFrame:
        """Filter timestamp column"""
        try:
            # Support range filtering (e.g., "1000-2000" or ">1000")
            if "-" in filter_text and not filter_text.startswith("-"):
                parts = filter_text.split("-", 1)
                start, end = float(parts[0]), float(parts[1])
                return data.filter(
                    (pl.col("timestamp") >= start) & (pl.col("timestamp") <= end)
                )
            elif filter_text.startswith(">"):
                value = float(filter_text[1:])
                return data.filter(pl.col("timestamp") > value)
            elif filter_text.startswith("<"):
                value = float(filter_text[1:])
                return data.filter(pl.col("timestamp") < value)
            else:
                # Convert to string and use wildcard matching
                return data.filter(
                    pl.col("timestamp").cast(pl.Utf8).str.contains(filter_text)
                )
        except (ValueError, TypeError):
            return data

    def _filter_bus(self, data: pl.DataFrame, filter_text: str) -> pl.DataFrame:
        """Filter bus column"""
        return data.filter(pl.col("bus").str.contains(filter_text))

    def _filter_id(self, data: pl.DataFrame, filter_text: str) -> pl.DataFrame:
        """Filter ID column"""
        # pattern = self._wildcard_to_regex(filter_text)
        # return data.filter(pl.col("id").str.contains(pattern))

        # try:
        #     # Support hex input (0x123) or decimal
        #     if filter_text.startswith("0x") or filter_text.startswith("0X"):
        #         id_value = int(filter_text, 16)
        #         return data.filter(pl.col("id") == id_value)
        #     elif filter_text.isdigit():
        #         id_value = int(filter_text)
        #         return data.filter(pl.col("id") == id_value)
        #     else:
        # Convert ID to hex string and use wildcard matching
        # pattern = self._wildcard_to_regex(filter_text)
        return data.filter(pl.col("id").str.contains(filter_text))
        # except (ValueError, TypeError):
        #     return data

    def _filter_dlc(self, data: pl.DataFrame, filter_text: str) -> pl.DataFrame:
        """Filter DLC column"""
        try:
            if filter_text.isdigit():
                dlc_value = int(filter_text)
                return data.filter(pl.col("dlc") == dlc_value)
            else:
                return data.filter(
                    pl.col("dlc").cast(pl.Utf8).str.contains(filter_text)
                )
        except (ValueError, TypeError):
            return data

    def _filter_data(self, data: pl.DataFrame, filter_text: str) -> pl.DataFrame:
        """Filter data column"""
        return data.filter(pl.col("data").str.contains(filter_text))

    def rowCount(self, parent=None):
        if self.filtered_data is not None:
            return min(self.filtered_data.height, self.view_size)
        return 0  # min(self.view_size, self.buffer.index)

    def columnCount(self, parent=None):
        return len(Trace2ViewColumn)

    def data(self, index, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None

        row = index.row()
        col = index.column()

        # Use filtered data if available
        if self.filtered_data is not None and not self.filtered_data.is_empty():
            if row >= self.filtered_data.height:
                return None

            frame_data = self.filtered_data.row(row, named=True)
            if col == Trace2ViewColumn.TIMESTAMP:
                return datetime.fromtimestamp(frame_data["timestamp"]).strftime(
                    "%H:%M:%S.%f"
                )
            elif col == Trace2ViewColumn.DIRECTION:
                return "Rx" if frame_data["direction"] else "Tx"
            elif col == Trace2ViewColumn.BUS:
                return frame_data["bus"]
            elif col == Trace2ViewColumn.ID:
                return frame_data["id"]
            elif col == Trace2ViewColumn.TYPE:
                return ("Ext" if frame_data["is_extended"] else "Std") + (
                    " RTR" if frame_data["is_rtr"] else ""
                )
            elif col == Trace2ViewColumn.DLC:
                return str(frame_data["dlc"])
            elif col == Trace2ViewColumn.DATA:
                return frame_data["data"]
            elif col == Trace2ViewColumn.DECODED:
                # Convert polars row to numpy array for decoding
                numpy_row = np.array(
                    [
                        (
                            frame_data["timestamp"],
                            frame_data["bus"],
                            frame_data["direction"],
                            frame_data["id"],
                            frame_data["is_extended"],
                            frame_data["is_rtr"],
                            frame_data["dlc"],
                            frame_data["data"],
                        )
                    ],
                    dtype=CAN_DTYPE,
                )
                return self.buffer.decode_frame_from_numpy(numpy_row[0])
        # else:
        #     print("dsqfgsdfggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")
        #     # Fallback to NumPy data
        #     frames = self.buffer.latest(self.view_size)
        #     if row >= len(frames):
        #         return None
        #
        #     frame = frames[row]
        #     if col == 0:
        #         return f"{frame['timestamp']:.6f}"
        #     elif col == 1:
        #         return f"can{frame['bus']}"
        #     elif col == 2:
        #         return hex(frame["id"])
        #     elif col == 3:
        #         return frame["dlc"]
        #     elif col == 4:
        #         return " ".join(f"{b:02X}" for b in frame["data"][: frame["dlc"]])

        return None

    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]
