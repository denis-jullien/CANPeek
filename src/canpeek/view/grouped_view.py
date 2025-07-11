"""
Lightweight grouped view implementation optimized for CAN message grouping.

This module provides a fast, independent grouped view that doesn't depend on Polars
and is separate from the trace view filtering system.
"""

import enum
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from PySide6.QtCore import (
    QAbstractItemModel,
    QModelIndex,
    Qt,
    QTimer,
)

from canpeek.data_utils import CANFrame
from canpeek.view.models import get_structured_decodings


class GroupedViewColumn(enum.IntEnum):
    """Defines the columns for the CANGroupedModel."""

    ID = 0
    BUS = 1
    NAME = 2
    DLC = 3
    DATA = 4
    CYCLE_TIME = 5
    COUNT = 6


@dataclass
class GroupedFrameInfo:
    """Information about a grouped CAN frame"""

    arbitration_id: int
    latest_timestamp: float
    previous_timestamp: Optional[float]
    cycle_time_ms: float
    count: int
    latest_data: bytes
    latest_dlc: int
    latest_bus: str
    is_extended: bool
    connection_id: Optional[str]
    decoded_name: str
    latest_frame: Optional[CANFrame] = None  # Store full frame for decoding
    children_populated: bool = False
    children: List[Dict[str, Any]] = None  # Decoded signals

    def __post_init__(self):
        if self.children is None:
            self.children = []


class FastCANGroupedModel(QAbstractItemModel):
    """Fast, independent grouped model for CAN messages"""

    def __init__(self, parent=None):
        super().__init__(parent)

        # Core data storage - dict for O(1) access using composite key (arb_id, connection_id)
        self.grouped_data: Dict[tuple, GroupedFrameInfo] = {}
        self.sorted_keys: List[tuple] = []

        # Sorting state
        self.sort_column = 0  # Default sort by ID
        self.sort_order = Qt.AscendingOrder

        # DBC configuration for decoding
        self.dbc_files = []
        self.pdo_databases = []
        self.canopen_enabled = True

        # Performance tracking
        # self.frame_times = deque(maxlen=60)
        self.last_update = time.perf_counter()
        self.update_count = 0

        # Frame counting for debugging
        self.total_frames_received = 0
        self.total_frames_processed = 0
        self.frame_loss_warnings = 0

        # Fixed 60 FPS timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self._refresh_view)
        self.update_timer.start(50)  # 50ms = 20 FPS

        # Batch processing and optimization
        self.pending_frames: List[CANFrame] = []
        self.needs_refresh = False
        self.decode_cache = {}  # Cache decoded names to avoid repeated decoding
        self.last_refresh_time = time.perf_counter()
        self.frames_since_refresh = 0

        # Track changes for selective model updates
        self.has_new_ids = False
        self.last_new_id_time = time.perf_counter()

        # Column headers
        self.headers = ["ID", "Bus", "Name", "DLC", "Data", "Cycle Time", "Count"]

    def set_dbc_config(self, dbc_files, pdo_databases, canopen_enabled):
        """Set DBC configuration for message decoding"""
        self.dbc_files = dbc_files
        self.pdo_databases = pdo_databases
        self.canopen_enabled = canopen_enabled

    def add_frame(self, frame: CANFrame):
        """Add a single frame efficiently with precise timing"""
        arb_id = frame.arbitration_id
        conn_id = str(frame.connection_id) if frame.connection_id else ""
        composite_key = (arb_id, conn_id)
        current_time = frame.timestamp

        # Frame counting for debugging
        self.total_frames_received += 1

        # Performance tracking for this frame
        frame_start = time.perf_counter()

        if composite_key in self.grouped_data:
            # Update existing entry - most common case, optimize for this
            existing = self.grouped_data[composite_key]

            # Calculate cycle time from previous frame (more precise)
            if existing.latest_timestamp is not None:
                cycle_time_s = current_time - existing.latest_timestamp
                cycle_time_ms = cycle_time_s * 1000.0

                # Validate cycle time to catch timing anomalies
                if cycle_time_ms < 0:
                    print(
                        f"Warning: Negative cycle time for ID 0x{arb_id:X} conn {conn_id}: {cycle_time_ms:.3f}ms"
                    )
                    cycle_time_ms = 0.0
                elif cycle_time_ms > 10000:  # > 10 seconds
                    print(
                        f"Warning: Very large cycle time for ID 0x{arb_id:X} conn {conn_id}: {cycle_time_ms:.3f}ms"
                    )
            else:
                cycle_time_ms = 0.0

            # Update the entry in-place (fast)
            existing.previous_timestamp = existing.latest_timestamp
            existing.latest_timestamp = current_time
            existing.cycle_time_ms = cycle_time_ms
            existing.count += 1
            existing.latest_data = frame.data
            existing.latest_dlc = frame.dlc
            existing.latest_bus = frame.bus or ""
            existing.is_extended = frame.is_extended
            existing.connection_id = (
                str(frame.connection_id) if frame.connection_id else ""
            )
            existing.latest_frame = frame  # Store full frame for decoding
            # Don't clear children on frame updates - decoded signals are based on ID, not data
            # Only clear if the frame structure might have changed (different DLC, etc.)
            if existing.latest_dlc != frame.dlc:
                existing.children_populated = False
                existing.children.clear()

        else:
            # Create new entry - only decode for new IDs
            decoded_name = self._decode_frame_name(frame)

            self.grouped_data[composite_key] = GroupedFrameInfo(
                arbitration_id=arb_id,
                latest_timestamp=current_time,
                previous_timestamp=None,
                cycle_time_ms=0.0,
                count=1,
                latest_data=frame.data,
                latest_dlc=frame.dlc,
                latest_bus=frame.bus or "",
                is_extended=frame.is_extended,
                connection_id=str(frame.connection_id) if frame.connection_id else "",
                decoded_name=decoded_name,
                latest_frame=frame,  # Store full frame for decoding
            )

            # Add to sorted list and maintain order
            self._insert_sorted_key(composite_key)

            # Track that we have new IDs to show
            self.has_new_ids = True
            self.last_new_id_time = time.perf_counter()

        # More aggressive UI update strategy for better responsiveness
        self.frames_since_refresh += 1
        current_refresh_time = time.perf_counter()

        # Reduce batching to improve responsiveness while maintaining 60 FPS
        # Update UI if enough frames processed OR enough time passed
        if (
            self.frames_since_refresh >= 10  # Reduced from 50 to 10 frames
            or current_refresh_time - self.last_refresh_time > 0.016
        ):  # 16ms (60 FPS)
            self.needs_refresh = True

        # Mark frame as successfully processed
        self.total_frames_processed += 1

        # Track frame processing time
        frame_time = (time.perf_counter() - frame_start) * 1000
        if frame_time > 1.0:  # Log slow frame processing
            print(
                f"Slow frame processing for ID 0x{arb_id:X} conn {conn_id}: {frame_time:.3f}ms"
            )

        # Check for frame loss periodically
        if self.total_frames_received % 1000 == 0:
            frame_loss = self.total_frames_received - self.total_frames_processed
            if frame_loss > 0:
                self.frame_loss_warnings += 1
                print(
                    f"Warning: {frame_loss} frames lost/not processed out of {self.total_frames_received}"
                )

    def add_frames_batch(self, frames: List[CANFrame]):
        """Add multiple frames efficiently"""
        for frame in frames:
            self.add_frame(frame)

    def _decode_frame_name(self, frame: CANFrame) -> str:
        """Decode frame name using DBC files with caching"""
        arb_id = frame.arbitration_id
        conn_id = str(frame.connection_id) if frame.connection_id else ""
        cache_key = (arb_id, conn_id)

        # Check cache first
        if cache_key in self.decode_cache:
            return self.decode_cache[cache_key]

        # Decode and cache the result
        try:
            # Use existing decoding infrastructure
            decodings = get_structured_decodings(
                frame, self.dbc_files, self.pdo_databases, self.canopen_enabled
            )

            if decodings:
                decoded_name = decodings[0].name
            else:
                decoded_name = ""

            # Cache the result
            self.decode_cache[cache_key] = decoded_name
            return decoded_name

        except Exception:
            # Cache the failure too
            decoded_name = "err"
            self.decode_cache[cache_key] = decoded_name
            return decoded_name

    def _insert_sorted_key(self, composite_key: tuple):
        """Insert composite key maintaining sorted order efficiently"""
        if self.sort_column == GroupedViewColumn.ID:
            # Binary search insertion for ID sorting (most common case)
            left, right = 0, len(self.sorted_keys)
            reverse = self.sort_order == Qt.DescendingOrder

            while left < right:
                mid = (left + right) // 2
                # Compare by arbitration_id first, then connection_id
                if (composite_key < self.sorted_keys[mid]) ^ reverse:
                    right = mid
                else:
                    left = mid + 1

            self.sorted_keys.insert(left, composite_key)
        else:
            # For other columns, just append and defer sorting
            # Only re-sort when there are many new items to avoid frequent sorts
            self.sorted_keys.append(composite_key)

            # Defer expensive sorting operations
            # Only sort if we have accumulated many unsorted items
            if len(self.sorted_keys) % 50 == 0:  # Re-sort every 50 new items
                self._apply_sorting()

    def _refresh_view(self):
        """Refresh the view if needed (60 FPS) with detailed performance tracking"""
        if not self.needs_refresh and not self.has_new_ids:
            return

        # Update FPS tracking
        current_time = time.perf_counter()
        # self.frame_times.append(current_time)
        self.update_count += 1

        # Only use model reset for new IDs after a delay (to batch them)
        # or when we have many new IDs to avoid constant expansion loss
        if self.has_new_ids and (current_time - self.last_new_id_time > 0.1):
            # Use model reset for new IDs but only after a delay
            self.beginResetModel()
            self.endResetModel()
            self.has_new_ids = False
        elif self.needs_refresh:
            # For existing data updates, use dataChanged to preserve expansion
            if self.sorted_keys:
                top_left = self.index(0, 0)
                bottom_right = self.index(
                    len(self.sorted_keys) - 1, len(self.headers) - 1
                )
                self.dataChanged.emit(top_left, bottom_right)

        # model_time = (time.perf_counter() - model_start) * 1000

        # Reset batching counters
        self.needs_refresh = False
        self.frames_since_refresh = 0
        self.last_refresh_time = current_time

        # # Performance logging for debugging
        # refresh_time = (time.perf_counter() - refresh_start) * 1000
        # if refresh_time > 5.0 or unique_ids > 1000:  # Log slow refreshes or high ID counts
        #     print(f"Grouped view refresh: {refresh_time:.2f}ms, {unique_ids} IDs, {frames_processed} frames, model: {model_time:.2f}ms")

    def clear_data(self):
        """Clear all grouped data"""
        self.beginResetModel()
        self.grouped_data.clear()
        self.sorted_keys.clear()
        self.has_new_ids = False
        self.endResetModel()

    # Qt Model Interface
    def index(self, row, column, parent=QModelIndex()):
        try:
            if not self.hasIndex(row, column, parent):
                return QModelIndex()

            if not parent.isValid():
                # Top-level item (CAN frame)
                if row < len(self.sorted_keys):
                    composite_key = self.sorted_keys[row]
                    if composite_key in self.grouped_data:
                        frame_info = self.grouped_data[composite_key]
                        return self.createIndex(row, column, frame_info)
                return QModelIndex()

            # Child item (decoded signal)
            parent_data = parent.internalPointer()
            if isinstance(parent_data, GroupedFrameInfo):
                # Only return valid indices if children are already populated
                if (
                    parent_data.children_populated
                    and hasattr(parent_data, "children")
                    and parent_data.children
                    and row < len(parent_data.children)
                ):
                    signal_data = parent_data.children[row]
                    # Create a copy to avoid modifying the original data
                    signal_data_copy = (
                        signal_data.copy()
                        if isinstance(signal_data, dict)
                        else signal_data
                    )
                    if isinstance(signal_data_copy, dict):
                        signal_data_copy["parent_key"] = (
                            parent_data.arbitration_id,
                            parent_data.connection_id,
                        )
                    return self.createIndex(row, column, signal_data_copy)

            return QModelIndex()
        except Exception as e:
            print(f"Error in index(): {e}")
            return QModelIndex()

    def parent(self, index):
        if not index.isValid():
            return QModelIndex()

        try:
            # Get the internal pointer
            internal_data = index.internalPointer()
            if internal_data is None:
                return QModelIndex()

            # If it's a signal (child), find its parent frame
            if isinstance(internal_data, dict) and "parent_key" in internal_data:
                parent_key = internal_data["parent_key"]
                if parent_key in self.grouped_data:
                    # Find the row of the parent in sorted_keys
                    try:
                        parent_row = self.sorted_keys.index(parent_key)
                        frame_info = self.grouped_data[parent_key]
                        return self.createIndex(parent_row, 0, frame_info)
                    except (ValueError, KeyError):
                        return QModelIndex()

            # Top-level frames don't have parents
            return QModelIndex()
        except Exception:
            # If any error occurs, return invalid index
            return QModelIndex()

    def rowCount(self, parent=QModelIndex()):
        try:
            if not parent.isValid():
                # Top-level: return number of CAN entries
                return len(self.sorted_keys)

            # Get parent's internal data
            parent_data = parent.internalPointer()
            if isinstance(parent_data, GroupedFrameInfo):
                # This is a CAN frame, return number of decoded signals
                if parent_data.children_populated:
                    return len(parent_data.children)
                else:
                    # Check if we have signals to show
                    if parent_data.latest_frame:
                        signals = self._decode_frame_signals(parent_data.latest_frame)
                        return len(signals)
                    return 0

            # Signals don't have children
            return 0
        except Exception:
            # If any error occurs, return 0
            return 0

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def hasChildren(self, parent=QModelIndex()):
        try:
            if not parent.isValid():
                return len(self.sorted_keys) > 0

            # Disable tree expansion for now due to Qt model complexity
            # TODO: Re-implement tree expansion with a simpler approach
            return False
        except Exception:
            return False

    def canFetchMore(self, parent=QModelIndex()):
        try:
            if not parent.isValid():
                return False

            parent_data = parent.internalPointer()
            if isinstance(parent_data, GroupedFrameInfo):
                return (
                    not parent_data.children_populated
                    and parent_data.latest_frame is not None
                )

            return False
        except Exception:
            return False

    def fetchMore(self, parent=QModelIndex()):
        try:
            if not parent.isValid():
                return

            parent_data = parent.internalPointer()
            if (
                isinstance(parent_data, GroupedFrameInfo)
                and not parent_data.children_populated
            ):
                # Get decoded signals
                signals = (
                    self._decode_frame_signals(parent_data.latest_frame)
                    if parent_data.latest_frame
                    else []
                )

                # Store children and mark as populated (without Qt signals to avoid issues)
                parent_data.children = signals
                parent_data.children_populated = True

        except Exception as e:
            print(f"Error in fetchMore: {e}")
            try:
                if hasattr(parent_data, "children_populated"):
                    parent_data.children_populated = True
            except Exception as e:
                pass

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.headers[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        try:
            if role == Qt.TextAlignmentRole:
                if index.column() == GroupedViewColumn.CYCLE_TIME:
                    return Qt.AlignRight
                else:
                    return None

            if not index.isValid() or role != Qt.DisplayRole:
                return None

            internal_data = index.internalPointer()
            if internal_data is None:
                return None

            col = index.column()

            if isinstance(internal_data, GroupedFrameInfo):
                # Top-level CAN frame
                frame_info = internal_data
                arb_id = frame_info.arbitration_id

                if col == GroupedViewColumn.ID:
                    return f"0x{arb_id:X}"
                elif col == GroupedViewColumn.BUS:
                    return frame_info.latest_bus
                elif col == GroupedViewColumn.NAME:
                    return frame_info.decoded_name
                elif col == GroupedViewColumn.DLC:
                    return str(frame_info.latest_dlc)
                elif col == GroupedViewColumn.DATA:
                    return frame_info.latest_data.hex(" ").upper()
                elif col == GroupedViewColumn.CYCLE_TIME:
                    if frame_info.cycle_time_ms > 0:
                        return f"{frame_info.cycle_time_ms:.1f}"
                    else:
                        return "N/A"
                elif col == GroupedViewColumn.COUNT:
                    return str(frame_info.count)

            elif isinstance(internal_data, dict):
                # Child signal
                signal_data = internal_data

                if col == GroupedViewColumn.ID:
                    return f"  └ {signal_data.get('name', 'Unknown')}"
                elif col == GroupedViewColumn.NAME:
                    return signal_data.get("unit", "")
                elif col == GroupedViewColumn.DATA:
                    return str(signal_data.get("value", ""))
                # Other columns empty for signals

            return None
        except Exception:
            # If any error occurs, return None
            return None

    def sort(self, column: int, order: Qt.SortOrder) -> None:
        """Sort the model by the specified column and order"""
        self.beginResetModel()
        self.sort_column = column
        self.sort_order = order
        self._apply_sorting()
        self.endResetModel()

    def _apply_sorting(self) -> None:
        """Apply current sorting to the composite key list"""
        if not self.sorted_keys:
            return

        def sort_key(composite_key):
            if composite_key not in self.grouped_data:
                return (0, "")  # Fallback

            frame_info = self.grouped_data[composite_key]
            col = self.sort_column
            arb_id, conn_id = composite_key

            if col == GroupedViewColumn.ID:
                return (arb_id, conn_id)  # Sort by ID first, then connection
            elif col == GroupedViewColumn.BUS:
                return frame_info.latest_bus
            elif col == GroupedViewColumn.NAME:
                return frame_info.decoded_name
            elif col == GroupedViewColumn.DLC:
                return frame_info.latest_dlc
            elif col == GroupedViewColumn.DATA:
                return frame_info.latest_data.hex()
            elif col == GroupedViewColumn.CYCLE_TIME:
                return frame_info.cycle_time_ms
            elif col == GroupedViewColumn.COUNT:
                return frame_info.count
            else:
                return (arb_id, conn_id)

        # Sort the composite key list
        reverse = self.sort_order == Qt.DescendingOrder
        self.sorted_keys.sort(key=sort_key, reverse=reverse)

    def _decode_frame_signals(self, frame):
        """Decode frame signals using the existing get_structured_decodings function"""
        try:
            structured_results = get_structured_decodings(
                frame, self.dbc_files, self.pdo_databases, self.canopen_enabled
            )

            all_signals = []
            for result in structured_results:
                # Add a header for the decoding source if there are multiple
                if len(structured_results) > 1:
                    header_name = f"--- {result.source}: {result.name} ---"
                    all_signals.append({"name": header_name, "value": "", "unit": ""})

                # Add the actual signals
                for sig_info in result.signals:
                    all_signals.append(
                        {
                            "name": sig_info.name,
                            "value": sig_info.value,
                            "unit": sig_info.unit,
                        }
                    )

            return all_signals
        except Exception as e:
            print(f"Error decoding frame signals: {e}")
            return []
