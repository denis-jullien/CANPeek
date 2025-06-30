from __future__ import annotations
import cantools
from collections import deque
from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict

from PySide6.QtCore import QAbstractItemModel, QAbstractTableModel, QModelIndex, Qt

from .data_utils import CANFrame
from .co.canopen_utils import CANopenDecoder

# --- Data Structures ---


@dataclass
class DisplayItem:  # Used for Grouped View
    parent: Optional[DisplayItem]
    data_source: Any
    is_signal: bool = False
    children: List[DisplayItem] = field(default_factory=list)
    children_populated: bool = False
    row_in_parent: int = 0


@dataclass
class SignalInfo:
    """Represents a single decoded signal or field."""

    name: str
    value: Any
    unit: str


@dataclass
class DecodingResult:
    """Represents the complete decoding of a message from a single source."""

    source: str  # e.g., "DBC", "PDO", "CANopen"
    name: str  # e.g., "EngineStatus", "TPDO1_Node5", "NMT"
    signals: List[SignalInfo]


# --- Helper Function for Decoding ---


def get_structured_decodings(
    frame: CANFrame,
    dbc_databases: List[cantools.db.Database],
    pdo_databases: List[cantools.db.Database],
    canopen_enabled: bool,
) -> List[DecodingResult]:
    """
    Decodes a CAN frame from all available sources and returns structured results.

    This is the centralized decoding function.
    """
    results: List[DecodingResult] = []

    def _process_database(db: cantools.db.Database, source_name: str) -> None:
        """Helper to decode from a cantools database and append to results."""
        try:
            message = db.get_message_by_frame_id(frame.arbitration_id)
            decoded_signals = db.decode_message(
                frame.arbitration_id, frame.data, decode_choices=False
            )

            signal_infos = [
                SignalInfo(
                    name=s.name,
                    value=decoded_signals.get(s.name, "N/A"),
                    unit=s.unit or "",
                )
                for s in message.signals
            ]

            results.append(
                DecodingResult(
                    source=source_name, name=message.name, signals=signal_infos
                )
            )
        except (KeyError, ValueError):
            pass  # Frame not in this database

    # 1. Process regular DBCs
    for db in dbc_databases:
        _process_database(db, "DBC")

    # 2. Process CANopen PDO databases
    for db in pdo_databases:
        _process_database(db, "PDO")

    # 3. Process generic CANopen
    if canopen_enabled:
        if co_info := CANopenDecoder.decode(frame):
            # The 'CANopen Type' becomes the name, the rest are signals
            canopen_type = co_info.pop("CANopen Type", "Unknown")
            signal_infos = [
                SignalInfo(name=k, value=v, unit="") for k, v in co_info.items()
            ]
            results.append(
                DecodingResult(
                    source="CANopen", name=canopen_type, signals=signal_infos
                )
            )

    return results


# --- Models ---
class CANTraceModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self.headers = ["Timestamp", "ID", "Type", "DLC", "Data", "Decoded"]
        self.frames: deque[CANFrame] = deque(maxlen=10000)
        self.dbc_databases: List[cantools.db.Database] = []
        self.pdo_databases: List[cantools.db.Database] = []
        self.canopen_enabled = True

    def set_data(self, frames: List[CANFrame]):
        self.beginResetModel()
        self.frames.clear()
        self.frames.extend(frames)
        self.endResetModel()

    def set_config(
        self,
        dbs: List[cantools.db.Database],
        co_enabled: bool,
        pdo_dbs: List[cantools.db.Database] | None = None,
    ):
        self.dbc_databases = dbs
        self.canopen_enabled = co_enabled
        self.pdo_databases = pdo_dbs or []
        self.layoutChanged.emit()

    def rowCount(self, p=QModelIndex()):
        return len(self.frames)

    def columnCount(self, p=QModelIndex()):
        return len(self.headers)

    def headerData(self, s, o, r):
        if o == Qt.Horizontal and r == Qt.DisplayRole:
            return self.headers[s]

    def data(self, index, role):
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        frame = self.frames[index.row()]
        col = index.column()
        if col == 0:
            return f"{frame.timestamp:.6f}"
        if col == 1:
            return f"0x{frame.arbitration_id:X}"
        if col == 2:
            return ("Ext" if frame.is_extended else "Std") + (
                " RTR" if frame.is_remote else ""
            )
        if col == 3:
            return str(frame.dlc)
        if col == 4:
            return frame.data.hex(" ")
        if col == 5:
            return self._decode_frame(frame)
        return None

    def _decode_frame(self, frame: CANFrame) -> str:
        """Formats structured decoding results into a string for the Trace view."""
        structured_results = get_structured_decodings(
            frame, self.dbc_databases, self.pdo_databases, self.canopen_enabled
        )

        output_strings = []
        for result in structured_results:
            signals_str = " ".join(f"{s.name}={s.value}" for s in result.signals)
            output_strings.append(f"{result.source}: {result.name} | {signals_str}")

        return " || ".join(output_strings)


class CANGroupedModel(QAbstractItemModel):
    def __init__(self):
        super().__init__()
        self.headers = ["ID", "Name", "Count", "Cycle Time", "DLC", "Data"]
        self.top_level_items: List[DisplayItem] = []
        self.dbc_databases: List[cantools.db.Database] = []
        self.pdo_databases: List[cantools.db.Database] = []
        self.canopen_enabled = True
        self.frame_counts = {}
        self.timestamps = {}
        self.item_map = {}

    def set_config(
        self,
        dbs: List[cantools.db.Database],
        co_enabled: bool,
        pdo_dbs: List[cantools.db.Database] | None = None,
    ):
        self.dbc_databases = dbs
        self.canopen_enabled = co_enabled
        self.pdo_databases = pdo_dbs or []
        self.layoutChanged.emit()

    def columnCount(self, p=QModelIndex()):
        return len(self.headers)

    def headerData(self, s, o, r):
        if o == Qt.Horizontal and r == Qt.DisplayRole:
            return self.headers[s]

    def rowCount(self, p=QModelIndex()):
        if not p.isValid():
            return len(self.top_level_items)
        return (
            len(p.internalPointer().children)
            if p.internalPointer().children_populated
            else 0
        )

    def index(self, r, c, p=QModelIndex()):
        if not self.hasIndex(r, c, p):
            return QModelIndex()
        parent = p.internalPointer() if p.isValid() else None
        items = self.top_level_items if not parent else parent.children
        return self.createIndex(r, c, items[r]) if r < len(items) else QModelIndex()

    def parent(self, i):
        if not i.isValid():
            return QModelIndex()
        parent = i.internalPointer().parent
        return (
            self.createIndex(parent.row_in_parent, 0, parent)
            if parent
            else QModelIndex()
        )

    def hasChildren(self, p=QModelIndex()):
        if not p.isValid():
            return True
        item = p.internalPointer()
        if item.is_signal:
            return False
        if item.children_populated:
            return len(item.children) > 0

        # Check for any possible signals from any source
        signals = self._decode_frame_to_signals(item.data_source)
        return len(signals) > 0

    def canFetchMore(self, p: QModelIndex):
        return not p.internalPointer().children_populated if p.isValid() else False

    def fetchMore(self, p: QModelIndex):
        item = p.internalPointer()
        if item.children_populated:
            return

        signals = self._decode_frame_to_signals(item.data_source)
        if not signals:
            item.children_populated = True
            return

        self.beginInsertRows(p, 0, len(signals) - 1)
        item.children = [
            DisplayItem(item, s, True, row_in_parent=i) for i, s in enumerate(signals)
        ]
        item.children_populated = True
        self.endInsertRows()

    def _decode_frame_to_signals(self, frame: CANFrame) -> List[Dict]:
        """Formats structured decoding results into a list of dicts for the Grouped view."""
        structured_results = get_structured_decodings(
            frame, self.dbc_databases, self.pdo_databases, self.canopen_enabled
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

    def clear_frames(self):
        self.beginResetModel()
        self.top_level_items.clear()
        self.frame_counts.clear()
        self.timestamps.clear()
        self.item_map.clear()
        self.endResetModel()

    def update_frames(self, frames: List[CANFrame]):
        if not frames:
            return
        self.beginResetModel()
        for frame in frames:
            can_id = frame.arbitration_id
            self.frame_counts[can_id] = self.frame_counts.get(can_id, 0) + 1
            if can_id not in self.timestamps:
                self.timestamps[can_id] = deque(maxlen=10)
            self.timestamps[can_id].append(frame.timestamp)
            if can_id not in self.item_map:
                item = DisplayItem(parent=None, data_source=frame)
                item.row_in_parent = len(self.top_level_items)
                self.top_level_items.append(item)
                self.item_map[can_id] = item
            else:
                item = self.item_map[can_id]
                item.data_source = frame
                if item.children_populated:
                    # Mark for refetching on next expansion
                    item.children.clear()
                    item.children_populated = False
        self.endResetModel()

    def _get_message_name(self, can_id: int) -> str:
        """Helper to get a message name from any available database."""
        # Prioritize regular DBCs
        for db in self.dbc_databases:
            try:
                return db.get_message_by_frame_id(can_id).name
            except KeyError:
                pass
        # Then PDO DBCs
        for db in self.pdo_databases:
            try:
                return db.get_message_by_frame_id(can_id).name
            except KeyError:
                pass
        return ""

    def data(self, index, role):
        if not index.isValid():
            return None
        item: DisplayItem = index.internalPointer()
        col = index.column()

        if role == Qt.UserRole:
            if item.is_signal:
                return None
            return (
                item.data_source.arbitration_id
                if col == 0
                else self.frame_counts.get(item.data_source.arbitration_id, 0)
            )

        if role != Qt.DisplayRole:
            return None

        if item.is_signal:
            sig = item.data_source
            if col == 0:
                return f"  └ {sig['name']}"
            if col == 1:
                return sig.get("unit", "")  # Show unit in name column
            if col == 5:
                return f"{sig['value']}"
        else:
            frame: CANFrame = item.data_source
            can_id = frame.arbitration_id
            if col == 0:
                return f"0x{can_id:X}"
            if col == 1:
                return self._get_message_name(can_id)
            if col == 2:
                return str(self.frame_counts.get(can_id, 0))
            if col == 3:
                ts_list = self.timestamps.get(can_id, [])
                if len(ts_list) > 1:
                    cycle_times = [
                        ts_list[i] - ts_list[i - 1] for i in range(1, len(ts_list))
                    ]
                    avg_cycle_ms = sum(cycle_times) / len(cycle_times) * 1000
                    return f"{avg_cycle_ms:.1f} ms"
                return "-"
            if col == 4:
                return str(frame.dlc)
            if col == 5:
                return frame.data.hex(" ")
        return None
