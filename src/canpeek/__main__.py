#!/usr/bin/env python3
"""
CAN Bus Observer GUI
Features:
- Project-based configuration with Tree View
- Highly performant, batched-update Trace/Grouped views
- Multi-DBC and Multi-Filter support, enhanced CANopen decoding
- DBC content viewer
- DBC decoding and signal-based transmitting
- CAN log file saving/loading
- Real-time monitoring
"""

import sys
import struct
import json
from typing import Dict, List, Optional, Any, TYPE_CHECKING
from dataclasses import dataclass, field, asdict
from pathlib import Path
from functools import partial
from collections import deque
import faulthandler
import qdarktheme
import inspect
import importlib
import logging
from contextlib import contextmanager
from docstring_parser import parse
import enum
from . import rc_icons
from .dcf2db import dcf_2_db

__all__ = [
    "rc_icons",  # remove ruff "Remove unused import: `.rc_icons`"
]


from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QPushButton,
    QLabel,
    QLineEdit,
    QCheckBox,
    QComboBox,
    QSpinBox,
    QGroupBox,
    QFormLayout,
    QHeaderView,
    QFileDialog,
    QMessageBox,
    QMenu,
    QTreeView,
    QTreeWidget,
    QTreeWidgetItem,
    QTableView,
    QToolBar,
    QDockWidget,
    QStyle,
    QDialog,
    QTextEdit,
    QSplitter,
    QProgressBar,
    QSizePolicy,
)

from PySide6.QtCore import (
    QThread,
    QTimer,
    Signal,
    Qt,
    QObject,
    QAbstractItemModel,
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    QSettings,
)
from PySide6.QtGui import QAction, QKeyEvent, QIcon, QPixmap


import can
import cantools
import canopen

if TYPE_CHECKING:
    from __main__ import ProjectExplorer, CANInterfaceManager, CANBusObserver


faulthandler.enable()

# --- Data Structures ---
TRACE_BUFFER_LIMIT = 5000


@dataclass
class CANFrame:
    timestamp: float
    arbitration_id: int
    data: bytes
    dlc: int
    is_extended: bool = False
    is_error: bool = False
    is_remote: bool = False
    channel: str = "CAN1"


@dataclass
class DisplayItem:  # Used for Grouped View
    parent: Optional["DisplayItem"]
    data_source: Any
    is_signal: bool = False
    children: List["DisplayItem"] = field(default_factory=list)
    children_populated: bool = False
    row_in_parent: int = 0


@dataclass
class DBCFile:
    path: Path
    database: object
    enabled: bool = True


@dataclass
class CANopenNode:
    path: Path
    node_id: int
    enabled: bool = True
    pdo_decoding_enabled: bool = True  # Add PDO decoding option

    def to_dict(self) -> Dict:
        return {
            "path": str(self.path),
            "node_id": self.node_id,
            "enabled": self.enabled,
            "pdo_decoding_enabled": self.pdo_decoding_enabled,  # Add to serialization
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "CANopenNode":
        path = Path(data["path"])
        if not path.exists():
            raise FileNotFoundError(f"EDS/DCF file not found: {path}")
        return cls(
            path=path, 
            node_id=data["node_id"], 
            enabled=data["enabled"],
            pdo_decoding_enabled=data.get("pdo_decoding_enabled", True)  # Add with default
        )


@dataclass
class CANFrameFilter:
    name: str = "New Filter"
    enabled: bool = True
    min_id: int = 0x000
    max_id: int = 0x7FF
    mask: int = 0x7FF
    accept_extended: bool = True
    accept_standard: bool = True
    accept_data: bool = True
    accept_remote: bool = True

    def matches(self, frame: CANFrame) -> bool:
        if frame.is_extended and not self.accept_extended:
            return False
        if not frame.is_extended and not self.accept_standard:
            return False
        if frame.is_remote and not self.accept_remote:
            return False
        if not frame.is_remote and not self.accept_data:
            return False
        return self.min_id <= (frame.arbitration_id & self.mask) <= self.max_id


@dataclass
class Project:
    dbcs: List[DBCFile] = field(default_factory=list)
    filters: List[CANFrameFilter] = field(default_factory=list)
    canopen_enabled: bool = False
    canopen_nodes: List[CANopenNode] = field(default_factory=list)
    can_interface: str = "virtual"
    can_config: Dict[str, Any] = field(default_factory=lambda: {"channel": "vcan0"})

    def get_active_dbcs(self) -> List[object]:
        return [dbc.database for dbc in self.dbcs if dbc.enabled]

    def get_active_filters(self) -> List[CANFrameFilter]:
        return [f for f in self.filters if f.enabled]

    def to_dict(self) -> Dict:
        serializable_can_config = {
            k: v.name if isinstance(v, enum.Enum) else v
            for k, v in self.can_config.items()
        }
        return {
            "dbcs": [
                {"path": str(dbc.path), "enabled": dbc.enabled} for dbc in self.dbcs
            ],
            "filters": [asdict(f) for f in self.filters],
            "canopen_enabled": self.canopen_enabled,
            "canopen_nodes": [node.to_dict() for node in self.canopen_nodes],
            "can_interface": self.can_interface,
            "can_config": serializable_can_config,
        }

    @classmethod
    def from_dict(
        cls, data: Dict, interface_manager: "CANInterfaceManager"
    ) -> "Project":
        project = cls()
        project.canopen_enabled = data.get("canopen_enabled", False)
        project.can_interface = data.get("can_interface", "virtual")

        for node_data in data.get("canopen_nodes", []):
            try:
                project.canopen_nodes.append(CANopenNode.from_dict(node_data))
            except Exception as e:
                print(f"Warning: Could not load CANopen node from project: {e}")

        config_from_file = data.get("can_config", {})
        hydrated_config = {}
        param_defs = interface_manager.get_interface_params(project.can_interface)

        if param_defs:
            for key, value in config_from_file.items():
                if key not in param_defs:
                    hydrated_config[key] = value
                    continue

                param_info = param_defs[key]
                expected_type = param_info.get("type")
                is_enum = False
                try:
                    if inspect.isclass(expected_type) and issubclass(
                        expected_type, enum.Enum
                    ):
                        is_enum = True
                except TypeError:
                    pass

                if is_enum and isinstance(value, str):
                    try:
                        hydrated_config[key] = expected_type[value]
                    except KeyError:
                        hydrated_config[key] = param_info.get("default")
                else:
                    hydrated_config[key] = value
        else:
            hydrated_config = config_from_file

        project.can_config = hydrated_config
        project.filters = [
            CANFrameFilter(**f_data) for f_data in data.get("filters", [])
        ]
        for dbc_data in data.get("dbcs", []):
            try:
                path = Path(dbc_data["path"])
                if not path.exists():
                    raise FileNotFoundError(f"DBC file not found: {path}")
                db = cantools.database.load_file(path)
                project.dbcs.append(DBCFile(path, db, dbc_data.get("enabled", True)))
            except Exception as e:
                print(f"Warning: Could not load DBC from project file: {e}")
        return project


class LogCaptureHandler(logging.Handler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []

    def emit(self, record):
        self.records.append(record)


@contextmanager
def capture_logs(logger_name: str):
    log_handler = LogCaptureHandler()
    target_logger = logging.getLogger(logger_name)
    original_handlers = target_logger.handlers[:]
    original_level = target_logger.level
    try:
        target_logger.handlers.clear()
        target_logger.addHandler(log_handler)
        target_logger.setLevel(logging.WARNING)
        yield log_handler
    finally:
        target_logger.handlers = original_handlers
        target_logger.setLevel(original_level)


class CANInterfaceManager:
    def __init__(self):
        self._interfaces = self._discover_interfaces()

    def _discover_interfaces(self):
        interfaces = {}
        for name, (module_name, class_name) in can.interfaces.BACKENDS.items():
            try:
                parsed_doc_dict = {}
                with capture_logs("can") as log_handler:
                    module = importlib.import_module(module_name)
                    bus_class = getattr(module, class_name)
                    if log_handler.records:
                        continue
                sig = inspect.signature(bus_class.__init__)
                params = {}
                for param in sig.parameters.values():
                    if param.name in ["self", "args", "kwargs", "receive_own_messages"]:
                        continue
                    param_info = {
                        "default": param.default
                        if param.default is not inspect.Parameter.empty
                        else None,
                        "type": param.annotation
                        if param.annotation is not inspect.Parameter.empty
                        else type(param.default),
                    }
                    params[param.name] = param_info
                interfaces[name] = {"class": bus_class, "params": params}
            except (ImportError, AttributeError, OSError, TypeError) as e:
                print(f"Info: Skipping interface '{name}' due to error on load: {e}")
            except Exception as e:
                print(f"Warning: Could not load or inspect CAN interface '{name}': {e}")

        return dict(sorted(interfaces.items()))

    def get_available_interfaces(self) -> List[str]:
        return list(self._interfaces.keys())

    def get_interface_params(self, name: str) -> Optional[Dict]:
        return self._interfaces.get(name, {}).get("params")


class CANopenDecoder:
    @staticmethod
    def decode(frame: CANFrame) -> Optional[Dict]:
        cob_id = frame.arbitration_id
        if cob_id == 0x000:
            return CANopenDecoder._nmt(frame.data)
        if cob_id == 0x080:
            return CANopenDecoder._sync()
        if cob_id == 0x100:
            return CANopenDecoder._time(frame.data)
        node_id = cob_id & 0x7F
        if node_id == 0:
            return None
        function_code = cob_id & 0x780
        if function_code == 0x80:
            return CANopenDecoder._emcy(frame.data, node_id)
        if function_code in [0x180, 0x280, 0x380, 0x480]:
            return CANopenDecoder._pdo("TX", function_code, node_id)
        if function_code in [0x200, 0x300, 0x400, 0x500]:
            return CANopenDecoder._pdo("RX", function_code, node_id)
        if function_code == 0x580:
            return CANopenDecoder._sdo("TX", frame.data, node_id)
        if function_code == 0x600:
            return CANopenDecoder._sdo("RX", frame.data, node_id)
        if function_code == 0x700:
            return CANopenDecoder._heartbeat(frame.data, node_id)
        return None

    @staticmethod
    def _nmt(data: bytes) -> Dict:
        if len(data) != 2:
            return None
        cs_map = {
            1: "Start",
            2: "Stop",
            128: "Pre-Operational",
            129: "Reset Node",
            130: "Reset Comm",
        }
        cs, nid = data[0], data[1]
        target = f"Node {nid}" if nid != 0 else "All Nodes"
        return {
            "CANopen Type": "NMT",
            "Command": cs_map.get(cs, "Unknown"),
            "Target": target,
        }

    @staticmethod
    def _sync() -> Dict:
        return {"CANopen Type": "SYNC"}

    @staticmethod
    def _time(data: bytes) -> Dict:
        return {"CANopen Type": "TIME", "Raw": data.hex(" ")}

    @staticmethod
    def _emcy(data: bytes, node_id: int) -> Dict:
        if len(data) != 8:
            return {
                "CANopen Type": "EMCY",
                "CANopen Node": node_id,
                "Error": "Invalid Length",
            }
        err_code, err_reg, _ = struct.unpack("<H B 5s", data)
        return {
            "CANopen Type": "EMCY",
            "CANopen Node": node_id,
            "Code": f"0x{err_code:04X}",
            "Register": f"0x{err_reg:02X}",
        }

    @staticmethod
    def _pdo(direction: str, function_code: int, node_id: int) -> Dict:
        pdo_num = (
            ((function_code - 0x180) // 0x100 + 1)
            if direction == "TX"
            else ((function_code - 0x200) // 0x100 + 1)
        )
        return {"CANopen Type": f"PDO{pdo_num} {direction}", "CANopen Node": node_id}

    @staticmethod
    def _sdo(direction: str, data: bytes, node_id: int) -> Dict:
        if not data:
            return None
        cmd, specifier = data[0], (data[0] >> 5) & 0x7
        base_info = {"CANopen Type": f"SDO {direction}", "CANopen Node": node_id}
        if specifier in [1, 2]:
            if len(data) < 4:
                return {**base_info, "Error": "Invalid SDO Initiate"}
            command = "Initiate Upload" if specifier == 1 else "Initiate Download"
            idx, sub = struct.unpack_from("<HB", data, 1)
            base_info.update(
                {"Command": command, "Index": f"0x{idx:04X}", "Sub-Index": sub}
            )
        elif specifier in [0, 3]:
            base_info.update(
                {"Command": "Segment " + ("Upload" if specifier == 3 else "Download")}
            )
        elif specifier == 4:
            if len(data) < 8:
                return {**base_info, "Error": "Invalid SDO Abort"}
            idx, sub, code = struct.unpack_from("<HBL", data, 1)
            base_info.update(
                {
                    "Command": "Abort",
                    "Index": f"0x{idx:04X}",
                    "Sub-Index": sub,
                    "Code": f"0x{code:08X}",
                }
            )
        else:
            base_info.update({"Command": f"Unknown ({cmd:#04x})"})
        return base_info

    @staticmethod
    def _heartbeat(data: bytes, node_id: int) -> Dict:
        if len(data) != 1:
            return None
        state_map = {
            0: "Boot-up",
            4: "Stopped",
            5: "Operational",
            127: "Pre-operational",
        }
        state = data[0] & 0x7F
        return {
            "CANopen Type": "Heartbeat",
            "CANopen Node": node_id,
            "State": state_map.get(state, f"Unknown ({state})"),
        }


# --- Models ---
class CANTraceModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self.headers = ["Timestamp", "ID", "Type", "DLC", "Data", "Decoded"]
        self.frames: deque[CANFrame] = deque(maxlen=10000)
        self.dbc_databases: List[object] = []
        self.pdo_databases: List[object] = []  # Add PDO databases
        self.canopen_enabled = True

    def set_data(self, frames: List[CANFrame]):
        self.beginResetModel()
        self.frames.clear()
        self.frames.extend(frames)
        self.endResetModel()

    def set_config(self, dbs: List[object], co_enabled: bool, pdo_dbs: List[object] = None):
        self.dbc_databases = dbs
        self.canopen_enabled = co_enabled
        self.pdo_databases = pdo_dbs or []  # Set PDO databases
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
        decoded_parts = []
        
        # Try DBC databases first
        for db in self.dbc_databases:
            try:
                message = db.get_message_by_frame_id(frame.arbitration_id)
                decoded = db.decode_message(
                    frame.arbitration_id, frame.data, decode_choices=False
                )
                s = [f"{n}={v}" for n, v in decoded.items()]
                decoded_parts.append(f"DBC: {message.name} {' '.join(s)}")
                return " | ".join(decoded_parts)
            except (KeyError, ValueError):
                continue
        
        # Try PDO databases
        for db in self.pdo_databases:
            try:
                message = db.get_message_by_frame_id(frame.arbitration_id)
                decoded = db.decode_message(
                    frame.arbitration_id, frame.data, decode_choices=False
                )
                s = [f"{n}={v}" for n, v in decoded.items()]
                decoded_parts.append(f"PDO: {message.name} {' '.join(s)}")
                return " | ".join(decoded_parts)
            except (KeyError, ValueError):
                continue
        
        # Fallback to CANopen decoding
        if self.canopen_enabled:
            if co_info := CANopenDecoder.decode(frame):
                details = ", ".join(
                    f"{k}={v}" for k, v in co_info.items() if k != "CANopen Type"
                )
                decoded_parts.append(f"CANopen {co_info['CANopen Type']}: {details}")
        
        return " | ".join(decoded_parts)


class CANGroupedModel(QAbstractItemModel):
    def __init__(self):
        super().__init__()
        self.headers = ["ID", "Name", "Count", "Cycle Time", "DLC", "Data"]
        self.top_level_items: List[DisplayItem] = []
        self.dbc_databases: List[object] = []
        self.canopen_enabled = True
        self.frame_counts = {}
        self.timestamps = {}
        self.item_map = {}

    def set_config(self, dbs: List[object], co_enabled: bool):
        self.dbc_databases = dbs
        self.canopen_enabled = co_enabled
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
        if self.canopen_enabled and CANopenDecoder.decode(item.data_source):
            return True
        for db in self.dbc_databases:
            try:
                if db.get_message_by_frame_id(item.data_source.arbitration_id):
                    return True
            except KeyError:
                continue
        return False

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
            DisplayItem(p, s, True, row_in_parent=i) for i, s in enumerate(signals)
        ]
        item.children_populated = True
        self.endInsertRows()

    def _decode_frame_to_signals(self, frame: CANFrame) -> List[Dict]:
        sigs = []
        if self.canopen_enabled:
            if co_info := CANopenDecoder.decode(frame):
                sigs += [
                    {"name": k, "value": v, "unit": ""} for k, v in co_info.items()
                ]
        for db in self.dbc_databases:
            try:
                msg_def = db.get_message_by_frame_id(frame.arbitration_id)
                decoded = db.decode_message(
                    frame.arbitration_id, frame.data, decode_choices=False
                )
                sigs += [
                    {
                        "name": s.name,
                        "value": decoded.get(s.name, "N/A"),
                        "unit": s.unit or "",
                    }
                    for s in msg_def.signals
                ]
                break
            except (KeyError, ValueError):
                continue
        return sigs

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
                    item.children.clear()
                    item.children_populated = False
        self.endResetModel()

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
            if col == 5:
                return f"{sig['value']}"
        else:
            frame: CANFrame = item.data_source
            can_id = frame.arbitration_id
            if col == 0:
                return f"0x{can_id:X}"
            if col == 1:
                for db in self.dbc_databases:
                    try:
                        return db.get_message_by_frame_id(can_id).name
                    except KeyError:
                        pass
                return ""
            if col == 2:
                return str(self.frame_counts.get(can_id, 0))
            if col == 3:
                ts_list = self.timestamps.get(can_id, [])
                if len(ts_list) > 1:
                    return f"{sum(ts_list[i] - ts_list[i - 1] for i in range(1, len(ts_list))) / (len(ts_list) - 1) * 1000:.1f} ms"
                return "-"
            if col == 4:
                return str(frame.dlc)
            if col == 5:
                return frame.data.hex(" ")
        return None


# --- CAN Communication ---
class CANReaderThread(QThread):
    frame_received = Signal(object)
    error_occurred = Signal(str)
    send_frame = Signal(object)

    def __init__(self, interface: str, config: Dict[str, Any]):
        super().__init__()
        self.interface = interface
        self.config = config
        self.running = False
        self.bus = None
        self.daemon = True
        self.send_frame.connect(self._send_frame_internal)

    def _send_frame_internal(self, message):
        if self.bus and self.running:
            try:
                self.bus.send(message)
            except Exception as e:
                self.error_occurred.emit(f"Send error: {e}")

    def start_reading(self):
        self.running = True
        self.start()
        return True

    def stop_reading(self):
        self.running = False
        self.wait(3000)

    def run(self):
        try:
            self.bus = can.Bus(
                interface=self.interface, receive_own_messages=True, **self.config
            )
            while self.running:
                msg = self.bus.recv(timeout=0.1)
                if msg and self.running:
                    frame = CANFrame(
                        msg.timestamp,
                        msg.arbitration_id,
                        msg.data,
                        msg.dlc,
                        msg.is_extended_id,
                        msg.is_error_frame,
                        msg.is_remote_frame,
                    )
                    self.frame_received.emit(frame)
        except can.CanOperationError as e:
            if self.running:
                self.error_occurred.emit(
                    f"CAN bus error: {e}\n\nCheck connection settings and hardware."
                )
        except Exception as e:
            if self.running:
                self.error_occurred.emit(f"CAN reader error: {e}")
        finally:
            if self.bus:
                try:
                    self.bus.shutdown()
                except Exception as e:
                    print(f"Error shutting down CAN bus: {e}")
                finally:
                    self.bus = None


# --- UI Classes ---
class DBCEditor(QWidget):
    def __init__(self, dbc_file: DBCFile):
        super().__init__()
        self.dbc_file = dbc_file
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        group = QGroupBox(f"DBC Content: {self.dbc_file.path.name}")
        layout = QVBoxLayout(group)
        main_layout.addWidget(group)
        self.table = QTableWidget()
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Message", "ID (hex)", "DLC", "Signals"])
        layout.addWidget(self.table)
        self.populate_table()
        self.table.resizeColumnsToContents()

    def populate_table(self):
        messages = sorted(self.dbc_file.database.messages, key=lambda m: m.frame_id)
        self.table.setRowCount(len(messages))
        for r, m in enumerate(messages):
            self.table.setItem(r, 0, QTableWidgetItem(m.name))
            self.table.setItem(r, 1, QTableWidgetItem(f"0x{m.frame_id:X}"))
            self.table.setItem(r, 2, QTableWidgetItem(str(m.length)))
            self.table.setItem(
                r, 3, QTableWidgetItem(", ".join(s.name for s in m.signals))
            )


class FilterEditor(QWidget):
    filter_changed = Signal()

    def __init__(self, can_filter: CANFrameFilter):
        super().__init__()
        self.filter = can_filter
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        group = QGroupBox("Filter Properties")
        layout = QFormLayout(group)
        main_layout.addWidget(group)
        self.name_edit = QLineEdit(self.filter.name)
        layout.addRow("Name:", self.name_edit)
        id_layout = QHBoxLayout()
        self.min_id_edit = QLineEdit(f"0x{self.filter.min_id:X}")
        self.max_id_edit = QLineEdit(f"0x{self.filter.max_id:X}")
        self.mask_edit = QLineEdit(f"0x{self.filter.mask:X}")
        id_layout.addWidget(QLabel("Min:"))
        id_layout.addWidget(self.min_id_edit)
        id_layout.addWidget(QLabel("Max:"))
        id_layout.addWidget(self.max_id_edit)
        id_layout.addWidget(QLabel("Mask:"))
        id_layout.addWidget(self.mask_edit)
        layout.addRow("ID (hex):", id_layout)
        self.standard_cb = QCheckBox("Standard")
        self.standard_cb.setChecked(self.filter.accept_standard)
        self.extended_cb = QCheckBox("Extended")
        self.extended_cb.setChecked(self.filter.accept_extended)
        self.data_cb = QCheckBox("Data")
        self.data_cb.setChecked(self.filter.accept_data)
        self.remote_cb = QCheckBox("Remote")
        self.remote_cb.setChecked(self.filter.accept_remote)
        type_layout = QHBoxLayout()
        type_layout.addWidget(self.standard_cb)
        type_layout.addWidget(self.extended_cb)
        type_layout.addWidget(self.data_cb)
        type_layout.addWidget(self.remote_cb)
        type_layout.addStretch()
        layout.addRow("Frame Types:", type_layout)
        self.name_edit.editingFinished.connect(self._update_filter)
        [
            w.editingFinished.connect(self._update_filter)
            for w in [self.min_id_edit, self.max_id_edit, self.mask_edit]
        ]
        [
            cb.toggled.connect(self._update_filter)
            for cb in [self.standard_cb, self.extended_cb, self.data_cb, self.remote_cb]
        ]

    def _update_filter(self):
        self.filter.name = self.name_edit.text()
        try:
            self.filter.min_id = int(self.min_id_edit.text(), 16)
        except ValueError:
            self.min_id_edit.setText(f"0x{self.filter.min_id:X}")
        try:
            self.filter.max_id = int(self.max_id_edit.text(), 16)
        except ValueError:
            self.max_id_edit.setText(f"0x{self.filter.max_id:X}")
        try:
            self.filter.mask = int(self.mask_edit.text(), 16)
        except ValueError:
            self.mask_edit.setText(f"0x{self.filter.mask:X}")
        self.filter.accept_standard = self.standard_cb.isChecked()
        self.filter.accept_extended = self.extended_cb.isChecked()
        self.filter.accept_data = self.data_cb.isChecked()
        self.filter.accept_remote = self.remote_cb.isChecked()
        self.filter_changed.emit()


class ConnectionEditor(QWidget):
    project_changed = Signal()

    def __init__(self, project: Project, interface_manager: CANInterfaceManager):
        super().__init__()
        self.project = project
        self.interface_manager = interface_manager
        self.dynamic_widgets = {}
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        group = QGroupBox("Connection Properties")
        self.form_layout = QFormLayout(group)
        main_layout.addWidget(group)
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.interface_manager.get_available_interfaces())
        self.form_layout.addRow("Interface:", self.interface_combo)
        self.dynamic_fields_container = QWidget()
        self.dynamic_layout = QFormLayout(self.dynamic_fields_container)
        self.dynamic_layout.setContentsMargins(0, 0, 0, 0)
        self.form_layout.addRow(self.dynamic_fields_container)
        self.interface_combo.currentTextChanged.connect(self._on_interface_changed)
        self.interface_combo.setCurrentText(self.project.can_interface)
        self._rebuild_dynamic_fields(self.project.can_interface)

    def _on_interface_changed(self, interface_name: str):
        self.project.can_interface = interface_name
        self.project.can_config.clear()
        self._rebuild_dynamic_fields(interface_name)

    def _rebuild_dynamic_fields(self, interface_name: str):
        while self.dynamic_layout.count():
            item = self.dynamic_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.dynamic_widgets.clear()
        params = self.interface_manager.get_interface_params(interface_name)
        if not params:
            self._update_project()
            return
        for name, info in params.items():
            default_value = self.project.can_config.get(name, info.get("default"))
            expected_type = info["type"]
            widget = None
            is_enum = False
            try:
                if inspect.isclass(expected_type) and issubclass(
                    expected_type, enum.Enum
                ):
                    is_enum = True
            except TypeError:
                pass
            if is_enum:
                widget = QComboBox()
                widget.setProperty("enum_class", expected_type)
                widget.addItems([m.name for m in list(expected_type)])
                current_value = default_value
                if isinstance(current_value, enum.Enum):
                    widget.setCurrentText(current_value.name)
                elif isinstance(current_value, str):
                    widget.setCurrentText(current_value)
                widget.currentTextChanged.connect(self._update_project)
            elif expected_type is bool:
                widget = QCheckBox()
                widget.setChecked(
                    bool(default_value) if default_value is not None else False
                )
                widget.toggled.connect(self._update_project)
            elif name == "bitrate" and expected_type is int:
                widget = QSpinBox()
                widget.setRange(1000, 4000000)
                widget.setSuffix(" bps")
                widget.setValue(
                    int(default_value) if default_value is not None else 125000
                )
                widget.valueChanged.connect(self._update_project)
            else:
                widget = QLineEdit()
                widget.setText(str(default_value) if default_value is not None else "")
                widget.editingFinished.connect(self._update_project)
            if widget:
                label_text = f"{name.replace('_', ' ').title()}:"
                self.dynamic_layout.addRow(label_text, widget)
                self.dynamic_widgets[name] = widget
        self._update_project()

    def _convert_line_edit_text(self, text: str, param_info: Dict) -> Any:
        text = text.strip()
        expected_type, default_value = param_info.get("type"), param_info.get("default")
        if not text and default_value is None:
            return None
        if expected_type is int:
            try:
                return int(text)
            except ValueError:
                return int(text, 16)
        elif expected_type is float:
            return float(text)
        elif expected_type is bool:
            return text.lower() in ("true", "1", "t", "yes", "y")
        return text

    def _update_project(self):
        config = {}
        params = (
            self.interface_manager.get_interface_params(self.project.can_interface)
            or {}
        )
        for name, widget in self.dynamic_widgets.items():
            param_info = params.get(name)
            if not param_info:
                continue
            value = None
            try:
                if isinstance(widget, QCheckBox):
                    value = widget.isChecked()
                elif isinstance(widget, QSpinBox):
                    value = widget.value()
                elif isinstance(widget, QComboBox):
                    enum_class = widget.property("enum_class")
                    if enum_class:
                        value = enum_class[widget.currentText()]
                elif isinstance(widget, QLineEdit):
                    value = self._convert_line_edit_text(widget.text(), param_info)
            except (ValueError, TypeError, KeyError) as e:
                print(
                    f"Warning: Could not get value for '{name}'. Invalid input. Error: {e}"
                )
                continue
            config[name] = value
        self.project.can_interface = self.interface_combo.currentText()
        self.project.can_config = config
        self.project_changed.emit()


class CANopenNodeEditor(QWidget):
    node_changed = Signal()

    def __init__(self, node: CANopenNode):
        super().__init__()
        self.node = node
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        group = QGroupBox("CANopen Node Properties")
        layout = QFormLayout(group)
        main_layout.addWidget(group)
        path_edit = QLineEdit(str(self.node.path))
        path_edit.setReadOnly(True)
        layout.addRow("EDS/DCF File:", path_edit)
        self.node_id_spinbox = QSpinBox()
        self.node_id_spinbox.setRange(1, 127)
        self.node_id_spinbox.setValue(self.node.node_id)
        layout.addRow("Node ID:", self.node_id_spinbox)
        self.node_id_spinbox.valueChanged.connect(self._update_node)
        
        # Add PDO decoding checkbox
        self.pdo_decoding_cb = QCheckBox("Enable PDO Decoding")
        self.pdo_decoding_cb.setChecked(self.node.pdo_decoding_enabled)
        self.pdo_decoding_cb.setToolTip("Decode PDO messages using EDS/DCF file")
        layout.addRow(self.pdo_decoding_cb)
        self.pdo_decoding_cb.toggled.connect(self._update_node)

    def _update_node(self):
        self.node.node_id = self.node_id_spinbox.value()
        self.node.pdo_decoding_enabled = self.pdo_decoding_cb.isChecked()  # Update PDO setting
        self.node_changed.emit()


class ScanWorker(QObject):
    finished = Signal()
    error = Signal(str)

    def __init__(self, network: canopen.Network):
        super().__init__()
        self.network = network

    def run(self):
        try:
            self.network.scanner.search()
            self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))


class CANopenRootEditor(QWidget):
    settings_changed = Signal()

    def __init__(self, project: Project, network: canopen.Network):
        super().__init__()
        self.project = project
        self.network = network
        self.scan_thread = None
        self.scan_worker = None
        self.passive_scan_timer = QTimer(self)
        self.passive_scan_timer.setInterval(1000)
        self.passive_scan_timer.timeout.connect(self._update_discovered_nodes)
        self.last_known_nodes = set()
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        group = QGroupBox("CANopen Settings")
        layout = QFormLayout(group)
        main_layout.addWidget(group)
        self.enabled_cb = QCheckBox("Enable CANopen Processing")
        self.enabled_cb.setChecked(self.project.canopen_enabled)
        layout.addRow(self.enabled_cb)
        scan_group = QGroupBox("Node Discovery")
        scan_layout = QVBoxLayout(scan_group)
        passive_layout = QFormLayout()
        self.discovery_status_label = QLabel("Disconnected")
        passive_layout.addRow("Status:", self.discovery_status_label)
        discovered_nodes_layout = QHBoxLayout()
        self.discovered_nodes_text = QLineEdit()
        self.discovered_nodes_text.setReadOnly(True)
        self.discovered_nodes_text.setPlaceholderText("No nodes detected")
        self.clear_nodes_button = QPushButton("Clear")
        discovered_nodes_layout.addWidget(self.discovered_nodes_text)
        discovered_nodes_layout.addWidget(self.clear_nodes_button)
        passive_layout.addRow("Discovered Nodes:", discovered_nodes_layout)
        scan_layout.addLayout(passive_layout)
        self.active_scan_button = QPushButton("Actively Scan for Nodes")
        scan_layout.addWidget(self.active_scan_button)
        layout.addRow(scan_group)
        self.enabled_cb.toggled.connect(self._update_settings)
        self.active_scan_button.clicked.connect(self._start_active_scan)
        self.clear_nodes_button.clicked.connect(self._clear_discovered_nodes)

    def set_connection_status(self, is_connected: bool):
        self.active_scan_button.setEnabled(is_connected)
        self.clear_nodes_button.setEnabled(is_connected)
        if is_connected:
            self.discovery_status_label.setText("Passively Listening...")
            self.passive_scan_timer.start()
        else:
            self.discovery_status_label.setText("Disconnected")
            self.passive_scan_timer.stop()
            self._clear_discovered_nodes()

    def _update_settings(self):
        self.project.canopen_enabled = self.enabled_cb.isChecked()
        self.settings_changed.emit()

    def _clear_discovered_nodes(self):
        if self.network.bus:
            self.network.scanner.reset()
        self.last_known_nodes.clear()
        self.discovered_nodes_text.clear()

    def _update_discovered_nodes(self):
        if not self.network.bus:
            return
        current_nodes = set(self.network.scanner.nodes)
        if current_nodes != self.last_known_nodes:
            self.last_known_nodes = current_nodes
            self.discovered_nodes_text.setText(
                ", ".join(map(str, sorted(list(current_nodes))))
            )

    def _start_active_scan(self):
        # Check if a scan is already running by checking the thread object
        if self.scan_thread is not None:
            return

        self.active_scan_button.setEnabled(False)
        self.discovery_status_label.setText("Actively Scanning...")

        self.scan_thread = QThread()
        self.scan_worker = ScanWorker(self.network)
        self.scan_worker.moveToThread(self.scan_thread)

        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_worker.finished.connect(self.on_active_scan_finished)
        self.scan_worker.error.connect(self.on_active_scan_error)

        # Proper cleanup
        self.scan_worker.finished.connect(self.scan_worker.deleteLater)
        self.scan_thread.finished.connect(
            self._on_scan_thread_finished
        )  # Use our cleanup slot

        self.scan_thread.start()

    def _on_scan_thread_finished(self):
        """Slot to safely clean up the thread and worker objects."""
        if self.scan_thread:
            self.scan_thread.deleteLater()
        self.scan_thread = None
        self.scan_worker = None

    def on_active_scan_finished(self):
        self.active_scan_button.setEnabled(True)
        self.discovery_status_label.setText("Passively Listening...")
        QTimer.singleShot(250, self._update_discovered_nodes)
        # Now that the worker's job is done, we can quit the thread
        if self.scan_thread:
            self.scan_thread.quit()

    def on_active_scan_error(self, error_msg: str):
        self.active_scan_button.setEnabled(True)
        self.discovery_status_label.setText("Active scan error!")
        QMessageBox.warning(
            self, "Scan Error", f"An error occurred during active scan:\n{error_msg}"
        )
        # Quit the thread on error too
        if self.scan_thread:
            self.scan_thread.quit()


class PropertiesPanel(QWidget):
    def __init__(
        self,
        project: Project,
        explorer: "ProjectExplorer",
        interface_manager: "CANInterfaceManager",
        main_window: "CANBusObserver",
    ):
        super().__init__()
        self.project = project
        self.explorer = explorer
        self.interface_manager = interface_manager
        self.main_window = main_window
        self.current_widget = None
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.placeholder = QLabel("Select an item to see its properties.")
        self.placeholder.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.placeholder)

    def show_properties(self, item: QTreeWidgetItem):
        self.clear()
        data = item.data(0, Qt.UserRole) if item else None
        if data == "connection_settings":
            editor = ConnectionEditor(self.project, self.interface_manager)
            editor.project_changed.connect(self.explorer.rebuild_tree)
            self.current_widget = editor
        elif data == "canopen_root":
            editor = CANopenRootEditor(self.project, self.main_window.canopen_network)
            editor.settings_changed.connect(self.explorer.rebuild_tree)
            is_connected = (
                self.main_window.can_reader is not None
                and self.main_window.can_reader.isRunning()
            )
            editor.set_connection_status(is_connected)
            self.current_widget = editor
        elif isinstance(data, CANopenNode):
            editor = CANopenNodeEditor(data)
            editor.node_changed.connect(self.explorer.rebuild_tree)
            editor.node_changed.connect(self.explorer.project_changed.emit)
            self.current_widget = editor
        elif isinstance(data, CANFrameFilter):
            editor = FilterEditor(data)
            editor.filter_changed.connect(lambda: item.setText(0, data.name))
            editor.filter_changed.connect(self.explorer.project_changed.emit)
            self.current_widget = editor
        elif isinstance(data, DBCFile):
            self.current_widget = DBCEditor(data)
        else:
            self.layout.addWidget(self.placeholder)
            self.placeholder.show()
            return
        self.layout.addWidget(self.current_widget)

    def clear(self):
        if self.current_widget:
            self.current_widget.deleteLater()
            self.current_widget = None
        self.placeholder.hide()


class ProjectExplorer(QGroupBox):
    project_changed = Signal()

    def __init__(self, project: Project, main_window: "CANBusObserver"):
        super().__init__("Project Explorer")
        self.project = project
        self.main_window = main_window
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        layout.addWidget(self.tree)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.open_context_menu)
        self.tree.itemChanged.connect(self.on_item_changed)
        self.rebuild_tree()

    def set_project(self, project: Project):
        self.project = project
        self.rebuild_tree()

    def rebuild_tree(self):
        self.tree.blockSignals(True)
        expanded_items_data = set()
        for i in range(self.tree.topLevelItemCount()):
            root_item = self.tree.topLevelItem(i)
            if root_item.isExpanded():
                expanded_items_data.add(root_item.data(0, Qt.UserRole))
        self.tree.clear()
        self.add_item(
            None, f"Connection ({self.project.can_interface})", "connection_settings"
        )
        self.dbc_root = self.add_item(None, "Symbol Files (.dbc)", "dbc_root")
        [
            self.add_item(self.dbc_root, dbc.path.name, dbc, dbc.enabled)
            for dbc in self.project.dbcs
        ]
        self.filter_root = self.add_item(None, "Message Filters", "filter_root")
        [
            self.add_item(self.filter_root, f.name, f, f.enabled)
            for f in self.project.filters
        ]
        self.co_root = self.add_item(None, "CANopen", "canopen_root")
        [
            self.add_item(
                self.co_root,
                f"{node.path.name} [ID: {node.node_id}]",
                node,
                node.enabled,
            )
            for node in self.project.canopen_nodes
        ]
        for i in range(self.tree.topLevelItemCount()):
            root_item = self.tree.topLevelItem(i)
            if root_item.data(0, Qt.UserRole) in expanded_items_data:
                root_item.setExpanded(True)
        self.tree.blockSignals(False)
        self.project_changed.emit()

    def add_item(self, parent, text, data=None, checked=None):
        item = QTreeWidgetItem(parent or self.tree, [text])
        if data:
            item.setData(0, Qt.UserRole, data)
        if checked is not None:
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(0, Qt.Checked if checked else Qt.Unchecked)
        return item

    def on_item_changed(self, item, column):
        if data := item.data(0, Qt.UserRole):
            if isinstance(data, (DBCFile, CANFrameFilter, CANopenNode)):
                data.enabled = item.checkState(0) == Qt.Checked
            self.project_changed.emit()

    def open_context_menu(self, position):
        menu = QMenu()
        item = self.tree.itemAt(position)
        data = item.data(0, Qt.UserRole) if item else None
        if data in [None, "dbc_root"]:
            menu.addAction("Add Symbol File...").triggered.connect(self.add_dbc)
        if data in [None, "filter_root"]:
            menu.addAction("Add Filter").triggered.connect(self.add_filter)
        if data in [None, "canopen_root"]:
            menu.addAction("Add Node from EDS/DCF...").triggered.connect(
                self.add_canopen_node
            )
        if item and item.parent():
            menu.addAction("Remove").triggered.connect(lambda: self.remove_item(item))
        if menu.actions():
            menu.exec(self.tree.viewport().mapToGlobal(position))

    def add_dbc(self):
        fns, _ = QFileDialog.getOpenFileNames(
            self,
            "Select DBC File(s)",
            "",
            "DBC, KCD, SYM, ARXML 3&4 and CDD Files (*.dbc *.arxml *.kcd *.sym *.cdd);;All Files (*)",
        )
        if fns:
            for fn in fns:
                try:
                    self.project.dbcs.append(
                        DBCFile(Path(fn), cantools.database.load_file(fn))
                    )
                except Exception as e:
                    QMessageBox.critical(
                        self, "DBC Load Error", f"Failed to load {Path(fn).name}: {e}"
                    )
            self.rebuild_tree()

    def add_filter(self):
        self.project.filters.append(
            CANFrameFilter(name=f"Filter {len(self.project.filters) + 1}")
        )
        self.rebuild_tree()

    def remove_item(self, item):
        if data := item.data(0, Qt.UserRole):
            if isinstance(data, DBCFile):
                self.project.dbcs.remove(data)
            elif isinstance(data, CANFrameFilter):
                self.project.filters.remove(data)
            elif isinstance(data, CANopenNode):
                self.project.canopen_nodes.remove(data)
            self.rebuild_tree()

    def add_canopen_node(self):
        fns, _ = QFileDialog.getOpenFileNames(
            self,
            "Select EDS/DCF File(s)",
            "",
            "CANopen Object Dictionary (*.eds *.dcf);;All Files (*)",
        )
        if fns:
            for fn in fns:
                self.project.canopen_nodes.append(CANopenNode(path=Path(fn), node_id=1))
            self.rebuild_tree()


class TransmitPanel(QGroupBox):
    frame_to_send = Signal(object)
    row_selection_changed = Signal(int, str)
    config_changed = Signal()

    def __init__(self):
        super().__init__("Transmit")
        self.timers: Dict[int, QTimer] = {}
        self.dbcs: List[object] = []
        self.setup_ui()
        self.setEnabled(False)

    def set_dbc_databases(self, dbs):
        self.dbcs = dbs

    def get_message_from_id(self, can_id):
        for db in self.dbcs:
            try:
                return db.get_message_by_frame_id(can_id)
            except KeyError:
                continue

    def setup_ui(self):
        layout = QVBoxLayout(self)
        ctrl_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add")
        self.rem_btn = QPushButton("Remove")
        ctrl_layout.addWidget(self.add_btn)
        ctrl_layout.addWidget(self.rem_btn)
        ctrl_layout.addStretch()
        layout.addLayout(ctrl_layout)
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(
            ["On", "ID(hex)", "Type", "RTR", "DLC", "Data(hex)", "Cycle", "Send"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.table)
        self.add_btn.clicked.connect(self.add_frame)
        self.rem_btn.clicked.connect(self.remove_frames)
        self.table.currentItemChanged.connect(self._on_item_changed)
        self.table.cellChanged.connect(self._on_cell_changed)

    def add_frame(self):
        r = self.table.rowCount()
        self.table.insertRow(r)
        self._setup_row_widgets(r)
        self.config_changed.emit()

    def remove_frames(self):
        if self.table.selectionModel().selectedRows():
            [
                self.table.removeRow(r)
                for r in sorted(
                    [i.row() for i in self.table.selectionModel().selectedRows()],
                    reverse=True,
                )
            ]
            self.config_changed.emit()

    def _setup_row_widgets(self, r):
        self.table.setItem(r, 1, QTableWidgetItem("100"))
        combo = QComboBox()
        combo.addItems(["Std", "Ext"])
        self.table.setCellWidget(r, 2, combo)
        self.table.setItem(r, 4, QTableWidgetItem("0"))
        self.table.setItem(r, 5, QTableWidgetItem(""))
        self.table.setItem(r, 6, QTableWidgetItem("100"))
        btn = QPushButton("Send")
        btn.clicked.connect(partial(self.send_from_row, r))
        self.table.setCellWidget(r, 7, btn)
        cb_on = QCheckBox()
        cb_on.toggled.connect(partial(self._toggle_periodic, r))
        self.table.setCellWidget(r, 0, self._center(cb_on))
        cb_rtr = QCheckBox()
        self.table.setCellWidget(r, 3, self._center(cb_rtr))
        combo.currentIndexChanged.connect(self.config_changed.emit)
        cb_rtr.toggled.connect(self.config_changed.emit)

    def _center(self, w):
        c = QWidget()
        layout = QHBoxLayout(c)
        layout.addWidget(w)
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(0, 0, 0, 0)
        return c

    def _on_item_changed(self, curr, prev):
        if curr and (not prev or curr.row() != prev.row()):
            self.row_selection_changed.emit(
                curr.row(), self.table.item(curr.row(), 1).text()
            )

    def _on_cell_changed(self, r, c):
        self.config_changed.emit()
        if c == 1:
            self.row_selection_changed.emit(r, self.table.item(r, 1).text())
        elif c == 5:
            self._update_dlc(r)

    def _update_dlc(self, r):
        try:
            self.table.item(r, 4).setText(
                str(len(bytes.fromhex(self.table.item(r, 5).text().replace(" ", ""))))
            )
        except (ValueError, TypeError):
            pass

    def update_row_data(self, r, data):
        self.table.blockSignals(True)
        self.table.item(r, 5).setText(data.hex(" "))
        self.table.item(r, 4).setText(str(len(data)))
        self.table.blockSignals(False)
        self.config_changed.emit()

    def _toggle_periodic(self, r, state):
        self.config_changed.emit()
        if state:
            try:
                cycle = int(self.table.item(r, 6).text())
                t = QTimer(self)
                t.timeout.connect(partial(self.send_from_row, r))
                t.start(cycle)
                self.timers[r] = t
            except (ValueError, TypeError):
                QMessageBox.warning(self, "Bad Cycle", f"Row {r + 1}: bad cycle time.")
                self.table.cellWidget(r, 0).findChild(QCheckBox).setChecked(False)
        elif r in self.timers:
            self.timers.pop(r).stop()

    def stop_all_timers(self):
        [t.stop() for t in self.timers.values()]
        self.timers.clear()
        [
            self.table.cellWidget(r, 0).findChild(QCheckBox).setChecked(False)
            for r in range(self.table.rowCount())
        ]

    def send_from_row(self, r):
        try:
            self.frame_to_send.emit(
                can.Message(
                    arbitration_id=int(self.table.item(r, 1).text(), 16),
                    is_extended_id=self.table.cellWidget(r, 2).currentIndex() == 1,
                    is_remote_frame=self.table.cellWidget(r, 3)
                    .findChild(QCheckBox)
                    .isChecked(),
                    dlc=int(self.table.item(r, 4).text()),
                    data=bytes.fromhex(self.table.item(r, 5).text().replace(" ", "")),
                )
            )
        except (ValueError, TypeError) as e:
            QMessageBox.warning(self, "Bad Tx Data", f"Row {r + 1}: {e}")
            self._toggle_periodic(r, False)

    def send_selected(self):
        [
            self.send_from_row(r)
            for r in sorted(
                {i.row() for i in self.table.selectionModel().selectedIndexes()}
            )
        ]

    def get_config(self) -> List[Dict]:
        return [
            {
                "on": self.table.cellWidget(r, 0).findChild(QCheckBox).isChecked(),
                "id": self.table.item(r, 1).text(),
                "type_idx": self.table.cellWidget(r, 2).currentIndex(),
                "rtr": self.table.cellWidget(r, 3).findChild(QCheckBox).isChecked(),
                "dlc": self.table.item(r, 4).text(),
                "data": self.table.item(r, 5).text(),
                "cycle": self.table.item(r, 6).text(),
            }
            for r in range(self.table.rowCount())
        ]

    def set_config(self, config: List[Dict]):
        self.stop_all_timers()
        self.table.clearContents()
        self.table.setRowCount(0)
        self.table.setRowCount(len(config))
        self.table.blockSignals(True)
        for r, row_data in enumerate(config):
            self._setup_row_widgets(r)
            self.table.cellWidget(r, 0).findChild(QCheckBox).setChecked(
                row_data.get("on", False)
            )
            self.table.item(r, 1).setText(row_data.get("id", "0"))
            self.table.cellWidget(r, 2).setCurrentIndex(row_data.get("type_idx", 0))
            self.table.cellWidget(r, 3).findChild(QCheckBox).setChecked(
                row_data.get("rtr", False)
            )
            self.table.item(r, 4).setText(row_data.get("dlc", "0"))
            self.table.item(r, 5).setText(row_data.get("data", ""))
            self.table.item(r, 6).setText(row_data.get("cycle", "100"))
        self.table.blockSignals(False)
        self.config_changed.emit()


class SignalTransmitPanel(QGroupBox):
    data_encoded = Signal(bytes)

    def __init__(self):
        super().__init__("Signal Config")
        self.message = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Signal", "Value", "Unit"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)
        self.table.cellChanged.connect(self._encode)

    def clear_panel(self):
        self.message = None
        self.table.setRowCount(0)
        self.setTitle("Signal Config")
        self.setVisible(False)

    def populate(self, msg):
        self.message = msg
        self.table.blockSignals(True)
        self.table.setRowCount(len(msg.signals))
        for r, s in enumerate(msg.signals):
            self.table.setItem(r, 0, QTableWidgetItem(s.name))
            self.table.item(r, 0).setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            self.table.setItem(
                r, 1, QTableWidgetItem(str(s.initial if s.initial is not None else 0))
            )
            self.table.setItem(r, 2, QTableWidgetItem(str(s.unit or "")))
            self.table.item(r, 2).setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        self.table.blockSignals(False)
        self.setTitle(f"Signal Config: {msg.name}")
        self.setVisible(True)
        self._encode()

    def _encode(self):
        if not self.message:
            return
        try:
            self.data_encoded.emit(
                self.message.encode(
                    {
                        self.table.item(r, 0).text(): float(
                            self.table.item(r, 1).text()
                        )
                        for r in range(self.table.rowCount())
                    },
                    strict=True,
                )
            )
        except (ValueError, TypeError, KeyError):
            pass


class ObjectDictionaryViewer(QWidget):
    """CANopen Object Dictionary Viewer with SDO read/write capabilities"""
    
    def __init__(self, canopen_network):
        super().__init__()
        self.canopen_network = canopen_network
        self.current_node = None
        self.current_node_id = None
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Node info header
        self.node_info_label = QLabel("No CANopen node selected")
        self.node_info_label.setStyleSheet("font-weight: bold; padding: 2px;")
        self.node_info_label.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.node_info_label.setMaximumHeight(20)
        layout.addWidget(self.node_info_label)
        
        # Splitter for tree and details
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)
        
        # Object dictionary tree
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Index", "Sub", "Name", "Type", "Access", "Value", "Hex Value"])
        self.tree.setAlternatingRowColors(True)
        self.tree.itemSelectionChanged.connect(self.on_item_selected)
        splitter.addWidget(self.tree)
        
        # Details panel
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        
        # Object details
        self.details_group = QGroupBox("Object Details")
        details_form = QFormLayout(self.details_group)
        
        self.index_label = QLabel("-")
        self.subindex_label = QLabel("-")
        self.name_label = QLabel("-")
        self.type_label = QLabel("-")
        self.access_label = QLabel("-")
        
        details_form.addRow("Index:", self.index_label)
        details_form.addRow("Sub-Index:", self.subindex_label)
        details_form.addRow("Name:", self.name_label)
        details_form.addRow("Data Type:", self.type_label)
        details_form.addRow("Access:", self.access_label)
        
        details_layout.addWidget(self.details_group)
        
        # SDO operations
        self.sdo_group = QGroupBox("SDO Operations")
        sdo_layout = QVBoxLayout(self.sdo_group)
        
        # Current value display
        value_layout = QHBoxLayout()
        value_layout.addWidget(QLabel("Current Value:"))
        self.current_value_label = QLabel("-")
        self.current_value_label.setStyleSheet("border: 1px solid gray; padding: 2px;")
        value_layout.addWidget(self.current_value_label)
        sdo_layout.addLayout(value_layout)
        
        # Read button
        self.read_btn = QPushButton("Read Value")
        self.read_btn.clicked.connect(self.read_sdo)
        self.read_btn.setEnabled(False)
        sdo_layout.addWidget(self.read_btn)
        
        # Write section
        write_layout = QHBoxLayout()
        write_layout.addWidget(QLabel("New Value:"))
        self.write_value_edit = QLineEdit()
        self.write_btn = QPushButton("Write")
        self.write_btn.clicked.connect(self.write_sdo)
        self.write_btn.setEnabled(False)
        write_layout.addWidget(self.write_value_edit)
        write_layout.addWidget(self.write_btn)
        sdo_layout.addLayout(write_layout)
        
        # Progress bar for operations
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        sdo_layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: gray;")
        sdo_layout.addWidget(self.status_label)
        
        details_layout.addWidget(self.sdo_group)
        details_layout.addStretch()
        
        splitter.addWidget(details_widget)
        splitter.setSizes([400, 300])
        
    def set_node(self, node_config: CANopenNode):
        """Set the current CANopen node to display"""
        self.current_node_config = node_config
        self.current_node_id = node_config.node_id
        
        # Update node info
        self.node_info_label.setText(
            f"CANopen Node {node_config.node_id} - {node_config.path.name}"
        )
        
        # Try to get the node from the network
        try:
            if self.current_node_id in self.canopen_network.nodes:
                self.current_node = self.canopen_network.nodes[self.current_node_id]
                self.populate_object_dictionary()
            else:
                # Load the EDS/DCF file to show the dictionary structure
                self.load_eds_file(node_config.path)
        except Exception as e:
            self.status_label.setText(f"Error loading node: {e}")
            self.status_label.setStyleSheet("color: red;")
            
    def load_eds_file(self, eds_path: Path):
        """Load EDS/DCF file and populate the object dictionary tree"""
        try:
            import canopen
            # Create a temporary node to read the EDS file
            temp_node = canopen.RemoteNode(1, str(eds_path))
            self.populate_from_eds(temp_node.object_dictionary)
        except Exception as e:
            self.status_label.setText(f"Error loading EDS file: {e}")
            self.status_label.setStyleSheet("color: red;")
            
    def populate_object_dictionary(self):
        """Populate the tree with object dictionary entries"""
        if not self.current_node:
            return
            
        self.tree.clear()
        
        try:
            od = self.current_node.object_dictionary
            self.populate_from_eds(od)
        except Exception as e:
            self.status_label.setText(f"Error populating dictionary: {e}")
            self.status_label.setStyleSheet("color: red;")
            
    def populate_from_eds(self, object_dictionary):
        """Populate tree from object dictionary"""
        self.tree.clear()
        
        # Group objects by category
        categories = {
            "Communication Parameters (0x1000-0x1FFF)": [],
            "Manufacturer Specific (0x2000-0x5FFF)": [],
            "Profile Specific (0x6000-0x9FFF)": [],
            "Reserved (0xA000-0xFFFF)": []
        }
        
        for index, obj in object_dictionary.items():
            if isinstance(index, int):
                if 0x1000 <= index <= 0x1FFF:
                    category = "Communication Parameters (0x1000-0x1FFF)"
                elif 0x2000 <= index <= 0x5FFF:
                    category = "Manufacturer Specific (0x2000-0x5FFF)"
                elif 0x6000 <= index <= 0x9FFF:
                    category = "Profile Specific (0x6000-0x9FFF)"
                else:
                    category = "Reserved (0xA000-0xFFFF)"
                    
                categories[category].append((index, obj))
        
        # Create category items
        for category_name, objects in categories.items():
            if not objects:
                continue
                
            category_item = QTreeWidgetItem(self.tree, [category_name])
            category_item.setExpanded(True)
            
            for index, obj in sorted(objects):
                self.add_object_to_tree(category_item, index, obj)
                
    def add_object_to_tree(self, parent_item, index, obj):
        """Add an object dictionary entry to the tree"""
        try:
            # Handle different object types
            if hasattr(obj, 'subindices') and obj.subindices:
                # Array or record with subindices
                obj_item = QTreeWidgetItem(parent_item, [
                    f"0x{index:04X}", "", 
                    getattr(obj, 'name', f"Object_{index:04X}"),
                    "",
                    "",
                    "",
                    ""
                ])
                obj_item.setData(0, Qt.UserRole, {'index': index, 'subindex': None, 'obj': obj})
                
                # Add subindices
                for subindex, subobj in obj.subindices.items():
                    if isinstance(subindex, int):
                        sub_item = QTreeWidgetItem(obj_item, [
                            f"0x{index:04X}",
                            f"0x{subindex:02X}",
                            getattr(subobj, 'name', f"Sub_{subindex:02X}"),
                            str(getattr(subobj, 'data_type', 'Unknown')),
                            self.get_access_string(getattr(subobj, 'access_type', None)),
                            "-",
                            "-"
                        ])
                        sub_item.setData(0, Qt.UserRole, {
                            'index': index, 
                            'subindex': subindex, 
                            'obj': subobj
                        })
            else:
                # Simple variable
                obj_item = QTreeWidgetItem(parent_item, [
                    f"0x{index:04X}", "0x00",
                    getattr(obj, 'name', f"Object_{index:04X}"),
                    str(getattr(obj, 'data_type', 'Unknown')),
                    self.get_access_string(getattr(obj, 'access_type', None)),
                    "-",
                    "-"
                ])
                obj_item.setData(0, Qt.UserRole, {
                    'index': index, 
                    'subindex': 0, 
                    'obj': obj
                })
                
        except Exception as e:
            print(f"Error adding object 0x{index:04X} to tree: {e}")
    
    def update_tree_item_value(self, value, raw_value=None):
        """Update the value columns of the currently selected tree item"""
        current_item = self.tree.currentItem()
        if current_item:
            current_item.setText(5, value)  # Column 5 is the Value column
            
            # Generate hex value for column 6
            if raw_value is not None:
                if isinstance(raw_value, bytes):
                    hex_value = raw_value.hex(' ').upper()
                elif isinstance(raw_value, int):
                    hex_value = f"0x{raw_value:X}"
                else:
                    hex_value = "-"
                current_item.setText(6, hex_value)  # Column 6 is the Hex Value column
            else:
                current_item.setText(6, "-")
             
    def get_access_string(self, access_type):
        """Convert access type to readable string"""
        if access_type is None:
            return "Unknown"
        
        access_map = {
            'ro': 'Read Only',
            'wo': 'Write Only', 
            'rw': 'Read/Write',
            'rww': 'Read/Write/Write',
            'rwr': 'Read/Write/Read',
            'const': 'Constant'
        }
        
        if hasattr(access_type, 'name'):
            return access_map.get(access_type.name.lower(), str(access_type))
        return access_map.get(str(access_type).lower(), str(access_type))
        
    def on_item_selected(self):
        """Handle tree item selection"""
        selected_items = self.tree.selectedItems()
        if not selected_items:
            self.clear_details()
            return
            
        item = selected_items[0]
        data = item.data(0, Qt.UserRole)
        
        if not data or 'index' not in data:
            self.clear_details()
            return
            
        self.show_object_details(data)
        
    def show_object_details(self, data):
        """Show details for selected object"""
        index = data['index']
        subindex = data['subindex']
        obj = data['obj']
        
        # Update details
        self.index_label.setText(f"0x{index:04X}")
        self.subindex_label.setText(f"0x{subindex:02X}" if subindex is not None else "-")
        self.name_label.setText(getattr(obj, 'name', 'Unknown'))
        self.type_label.setText(str(getattr(obj, 'data_type', 'Unknown')))
        self.access_label.setText(self.get_access_string(getattr(obj, 'access_type', None)))
        
        # Enable/disable SDO operations based on access type
        access_type = getattr(obj, 'access_type', None)
        can_read = access_type in ['ro', 'rw', 'rww', 'rwr'] if access_type else True
        can_write = access_type in ['wo', 'rw', 'rww', 'rwr'] if access_type else True
        
        # Only enable if we have a connected node
        has_connection = (self.current_node is not None and 
                         self.canopen_network.bus is not None)
        
        self.read_btn.setEnabled(can_read and has_connection and subindex is not None)
        self.write_btn.setEnabled(can_write and has_connection and subindex is not None)
        
        # Store current selection for SDO operations
        self.selected_index = index
        self.selected_subindex = subindex if subindex is not None else 0
        
    def clear_details(self):
        """Clear the details panel"""
        self.index_label.setText("-")
        self.subindex_label.setText("-")
        self.name_label.setText("-")
        self.type_label.setText("-")
        self.access_label.setText("-")
        self.current_value_label.setText("-")
        self.read_btn.setEnabled(False)
        self.write_btn.setEnabled(False)
        
    def read_sdo(self):
        """Read value via SDO"""
        if not self.current_node or not hasattr(self, 'selected_index'):
            return
            
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.status_label.setText("Reading...")
        self.status_label.setStyleSheet("color: blue;")
        
        try:
            # Perform SDO read
            if self.selected_subindex == 0:
                # Simple variable - access directly
                value = self.current_node.sdo[self.selected_index].raw
            else:
                # Complex object with subindex
                value = self.current_node.sdo[self.selected_index][self.selected_subindex].raw
            
            # Display the value
            if isinstance(value, bytes):
                display_value = value.hex(' ').upper()
            else:
                display_value = str(value)
                
            self.current_value_label.setText(display_value)
            self.status_label.setText("Read successful")
            self.status_label.setStyleSheet("color: green;")
            
            # Update the tree item's value columns
            self.update_tree_item_value(display_value, value)
            
        except Exception as e:
            self.status_label.setText(f"Read failed: {e}")
            self.status_label.setStyleSheet("color: red;")
            
        finally:
            self.progress_bar.setVisible(False)
            
    def write_sdo(self):
        """Write value via SDO"""
        if not self.current_node or not hasattr(self, 'selected_index'):
            return
            
        value_text = self.write_value_edit.text().strip()
        if not value_text:
            self.status_label.setText("Please enter a value to write")
            self.status_label.setStyleSheet("color: red;")
            return
            
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.status_label.setText("Writing...")
        self.status_label.setStyleSheet("color: blue;")
        
        try:
            # Try to parse the value
            if value_text.startswith('0x') or value_text.startswith('0X'):
                # Hexadecimal
                value = int(value_text, 16)
            elif value_text.replace('.', '').replace('-', '').isdigit():
                # Try as float first, then int
                if '.' in value_text:
                    value = float(value_text)
                else:
                    value = int(value_text)
            else:
                # String value
                value = value_text
                
            # Perform SDO write
            self.current_node.sdo[self.selected_index][self.selected_subindex].raw = value
            
            self.status_label.setText("Write successful")
            self.status_label.setStyleSheet("color: green;")
            self.write_value_edit.clear()
            
            # Automatically read back the value
            QTimer.singleShot(100, self.read_sdo)
            
        except Exception as e:
            self.status_label.setText(f"Write failed: {e}")
            self.status_label.setStyleSheet("color: red;")
            
        finally:
            self.progress_bar.setVisible(False)
            
    def clear_node(self):
        """Clear the current node"""
        self.current_node = None
        self.current_node_id = None
        self.node_info_label.setText("No CANopen node selected")
        self.tree.clear()
        self.clear_details()
        self.status_label.setText("Ready")
        self.status_label.setStyleSheet("color: gray;")


# --- Main Application Window ---
class CANBusObserver(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CANPeek")
        self.setGeometry(100, 100, 1400, 900)
        self.canopen_network = canopen.Network()
        self.MAX_RECENT_PROJECTS = 10
        self.recent_projects_paths = []
        self.interface_manager = CANInterfaceManager()
        self.project = Project()
        self.current_project_path: Optional[Path] = None
        self.project_dirty = False
        file_loggers = {
            "ASCWriter": ".asc",
            "BLFWriter": ".blf",
            "CSVWriter": ".csv",
            "SqliteWriter": ".db",
            "CanutilsLogWriter": ".log",
            "TRCWriter": ".trc",
            "Printer": ".txt",
        }
        sorted_loggers = sorted(file_loggers.items())
        filters = [f"{ext} : {name} Log (*{ext})" for name, ext in sorted_loggers]
        filters += [
            f"{ext}.gz : Compressed {name} Log (*{ext}.gz)"
            for name, ext in sorted_loggers
        ]
        self.log_file_filter = ";;".join(filters)
        self.log_file_filter_open = (
            f"All Supported ({' '.join(['*' + ext for _, ext in sorted_loggers])});;"
            + self.log_file_filter
        )
        self.trace_model = CANTraceModel()
        self.grouped_model = CANGroupedModel()
        self.grouped_proxy_model = QSortFilterProxyModel()
        self.grouped_proxy_model.setSourceModel(self.grouped_model)
        self.grouped_proxy_model.setSortRole(Qt.UserRole)
        self.can_reader = None
        self.frame_batch = []
        self.all_received_frames = []
        self.setDockOptions(QMainWindow.AnimatedDocks | QMainWindow.AllowNestedDocks)
        self.setup_actions()
        self.setup_ui()
        self.setup_docks()
        self.setup_toolbar()
        self.setup_menubar()
        self.setup_statusbar()
        self._load_recent_projects()
        self._update_recent_projects_menu()
        self.project_explorer.project_changed.connect(lambda: self._set_dirty(True))
        self.transmit_panel.config_changed.connect(lambda: self._set_dirty(True))
        self.restore_layout()
        self.gui_update_timer = QTimer(self)
        self.gui_update_timer.timeout.connect(self.update_views)
        self.gui_update_timer.start(50)
        self._update_window_title()

    def setup_actions(self):
        style = self.style()
        self.new_project_action = QAction(
            style.standardIcon(QStyle.SP_FileIcon), "&New Project", self
        )
        self.open_project_action = QAction(
            style.standardIcon(QStyle.SP_DialogOpenButton), "&Open Project...", self
        )
        self.save_project_action = QAction(
            style.standardIcon(QStyle.SP_DialogSaveButton), "Save &Project", self
        )
        self.save_project_as_action = QAction(
            QIcon(QPixmap(":/icons/document-save-as.png")), "Save Project &As...", self
        )
        self.connect_action = QAction(
            style.standardIcon(QStyle.SP_DialogYesButton), "&Connect", self
        )
        self.disconnect_action = QAction(
            style.standardIcon(QStyle.SP_DialogNoButton), "&Disconnect", self
        )
        self.clear_action = QAction(
            style.standardIcon(QStyle.SP_TrashIcon), "&Clear Data", self
        )
        self.save_log_action = QAction(
            QIcon(QPixmap(":/icons/document-export.png")), "&Save Log...", self
        )
        self.load_log_action = QAction(
            QIcon(QPixmap(":/icons/document-import.png")), "&Load Log...", self
        )
        self.exit_action = QAction("&Exit", self)
        self.new_project_action.triggered.connect(self._new_project)
        self.open_project_action.triggered.connect(self._open_project)
        self.save_project_action.triggered.connect(self._save_project)
        self.save_project_as_action.triggered.connect(self._save_project_as)
        self.connect_action.triggered.connect(self.connect_can)
        self.disconnect_action.triggered.connect(self.disconnect_can)
        self.clear_action.triggered.connect(self.clear_data)
        self.save_log_action.triggered.connect(self.save_log)
        self.load_log_action.triggered.connect(self.load_log)
        self.exit_action.triggered.connect(self.close)
        self.disconnect_action.setEnabled(False)

    def setup_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setObjectName("MainToolbar")
        self.addToolBar(toolbar)
        toolbar.addAction(self.new_project_action)
        toolbar.addAction(self.open_project_action)
        toolbar.addAction(self.save_project_action)
        toolbar.addSeparator()
        toolbar.addAction(self.connect_action)
        toolbar.addAction(self.disconnect_action)
        toolbar.addSeparator()
        toolbar.addAction(self.clear_action)
        toolbar.addAction(self.save_log_action)
        toolbar.addAction(self.load_log_action)

    def setup_ui(self):
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)
        self.grouped_view = QTreeView()
        self.grouped_view.setModel(self.grouped_proxy_model)
        self.grouped_view.setAlternatingRowColors(True)
        self.grouped_view.setSortingEnabled(True)
        self.tab_widget.addTab(self.grouped_view, "Grouped")
        trace_view_widget = QWidget()
        trace_layout = QVBoxLayout(trace_view_widget)
        trace_layout.setContentsMargins(5, 5, 5, 5)
        self.trace_view = QTableView()
        self.trace_view.setModel(self.trace_model)
        self.trace_view.setAlternatingRowColors(True)
        self.trace_view.horizontalHeader().setStretchLastSection(True)
        self.autoscroll_cb = QCheckBox("Autoscroll", checked=True)
        trace_layout.addWidget(self.trace_view)
        trace_layout.addWidget(self.autoscroll_cb)
        self.tab_widget.addTab(trace_view_widget, "Trace")
        
        # Add Object Dictionary tab
        self.object_dictionary_viewer = ObjectDictionaryViewer(self.canopen_network)
        self.tab_widget.addTab(self.object_dictionary_viewer, "Object Dictionary")

    def setup_docks(self):
        self.project_explorer = ProjectExplorer(self.project, self)
        explorer_dock = QDockWidget("Project", self)
        explorer_dock.setObjectName("ProjectExplorerDock")
        explorer_dock.setWidget(self.project_explorer)
        self.addDockWidget(Qt.RightDockWidgetArea, explorer_dock)
        self.properties_panel = PropertiesPanel(
            self.project, self.project_explorer, self.interface_manager, self
        )
        properties_dock = QDockWidget("Properties", self)
        properties_dock.setObjectName("PropertiesDock")
        properties_dock.setWidget(self.properties_panel)
        self.addDockWidget(Qt.RightDockWidgetArea, properties_dock)
        transmit_container = QWidget()
        transmit_layout = QVBoxLayout(transmit_container)
        transmit_layout.setContentsMargins(0, 0, 0, 0)
        self.transmit_panel = TransmitPanel()
        self.signal_transmit_panel = SignalTransmitPanel()
        transmit_layout.addWidget(self.transmit_panel)
        transmit_layout.addWidget(self.signal_transmit_panel)
        self.signal_transmit_panel.setVisible(False)
        self.transmit_panel.setEnabled(False)
        transmit_dock = QDockWidget("Transmit", self)
        transmit_dock.setObjectName("TransmitDock")
        transmit_dock.setWidget(transmit_container)
        self.addDockWidget(Qt.BottomDockWidgetArea, transmit_dock)
        self.docks = {
            "explorer": explorer_dock,
            "properties": properties_dock,
            "transmit": transmit_dock,
        }
        self.transmit_panel.frame_to_send.connect(self.send_can_frame)
        self.transmit_panel.row_selection_changed.connect(self.on_transmit_row_selected)
        self.signal_transmit_panel.data_encoded.connect(self.on_signal_data_encoded)
        self.project_explorer.project_changed.connect(self.on_project_changed)
        self.project_explorer.tree.currentItemChanged.connect(
            self.properties_panel.show_properties
        )
        self.project_explorer.tree.currentItemChanged.connect(
            self.on_project_explorer_selection_changed
        )

    def setup_menubar(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("&File")
        file_menu.addAction(self.new_project_action)
        file_menu.addAction(self.open_project_action)
        self.recent_menu = QMenu("Open &Recent", self)
        self.recent_menu.setIcon(QIcon(QPixmap(":/icons/document-open-recent.png")))
        file_menu.addMenu(self.recent_menu)
        file_menu.addAction(self.save_project_action)
        file_menu.addAction(self.save_project_as_action)
        file_menu.addSeparator()
        file_menu.addAction(self.clear_action)
        file_menu.addAction(self.load_log_action)
        file_menu.addAction(self.save_log_action)
        file_menu.addSeparator()
        file_menu.addAction(self.exit_action)
        connect_menu = menubar.addMenu("&Connect")
        connect_menu.addAction(self.connect_action)
        connect_menu.addAction(self.disconnect_action)
        view_menu = menubar.addMenu("&View")
        view_menu.addAction(self.docks["explorer"].toggleViewAction())
        view_menu.addAction(self.docks["properties"].toggleViewAction())
        view_menu.addAction(self.docks["transmit"].toggleViewAction())

    def setup_statusbar(self):
        self.statusBar().showMessage("Ready")
        self.frame_count_label = QLabel("Frames: 0")
        self.connection_label = QLabel("Disconnected")
        self.statusBar().addPermanentWidget(self.frame_count_label)
        self.statusBar().addPermanentWidget(self.connection_label)

    def keyPressEvent(self, event: QKeyEvent):
        if event.key() == Qt.Key_Space and self.transmit_panel.table.hasFocus():
            self.transmit_panel.send_selected()
            event.accept()
        else:
            super().keyPressEvent(event)

    def _process_frame(self, frame: CANFrame):
        try:
            if self.project.canopen_enabled:
                self.canopen_network.notify(
                    frame.arbitration_id, frame.data, frame.timestamp
                )
            self.frame_batch.append(frame)
        except Exception as e:
            print(f"Error processing frame: {e}")

    def update_views(self):
        if not self.frame_batch:
            return
        try:
            frames_to_process, self.frame_batch = self.frame_batch[:], []
            active_filters = self.project.get_active_filters()
            filtered_frames = [
                f
                for f in frames_to_process
                if not active_filters or any(filt.matches(f) for filt in active_filters)
            ]
            if not filtered_frames:
                return
            expanded_ids = {
                self.grouped_model.data(
                    self.grouped_proxy_model.mapToSource(
                        self.grouped_proxy_model.index(row, 0)
                    ),
                    Qt.UserRole,
                )
                for row in range(self.grouped_proxy_model.rowCount())
                if self.grouped_view.isExpanded(self.grouped_proxy_model.index(row, 0))
            }
            self.grouped_model.update_frames(filtered_frames)
            self.all_received_frames.extend(filtered_frames)
            if len(self.all_received_frames) > TRACE_BUFFER_LIMIT:
                del self.all_received_frames[:-TRACE_BUFFER_LIMIT]
            self.trace_model.set_data(self.all_received_frames)
            for row in range(self.grouped_proxy_model.rowCount()):
                proxy_index = self.grouped_proxy_model.index(row, 0)
                if (
                    self.grouped_model.data(
                        self.grouped_proxy_model.mapToSource(proxy_index), Qt.UserRole
                    )
                    in expanded_ids
                ):
                    self.grouped_view.setExpanded(proxy_index, True)
            if self.autoscroll_cb.isChecked():
                self.trace_view.scrollToBottom()
            self.frame_count_label.setText(f"Frames: {len(self.all_received_frames)}")
        except Exception as e:
            import traceback

            print(f"Error in update_views: {e}")
            traceback.print_exc()

    def _create_pdo_databases(self) -> List[object]:
        """Create PDO databases from enabled CANopen nodes"""
        pdo_databases = []
        for node_config in self.project.canopen_nodes:
            if node_config.enabled and node_config.pdo_decoding_enabled:
                try:
                    # Create slave name from file and node ID
                    slave_name = f"{node_config.path.stem}_Node{node_config.node_id}"
                    pdo_db = dcf_2_db(str(node_config.path), node_config.node_id, slave_name)
                    pdo_databases.append(pdo_db)
                    print(f"Created PDO database for node {node_config.node_id}")
                except Exception as e:
                    print(f"Error creating PDO database for node {node_config.node_id}: {e}")
        
        return pdo_databases

    def on_project_changed(self):
        active_dbcs = self.project.get_active_dbcs()
        pdo_databases = self._create_pdo_databases()  # Create PDO databases
        
        self.trace_model.set_config(active_dbcs, self.project.canopen_enabled, pdo_databases)
        self.grouped_model.set_config(active_dbcs, self.project.canopen_enabled)
        # if self.canopen_network.bus:
        #     self.canopen_network.disconnect()
        # self.canopen_network.clear()
        if self.project.canopen_enabled:
            for node_config in self.project.canopen_nodes:
                if node_config.enabled and node_config.path.exists():
                    try:
                        self.canopen_network.add_node(
                            node_config.node_id, str(node_config.path)
                        )
                    except Exception as e:
                        print(f"Error adding CANopen node {node_config.node_id}: {e}")
        if self.can_reader and self.can_reader.bus:
            self.canopen_network.bus = self.can_reader.bus
            self.canopen_network.connect()
        self.transmit_panel.set_dbc_databases(active_dbcs)
        current_item = self.transmit_panel.table.currentItem()
        self.on_transmit_row_selected(
            self.transmit_panel.table.currentRow(),
            current_item.text() if current_item else "",
        )
        self.properties_panel.project = self.project
        
        # Update object dictionary viewer
        current_item = self.project_explorer.tree.currentItem()
        if current_item:
            self.on_project_explorer_selection_changed(current_item, None)
        else:
            self.object_dictionary_viewer.clear_node()

    def on_transmit_row_selected(self, row, id_text):
        self.signal_transmit_panel.clear_panel()
        if row < 0 or not id_text:
            return
        try:
            if message := self.transmit_panel.get_message_from_id(int(id_text, 16)):
                self.signal_transmit_panel.populate(message)
        except ValueError:
            pass

    def on_signal_data_encoded(self, data_bytes):
        if (row := self.transmit_panel.table.currentRow()) >= 0:
            self.transmit_panel.update_row_data(row, data_bytes)
            
    def on_project_explorer_selection_changed(self, current, previous):
        """Handle project explorer selection changes"""
        if not current:
            self.object_dictionary_viewer.clear_node()
            return
            
        data = current.data(0, Qt.UserRole)
        if isinstance(data, CANopenNode) and data.enabled:
            # CANopen node selected
            self.object_dictionary_viewer.set_node(data)
        else:
            # Non-CANopen item selected
            self.object_dictionary_viewer.clear_node()

    def connect_can(self):
        self.can_reader = CANReaderThread(
            self.project.can_interface, self.project.can_config
        )
        self.can_reader.frame_received.connect(self._process_frame)
        self.can_reader.error_occurred.connect(self.on_can_error)
        if self.can_reader.start_reading():
            QTimer.singleShot(200, self._finalize_connection)
        else:
            self.can_reader = None

    def _finalize_connection(self):
        if not self.can_reader or not self.can_reader.bus:
            self.on_can_error("Failed to establish bus object in reader thread.")
            return
        self.canopen_network.bus = self.can_reader.bus
        self.canopen_network.connect()
        self.connect_action.setEnabled(False)
        self.disconnect_action.setEnabled(True)
        self.transmit_panel.setEnabled(True)
        config_str = ", ".join(f"{k}={v}" for k, v in self.project.can_config.items())
        self.connection_label.setText(
            f"Connected ({self.project.can_interface}: {config_str})"
        )
        if current_item := self.project_explorer.tree.currentItem():
            self.properties_panel.show_properties(current_item)

    def disconnect_can(self):
        # Disconnect the canopen network
        # self.canopen_network.disconnect()
        for node in self.canopen_network.nodes.values():
            if hasattr(node, "pdo"):
                node.pdo.stop()
        if self.canopen_network.notifier is not None:
            self.canopen_network.notifier.stop()

        if self.can_reader:
            self.can_reader.stop_reading()
            self.can_reader.deleteLater()
            self.can_reader = None

        self.connect_action.setEnabled(True)
        self.disconnect_action.setEnabled(False)
        self.transmit_panel.setEnabled(False)
        self.transmit_panel.stop_all_timers()
        self.connection_label.setText("Disconnected")
        if current_item := self.project_explorer.tree.currentItem():
            self.properties_panel.show_properties(current_item)

    def send_can_frame(self, message: can.Message):
        if self.can_reader and self.can_reader.running:
            self.can_reader.send_frame.emit(message)
        else:
            QMessageBox.warning(
                self, "Not Connected", "Connect to a CAN bus before sending frames."
            )

    def on_can_error(self, error_message: str):
        QMessageBox.warning(self, "CAN Error", error_message)
        self.statusBar().showMessage(f"Error: {error_message}")
        self.disconnect_can()

    def clear_data(self):
        self.all_received_frames.clear()
        self.grouped_model.clear_frames()
        self.trace_model.set_data([])
        self.frame_count_label.setText("Frames: 0")

    def save_log(self):
        if not self.all_received_frames:
            QMessageBox.information(self, "No Data", "No frames to save.")
            return
        dialog = QFileDialog(self, "Save CAN Log", "", self.log_file_filter)
        dialog.setDefaultSuffix("log")
        dialog.setAcceptMode(QFileDialog.AcceptSave)
        if not dialog.exec():
            return
        filename = dialog.selectedFiles()[0]
        logger = None
        try:
            logger = can.Logger(filename)
            for frame in self.all_received_frames:
                logger.on_message_received(
                    can.Message(
                        timestamp=frame.timestamp,
                        arbitration_id=frame.arbitration_id,
                        is_extended_id=frame.is_extended,
                        is_remote_frame=frame.is_remote,
                        is_error_frame=frame.is_error,
                        dlc=frame.dlc,
                        data=frame.data,
                        channel=frame.channel,
                    )
                )
            self.statusBar().showMessage(f"Log saved to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to save log: {e}")
        finally:
            if logger:
                logger.stop()

    def load_log(self):
        filename, _ = QFileDialog.getOpenFileName(
            self, "Load CAN Log", "", self.log_file_filter_open
        )
        if not filename:
            return
        try:
            self.clear_data()
            frames_to_add = []
            for msg in can.LogReader(filename):
                frames_to_add.append(
                    CANFrame(
                        timestamp=msg.timestamp,
                        arbitration_id=msg.arbitration_id,
                        data=msg.data,
                        dlc=msg.dlc,
                        is_extended=msg.is_extended_id,
                        is_error=msg.is_error_frame,
                        is_remote=msg.is_remote_frame,
                        channel=msg.channel or "CAN1",
                    )
                )
            self.frame_batch.extend(frames_to_add)
            self.update_views()
            self.statusBar().showMessage(
                f"Loaded {len(self.all_received_frames)} frames from {filename}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Load Error", f"Failed to load log: {e}")

    def _load_recent_projects(self):
        self.recent_projects_paths = QSettings().value("recentProjects", [], type=list)

    def _save_recent_projects(self):
        QSettings().setValue("recentProjects", self.recent_projects_paths)

    def _add_to_recent_projects(self, path: Path):
        path_str = str(path.resolve())
        if path_str in self.recent_projects_paths:
            self.recent_projects_paths.remove(path_str)
        self.recent_projects_paths.insert(0, path_str)
        self.recent_projects_paths = self.recent_projects_paths[
            : self.MAX_RECENT_PROJECTS
        ]
        self._update_recent_projects_menu()
        self._save_recent_projects()

    def _update_recent_projects_menu(self):
        self.recent_menu.clear()
        if not self.recent_projects_paths:
            self.recent_menu.addAction(
                QAction("No Recent Projects", self, enabled=False)
            )
            return
        for i, path_str in enumerate(self.recent_projects_paths):
            action = QAction(f"&{i + 1} {Path(path_str).name}", self)
            action.setData(path_str)
            action.setToolTip(path_str)
            action.triggered.connect(self._open_recent_project)
            self.recent_menu.addAction(action)
        self.recent_menu.addSeparator()
        clear_action = QAction("Clear List", self)
        clear_action.triggered.connect(self._clear_recent_projects)
        self.recent_menu.addAction(clear_action)

    def _open_recent_project(self):
        action = self.sender()
        if isinstance(action, QAction):
            path_str = action.data()
            if path_str and Path(path_str).exists():
                self._open_project(path_str)
            else:
                QMessageBox.warning(
                    self, "File Not Found", f"The file '{path_str}' could not be found."
                )
                if path_str in self.recent_projects_paths:
                    self.recent_projects_paths.remove(path_str)
                    self._update_recent_projects_menu()
                    self._save_recent_projects()

    def _clear_recent_projects(self):
        self.recent_projects_paths.clear()
        self._update_recent_projects_menu()
        self._save_recent_projects()

    def _set_dirty(self, dirty: bool):
        if self.project_dirty != dirty:
            self.project_dirty = dirty
        self._update_window_title()

    def _update_window_title(self):
        title = "CANPeek - " + (
            self.current_project_path.name
            if self.current_project_path
            else "Untitled Project"
        )
        if self.project_dirty:
            title += "*"
        self.setWindowTitle(title)

    def _prompt_save_if_dirty(self) -> bool:
        if not self.project_dirty:
            return True
        reply = QMessageBox.question(
            self,
            "Save Changes?",
            "You have unsaved changes. Would you like to save them?",
            QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
        )
        if reply == QMessageBox.Save:
            return self._save_project()
        return reply != QMessageBox.Cancel

    def _new_project(self):
        if not self._prompt_save_if_dirty():
            return
        self.disconnect_can()
        self.clear_data()
        self.project = Project()
        self.current_project_path = None
        self.project_explorer.set_project(self.project)
        self.transmit_panel.set_config([])
        self._set_dirty(False)

    def _open_project(self, path: Optional[str] = None):
        if not self._prompt_save_if_dirty():
            return
        if not path:
            path, _ = QFileDialog.getOpenFileName(
                self, "Open Project", "", "CANPeek Project (*.cpeek);;All Files (*)"
            )
        if not path:
            return
        try:
            with open(path, "r") as f:
                data = json.load(f)
            self.disconnect_can()
            self.clear_data()
            self.project = Project.from_dict(
                data.get("project", {}), self.interface_manager
            )
            self.project_explorer.set_project(self.project)
            self.transmit_panel.set_config(data.get("transmit_config", []))
            self.current_project_path = Path(path)
            self._add_to_recent_projects(self.current_project_path)
            self._set_dirty(False)
            self.statusBar().showMessage(
                f"Project '{self.current_project_path.name}' loaded."
            )
        except Exception as e:
            QMessageBox.critical(
                self, "Open Project Error", f"Failed to load project:\n{e}"
            )
            self._new_project()

    def _save_project(self) -> bool:
        return (
            self._save_project_as()
            if not self.current_project_path
            else self._save_project_to_path(self.current_project_path)
        )

    def _save_project_as(self) -> bool:
        dialog = QFileDialog(
            self, "Save Project As", "", "CANPeek Project (*.cpeek);;All Files (*)"
        )
        dialog.setAcceptMode(QFileDialog.AcceptSave)
        dialog.setDefaultSuffix("cpeek")
        if dialog.exec():
            self.current_project_path = Path(dialog.selectedFiles()[0])
            return self._save_project_to_path(self.current_project_path)
        return False

    def _save_project_to_path(self, path: Path) -> bool:
        try:
            with open(path, "w") as f:
                json.dump(
                    {
                        "project": self.project.to_dict(),
                        "transmit_config": self.transmit_panel.get_config(),
                    },
                    f,
                    indent=2,
                )
            self._set_dirty(False)
            self.statusBar().showMessage(f"Project saved to '{path.name}'.")
            self._add_to_recent_projects(path)
            return True
        except Exception as e:
            QMessageBox.critical(
                self, "Save Project Error", f"Failed to save project:\n{e}"
            )
            return False

    def save_layout(self):
        settings = QSettings()
        settings.setValue("geometry", self.saveGeometry())
        settings.setValue("windowState", self.saveState())
        if self.current_project_path:
            settings.setValue("lastProjectPath", str(self.current_project_path))

    def restore_layout(self):
        settings = QSettings()
        geometry = settings.value("geometry")
        state = settings.value("windowState")
        last_project = settings.value("lastProjectPath")
        if geometry:
            self.restoreGeometry(geometry)
        if state:
            self.restoreState(state)
        if last_project and Path(last_project).exists():
            self._open_project(last_project)

    def closeEvent(self, event):
        if not self._prompt_save_if_dirty():
            event.ignore()
            return
        self.save_layout()
        self.disconnect_can()
        QApplication.processEvents()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setOrganizationName("CANPeek")
    app.setApplicationName("CANPeek")
    window = CANBusObserver()
    qdarktheme.setup_theme("auto")
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
