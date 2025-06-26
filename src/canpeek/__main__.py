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

### MODIFIED ### - Add QDockWidget, QToolBar, QStyle, QIcon
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
)

### MODIFIED ### - Add QProcess, QSettings
from PySide6.QtCore import (
    QThread,
    QTimer,
    Signal,
    Qt,
    QAbstractItemModel,
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    QSettings,
)
from PySide6.QtGui import QAction, QKeyEvent


import can
import cantools

# ### NEW ### Forward reference for type hinting
if TYPE_CHECKING:
    from __main__ import ProjectExplorer, CANInterfaceManager  # <-- MODIFIED THIS LINE


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
    can_interface: str = "virtual"
    can_config: Dict[str, Any] = field(default_factory=lambda: {"channel": "vcan0"})

    def get_active_dbcs(self) -> List[object]:
        return [dbc.database for dbc in self.dbcs if dbc.enabled]

    def get_active_filters(self) -> List[CANFrameFilter]:
        return [f for f in self.filters if f.enabled]

    def to_dict(self) -> Dict:
        serializable_can_config = {}
        for key, value in self.can_config.items():
            if isinstance(value, enum.Enum):
                serializable_can_config[key] = value.name
            else:
                serializable_can_config[key] = value
        return {
            "dbcs": [
                {"path": str(dbc.path), "enabled": dbc.enabled} for dbc in self.dbcs
            ],
            "filters": [asdict(f) for f in self.filters],
            "canopen_enabled": self.canopen_enabled,
            "can_interface": self.can_interface,
            "can_config": serializable_can_config,
        }

    ### MODIFIED ### - Now accepts interface_manager to "hydrate" the config
    @classmethod
    def from_dict(
        cls, data: Dict, interface_manager: "CANInterfaceManager"
    ) -> "Project":
        project = cls()
        project.canopen_enabled = data.get("canopen_enabled", True)
        project.can_interface = data.get("can_interface", "virtual")

        # Hydrate the can_config: convert strings from file back to real objects (enums)
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
                        # Convert saved string name back to the actual Enum member
                        hydrated_config[key] = expected_type[value]
                    except KeyError:
                        print(
                            f"Warning: Stored enum member '{value}' for '{key}' is invalid. Using default."
                        )
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


### NEW ### - A custom logging handler to capture log records in a list
class LogCaptureHandler(logging.Handler):
    """A logging handler that captures records to a list."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []

    def emit(self, record):
        self.records.append(record)


### NEW ### - A context manager to temporarily capture logs from a specific logger
@contextmanager
def capture_logs(logger_name: str):
    """
    A context manager to temporarily capture logs of level WARNING or higher
    from the specified logger.
    """
    log_handler = LogCaptureHandler()
    target_logger = logging.getLogger(logger_name)

    # Store the original state to restore it later
    original_handlers = target_logger.handlers[:]
    original_level = target_logger.level

    try:
        # Clear existing handlers and set a low level to catch everything
        target_logger.handlers.clear()
        target_logger.addHandler(log_handler)
        target_logger.setLevel(
            logging.WARNING
        )  # We only care about warnings and errors

        yield log_handler  # Pass the handler to the 'with' block

    finally:
        # Restore the logger to its original state, no matter what
        target_logger.handlers = original_handlers
        target_logger.setLevel(original_level)


# A manager to dynamically and safely find and inspect python-can interfaces
class CANInterfaceManager:
    """
    Dynamically discovers available python-can interfaces. It uses the
    'docstring-parser' library to parse their docstrings, finds their
    configuration parameters, and filters out any interfaces that produce
    warnings or errors during discovery.
    """

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

                    init_doc = inspect.getdoc(bus_class.__init__)
                    raw_doc = init_doc if init_doc else inspect.getdoc(bus_class)

                    if raw_doc:
                        parsed = parse(raw_doc)

                        desc_parts = []
                        if parsed.short_description:
                            desc_parts.append(parsed.short_description)
                        if parsed.long_description:
                            desc_parts.append(parsed.long_description)
                        description = "\n\n".join(desc_parts)

                        ### MODIFIED ### - Store type_name along with description
                        params_dict = {
                            param.arg_name: {
                                "type_name": param.type_name,
                                "description": param.description or "",
                            }
                            for param in parsed.params
                        }

                        parsed_doc_dict = {
                            "description": description,
                            "params": params_dict,
                        }
                    else:
                        parsed_doc_dict = {"description": "", "params": {}}

                    if log_handler.records:
                        first_warning = log_handler.records[0].getMessage()
                        print(
                            f"Info: Skipping interface '{name}' due to warning: {first_warning}"
                        )
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

                interfaces[name] = {
                    "class": bus_class,
                    "params": params,
                    "docstring": parsed_doc_dict,
                }

            except (ImportError, AttributeError, OSError, TypeError) as e:
                print(f"Info: Skipping interface '{name}' due to error on load: {e}")
            except Exception as e:
                print(f"Warning: Could not load or inspect CAN interface '{name}': {e}")

        return dict(sorted(interfaces.items()))

    def get_available_interfaces(self) -> List[str]:
        return list(self._interfaces.keys())

    def get_interface_params(self, name: str) -> Optional[Dict]:
        return self._interfaces.get(name, {}).get("params")

    def get_interface_docstring(self, name: str) -> Optional[Dict]:
        """Returns the parsed docstring for the given interface name."""
        return self._interfaces.get(name, {}).get("docstring")


# --- Decoders ---
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
        cmd = data[0]
        base_info = {"CANopen Type": f"SDO {direction}", "CANopen Node": node_id}
        specifier = (cmd >> 5) & 0x7
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
        self.frames: List[CANFrame] = []
        self.headers = ["Timestamp", "ID", "Type", "DLC", "Data", "Decoded"]
        self.dbc_databases: List[object] = []
        self.canopen_enabled = True

    def set_data(self, frames: List[CANFrame]):
        self.beginResetModel()
        self.frames = frames
        self.endResetModel()

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
        if self.canopen_enabled:
            if co_info := CANopenDecoder.decode(frame):
                details = ", ".join(
                    f"{k}={v}" for k, v in co_info.items() if k not in ["CANopen Type"]
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


class CANReaderThread(QThread):
    frame_received = Signal(object)
    error_occurred = Signal(str)
    send_frame = Signal(object)

    ### MODIFIED ### - Accept a flexible config dictionary
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
            ### MODIFIED ### - Pass the config dict directly to the Bus
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


### NEW ### - A reusable, modeless dialog to display documentation
class DocumentationWindow(QDialog):
    """A separate, non-blocking window for displaying parsed documentation."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Interface Documentation")
        self.setMinimumSize(600, 450)

        layout = QVBoxLayout(self)
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setObjectName("documentationViewer")
        layout.addWidget(self.text_edit)

    def set_content(self, interface_name: str, parsed_doc: Dict):
        """
        Updates the window title and content by building an HTML string
        from the parsed docstring dictionary, including type information.
        """
        self.setWindowTitle(f"Documentation for '{interface_name}'")

        ### MODIFIED ### - Added styling for the type information
        html = """
        <style>
            body { font-family: sans-serif; font-size: 14px; }
            p { margin-bottom: 12px; }
            dl { margin-left: 10px; }
            dt { font-weight: bold; color: #af5aed; margin-top: 8px; }
            dt .param-type { font-style: italic; color: #555555; font-weight: normal; }
            dd { margin-left: 20px; margin-bottom: 8px; }
            hr { border: 1px solid #cccccc; }
        </style>
        """

        if parsed_doc and parsed_doc.get("description"):
            desc = parsed_doc["description"].replace("<", "<").replace(">", ">")
            html += f"<p>{desc.replace(chr(10), '<br>')}</p>"

        if parsed_doc and parsed_doc.get("params"):
            html += "<hr><h3>Parameters:</h3>"
            html += "<dl>"
            ### MODIFIED ### - Loop now handles the richer param_info dictionary
            for name, param_info in parsed_doc["params"].items():
                type_name = param_info.get("type_name")
                description = (
                    param_info.get("description", "")
                    .replace("<", "<")
                    .replace(">", ">")
                )

                # Build the header line (dt) with optional type info
                header = f"<strong>{name}</strong>"
                if type_name:
                    header += f' <span class="param-type">({type_name})</span>'

                html += f"<dt>{header}:</dt><dd>{description}</dd>"
            html += "</dl>"

        if not (
            parsed_doc and (parsed_doc.get("description") or parsed_doc.get("params"))
        ):
            html += "<p>No documentation available.</p>"

        self.text_edit.setHtml(html)


# Fully dynamic editor for connection settings
class ConnectionEditor(QWidget):
    project_changed = Signal()

    def __init__(self, project: Project, interface_manager: CANInterfaceManager):
        super().__init__()
        self.project = project
        self.interface_manager = interface_manager
        self.dynamic_widgets = {}

        # Create a single, persistent instance of the documentation window
        self.docs_window = DocumentationWindow(self)

        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        group = QGroupBox("Connection Properties")
        self.form_layout = QFormLayout(group)
        main_layout.addWidget(group)

        # --- Interface Selection ---
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.interface_manager.get_available_interfaces())
        self.form_layout.addRow("Interface:", self.interface_combo)

        # --- NEW: Button to show the documentation in a separate window ---
        self.show_docs_button = QPushButton("Show python-can Documentation...")
        self.form_layout.addRow(self.show_docs_button)

        # --- Dynamic Fields ---
        self.dynamic_fields_container = QWidget()
        self.dynamic_layout = QFormLayout(self.dynamic_fields_container)
        self.dynamic_layout.setContentsMargins(0, 0, 0, 0)
        self.form_layout.addRow(self.dynamic_fields_container)

        # --- Connections and Initial State ---
        self.show_docs_button.clicked.connect(self._show_documentation_window)
        self.interface_combo.currentTextChanged.connect(self._on_interface_changed)
        self.interface_combo.setCurrentText(self.project.can_interface)
        self._rebuild_dynamic_fields(self.project.can_interface)

    # Method to show the documentation dialog
    def _show_documentation_window(self):
        interface_name = self.interface_combo.currentText()
        docstring = self.interface_manager.get_interface_docstring(interface_name)
        self.docs_window.set_content(interface_name, docstring)
        self.docs_window.show()
        # Bring the window to the front
        self.docs_window.raise_()
        self.docs_window.activateWindow()

    def _on_interface_changed(self, interface_name: str):
        self.project.can_interface = interface_name
        self.project.can_config.clear()
        self._rebuild_dynamic_fields(interface_name)
        # _rebuild_dynamic_fields now calls _update_project at the end
        # self._update_project() # This call is now redundant

    ### MODIFIED ### - Creates widgets based on parameter type (Enum, bool, int, str)
    def _rebuild_dynamic_fields(self, interface_name: str):
        # Fetch the parsed docstring data once
        parsed_doc = self.interface_manager.get_interface_docstring(interface_name)
        param_docs = parsed_doc.get("params", {}) if parsed_doc else {}

        has_docs = bool(
            parsed_doc and (parsed_doc.get("description") or parsed_doc.get("params"))
        )
        self.show_docs_button.setVisible(has_docs)

        # --- Clear and rebuild the dynamic input fields ---
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

            # Check if the parameter's type is an Enum
            is_enum = False
            try:
                if inspect.isclass(expected_type) and issubclass(
                    expected_type, enum.Enum
                ):
                    is_enum = True
            except TypeError:
                pass  # Not a class, so cannot be an enum

            if is_enum:
                widget = QComboBox()
                widget.setProperty("enum_class", expected_type)
                members = list(expected_type)
                widget.addItems([m.name for m in members])

                # Set current value from saved config or default
                current_value = default_value
                if isinstance(current_value, enum.Enum):
                    widget.setCurrentText(current_value.name)
                elif isinstance(current_value, str):
                    widget.setCurrentText(current_value)

                widget.currentTextChanged.connect(self._update_project)

            elif expected_type is bool:
                widget = QCheckBox()
                if default_value is not None:
                    widget.setChecked(bool(default_value))
                widget.toggled.connect(self._update_project)

            elif name == "bitrate" and expected_type is int:
                widget = QSpinBox()
                widget.setRange(1000, 4000000)
                widget.setSingleStep(1000)
                widget.setSuffix(" bps")
                if default_value is not None:
                    widget.setValue(int(default_value))
                widget.valueChanged.connect(self._update_project)
            else:
                widget = QLineEdit()
                # Set text to empty if default is None, otherwise string representation
                widget.setText(str(default_value) if default_value is not None else "")
                widget.editingFinished.connect(self._update_project)

            if widget:
                tooltip_info = param_docs.get(name)
                if tooltip_info and tooltip_info.get("description"):
                    tooltip_parts = []
                    type_name = tooltip_info.get("type_name")
                    if type_name:
                        tooltip_parts.append(f"({type_name})")
                    tooltip_parts.append(tooltip_info["description"])
                    tooltip_text = " ".join(tooltip_parts)
                    widget.setToolTip(tooltip_text)

                label_text = f"{name.replace('_', ' ').title()}:"
                self.dynamic_layout.addRow(label_text, widget)
                self.dynamic_widgets[name] = widget

        self._update_project()

    ### NEW ### - Helper function to robustly convert text input
    def _convert_line_edit_text(self, text: str, param_info: Dict) -> Any:
        """
        Converts text from a QLineEdit to the appropriate type.
        Handles optional values (empty string -> None) and hex/dec integers.
        """
        text = text.strip()
        expected_type = param_info.get("type")
        default_value = param_info.get("default")

        # If parameter is optional (indicated by default=None), empty text becomes None
        if not text and default_value is None:
            return None

        # Attempt type conversion based on inspection
        if expected_type is int:
            try:
                return int(text)  # Try decimal first
            except ValueError:
                return int(text, 16)  # Fallback to hex
        elif expected_type is float:
            return float(text)
        elif expected_type is bool:
            return text.lower() in ("true", "1", "t", "yes", "y")

        # Fallback for strings or other complex types we don't handle
        return text

    ### MODIFIED ### - Smarter value conversion based on widget type
    def _update_project(self):
        config = {}
        params = self.interface_manager.get_interface_params(self.project.can_interface)
        if not params:
            params = {}

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
                        # Convert selected string back to the actual Enum member
                        value = enum_class[widget.currentText()]
                elif isinstance(widget, QLineEdit):
                    value = self._convert_line_edit_text(widget.text(), param_info)

            except (ValueError, TypeError, KeyError) as e:
                print(
                    f"Warning: Could not get value for '{name}'. Input may be invalid. Error: {e}"
                )
                # Skip adding this parameter to the config if conversion fails
                continue

            # Only add to config if a valid value was determined
            config[name] = value

        self.project.can_interface = self.interface_combo.currentText()
        self.project.can_config = config
        self.project_changed.emit()


class PropertiesPanel(QWidget):
    ### MODIFIED ### - Accept interface_manager in constructor
    def __init__(
        self,
        project: Project,
        explorer: "ProjectExplorer",
        interface_manager: "CANInterfaceManager",
    ):
        super().__init__()
        self.project = project
        self.explorer = explorer
        self.interface_manager = interface_manager  # Store the manager
        self.current_widget = None
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.placeholder = QLabel("Select an item to see its properties.")
        self.placeholder.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.placeholder)

    ### MODIFIED ### - Use the stored interface_manager
    def show_properties(self, item: QTreeWidgetItem):
        self.clear()
        data = item.data(0, Qt.UserRole) if item else None

        if data == "connection_settings":
            # Now self.interface_manager exists and can be passed
            editor = ConnectionEditor(self.project, self.interface_manager)
            editor.project_changed.connect(self.explorer.rebuild_tree)
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

    def __init__(self, project: Project):
        super().__init__("Project Explorer")
        self.project = project
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

    ### MODIFIED ### - Rebuild tree to include connection settings
    def rebuild_tree(self):
        self.tree.blockSignals(True)
        self.tree.clear()

        connection_text = f"Connection ({self.project.can_interface})"
        self.add_item(None, connection_text, "connection_settings", checked=None)

        self.dbc_root = self.add_item(None, "Symbol Files (.dbc)")
        [
            self.add_item(self.dbc_root, dbc.path.name, dbc, dbc.enabled)
            for dbc in self.project.dbcs
        ]

        self.filter_root = self.add_item(None, "Message Filters")
        [
            self.add_item(self.filter_root, f.name, f, f.enabled)
            for f in self.project.filters
        ]

        self.co_item = self.add_item(
            None, "CANopen Decoding", self.project, self.project.canopen_enabled
        )

        self.tree.expandAll()
        self.tree.blockSignals(False)
        self.project_changed.emit()

    ### MODIFIED ### - Allow non-checkable items
    def add_item(self, parent, text, data=None, checked=None):
        item = QTreeWidgetItem(parent or self.tree, [text])
        if data:
            item.setData(0, Qt.UserRole, data)
        if checked is not None:
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(0, Qt.Checked if checked else Qt.Unchecked)
        return item

    ### MODIFIED ### - More robust item change handling
    def on_item_changed(self, item, column):
        if data := item.data(0, Qt.UserRole):
            if data == self.project:  # This is the CANopen item
                self.project.canopen_enabled = item.checkState(0) == Qt.Checked
            elif isinstance(data, (DBCFile, CANFrameFilter)):
                data.enabled = item.checkState(0) == Qt.Checked
            self.project_changed.emit()

    def open_context_menu(self, position):
        menu = QMenu()
        item = self.tree.itemAt(position)
        if not item or item == self.dbc_root:
            menu.addAction("Add Symbol File...").triggered.connect(self.add_dbc)
        if not item or item == self.filter_root:
            menu.addAction("Add Filter").triggered.connect(self.add_filter)
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
            self.rebuild_tree()


class TransmitPanel(QGroupBox):
    frame_to_send = Signal(object)
    row_selection_changed = Signal(int, str)
    ### NEW ### - Signal for tracking unsaved changes
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
        if not self.table.selectionModel().selectedRows():
            return
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
                if cycle <= 0:
                    raise ValueError
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

    ### NEW ### - Methods for config serialization
    def get_config(self) -> List[Dict]:
        config = []
        for r in range(self.table.rowCount()):
            row_data = {
                "on": self.table.cellWidget(r, 0).findChild(QCheckBox).isChecked(),
                "id": self.table.item(r, 1).text(),
                "type_idx": self.table.cellWidget(r, 2).currentIndex(),
                "rtr": self.table.cellWidget(r, 3).findChild(QCheckBox).isChecked(),
                "dlc": self.table.item(r, 4).text(),
                "data": self.table.item(r, 5).text(),
                "cycle": self.table.item(r, 6).text(),
            }
            config.append(row_data)
        return config

    def set_config(self, config: List[Dict]):
        self.stop_all_timers()
        self.table.clearContents()
        self.table.setRowCount(0)  # Clear all rows
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


# --- Main Application Window ---
class CANBusObserver(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CANPeek")
        self.setGeometry(100, 100, 1400, 900)

        self.interface_manager = CANInterfaceManager()

        # Project state attributes
        self.project = Project()
        self.current_project_path: Optional[Path] = None
        self.project_dirty = False

        # Create log file filter string
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
        self.process = None

        self.setDockOptions(QMainWindow.AnimatedDocks | QMainWindow.AllowNestedDocks)

        self.setup_actions()
        self.setup_ui()
        self.setup_docks()
        self.setup_toolbar()
        self.setup_menubar()
        self.setup_statusbar()

        # Connect signals for dirty state tracking
        self.project_explorer.project_changed.connect(lambda: self._set_dirty(True))
        self.transmit_panel.config_changed.connect(lambda: self._set_dirty(True))

        self.restore_layout()  # Restore layout and last project

        self.gui_update_timer = QTimer(self)
        self.gui_update_timer.timeout.connect(self.update_views)
        self.gui_update_timer.start(50)
        self._update_window_title()

    def setup_actions(self):
        style = self.style()
        self.new_project_action = QAction("&New Project", self)
        self.open_project_action = QAction("&Open Project...", self)
        self.save_project_action = QAction("&Save Project", self)
        self.save_project_as_action = QAction("Save Project &As...", self)

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
            style.standardIcon(QStyle.SP_DialogSaveButton), "&Save Log...", self
        )
        self.load_log_action = QAction(
            style.standardIcon(QStyle.SP_DialogOpenButton), "&Load Log...", self
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

    def setup_docks(self):
        self.project_explorer = ProjectExplorer(self.project)
        explorer_dock = QDockWidget("Project", self)
        explorer_dock.setObjectName("ProjectExplorerDock")
        explorer_dock.setWidget(self.project_explorer)
        self.addDockWidget(Qt.RightDockWidgetArea, explorer_dock)

        ### MODIFIED ### - Pass the interface_manager during instantiation
        self.properties_panel = PropertiesPanel(
            self.project, self.project_explorer, self.interface_manager
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

    def setup_menubar(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("&File")
        file_menu.addAction(self.new_project_action)
        file_menu.addAction(self.open_project_action)
        file_menu.addAction(self.save_project_action)
        file_menu.addAction(self.save_project_as_action)
        file_menu.addSeparator()
        file_menu.addAction(self.load_log_action)
        file_menu.addAction(self.save_log_action)
        file_menu.addSeparator()
        file_menu.addAction(self.exit_action)
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

    def keyPressEvent(self, event: QKeyEvent):  # ...
        if event.key() == Qt.Key_Space and self.transmit_panel.table.hasFocus():
            self.transmit_panel.send_selected()
            event.accept()
        else:
            super().keyPressEvent(event)

    def _process_frame(self, frame: CANFrame):
        try:
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
            print(f"Error in update_views: {e}")
            import traceback

            traceback.print_exc()

    def on_project_changed(self):
        active_dbcs = self.project.get_active_dbcs()
        self.trace_model.dbc_databases = active_dbcs
        self.trace_model.canopen_enabled = self.project.canopen_enabled
        self.trace_model.layoutChanged.emit()
        self.grouped_model.set_config(active_dbcs, self.project.canopen_enabled)
        self.transmit_panel.set_dbc_databases(active_dbcs)
        current_item = self.transmit_panel.table.currentItem()
        self.on_transmit_row_selected(
            self.transmit_panel.table.currentRow(),
            current_item.text() if current_item else "",
        )
        self.properties_panel.project = (
            self.project
        )  # ensure properties panel has latest project

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

    def connect_can(self):
        ### MODIFIED ### - Pass the flexible config dictionary to the thread
        self.can_reader = CANReaderThread(
            self.project.can_interface,
            self.project.can_config,
        )
        self.can_reader.frame_received.connect(self._process_frame)
        self.can_reader.error_occurred.connect(self.on_can_error)
        if self.can_reader.start_reading():
            self.connect_action.setEnabled(False)
            self.disconnect_action.setEnabled(True)
            self.transmit_panel.setEnabled(True)
            # Create a nice string for the status bar
            config_str = ", ".join(
                f"{k}={v}" for k, v in self.project.can_config.items()
            )
            self.connection_label.setText(
                f"Connected ({self.project.can_interface}: {config_str})"
            )
        else:
            self.can_reader = None

    def disconnect_can(self):
        if self.can_reader:
            self.can_reader.stop_reading()
            self.can_reader.deleteLater()
            self.can_reader = None
        self.connect_action.setEnabled(True)
        self.disconnect_action.setEnabled(False)
        self.transmit_panel.setEnabled(False)
        self.transmit_panel.stop_all_timers()
        self.connection_label.setText("Disconnected")

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

    ### MODIFIED ### - Replaced with python-can based log saving
    def save_log(self):
        if not self.all_received_frames:
            QMessageBox.information(self, "No Data", "No frames to save.")
            return

        dialog = QFileDialog(self, "Save CAN Log", "", self.log_file_filter)
        dialog.setDefaultSuffix("log")
        dialog.setAcceptMode(QFileDialog.AcceptSave)
        if dialog.exec():
            filename = dialog.selectedFiles()[0]
        else:
            return

        logger = None
        try:
            # Logger type is inferred from the file extension
            logger = can.Logger(filename)
            for frame in self.all_received_frames:
                # Convert our internal CANFrame back to a can.Message
                msg = can.Message(
                    timestamp=frame.timestamp,
                    arbitration_id=frame.arbitration_id,
                    is_extended_id=frame.is_extended,
                    is_remote_frame=frame.is_remote,
                    is_error_frame=frame.is_error,
                    dlc=frame.dlc,
                    data=frame.data,
                    channel=frame.channel,
                )
                logger.on_message_received(msg)
            self.statusBar().showMessage(f"Log saved to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to save log: {e}")
        finally:
            if logger:
                logger.stop()  # This is crucial to flush buffers and close the file

    ### MODIFIED ### - Replaced with python-can based log loading
    def load_log(self):
        filename, _ = QFileDialog.getOpenFileName(
            self, "Load CAN Log", "", self.log_file_filter_open
        )
        if not filename:
            return

        try:
            self.clear_data()
            frames_to_add = []
            # CANLogReader infers file type from extension and works as an iterator
            for msg in can.LogReader(filename):
                # Convert can.Message to our internal CANFrame format
                frames_to_add.append(
                    CANFrame(
                        timestamp=msg.timestamp,
                        arbitration_id=msg.arbitration_id,
                        data=msg.data,
                        dlc=msg.dlc,
                        is_extended=msg.is_extended_id,
                        is_error=msg.is_error_frame,
                        is_remote=msg.is_remote_frame,
                        channel=msg.channel if msg.channel is not None else "CAN1",
                    )
                )

            # Batch add frames to the view for performance
            self.frame_batch.extend(frames_to_add)
            self.update_views()
            self.statusBar().showMessage(
                f"Loaded {len(self.all_received_frames)} frames from {filename}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Load Error", f"Failed to load log: {e}")

    ### NEW ### - Methods for project handling and state management
    def _set_dirty(self, dirty: bool):
        if self.project_dirty != dirty:
            self.project_dirty = dirty
        self._update_window_title()

    def _update_window_title(self):
        title = "CANPeek - "
        if self.current_project_path:
            title += self.current_project_path.name
        else:
            title += "Untitled Project"
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
        elif reply == QMessageBox.Cancel:
            return False
        return True  # Discard

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

            # ### MODIFIED ### - Pass self.interface_manager to the factory method
            self.project = Project.from_dict(
                data.get("project", {}), self.interface_manager
            )

            self.project_explorer.set_project(self.project)
            self.transmit_panel.set_config(data.get("transmit_config", []))
            self.current_project_path = Path(path)
            self._set_dirty(False)
            self.statusBar().showMessage(
                f"Project '{self.current_project_path.name}' loaded."
            )
        except Exception as e:
            QMessageBox.critical(
                self, "Open Project Error", f"Failed to load project:\n{e}"
            )
            self._new_project()  # Reset to a clean state

    def _save_project(self) -> bool:
        if self.current_project_path:
            return self._save_project_to_path(self.current_project_path)
        else:
            return self._save_project_as()

    def _save_project_as(self) -> bool:
        dialog = QFileDialog(
            self, "Save Project As", "", "CANPeek Project (*.cpeek);;All Files (*)"
        )
        dialog.setAcceptMode(QFileDialog.AcceptSave)
        dialog.setDefaultSuffix("cpeek")
        if dialog.exec():
            path = dialog.selectedFiles()[0]
            self.current_project_path = Path(path)
            return self._save_project_to_path(self.current_project_path)
        return False

    def _save_project_to_path(self, path: Path) -> bool:
        try:
            config = {
                "project": self.project.to_dict(),
                "transmit_config": self.transmit_panel.get_config(),
            }
            with open(path, "w") as f:
                json.dump(config, f, indent=2)
            self._set_dirty(False)
            self.statusBar().showMessage(f"Project saved to '{path.name}'.")
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
        if geometry:
            self.restoreGeometry(geometry)
        state = settings.value("windowState")
        if state:
            self.restoreState(state)

        last_project = settings.value("lastProjectPath")
        if last_project and Path(last_project).exists():
            self._open_project(last_project)

    def closeEvent(self, event):
        if not self._prompt_save_if_dirty():
            event.ignore()
            return
        self.save_layout()
        if hasattr(self, "gui_update_timer"):
            self.gui_update_timer.stop()
        if self.process:
            self.process.kill()
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
