#!/usr/bin/env python3
"""
CAN Bus Observer GUI - Similar to PCAN-Explorer
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
import time
import struct
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path
from functools import partial
from collections import deque

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QTabWidget, QPushButton, QLabel,
    QLineEdit, QCheckBox, QComboBox, QSpinBox, QSplitter,
    QGroupBox, QFormLayout, QHeaderView, QFileDialog, QMessageBox,
    QStatusBar, QMenuBar, QMenu, QTreeView, QTreeWidget, QTreeWidgetItem, QTableView
)
from PySide6.QtCore import (
    QThread, QTimer, Signal, QObject, Qt, QAbstractItemModel, QAbstractTableModel,
    QModelIndex, QSortFilterProxyModel
)
from PySide6.QtGui import QAction, QKeyEvent

import qdarktheme
# Try importing CAN libraries
try:
    import can
    import cantools
    CAN_AVAILABLE = True
except ImportError:
    CAN_AVAILABLE = False
    class can:
        class Message: pass
        class Bus: pass
    class cantools:
        class database:
            @staticmethod
            def load_file(filename):
                raise ImportError("cantools library is not installed.")

# --- Data Structures ---
TRACE_BUFFER_LIMIT = 5000

@dataclass
class CANFrame:
    timestamp: float; arbitration_id: int; data: bytes; dlc: int
    is_extended: bool = False; is_error: bool = False; is_remote: bool = False; channel: str = "CAN1"

@dataclass
class DisplayItem:
    parent: Optional['DisplayItem']; data_source: Any; is_signal: bool = False
    children: List['DisplayItem'] = field(default_factory=list); children_populated: bool = False; row_in_parent: int = 0

@dataclass
class DBCFile:
    path: Path; database: object; enabled: bool = True

@dataclass
class CANFrameFilter:
    name: str = "New Filter"; enabled: bool = True; min_id: int = 0x000; max_id: int = 0x7FF; mask: int = 0x7FF
    accept_extended: bool = True; accept_standard: bool = True; accept_data: bool = True; accept_remote: bool = True
    def matches(self, frame: CANFrame) -> bool:
        if frame.is_extended and not self.accept_extended: return False
        if not frame.is_extended and not self.accept_standard: return False
        if frame.is_remote and not self.accept_remote: return False
        if not frame.is_remote and not self.accept_data: return False
        return self.min_id <= (frame.arbitration_id & self.mask) <= self.max_id

@dataclass
class Project:
    dbcs: List[DBCFile] = field(default_factory=list)
    filters: List[CANFrameFilter] = field(default_factory=list)
    canopen_enabled: bool = True
    def get_active_dbcs(self) -> List[object]: return [dbc.database for dbc in self.dbcs if dbc.enabled]
    def get_active_filters(self) -> List[CANFrameFilter]: return [f for f in self.filters if f.enabled]

# --- Decoders ---
class CANopenDecoder:
    @staticmethod
    def decode(frame: CANFrame) -> Optional[Dict]:
        """
        Decodes a CAN frame according to CiA 301 specification for common objects.
        """
        cob_id = frame.arbitration_id

        # Handle Broadcast Objects (NMT, SYNC, TIME)
        if cob_id == 0x000: return CANopenDecoder._nmt(frame.data)
        if cob_id == 0x080: return CANopenDecoder._sync()
        if cob_id == 0x100: return CANopenDecoder._time(frame.data)

        # Handle Peer-to-Peer Objects
        node_id = cob_id & 0x7F
        if node_id == 0: return None # Invalid node ID for these objects

        function_code = cob_id & 0x780 # Mask out the Node ID to get the base function

        if function_code == 0x80: return CANopenDecoder._emcy(frame.data, node_id)
        if function_code in [0x180, 0x280, 0x380, 0x480]: return CANopenDecoder._pdo("TX", function_code, node_id)
        if function_code in [0x200, 0x300, 0x400, 0x500]: return CANopenDecoder._pdo("RX", function_code, node_id)
        if function_code == 0x580: return CANopenDecoder._sdo("TX", frame.data, node_id) # Server -> Client
        if function_code == 0x600: return CANopenDecoder._sdo("RX", frame.data, node_id) # Client -> Server
        if function_code == 0x700: return CANopenDecoder._heartbeat(frame.data, node_id)

        return None

    @staticmethod
    def _nmt(data: bytes) -> Dict:
        if len(data) != 2: return None
        cs_map = {1: "Start", 2: "Stop", 128: "Pre-Operational", 129: "Reset Node", 130: "Reset Comm"}
        cs, nid = data[0], data[1]
        target = f"Node {nid}" if nid != 0 else "All Nodes"
        return { "CANopen Type": "NMT", "Command": cs_map.get(cs, "Unknown"), "Target": target}

    @staticmethod
    def _sync() -> Dict:
        return {"CANopen Type": "SYNC"}

    @staticmethod
    def _time(data: bytes) -> Dict:
        return {"CANopen Type": "TIME", "Raw": data.hex(' ')}

    @staticmethod
    def _emcy(data: bytes, node_id: int) -> Dict:
        if len(data) != 8: return {"CANopen Type": "EMCY", "CANopen Node": node_id, "Error": "Invalid Length"}
        err_code, err_reg, _ = struct.unpack("<H B 5s", data)
        return {"CANopen Type": "EMCY", "CANopen Node": node_id, "Code": f"0x{err_code:04X}", "Register": f"0x{err_reg:02X}"}

    @staticmethod
    def _pdo(direction: str, function_code: int, node_id: int) -> Dict:
        # Calculate PDO number (1-4)
        if direction == "TX":
            pdo_num = (function_code - 0x180) // 0x100 + 1
        else: # RX
            pdo_num = (function_code - 0x200) // 0x100 + 1
        return {"CANopen Type": f"PDO{pdo_num} {direction}", "CANopen Node": node_id}

    @staticmethod
    def _sdo(direction: str, data: bytes, node_id: int) -> Dict:
        if not data: return None
        cmd = data[0]

        base_info = {"CANopen Type": f"SDO {direction}", "CANopen Node": node_id}

        # Decode based on command specifier (first 3 bits)
        specifier = (cmd >> 5) & 0x7

        # Initiate Commands (contain Index/Subindex)
        if specifier in [1, 2]: # Initiate Upload/Download
            if len(data) < 4: return base_info.update({"Error": "Invalid SDO Initiate"})
            command = "Initiate Upload" if specifier == 1 else "Initiate Download"
            idx, sub = struct.unpack_from("<HB", data, 1)
            base_info.update({"Command": command, "Index": f"0x{idx:04X}", "Sub-Index": sub})
        # Segment Commands
        elif specifier in [0, 3]:
            command = "Download Segment" if specifier == 0 else "Upload Segment"
            base_info.update({"Command": command})
        # Abort Command
        elif specifier == 4:
            if len(data) < 8: return base_info.update({"Error": "Invalid SDO Abort"})
            idx, sub, code = struct.unpack_from("<HBL", data, 1)
            base_info.update({"Command": "Abort", "Index": f"0x{idx:04X}", "Sub-Index": sub, "Code": f"0x{code:08X}"})
        else:
             base_info.update({"Command": f"Unknown ({cmd:#04x})"})

        return base_info

    @staticmethod
    def _heartbeat(data: bytes, node_id: int) -> Dict:
        if len(data) != 1: return None
        state_map = {0: "Boot-up", 4: "Stopped", 5: "Operational", 127: "Pre-operational"}
        state = data[0] & 0x7F
        return {"CANopen Type": "Heartbeat", "CANopen Node": node_id, "State": state_map.get(state, f"Unknown ({state})")}

# --- Models ---
class CANTraceModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self.frames: List[CANFrame] = []; self.headers = ["Timestamp", "ID", "Type", "DLC", "Data", "Decoded"]
        self.dbc_databases: List[object] = []; self.canopen_enabled = True
    def set_data(self, frames: List[CANFrame]): self.beginResetModel(); self.frames = frames; self.endResetModel()
    def rowCount(self, p=QModelIndex()): return len(self.frames)
    def columnCount(self, p=QModelIndex()): return len(self.headers)
    def headerData(self, s, o, r):
        if o == Qt.Horizontal and r == Qt.DisplayRole: return self.headers[s]
    def data(self, index, role):
        if not index.isValid() or role != Qt.DisplayRole: return None
        frame = self.frames[index.row()]; col = index.column()
        if col == 0: return f"{frame.timestamp:.6f}"
        if col == 1: return f"0x{frame.arbitration_id:X}"
        if col == 2: return ("Ext" if frame.is_extended else "Std") + (" RTR" if frame.is_remote else "")
        if col == 3: return str(frame.dlc)
        if col == 4: return frame.data.hex(' ')
        if col == 5: return self._decode_frame(frame)
        return None
    def _decode_frame(self, frame: CANFrame) -> str:
        decoded_parts = []
        if CAN_AVAILABLE:
            for db in self.dbc_databases:
                try:
                    message = db.get_message_by_frame_id(frame.arbitration_id)
                    decoded = db.decode_message(frame.arbitration_id, frame.data, decode_choices=False)
                    s = [f"{n}={v}" for n,v in decoded.items()]
                    decoded_parts.append(f"DBC: {message.name} {' '.join(s)}")
                    return " | ".join(decoded_parts)
                except (KeyError, ValueError): continue
        if self.canopen_enabled:
            if co_info := CANopenDecoder.decode(frame):
                details = ", ".join(f"{k}={v}" for k, v in co_info.items() if k not in ["CANopen Type"])
                decoded_parts.append(f"CANopen {co_info['CANopen Type']}: {details}")
        return " | ".join(decoded_parts)

class CANGroupedModel(QAbstractItemModel):
    # This class remains largely the same, but its _decode method is updated
    # to also call the CANopen decoder. The UI logic for tree display is robust.
    def __init__(self):
        super().__init__()
        self.headers = ["ID", "Name", "Count", "Cycle Time", "DLC", "Data"]
        self.top_level_items: List[DisplayItem] = []
        self.dbc_databases: List[object] = []; self.canopen_enabled = True
        self.frame_counts = {}; self.timestamps = {}; self.item_map = {}
    def set_dbc_databases(self, dbs: List[object]): self.dbc_databases = dbs; self.layoutChanged.emit()
    def columnCount(self, p=QModelIndex()): return len(self.headers)
    def headerData(self, s, o, r):
        if o == Qt.Horizontal and r == Qt.DisplayRole: return self.headers[s]
    def rowCount(self, p=QModelIndex()):
        if not p.isValid(): return len(self.top_level_items)
        return len(p.internalPointer().children) if p.internalPointer().children_populated else 0
    def index(self, r, c, p=QModelIndex()):
        if not self.hasIndex(r, c, p): return QModelIndex()
        parent = p.internalPointer() if p.isValid() else None
        items = self.top_level_items if not parent else parent.children
        return self.createIndex(r, c, items[r]) if r < len(items) else QModelIndex()
    def parent(self, i):
        if not i.isValid(): return QModelIndex()
        parent = i.internalPointer().parent
        return self.createIndex(parent.row_in_parent, 0, parent) if parent else QModelIndex()
    def hasChildren(self, p=QModelIndex()):
        if not p.isValid(): return True
        item = p.internalPointer()
        if item.is_signal: return False
        if item.children_populated: return len(item.children) > 0
        if self.canopen_enabled and CANopenDecoder.decode(item.data_source): return True
        for db in self.dbc_databases:
            try:
                if db.get_message_by_frame_id(item.data_source.arbitration_id): return True
            except KeyError: continue
        return False
    def canFetchMore(self, p: QModelIndex):
        return not p.internalPointer().children_populated if p.isValid() else False
    def fetchMore(self, p: QModelIndex):
        item = p.internalPointer()
        if item.children_populated: return
        signals = self._decode_frame_to_signals(item.data_source)
        if not signals: item.children_populated = True; return
        self.beginInsertRows(p, 0, len(signals) - 1)
        item.children = [DisplayItem(p,s,True,row_in_parent=i) for i,s in enumerate(signals)]
        item.children_populated = True
        self.endInsertRows()
    def _decode_frame_to_signals(self, frame: CANFrame) -> List[Dict]:
        sigs = []
        if self.canopen_enabled:
            if co_info := CANopenDecoder.decode(frame):
                sigs += [{"name": k, "value": v, "unit": ""} for k,v in co_info.items()]
        if CAN_AVAILABLE:
            for db in self.dbc_databases:
                try:
                    msg_def = db.get_message_by_frame_id(frame.arbitration_id)
                    decoded = db.decode_message(frame.arbitration_id, frame.data, decode_choices=False)
                    sigs += [{'name':s.name,'value':decoded.get(s.name,'N/A'),'unit':s.unit or ''} for s in msg_def.signals]
                except (KeyError, ValueError): continue
        return sigs
    def clear_frames(self):
        self.beginResetModel(); self.top_level_items.clear(); self.frame_counts.clear(); self.timestamps.clear(); self.item_map.clear(); self.endResetModel()
    def add_frame(self, frame: CANFrame):
        can_id = frame.arbitration_id
        if can_id not in self.item_map:
            row = len(self.top_level_items); self.beginInsertRows(QModelIndex(), row, row)
            item = DisplayItem(None, frame, row_in_parent=row)
            self.top_level_items.append(item); self.item_map[can_id] = item
            self.frame_counts[can_id] = 0; self.timestamps[can_id] = []
            self.endInsertRows()
        else:
            item = self.item_map[can_id]; item.data_source = frame; item.children_populated = False
            p_idx = self.createIndex(item.row_in_parent, 0, item)
            if item.children:
                self.beginRemoveRows(p_idx, 0, len(item.children)-1); item.children.clear(); self.endRemoveRows()
            self.dataChanged.emit(p_idx, self.index(item.row_in_parent, self.columnCount()-1))
        self.frame_counts[can_id] += 1
        self.timestamps[can_id].append(frame.timestamp)
        if len(self.timestamps[can_id]) > 10: self.timestamps[can_id].pop(0)
    def data(self, index, role):
        if not index.isValid(): return None
        item: DisplayItem = index.internalPointer(); col = index.column()
        if role == Qt.UserRole:
            if item.is_signal: return None
            return item.data_source.arbitration_id if col==0 else self.frame_counts.get(item.data_source.arbitration_id, 0)
        if role != Qt.DisplayRole: return None
        if item.is_signal:
            sig = item.data_source
            if col == 0: return f"  └ {sig['name']}"
            if col == 5: return f"{sig['value']}"
        else:
            frame: CANFrame = item.data_source; can_id = frame.arbitration_id
            if col == 0: return f"0x{can_id:X}"
            if col == 1:
                for db in self.dbc_databases:
                    try: return db.get_message_by_frame_id(can_id).name
                    except KeyError: pass
                return ""
            if col == 2: return str(self.frame_counts.get(can_id, 0))
            if col == 3:
                ts_list = self.timestamps.get(can_id, [])
                if len(ts_list) > 1: return f"{sum(ts_list[i]-ts_list[i-1] for i in range(1,len(ts_list)))/(len(ts_list)-1)*1000:.1f} ms"
                return "-"
            if col == 4: return str(frame.dlc)
            if col == 5: return frame.data.hex(' ')
        return None

# --- Hardware and Worker Threads ---

class CANReaderThread(QThread):
    """
    A robust worker thread for reading CAN frames.
    The can.Bus object is created and destroyed exclusively within this thread's run() method.
    """
    error_occurred = Signal(str)

    def __init__(self, frame_queue: deque, interface: str, channel: str):
        super().__init__()
        self.frame_queue = frame_queue
        self.interface = interface
        self.channel = channel
        self.running = False
        self.bus = None

    def start_reading(self):
        """Starts the thread's execution."""
        if not CAN_AVAILABLE:
            self.error_occurred.emit("python-can library not available")
            return False
        self.running = True
        self.start()
        return True

    def stop_reading(self):
        """
        Signals the thread to stop. Does not directly touch the bus object.
        The run() method will handle the cleanup.
        """
        self.running = False
        self.wait(500) # Wait up to 500ms for the thread to finish cleanly

    def run(self):
        """
        Main thread loop. Creates, uses, and destroys the bus object here.
        """
        try:
            self.bus = can.Bus(interface=self.interface, channel=self.channel, receive_own_messages=True)
        except Exception as e:
            self.error_occurred.emit(f"Failed to connect to CAN bus: {e}")
            self.running = False # Ensure loop doesn't run
            return

        while self.running:
            try:
                msg = self.bus.recv(timeout=0.1)
                if msg:
                    # Create the frame and append it to the thread-safe deque
                    frame = CANFrame(
                        timestamp=msg.timestamp,
                        arbitration_id=msg.arbitration_id,
                        data=msg.data,
                        dlc=msg.dlc,
                        is_extended=msg.is_extended_id,
                        is_error=msg.is_error_frame,
                        is_remote=msg.is_remote_frame
                    )
                    self.frame_queue.append(frame)
            except can.CanError as e:
                # On a bus error (like disconnect), signal the main thread and exit loop
                if self.running: # Avoid sending error if we were already asked to stop
                    self.error_occurred.emit(f"CAN bus error: {e}")
                break # Exit the loop cleanly
            except Exception as e:
                if self.running:
                    self.error_occurred.emit(f"An unexpected error occurred in CAN reader: {e}")
                break


        if self.bus:
            try:
                self.bus.shutdown()
            except Exception as e:
                # Log if shutdown fails, but don't crash
                print(f"Error shutting down CAN bus: {e}")
        self.bus = None

# --- (UI classes are mostly unchanged, ProjectExplorer gets CANopen checkbox) ---
class DBCEditor(QWidget):
    def __init__(self, dbc_file: DBCFile): super().__init__(); self.dbc_file = dbc_file; self.setup_ui()
    def setup_ui(self):
        main_layout=QVBoxLayout(self); main_layout.setContentsMargins(0,0,0,0); group=QGroupBox(f"DBC Content: {self.dbc_file.path.name}"); layout=QVBoxLayout(group); main_layout.addWidget(group); self.table=QTableWidget(); self.table.setEditTriggers(QTableWidget.NoEditTriggers); self.table.setColumnCount(4); self.table.setHorizontalHeaderLabels(["Message","ID (hex)","DLC","Signals"]); layout.addWidget(self.table); self.populate_table(); self.table.resizeColumnsToContents()
    def populate_table(self):
        messages = sorted(self.dbc_file.database.messages, key=lambda m: m.frame_id); self.table.setRowCount(len(messages))
        for r,m in enumerate(messages): self.table.setItem(r,0,QTableWidgetItem(m.name)); self.table.setItem(r,1,QTableWidgetItem(f"0x{m.frame_id:X}")); self.table.setItem(r,2,QTableWidgetItem(str(m.length))); self.table.setItem(r,3,QTableWidgetItem(", ".join(s.name for s in m.signals)))

class FilterEditor(QWidget):
    filter_changed = Signal()
    def __init__(self, can_filter: CANFrameFilter): super().__init__(); self.filter=can_filter; self.setup_ui()
    def setup_ui(self):
        main_layout=QVBoxLayout(self); main_layout.setContentsMargins(0,0,0,0); group=QGroupBox("Filter Properties"); layout=QFormLayout(group); main_layout.addWidget(group); self.name_edit=QLineEdit(self.filter.name); layout.addRow("Name:",self.name_edit); id_layout=QHBoxLayout(); self.min_id_edit=QLineEdit(f"0x{self.filter.min_id:X}"); self.max_id_edit=QLineEdit(f"0x{self.filter.max_id:X}"); self.mask_edit=QLineEdit(f"0x{self.filter.mask:X}"); id_layout.addWidget(QLabel("Min:")); id_layout.addWidget(self.min_id_edit); id_layout.addWidget(QLabel("Max:")); id_layout.addWidget(self.max_id_edit); id_layout.addWidget(QLabel("Mask:")); id_layout.addWidget(self.mask_edit); layout.addRow("ID (hex):",id_layout); self.standard_cb=QCheckBox("Standard"); self.standard_cb.setChecked(self.filter.accept_standard); self.extended_cb=QCheckBox("Extended"); self.extended_cb.setChecked(self.filter.accept_extended); self.data_cb=QCheckBox("Data"); self.data_cb.setChecked(self.filter.accept_data); self.remote_cb=QCheckBox("Remote"); self.remote_cb.setChecked(self.filter.accept_remote); type_layout=QHBoxLayout(); type_layout.addWidget(self.standard_cb); type_layout.addWidget(self.extended_cb); type_layout.addWidget(self.data_cb); type_layout.addWidget(self.remote_cb); type_layout.addStretch(); layout.addRow("Frame Types:",type_layout); self.name_edit.editingFinished.connect(self._update_filter); [w.editingFinished.connect(self._update_filter) for w in [self.min_id_edit,self.max_id_edit,self.mask_edit]]; [cb.toggled.connect(self._update_filter) for cb in [self.standard_cb,self.extended_cb,self.data_cb,self.remote_cb]]
    def _update_filter(self):
        self.filter.name=self.name_edit.text()
        try: self.filter.min_id=int(self.min_id_edit.text(),16)
        except ValueError: self.min_id_edit.setText(f"0x{self.filter.min_id:X}")
        try: self.filter.max_id=int(self.max_id_edit.text(),16)
        except ValueError: self.max_id_edit.setText(f"0x{self.filter.max_id:X}")
        try: self.filter.mask=int(self.mask_edit.text(),16)
        except ValueError: self.mask_edit.setText(f"0x{self.filter.mask:X}")
        self.filter.accept_standard=self.standard_cb.isChecked(); self.filter.accept_extended=self.extended_cb.isChecked(); self.filter.accept_data=self.data_cb.isChecked(); self.filter.accept_remote=self.remote_cb.isChecked(); self.filter_changed.emit()

class PropertiesPanel(QWidget):
    def __init__(self): super().__init__(); self.current_widget=None; self.layout=QVBoxLayout(self); self.layout.setContentsMargins(0,0,0,0); self.placeholder=QLabel("Select an item to see its properties."); self.placeholder.setAlignment(Qt.AlignCenter); self.layout.addWidget(self.placeholder)
    def show_properties(self, item: QTreeWidgetItem):
        self.clear(); data=item.data(0,Qt.UserRole) if item else None
        if isinstance(data, CANFrameFilter): editor=FilterEditor(data); editor.filter_changed.connect(lambda: item.setText(0,data.name)); self.current_widget=editor
        elif isinstance(data, DBCFile): self.current_widget=DBCEditor(data)
        else: self.layout.addWidget(self.placeholder); self.placeholder.show(); return
        self.layout.addWidget(self.current_widget)
    def clear(self):
        if self.current_widget: self.current_widget.deleteLater(); self.current_widget=None
        self.placeholder.hide()

class ProjectExplorer(QGroupBox):
    project_changed = Signal()
    def __init__(self, project: Project): super().__init__("Project Explorer"); self.project=project; self.setup_ui()
    def setup_ui(self):
        layout=QVBoxLayout(self); self.tree=QTreeWidget(); self.tree.setHeaderHidden(True); layout.addWidget(self.tree); self.tree.setContextMenuPolicy(Qt.CustomContextMenu); self.tree.customContextMenuRequested.connect(self.open_context_menu); self.tree.itemChanged.connect(self.on_item_changed); self.rebuild_tree()
    def rebuild_tree(self):
        self.tree.blockSignals(True); self.tree.clear(); self.dbc_root=self.add_item(None,"Symbol Files (.dbc)"); [self.add_item(self.dbc_root,dbc.path.name,dbc,dbc.enabled) for dbc in self.project.dbcs]; self.filter_root=self.add_item(None,"Message Filters"); [self.add_item(self.filter_root,f.name,f,f.enabled) for f in self.project.filters]
        self.co_item = self.add_item(None, "CANopen Decoding", self.project, self.project.canopen_enabled)
        self.tree.expandAll(); self.tree.blockSignals(False); self.project_changed.emit()
    def add_item(self, parent, text, data=None, checked=False):
        item=QTreeWidgetItem(parent or self.tree,[text]);
        if data: item.setData(0,Qt.UserRole,data); item.setFlags(item.flags()|Qt.ItemIsUserCheckable); item.setCheckState(0,Qt.Checked if checked else Qt.Unchecked)
        return item
    def on_item_changed(self,item,column):
        if data := item.data(0,Qt.UserRole):
            if data == self.project: self.project.canopen_enabled = item.checkState(0) == Qt.Checked
            else: data.enabled=item.checkState(0)==Qt.Checked
            self.project_changed.emit()
    def open_context_menu(self,position):
        menu=QMenu(); item=self.tree.itemAt(position)
        if not item or item==self.dbc_root: menu.addAction("Add Symbol File...").triggered.connect(self.add_dbc)
        if not item or item==self.filter_root: menu.addAction("Add Filter").triggered.connect(self.add_filter)
        if item and item.parent(): menu.addAction("Remove").triggered.connect(lambda: self.remove_item(item))
        if menu.actions(): menu.exec(self.tree.viewport().mapToGlobal(position))
    def add_dbc(self):
        fns,_ = QFileDialog.getOpenFileNames(self, "Select DBC File(s)","", "DBC Files (*.dbc);;All Files (*)")
        if fns and CAN_AVAILABLE:
            for fn in fns:
                try: self.project.dbcs.append(DBCFile(Path(fn), cantools.database.load_file(fn)))
                except Exception as e: QMessageBox.critical(self,"DBC Load Error",f"Failed to load {Path(fn).name}: {e}")
            self.rebuild_tree()
    def add_filter(self): self.project.filters.append(CANFrameFilter(name=f"Filter {len(self.project.filters)+1}")); self.rebuild_tree()
    def remove_item(self,item):
        if data:=item.data(0,Qt.UserRole):
            if isinstance(data,DBCFile): self.project.dbcs.remove(data)
            elif isinstance(data,CANFrameFilter): self.project.filters.remove(data)
            self.rebuild_tree()

class TransmitPanel(QGroupBox):
    # This class remains unchanged from the previous version
    frame_to_send=Signal(object); row_selection_changed=Signal(int,str)
    def __init__(self): super().__init__("Transmit"); self.timers:Dict[int,QTimer]={}; self.dbcs:List[object]=[]; self.setup_ui(); self.setEnabled(not CAN_AVAILABLE)
    def set_dbc_databases(self, dbs): self.dbcs = dbs
    def get_message_from_id(self, can_id):
        for db in self.dbcs:
            try: return db.get_message_by_frame_id(can_id)
            except KeyError: continue
    def setup_ui(self):
        layout=QVBoxLayout(self); ctrl_layout=QHBoxLayout(); self.add_btn=QPushButton("Add"); self.rem_btn=QPushButton("Remove"); ctrl_layout.addWidget(self.add_btn); ctrl_layout.addWidget(self.rem_btn); ctrl_layout.addStretch(); layout.addLayout(ctrl_layout); self.table=QTableWidget(); self.table.setColumnCount(8); self.table.setHorizontalHeaderLabels(["On","ID(hex)","Type","RTR","DLC","Data(hex)","Cycle","Send"]); self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents); self.table.horizontalHeader().setStretchLastSection(True); self.table.setSelectionBehavior(QTableWidget.SelectRows); layout.addWidget(self.table); self.add_btn.clicked.connect(self.add_frame); self.rem_btn.clicked.connect(self.remove_frames); self.table.currentItemChanged.connect(self._on_item_changed); self.table.cellChanged.connect(self._on_cell_changed)
    def add_frame(self): r=self.table.rowCount(); self.table.insertRow(r); self._setup_row_widgets(r)
    def remove_frames(self): [self.table.removeRow(r) for r in sorted([i.row() for i in self.table.selectionModel().selectedRows()], reverse=True)]
    def _setup_row_widgets(self, r):
        self.table.setItem(r,1,QTableWidgetItem("100")); combo=QComboBox(); combo.addItems(["Std","Ext"]); self.table.setCellWidget(r,2,combo); self.table.setItem(r,4,QTableWidgetItem("0")); self.table.setItem(r,5,QTableWidgetItem("")); self.table.setItem(r,6,QTableWidgetItem("100")); btn=QPushButton("Send"); btn.clicked.connect(partial(self.send_from_row,r)); self.table.setCellWidget(r,7,btn); cb_on=QCheckBox(); cb_on.toggled.connect(partial(self._toggle_periodic,r)); self.table.setCellWidget(r,0,self._center(cb_on)); cb_rtr=QCheckBox(); self.table.setCellWidget(r,3,self._center(cb_rtr))
    def _center(self,w): c=QWidget(); l=QHBoxLayout(c); l.addWidget(w); l.setAlignment(Qt.AlignCenter); l.setContentsMargins(0,0,0,0); return c
    def _on_item_changed(self,curr,prev):
        if curr and (not prev or curr.row()!=prev.row()): self.row_selection_changed.emit(curr.row(), self.table.item(curr.row(),1).text())
    def _on_cell_changed(self,r,c):
        if c==1: self.row_selection_changed.emit(r, self.table.item(r,1).text())
        elif c==5: self._update_dlc(r)
    def _update_dlc(self,r):
        try: self.table.item(r,4).setText(str(len(bytes.fromhex(self.table.item(r,5).text().replace(" ","")))))
        except (ValueError,TypeError): pass
    def update_row_data(self,r,data): self.table.blockSignals(True); self.table.item(r,5).setText(data.hex(" ")); self.table.item(r,4).setText(str(len(data))); self.table.blockSignals(False)
    def _toggle_periodic(self, r, state):
        if state:
            try:
                cycle = int(self.table.item(r,6).text())
                if cycle<=0: raise ValueError
                t=QTimer(self); t.timeout.connect(partial(self.send_from_row,r)); t.start(cycle); self.timers[r]=t
            except (ValueError,TypeError): QMessageBox.warning(self,"Bad Cycle",f"Row {r+1}: bad cycle time."); self.table.cellWidget(r,0).findChild(QCheckBox).setChecked(False)
        elif r in self.timers: self.timers.pop(r).stop()
    def stop_all_timers(self): [t.stop() for t in self.timers.values()]; self.timers.clear(); [self.table.cellWidget(r,0).findChild(QCheckBox).setChecked(False) for r in range(self.table.rowCount())]
    def send_from_row(self, r):
        try: self.frame_to_send.emit(can.Message(arbitration_id=int(self.table.item(r,1).text(),16),is_extended_id=self.table.cellWidget(r,2).currentIndex()==1,is_remote_frame=self.table.cellWidget(r,3).findChild(QCheckBox).isChecked(),dlc=int(self.table.item(r,4).text()),data=bytes.fromhex(self.table.item(r,5).text().replace(" ",""))))
        except(ValueError,TypeError) as e: QMessageBox.warning(self,"Bad Tx Data",f"Row {r+1}: {e}"); self._toggle_periodic(r,False)
    def send_selected(self): [self.send_from_row(r) for r in sorted({i.row() for i in self.table.selectionModel().selectedIndexes()})]

class SignalTransmitPanel(QGroupBox):
    # This class remains unchanged from the previous version
    data_encoded=Signal(bytes)
    def __init__(self): super().__init__("Signal Config"); self.message=None; self.setup_ui()
    def setup_ui(self):
        layout=QVBoxLayout(self); self.table=QTableWidget(); self.table.setColumnCount(3); self.table.setHorizontalHeaderLabels(["Signal","Value","Unit"]); self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents); self.table.horizontalHeader().setStretchLastSection(True); layout.addWidget(self.table); self.table.cellChanged.connect(self._encode)
    def clear_panel(self): self.message=None; self.table.setRowCount(0); self.setTitle("Signal Config"); self.setVisible(False)
    def populate(self,msg):
        self.message=msg; self.table.blockSignals(True); self.table.setRowCount(len(msg.signals))
        for r,s in enumerate(msg.signals): self.table.setItem(r,0,QTableWidgetItem(s.name)); self.table.item(r,0).setFlags(Qt.ItemIsEnabled|Qt.ItemIsSelectable); self.table.setItem(r,1,QTableWidgetItem(str(s.initial if s.initial is not None else 0))); self.table.setItem(r,2,QTableWidgetItem(str(s.unit or ''))); self.table.item(r,2).setFlags(Qt.ItemIsEnabled|Qt.ItemIsSelectable)
        self.table.blockSignals(False); self.setTitle(f"Signal Config: {msg.name}"); self.setVisible(True); self._encode()
    def _encode(self):
        if not self.message: return
        try: self.data_encoded.emit(self.message.encode({self.table.item(r,0).text():float(self.table.item(r,1).text()) for r in range(self.table.rowCount())}, strict=True))
        except(ValueError,TypeError,KeyError): pass

# --- Main Application Window ---
class CANBusObserver(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle("CAN Bus Observer"); self.setGeometry(100, 100, 1400, 900)
        self.project = Project()
        self.trace_model = CANTraceModel(); self.grouped_model = CANGroupedModel()
        self.grouped_proxy_model = QSortFilterProxyModel(); self.grouped_proxy_model.setSourceModel(self.grouped_model); self.grouped_proxy_model.setSortRole(Qt.UserRole)
        self.can_reader = None; self.frame_queue = deque(); self.all_received_frames = []
        self.setup_ui(); self.setup_menubar(); self.setup_statusbar()
        self.gui_update_timer = QTimer(self); self.gui_update_timer.timeout.connect(self.update_views); self.gui_update_timer.start(50)
    def setup_ui(self):
        central_widget = QWidget(); self.setCentralWidget(central_widget); layout = QVBoxLayout(central_widget)
        toolbar_layout = QHBoxLayout(); self.connect_btn = QPushButton("Connect"); self.disconnect_btn = QPushButton("Disconnect", enabled=False)
        self.interface_combo = QComboBox(); self.interface_combo.addItems(["socketcan", "pcan", "kvaser", "vector", "virtual"]); self.channel_edit = QLineEdit("can0")
        toolbar_layout.addWidget(QLabel("Interface:")); toolbar_layout.addWidget(self.interface_combo); toolbar_layout.addWidget(QLabel("Channel:")); toolbar_layout.addWidget(self.channel_edit)
        toolbar_layout.addWidget(self.connect_btn); toolbar_layout.addWidget(self.disconnect_btn); toolbar_layout.addStretch(); layout.addLayout(toolbar_layout)
        main_splitter = QSplitter(Qt.Horizontal); layout.addWidget(main_splitter)
        left_pane = QWidget(); left_layout = QVBoxLayout(left_pane); left_layout.setContentsMargins(0,0,0,0)
        left_splitter = QSplitter(Qt.Vertical)
        receive_widget = QWidget(); receive_layout = QVBoxLayout(receive_widget); receive_layout.setContentsMargins(0,0,0,0)
        control_layout = QHBoxLayout(); self.clear_btn = QPushButton("Clear"); self.save_log_btn = QPushButton("Save Log"); self.load_log_btn = QPushButton("Load Log")
        control_layout.addWidget(self.clear_btn); control_layout.addWidget(self.save_log_btn); control_layout.addWidget(self.load_log_btn); control_layout.addStretch()
        receive_layout.addLayout(control_layout)
        self.tab_widget = QTabWidget()
        trace_view_widget = QWidget(); trace_layout = QVBoxLayout(trace_view_widget); trace_layout.setContentsMargins(0,0,0,0)
        self.trace_view = QTableView(); self.trace_view.setModel(self.trace_model); self.trace_view.setAlternatingRowColors(True)
        self.trace_view.horizontalHeader().setStretchLastSection(True)
        self.autoscroll_cb = QCheckBox("Autoscroll", checked=True); trace_layout.addWidget(self.trace_view); trace_layout.addWidget(self.autoscroll_cb); self.tab_widget.addTab(trace_view_widget, "Trace")
        self.grouped_view = QTreeView(); self.grouped_view.setModel(self.grouped_proxy_model); self.grouped_view.setAlternatingRowColors(True); self.grouped_view.setSortingEnabled(True)
        self.tab_widget.addTab(self.grouped_view, "Grouped")
        receive_layout.addWidget(self.tab_widget); left_splitter.addWidget(receive_widget)
        transmit_area = QWidget(); transmit_layout = QVBoxLayout(transmit_area); transmit_layout.setContentsMargins(0,0,0,0)
        self.transmit_panel = TransmitPanel(); self.transmit_panel.setEnabled(False)
        self.signal_transmit_panel = SignalTransmitPanel(); self.signal_transmit_panel.setVisible(False)
        transmit_layout.addWidget(self.transmit_panel); transmit_layout.addWidget(self.signal_transmit_panel); left_splitter.addWidget(transmit_area)
        left_splitter.setSizes([600, 300])
        left_layout.addWidget(left_splitter); main_splitter.addWidget(left_pane)
        right_pane = QWidget(); right_layout = QVBoxLayout(right_pane); right_layout.setContentsMargins(0,0,0,0)
        right_splitter = QSplitter(Qt.Vertical)
        self.project_explorer = ProjectExplorer(self.project); right_splitter.addWidget(self.project_explorer)
        self.properties_panel = PropertiesPanel(); right_splitter.addWidget(self.properties_panel)
        right_splitter.setSizes([400, 300])
        right_layout.addWidget(right_splitter); main_splitter.addWidget(right_pane)
        main_splitter.setSizes([900, 500])
        self.connect_btn.clicked.connect(self.connect_can); self.disconnect_btn.clicked.connect(self.disconnect_can); self.clear_btn.clicked.connect(self.clear_data); self.save_log_btn.clicked.connect(self.save_log); self.load_log_btn.clicked.connect(self.load_log)
        self.transmit_panel.frame_to_send.connect(self.send_can_frame); self.transmit_panel.row_selection_changed.connect(self.on_transmit_row_selected); self.signal_transmit_panel.data_encoded.connect(self.on_signal_data_encoded)
        self.project_explorer.project_changed.connect(self.on_project_changed); self.project_explorer.tree.currentItemChanged.connect(self.properties_panel.show_properties)
        if not CAN_AVAILABLE: self.connect_btn.setEnabled(False); self.connect_btn.setText("Connect (lib missing)"); self.statusBar().showMessage("python-can or cantools not found. Functionality limited.")
    def setup_menubar(self):
        menubar=self.menuBar(); file_menu=menubar.addMenu("File"); load_action=QAction("Load Log...",self); load_action.triggered.connect(self.load_log); file_menu.addAction(load_action); save_action=QAction("Save Log...",self); save_action.triggered.connect(self.save_log); file_menu.addAction(save_action); file_menu.addSeparator(); exit_action=QAction("Exit",self); exit_action.triggered.connect(self.close); file_menu.addAction(exit_action)
    def setup_statusbar(self):
        self.statusBar().showMessage("Ready"); self.frame_count_label = QLabel("Frames: 0"); self.connection_label = QLabel("Disconnected"); self.statusBar().addPermanentWidget(self.frame_count_label); self.statusBar().addPermanentWidget(self.connection_label)
    def keyPressEvent(self, event: QKeyEvent):
        if event.key() == Qt.Key_Space and self.transmit_panel.table.hasFocus(): self.transmit_panel.send_selected(); event.accept()
        else: super().keyPressEvent(event)
    def update_views(self):
        if not self.frame_queue: return
        new_frames = [self.frame_queue.popleft() for _ in range(len(self.frame_queue))]
        active_filters = self.project.get_active_filters()
        filtered_frames = [f for f in new_frames if not active_filters or any(filt.matches(f) for filt in active_filters)]
        for frame in filtered_frames: self.grouped_model.add_frame(frame)
        self.all_received_frames.extend(filtered_frames)
        self.trace_model.set_data(self.all_received_frames[-TRACE_BUFFER_LIMIT:])
        if self.autoscroll_cb.isChecked(): self.trace_view.scrollToBottom()
        self.frame_count_label.setText(f"Frames: {len(self.all_received_frames)}")
    def on_project_changed(self):
        active_dbcs = self.project.get_active_dbcs()
        self.trace_model.dbc_databases = active_dbcs; self.trace_model.canopen_enabled = self.project.canopen_enabled; self.trace_model.layoutChanged.emit()
        self.grouped_model.set_dbc_databases(active_dbcs); self.grouped_model.canopen_enabled = self.project.canopen_enabled
        self.transmit_panel.set_dbc_databases(active_dbcs)
        current_item = self.transmit_panel.table.currentItem()
        self.on_transmit_row_selected(self.transmit_panel.table.currentRow(), current_item.text() if current_item else "")
    def on_transmit_row_selected(self, row, id_text):
        self.signal_transmit_panel.clear_panel()
        if row < 0 or not id_text: return
        try:
            if message := self.transmit_panel.get_message_from_id(int(id_text, 16)):
                self.signal_transmit_panel.populate(message)
        except ValueError: pass
    def on_signal_data_encoded(self, data_bytes):
        if (row := self.transmit_panel.table.currentRow()) >= 0: self.transmit_panel.update_row_data(row, data_bytes)
    def connect_can(self):
        self.can_reader = CANReaderThread(self.frame_queue, self.interface_combo.currentText(), self.channel_edit.text())
        self.can_reader.error_occurred.connect(self.on_can_error)
        if self.can_reader.start_reading():
            self.connect_btn.setEnabled(False); self.disconnect_btn.setEnabled(True); self.transmit_panel.setEnabled(True)
            self.connection_label.setText(f"Connected ({self.interface_combo.currentText()}:{self.channel_edit.text()})")
        else: self.can_reader = None
    def disconnect_can(self):
        if self.can_reader: self.can_reader.stop_reading(); self.can_reader = None
        self.connect_btn.setEnabled(True); self.disconnect_btn.setEnabled(False); self.transmit_panel.setEnabled(False); self.transmit_panel.stop_all_timers(); self.connection_label.setText("Disconnected")
    def send_can_frame(self, message: can.Message):
        if self.can_reader and self.can_reader.bus:
            try: self.can_reader.bus.send(message)
            except Exception as e: QMessageBox.critical(self, "Transmit Error", f"Failed to send frame: {e}")
        else: QMessageBox.warning(self, "Not Connected", "Connect to a CAN bus before sending frames.")
    def on_can_error(self, error_message: str):
        QMessageBox.warning(self, "CAN Error", error_message); self.statusBar().showMessage(f"Error: {error_message}"); self.disconnect_can()
    def clear_data(self):
        self.all_received_frames.clear(); self.grouped_model.clear_frames(); self.trace_model.set_data([])
        self.frame_count_label.setText("Frames: 0")
    def save_log(self):
        if not self.all_received_frames: QMessageBox.information(self, "No Data", "No frames to save"); return
        filename, _ = QFileDialog.getSaveFileName(self, "Save CAN Log", "", "CAN Log Files (*.log);;All Files (*)")
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("# CAN Bus Log File\n# Format: timestamp id is_ext dlc data\n")
                    for frame in self.all_received_frames:
                        f.write(f"{frame.timestamp:.6f} {frame.arbitration_id:X} {'E' if frame.is_extended else 'S'} {frame.dlc} {frame.data.hex(' ')}\n")
                self.statusBar().showMessage(f"Log saved to {filename}")
            except Exception as e: QMessageBox.critical(self, "Save Error", f"Failed to save log: {e}")
    def load_log(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Load CAN Log", "", "CAN Log Files (*.log);;All Files (*)")
        if filename:
            try:
                self.clear_data(); frames_to_add = []
                with open(filename, 'r') as f:
                    for line in f:
                        if line.startswith('#') or not line.strip(): continue
                        parts = line.split()
                        try:
                            ts, id_hex, type_char, dlc_str, *data_hex = parts
                            frames_to_add.append(CANFrame(float(ts), int(id_hex,16), bytes.fromhex("".join(data_hex)), int(dlc_str), type_char=='E'))
                        except (ValueError, IndexError): print(f"Warning: Invalid line in log file: {line.strip()}")
                self.frame_queue.extend(frames_to_add)
                self.update_views()
                self.statusBar().showMessage(f"Loaded {len(self.all_received_frames)} frames from {filename}")
            except Exception as e: QMessageBox.critical(self, "Load Error", f"Failed to load log: {e}")
    def closeEvent(self, event): self.disconnect_can(); event.accept()

def main():
    app = QApplication(sys.argv)
    window = CANBusObserver()
    qdarktheme.setup_theme("auto")
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
