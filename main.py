#!/usr/bin/env python3
"""
CAN Bus Observer GUI - Similar to PCAN-Explorer
Features:
- Project-based configuration with Tree View
- Multi-DBC and Multi-Filter support
- DBC content viewer
- Frame view grouped by ID or chronological trace
- DBC decoding and signal-based transmitting
- CAN log file saving/loading
- Real-time monitoring
"""

import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from functools import partial

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QTabWidget, QPushButton, QLabel,
    QLineEdit, QCheckBox, QComboBox, QSpinBox, QSplitter,
    QGroupBox, QFormLayout, QHeaderView, QFileDialog, QMessageBox,
    QStatusBar, QMenuBar, QMenu, QTableView, QTreeWidget, QTreeWidgetItem
)
from PySide6.QtCore import (
    QThread, QTimer, Signal, QObject, Qt, QAbstractTableModel,
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

@dataclass
class CANFrame:
    """CAN Frame data structure"""
    timestamp: float; arbitration_id: int; data: bytes; dlc: int
    is_extended: bool = False; is_error: bool = False; is_remote: bool = False; channel: str = "CAN1"

@dataclass
class DBCFile:
    """Represents a loaded DBC file and its state."""
    path: Path
    database: object  # cantools.database.Database
    enabled: bool = True

@dataclass
class CANFrameFilter:
    """CAN Frame filter configuration with a name."""
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
        if frame.is_extended and not self.accept_extended: return False
        if not frame.is_extended and not self.accept_standard: return False
        if frame.is_remote and not self.accept_remote: return False
        if not frame.is_remote and not self.accept_data: return False
        masked_id = frame.arbitration_id & self.mask
        return self.min_id <= masked_id <= self.max_id

@dataclass
class Project:
    """Central data model for the application's configuration."""
    dbcs: List[DBCFile] = field(default_factory=list)
    filters: List[CANFrameFilter] = field(default_factory=list)

    def get_active_dbcs(self) -> List[object]:
        return [dbc.database for dbc in self.dbcs if dbc.enabled]

    def get_active_filters(self) -> List[CANFrameFilter]:
        return [f for f in self.filters if f.enabled]

# --- Models ---

class CANTraceModel(QAbstractTableModel):
    """Table model for CAN trace view"""
    def __init__(self):
        super().__init__()
        self.frames: List[CANFrame] = []
        self.headers = ["Timestamp", "ID", "Type", "DLC", "Data", "Decoded"]
        self.dbc_databases: List[object] = []
        self.show_canopen = False
    def set_dbc_databases(self, dbs: List[object]):
        self.dbc_databases = dbs; self.modelReset.emit()
    def set_canopen_enabled(self, enabled: bool):
        self.show_canopen = enabled; self.modelReset.emit()
    def add_frame(self, frame: CANFrame):
        self.beginInsertRows(QModelIndex(), len(self.frames), len(self.frames)); self.frames.append(frame); self.endInsertRows()
    def clear_frames(self):
        self.beginResetModel(); self.frames.clear(); self.endResetModel()
    def rowCount(self, parent=QModelIndex()): return len(self.frames)
    def columnCount(self, parent=QModelIndex()): return len(self.headers)
    def headerData(self, section, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole: return self.headers[section]
    def data(self, index, role):
        if not index.isValid() or index.row() >= len(self.frames): return None
        frame = self.frames[index.row()]; col = index.column()
        if role == Qt.DisplayRole:
            if col == 0: return f"{frame.timestamp:.6f}"
            if col == 1: return f"0x{frame.arbitration_id:X}"
            if col == 2: return ("Ext" if frame.is_extended else "Std") + (" RTR" if frame.is_remote else "")
            if col == 3: return str(frame.dlc)
            if col == 4: return " ".join(f"{b:02X}" for b in frame.data)
            if col == 5: return self._decode_frame(frame)
        return None
    def _decode_frame(self, frame: CANFrame) -> str:
        decoded_parts = []
        if CAN_AVAILABLE:
            for db in self.dbc_databases:
                try:
                    message = db.get_message_by_frame_id(frame.arbitration_id)
                    decoded_signals = db.decode_message(frame.arbitration_id, frame.data, decode_choices=False)
                    signal_strs = [f"{name}={value}" for name, value in decoded_signals.items()]
                    decoded_parts.append(f"DBC: {message.name} {' '.join(signal_strs)}")
                    break # Stop after first successful decode
                except KeyError: continue
                except Exception as e: print(f"DBC decoding error for ID 0x{frame.arbitration_id:X}: {e}")
        if self.show_canopen:
            if canopen_data := CANopenDecoder.decode_frame(frame): decoded_parts.append(f"CANopen: {canopen_data}")
        return " | ".join(decoded_parts) if decoded_parts else ""

class CANGroupedModel(CANTraceModel):
    """Table model for grouped CAN frames by ID. Inherits decoding logic."""
    def __init__(self):
        super().__init__()
        self.grouped_frames: Dict[int, List[CANFrame]] = {}; self.id_order: List[int] = []
        self.headers = ["ID", "Name", "DLC", "Data", "Decoded", "Count", "Cycle Time", "Last"]
    def add_frame(self, frame: CANFrame):
        if frame.arbitration_id not in self.grouped_frames:
            row = len(self.id_order)
            self.beginInsertRows(QModelIndex(), row, row)
            self.grouped_frames[frame.arbitration_id] = [frame]; self.id_order.append(frame.arbitration_id)
            self.endInsertRows()
        else:
            self.grouped_frames[frame.arbitration_id].append(frame)
            row = self.id_order.index(frame.arbitration_id)
            self.dataChanged.emit(self.index(row, 0), self.index(row, self.columnCount()-1))
    def clear_frames(self):
        self.beginResetModel(); self.grouped_frames.clear(); self.id_order.clear(); self.endResetModel()
    def rowCount(self, parent=QModelIndex()): return len(self.id_order)
    def columnCount(self, parent=QModelIndex()): return len(self.headers)
    def data(self, index, role):
        if not index.isValid() or index.row() >= len(self.id_order): return None
        can_id = self.id_order[index.row()]; frames = self.grouped_frames[can_id]; latest_frame = frames[-1]; col = index.column()
        if role == Qt.UserRole:
            if col == 0: return can_id
            if col == 2: return latest_frame.dlc
            if col == 5: return len(frames)
            if col == 6:
                if len(frames) > 1:
                    relevant = frames[-10:]
                    if len(relevant) > 1: return sum(relevant[i].timestamp - relevant[i-1].timestamp for i in range(1, len(relevant))) / (len(relevant)-1)
                return 0.0
            if col == 7: return latest_frame.timestamp
        if role == Qt.DisplayRole:
            if col == 0: return f"0x{can_id:X}"
            if col == 1:
                if CAN_AVAILABLE:
                    for db in self.dbc_databases:
                        try: return db.get_message_by_frame_id(can_id).name
                        except KeyError: pass
                return ""
            if col == 2: return str(latest_frame.dlc)
            if col == 3: return " ".join(f"{b:02X}" for b in latest_frame.data)
            if col == 4:
                decoded = self._decode_frame(latest_frame)
                return decoded.replace(f"DBC: {self.data(index.siblingAtColumn(1), Qt.DisplayRole)} ", "") if decoded else ""
            if col == 5: return str(len(frames))
            if col == 6:
                if len(frames) > 1:
                    relevant = frames[-10:]
                    if len(relevant) > 1: return f"{sum(relevant[i].timestamp - relevant[i-1].timestamp for i in range(1, len(relevant))) / (len(relevant)-1) * 1000:.1f} ms"
                return "-"
            if col == 7: return f"{latest_frame.timestamp:.6f}"
        return None

# --- Hardware and Worker Threads ---

class CANReaderThread(QThread):
    """Thread for reading CAN frames"""
    frame_received = Signal(CANFrame)
    error_occurred = Signal(str)
    def __init__(self, interface="socketcan", channel="vcan0"):
        super().__init__(); self.interface, self.channel, self.running, self.bus = interface, channel, False, None
    def start_reading(self):
        if not CAN_AVAILABLE: self.error_occurred.emit("python-can library not available"); return False
        try:
            self.bus = can.Bus(interface=self.interface, channel=self.channel, receive_own_messages=True)
            self.running = True; self.start(); return True
        except Exception as e: self.error_occurred.emit(f"Failed to connect to CAN bus: {e}"); return False
    def stop_reading(self):
        self.running = False
        if self.bus: self.bus.shutdown()
        self.wait()
    def run(self):
        while self.running and self.bus:
            try:
                if message := self.bus.recv(timeout=0.1):
                    frame = CANFrame(timestamp=message.timestamp, arbitration_id=message.arbitration_id, data=message.data, dlc=message.dlc, is_extended=message.is_extended_id, is_error=message.is_error_frame, is_remote=message.is_remote_frame)
                    self.frame_received.emit(frame)
            except Exception as e:
                if self.running: self.error_occurred.emit(f"CAN read error: {e}"); break

# --- UI Components ---
class DBCEditor(QWidget):
    """Widget for displaying the contents of a DBC file."""
    def __init__(self, dbc_file: DBCFile):
        super().__init__()
        self.dbc_file = dbc_file
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self); main_layout.setContentsMargins(0,0,0,0)
        group = QGroupBox(f"DBC Content: {self.dbc_file.path.name}"); layout = QVBoxLayout(group); main_layout.addWidget(group)
        self.table = QTableWidget(); self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setColumnCount(4); self.table.setHorizontalHeaderLabels(["Message", "ID (hex)", "DLC", "Signals"])
        layout.addWidget(self.table)
        self.populate_table()
        self.table.resizeColumnsToContents()

    def populate_table(self):
        messages = sorted(self.dbc_file.database.messages, key=lambda m: m.frame_id)
        self.table.setRowCount(len(messages))
        for row, msg in enumerate(messages):
            signals_str = ", ".join(s.name for s in msg.signals)
            self.table.setItem(row, 0, QTableWidgetItem(msg.name))
            self.table.setItem(row, 1, QTableWidgetItem(f"0x{msg.frame_id:X}"))
            self.table.setItem(row, 2, QTableWidgetItem(str(msg.length)))
            self.table.setItem(row, 3, QTableWidgetItem(signals_str))

class FilterEditor(QWidget):
    """Widget for editing a CANFrameFilter object."""
    filter_changed = Signal()
    def __init__(self, can_filter: CANFrameFilter):
        super().__init__()
        self.filter = can_filter
        self.setup_ui()
    def setup_ui(self):
        main_layout = QVBoxLayout(self); main_layout.setContentsMargins(0,0,0,0)
        group = QGroupBox("Filter Properties"); layout = QFormLayout(group); main_layout.addWidget(group)
        self.name_edit = QLineEdit(self.filter.name); layout.addRow("Name:", self.name_edit)
        id_layout = QHBoxLayout(); self.min_id_edit = QLineEdit(f"0x{self.filter.min_id:X}"); self.max_id_edit = QLineEdit(f"0x{self.filter.max_id:X}"); self.mask_edit = QLineEdit(f"0x{self.filter.mask:X}")
        id_layout.addWidget(QLabel("Min:")); id_layout.addWidget(self.min_id_edit); id_layout.addWidget(QLabel("Max:")); id_layout.addWidget(self.max_id_edit); id_layout.addWidget(QLabel("Mask:")); id_layout.addWidget(self.mask_edit); layout.addRow("ID (hex):", id_layout)
        self.standard_cb = QCheckBox("Standard"); self.standard_cb.setChecked(self.filter.accept_standard)
        self.extended_cb = QCheckBox("Extended"); self.extended_cb.setChecked(self.filter.accept_extended)
        self.data_cb = QCheckBox("Data"); self.data_cb.setChecked(self.filter.accept_data)
        self.remote_cb = QCheckBox("Remote"); self.remote_cb.setChecked(self.filter.accept_remote)
        type_layout = QHBoxLayout(); type_layout.addWidget(self.standard_cb); type_layout.addWidget(self.extended_cb); type_layout.addWidget(self.data_cb); type_layout.addWidget(self.remote_cb); type_layout.addStretch(); layout.addRow("Frame Types:", type_layout)
        # Connect signals
        self.name_edit.editingFinished.connect(self._update_filter)
        for w in [self.min_id_edit, self.max_id_edit, self.mask_edit]: w.editingFinished.connect(self._update_filter)
        for cb in [self.standard_cb, self.extended_cb, self.data_cb, self.remote_cb]: cb.toggled.connect(self._update_filter)
    def _update_filter(self):
        self.filter.name = self.name_edit.text()
        try: self.filter.min_id = int(self.min_id_edit.text(), 16)
        except ValueError: self.min_id_edit.setText(f"0x{self.filter.min_id:X}") # Revert on bad value
        try: self.filter.max_id = int(self.max_id_edit.text(), 16)
        except ValueError: self.max_id_edit.setText(f"0x{self.filter.max_id:X}")
        try: self.filter.mask = int(self.mask_edit.text(), 16)
        except ValueError: self.mask_edit.setText(f"0x{self.filter.mask:X}")
        self.filter.accept_standard = self.standard_cb.isChecked()
        self.filter.accept_extended = self.extended_cb.isChecked()
        self.filter.accept_data = self.data_cb.isChecked()
        self.filter.accept_remote = self.remote_cb.isChecked()
        self.filter_changed.emit()

class PropertiesPanel(QWidget):
    """Shows editors for items selected in the ProjectExplorer."""
    def __init__(self):
        super().__init__(); self.current_widget = None
        self.layout = QVBoxLayout(self); self.layout.setContentsMargins(0,0,0,0)
        self.placeholder = QLabel("Select an item in the Project Explorer to see its properties."); self.placeholder.setAlignment(Qt.AlignCenter); self.layout.addWidget(self.placeholder)
    def show_properties(self, item: QTreeWidgetItem):
        self.clear()
        data = item.data(0, Qt.UserRole) if item else None
        if isinstance(data, CANFrameFilter):
            editor = FilterEditor(data)
            editor.filter_changed.connect(lambda: item.setText(0, data.name)) # Update tree name
            self.current_widget = editor
        elif isinstance(data, DBCFile):
            self.current_widget = DBCEditor(data)
        else: # No item or an unconfigurable one
            self.layout.addWidget(self.placeholder); self.placeholder.show()
            return
        self.layout.addWidget(self.current_widget)
    def clear(self):
        if self.current_widget: self.current_widget.deleteLater(); self.current_widget = None
        self.placeholder.hide()

class ProjectExplorer(QGroupBox):
    """Tree view for managing project configurations like DBCs and Filters."""
    project_changed = Signal()
    def __init__(self, project: Project):
        super().__init__("Project Explorer"); self.project = project; self.setup_ui()
    def setup_ui(self):
        layout = QVBoxLayout(self)
        self.tree = QTreeWidget(); self.tree.setHeaderHidden(True); layout.addWidget(self.tree)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.open_context_menu)
        self.tree.itemChanged.connect(self.on_item_changed)
        self.rebuild_tree()
    def rebuild_tree(self):
        self.tree.blockSignals(True)
        self.tree.clear()
        self.dbc_root = self.add_item(None, "Symbol Files (.dbc)")
        for dbc_file in self.project.dbcs: self.add_item(self.dbc_root, dbc_file.path.name, dbc_file, dbc_file.enabled)
        self.filter_root = self.add_item(None, "Message Filters")
        for can_filter in self.project.filters: self.add_item(self.filter_root, can_filter.name, can_filter, can_filter.enabled)
        self.tree.expandAll()
        self.tree.blockSignals(False)
        self.project_changed.emit()
    def add_item(self, parent, text, data=None, checked=False):
        item = QTreeWidgetItem(parent or self.tree, [text])
        if data:
            item.setData(0, Qt.UserRole, data)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(0, Qt.Checked if checked else Qt.Unchecked)
        return item
    def on_item_changed(self, item, column):
        data = item.data(0, Qt.UserRole)
        if data: data.enabled = item.checkState(0) == Qt.Checked; self.project_changed.emit()
    def open_context_menu(self, position):
        menu = QMenu()
        item = self.tree.itemAt(position)
        if not item or item == self.dbc_root: menu.addAction("Add Symbol File...").triggered.connect(self.add_dbc)
        if not item or item == self.filter_root: menu.addAction("Add Filter").triggered.connect(self.add_filter)
        if item and item.parent(): menu.addAction("Remove").triggered.connect(lambda: self.remove_item(item))
        if menu.actions(): menu.exec(self.tree.viewport().mapToGlobal(position))
    def add_dbc(self):
        filenames, _ = QFileDialog.getOpenFileNames(self, "Select DBC File(s)", "", "DBC Files (*.dbc);;All Files (*)")
        if not filenames or not CAN_AVAILABLE: return
        for fn in filenames:
            path = Path(fn)
            try:
                db = cantools.database.load_file(path)
                self.project.dbcs.append(DBCFile(path=path, database=db))
            except Exception as e: QMessageBox.critical(self, "DBC Load Error", f"Failed to load {path.name}: {e}")
        self.rebuild_tree()
    def add_filter(self):
        new_filter = CANFrameFilter(name=f"Filter {len(self.project.filters) + 1}")
        self.project.filters.append(new_filter); self.rebuild_tree()
    def remove_item(self, item):
        data = item.data(0, Qt.UserRole)
        if isinstance(data, DBCFile): self.project.dbcs.remove(data)
        elif isinstance(data, CANFrameFilter): self.project.filters.remove(data)
        self.rebuild_tree()

class TransmitPanel(QGroupBox):
    frame_to_send = Signal(object)
    row_selection_changed = Signal(int, str)
    def __init__(self):
        super().__init__("Transmit"); self.timers: Dict[int, QTimer] = {}; self.dbcs: List[object] = []
        self.setup_ui()
        if not CAN_AVAILABLE: self.setEnabled(False); self.setTitle("Transmit (python-can not available)")
    def set_dbc_databases(self, dbs: List[object]): self.dbcs = dbs
    def get_message_from_id(self, can_id: int):
        for db in self.dbcs:
            try: return db.get_message_by_frame_id(can_id)
            except KeyError: continue
        return None
    def setup_ui(self):
        layout = QVBoxLayout(self)
        control_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add Frame"); self.remove_btn = QPushButton("Remove Selected")
        control_layout.addWidget(self.add_btn); control_layout.addWidget(self.remove_btn); control_layout.addStretch()
        layout.addLayout(control_layout)
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(["Enable", "ID (hex)", "Type", "RTR", "DLC", "Data (hex)", "Cycle (ms)", "Send"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.table)
        self.add_btn.clicked.connect(self.add_frame)
        self.remove_btn.clicked.connect(self.remove_selected_frames)
        self.table.currentItemChanged.connect(self._on_current_item_changed)
        self.table.cellChanged.connect(self._on_cell_changed)
    def add_frame(self):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self._setup_row_widgets(row)
    def remove_selected_frames(self):
        selected_rows = sorted([index.row() for index in self.table.selectionModel().selectedRows()], reverse=True)
        for row in selected_rows:
            self._stop_timer_for_row(row)
            self.table.removeRow(row)
    def _setup_row_widgets(self, row):
        self.table.setItem(row, 1, QTableWidgetItem("100"))
        type_combo = QComboBox(); type_combo.addItems(["Standard", "Extended"]); self.table.setCellWidget(row, 2, type_combo)
        self.table.setItem(row, 4, QTableWidgetItem("0"))
        self.table.setItem(row, 5, QTableWidgetItem(""))
        self.table.setItem(row, 6, QTableWidgetItem("100"))
        send_btn = QPushButton("Send"); send_btn.clicked.connect(partial(self.send_frame_from_row, row)); self.table.setCellWidget(row, 7, send_btn)
        enable_cb = QCheckBox(); enable_cb.toggled.connect(partial(self._toggle_periodic, row)); self.table.setCellWidget(row, 0, self._center_widget(enable_cb))
        rtr_cb = QCheckBox(); self.table.setCellWidget(row, 3, self._center_widget(rtr_cb))
    def _center_widget(self, widget):
        cell_widget = QWidget(); layout = QHBoxLayout(cell_widget); layout.addWidget(widget); layout.setAlignment(Qt.AlignCenter); layout.setContentsMargins(0,0,0,0); return cell_widget
    def _on_current_item_changed(self, current, previous):
        if current and (not previous or current.row() != previous.row()):
            self.row_selection_changed.emit(current.row(), self.table.item(current.row(), 1).text())
    def _on_cell_changed(self, row, column):
        if column == 1: self.row_selection_changed.emit(row, self.table.item(row, 1).text())
        elif column == 5: self._update_dlc_from_data(row)
    def _update_dlc_from_data(self, row):
        try:
            data_len = len(bytes.fromhex(self.table.item(row, 5).text().replace(" ", "")))
            if data_len <= 8: self.table.item(row, 4).setText(str(data_len))
        except (ValueError, TypeError): pass
    def update_row_data(self, row, data_bytes):
        self.table.blockSignals(True)
        self.table.item(row, 5).setText(data_bytes.hex(' '))
        self.table.item(row, 4).setText(str(len(data_bytes)))
        self.table.blockSignals(False)
    def _toggle_periodic(self, row, state):
        if state:
            try:
                cycle_ms = int(self.table.item(row, 6).text())
                if cycle_ms <= 0: raise ValueError
                timer = QTimer(self); timer.timeout.connect(partial(self.send_frame_from_row, row)); timer.start(cycle_ms); self.timers[row] = timer
            except (ValueError, TypeError):
                QMessageBox.warning(self, "Invalid Cycle Time", f"Row {row+1}: Cycle time must be a positive number."); self.table.cellWidget(row, 0).findChild(QCheckBox).setChecked(False)
        else: self._stop_timer_for_row(row)
    def _stop_timer_for_row(self, row):
        if row in self.timers: self.timers.pop(row).stop()
    def stop_all_timers(self):
        for timer in self.timers.values(): timer.stop(); self.timers.clear()
        for r in range(self.table.rowCount()): self.table.cellWidget(r, 0).findChild(QCheckBox).setChecked(False)
    def send_frame_from_row(self, row):
        try:
            message = can.Message(
                arbitration_id=int(self.table.item(row, 1).text(), 16),
                is_extended_id=self.table.cellWidget(row, 2).currentIndex() == 1,
                is_remote_frame=self.table.cellWidget(row, 3).findChild(QCheckBox).isChecked(),
                dlc=int(self.table.item(row, 4).text()),
                data=bytes.fromhex(self.table.item(row, 5).text().replace(" ", "")))
            self.frame_to_send.emit(message)
        except (ValueError, TypeError) as e:
            QMessageBox.warning(self, "Invalid Transmit Data", f"Row {row+1}: Could not send frame.\nError: {e}")
            self._stop_timer_for_row(row); self.table.cellWidget(row, 0).findChild(QCheckBox).setChecked(False)
    def send_selected_frames(self):
        for row in sorted(list(set(index.row() for index in self.table.selectionModel().selectedIndexes()))): self.send_frame_from_row(row)

class SignalTransmitPanel(QGroupBox):
    data_encoded = Signal(bytes)
    def __init__(self):
        super().__init__("Signal Configuration")
        self.message = None; self.setup_ui()
    def setup_ui(self):
        layout = QVBoxLayout(self)
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Signal", "Value", "Unit"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)
        self.table.cellChanged.connect(self._encode_signals)
    def clear_panel(self):
        self.message = None; self.table.setRowCount(0); self.setTitle("Signal Configuration"); self.setVisible(False)
    def populate_from_message(self, message):
        self.message = message; self.table.blockSignals(True)
        self.table.setRowCount(len(message.signals))
        for row, sig in enumerate(message.signals):
            self.table.setItem(row, 0, QTableWidgetItem(sig.name)); self.table.item(row, 0).setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            self.table.setItem(row, 1, QTableWidgetItem(str(sig.initial if sig.initial is not None else 0)))
            self.table.setItem(row, 2, QTableWidgetItem(str(sig.unit or ''))); self.table.item(row, 2).setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        self.table.blockSignals(False); self.setTitle(f"Signal Configuration: {message.name}"); self.setVisible(True)
        self._encode_signals()
    def _encode_signals(self):
        if not self.message: return
        try:
            signal_data = {self.table.item(r,0).text(): float(self.table.item(r,1).text()) for r in range(self.table.rowCount())}
            self.data_encoded.emit(self.message.encode(signal_data, strict=True))
        except (ValueError, TypeError, KeyError): pass # Ignore bad values during typing

# --- Main Application Window ---

class CANBusObserver(QMainWindow):
    """Main CAN Bus Observer application"""
    def __init__(self):
        super().__init__(); self.setWindowTitle("CAN Bus Observer"); self.setGeometry(100, 100, 1400, 900)
        self.project = Project()
        self.trace_model = CANTraceModel(); self.grouped_model = CANGroupedModel()
        self.grouped_proxy_model = QSortFilterProxyModel(); self.grouped_proxy_model.setSourceModel(self.grouped_model); self.grouped_proxy_model.setSortRole(Qt.UserRole)
        self.can_reader = None; self.log_file = None; self.frame_count = 0
        self.setup_ui(); self.setup_menubar(); self.setup_statusbar()
        self.update_timer = QTimer(); self.update_timer.timeout.connect(self.update_stats); self.update_timer.start(1000)
    def setup_ui(self):
        central_widget = QWidget(); self.setCentralWidget(central_widget); layout = QVBoxLayout(central_widget)
        # Toolbar
        toolbar_layout = QHBoxLayout(); self.connect_btn = QPushButton("Connect"); self.disconnect_btn = QPushButton("Disconnect"); self.disconnect_btn.setEnabled(False)
        self.interface_combo = QComboBox(); self.interface_combo.addItems(["socketcan", "pcan", "kvaser", "vector", "virtual"]); self.channel_edit = QLineEdit("vcan0")
        toolbar_layout.addWidget(QLabel("Interface:")); toolbar_layout.addWidget(self.interface_combo); toolbar_layout.addWidget(QLabel("Channel:")); toolbar_layout.addWidget(self.channel_edit)
        toolbar_layout.addWidget(self.connect_btn); toolbar_layout.addWidget(self.disconnect_btn); toolbar_layout.addStretch(); layout.addLayout(toolbar_layout)
        # Main Splitter
        main_splitter = QSplitter(Qt.Horizontal); layout.addWidget(main_splitter)
        # Left Pane (Receive/Transmit)
        left_pane = QWidget(); left_layout = QVBoxLayout(left_pane); left_layout.setContentsMargins(0,0,0,0)
        left_splitter = QSplitter(Qt.Vertical)
        # Receive Part
        receive_widget = QWidget(); receive_layout = QVBoxLayout(receive_widget); receive_layout.setContentsMargins(0,0,0,0)
        control_layout = QHBoxLayout(); self.clear_btn = QPushButton("Clear"); self.save_log_btn = QPushButton("Save Log"); self.load_log_btn = QPushButton("Load Log")
        control_layout.addWidget(self.clear_btn); control_layout.addWidget(self.save_log_btn); control_layout.addWidget(self.load_log_btn); control_layout.addStretch()
        receive_layout.addLayout(control_layout)
        self.tab_widget = QTabWidget()
        trace_view_widget = QWidget(); trace_layout = QVBoxLayout(trace_view_widget); trace_layout.setContentsMargins(0,0,0,0)
        self.trace_table = QTableView(); self.trace_table.setModel(self.trace_model); self.trace_table.horizontalHeader().setStretchLastSection(True); self.trace_table.setAlternatingRowColors(True); self.trace_table.setSelectionBehavior(QTableView.SelectRows)
        self.autoscroll_cb = QCheckBox("Autoscroll"); self.autoscroll_cb.setChecked(True); trace_layout.addWidget(self.trace_table); trace_layout.addWidget(self.autoscroll_cb); self.tab_widget.addTab(trace_view_widget, "Trace")
        self.grouped_table = QTableView(); self.grouped_table.setModel(self.grouped_proxy_model); self.grouped_table.setSortingEnabled(True); self.grouped_table.horizontalHeader().setStretchLastSection(True); self.grouped_table.setAlternatingRowColors(True); self.grouped_table.setSelectionBehavior(QTableView.SelectRows); self.tab_widget.addTab(self.grouped_table, "Grouped")
        receive_layout.addWidget(self.tab_widget); left_splitter.addWidget(receive_widget)
        # Transmit Part
        transmit_area = QWidget(); transmit_layout = QVBoxLayout(transmit_area); transmit_layout.setContentsMargins(0,0,0,0)
        self.transmit_panel = TransmitPanel(); self.transmit_panel.setEnabled(False)
        self.signal_transmit_panel = SignalTransmitPanel(); self.signal_transmit_panel.setVisible(False)
        transmit_layout.addWidget(self.transmit_panel); transmit_layout.addWidget(self.signal_transmit_panel); left_splitter.addWidget(transmit_area)
        left_splitter.setSizes([600, 300])
        left_layout.addWidget(left_splitter); main_splitter.addWidget(left_pane)
        # Right Pane (Project/Properties)
        right_pane = QWidget(); right_layout = QVBoxLayout(right_pane); right_layout.setContentsMargins(0,0,0,0)
        right_splitter = QSplitter(Qt.Vertical)
        self.project_explorer = ProjectExplorer(self.project); right_splitter.addWidget(self.project_explorer)
        self.properties_panel = PropertiesPanel(); right_splitter.addWidget(self.properties_panel)
        right_splitter.setSizes([400, 300])
        right_layout.addWidget(right_splitter); main_splitter.addWidget(right_pane)
        main_splitter.setSizes([900, 500])
        # Connect signals
        self.connect_btn.clicked.connect(self.connect_can); self.disconnect_btn.clicked.connect(self.disconnect_can); self.clear_btn.clicked.connect(self.clear_data); self.save_log_btn.clicked.connect(self.save_log); self.load_log_btn.clicked.connect(self.load_log)
        self.trace_model.rowsInserted.connect(self.autoscroll_trace_view)
        self.transmit_panel.frame_to_send.connect(self.send_can_frame); self.transmit_panel.row_selection_changed.connect(self.on_transmit_row_selected); self.signal_transmit_panel.data_encoded.connect(self.on_signal_data_encoded)
        self.project_explorer.project_changed.connect(self.on_project_changed); self.project_explorer.tree.currentItemChanged.connect(self.properties_panel.show_properties)
        if not CAN_AVAILABLE: self.connect_btn.setEnabled(False); self.connect_btn.setText("Connect (lib missing)"); self.statusBar().showMessage("python-can or cantools not found. Functionality limited.")
    def setup_menubar(self):
        menubar=self.menuBar(); file_menu=menubar.addMenu("File"); load_action=QAction("Load Log...",self); load_action.triggered.connect(self.load_log); file_menu.addAction(load_action); save_action=QAction("Save Log...",self); save_action.triggered.connect(self.save_log); file_menu.addAction(save_action); file_menu.addSeparator(); exit_action=QAction("Exit",self); exit_action.triggered.connect(self.close); file_menu.addAction(exit_action)
    def setup_statusbar(self):
        self.statusBar().showMessage("Ready"); self.frame_count_label = QLabel("Frames: 0"); self.connection_label = QLabel("Disconnected"); self.statusBar().addPermanentWidget(self.frame_count_label); self.statusBar().addPermanentWidget(self.connection_label)
    def keyPressEvent(self, event: QKeyEvent):
        if event.key() == Qt.Key_Space and self.transmit_panel.table.hasFocus(): self.transmit_panel.send_selected_frames(); event.accept()
        else: super().keyPressEvent(event)
    def on_project_changed(self):
        active_dbcs = self.project.get_active_dbcs()
        self.trace_model.set_dbc_databases(active_dbcs); self.grouped_model.set_dbc_databases(active_dbcs)
        self.transmit_panel.set_dbc_databases(active_dbcs)
        self.on_transmit_row_selected(self.transmit_panel.table.currentRow(), self.transmit_panel.table.currentItem().text() if self.transmit_panel.table.currentItem() else "")
    def on_transmit_row_selected(self, row, id_text):
        self.signal_transmit_panel.clear_panel()
        if row < 0: return
        try:
            can_id = int(id_text, 16)
            if message := self.transmit_panel.get_message_from_id(can_id):
                self.signal_transmit_panel.populate_from_message(message)
        except (ValueError, AttributeError): pass
    def on_signal_data_encoded(self, data_bytes):
        current_row = self.transmit_panel.table.currentRow()
        if current_row >= 0: self.transmit_panel.update_row_data(current_row, data_bytes)
    def connect_can(self):
        interface = self.interface_combo.currentText(); channel = self.channel_edit.text()
        self.can_reader = CANReaderThread(interface, channel); self.can_reader.frame_received.connect(self.on_frame_received); self.can_reader.error_occurred.connect(self.on_can_error)
        if self.can_reader.start_reading():
            self.connect_btn.setEnabled(False); self.disconnect_btn.setEnabled(True); self.transmit_panel.setEnabled(True); self.connection_label.setText(f"Connected ({interface}:{channel})"); self.statusBar().showMessage("CAN bus connected")
        else: self.can_reader = None
    def disconnect_can(self):
        if self.can_reader: self.can_reader.stop_reading(); self.can_reader = None
        self.connect_btn.setEnabled(True); self.disconnect_btn.setEnabled(False); self.transmit_panel.setEnabled(False); self.transmit_panel.stop_all_timers(); self.connection_label.setText("Disconnected"); self.statusBar().showMessage("CAN bus disconnected")
    def send_can_frame(self, message: can.Message):
        if self.can_reader and self.can_reader.bus:
            try: self.can_reader.bus.send(message); # self.statusBar().showMessage(f"Sent frame ID 0x{message.arbitration_id:X}")
            except Exception as e: QMessageBox.critical(self, "Transmit Error", f"Failed to send frame: {e}")
        else: QMessageBox.warning(self, "Not Connected", "Connect to a CAN bus before sending frames.")
    def autoscroll_trace_view(self):
        if self.autoscroll_cb.isChecked(): self.trace_table.scrollToBottom()
    def on_frame_received(self, frame: CANFrame):
        active_filters = self.project.get_active_filters()
        if active_filters and not any(f.matches(frame) for f in active_filters): return
        self.trace_model.add_frame(frame); self.grouped_model.add_frame(frame)
        if self.log_file: self.write_frame_to_log(frame)
        self.frame_count += 1
    def on_can_error(self, error_message: str):
        QMessageBox.warning(self, "CAN Error", error_message); self.statusBar().showMessage(f"Error: {error_message}"); self.disconnect_can()
    def clear_data(self):
        self.trace_model.clear_frames(); self.grouped_model.clear_frames(); self.frame_count = 0
    def save_log(self):
        if self.trace_model.rowCount() == 0: QMessageBox.information(self, "No Data", "No frames to save"); return
        filename, _ = QFileDialog.getSaveFileName(self, "Save CAN Log", "", "CAN Log Files (*.log);;All Files (*)")
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("# CAN Bus Log File\n# Format: timestamp id dlc data\n")
                    for frame in self.trace_model.frames: f.write(f"{frame.timestamp:.6f} {frame.arbitration_id:X} {frame.dlc} {' '.join(f'{b:02X}' for b in frame.data)}\n")
                self.statusBar().showMessage(f"Log saved to {filename}")
            except Exception as e: QMessageBox.critical(self, "Save Error", f"Failed to save log: {e}")
    def load_log(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Load CAN Log", "", "CAN Log Files (*.log);;All Files (*)")
        if filename:
            try:
                self.clear_data()
                with open(filename, 'r') as f:
                    for line in f:
                        if line.startswith('#') or not line.strip(): continue
                        parts = line.split()
                        if len(parts) < 3: continue
                        try:
                            frame = CANFrame(timestamp=float(parts[0]), arbitration_id=int(parts[1], 16), dlc=int(parts[2]), data=bytes.fromhex("".join(parts[3:])))
                            self.on_frame_received(frame)
                        except (ValueError, IndexError): print(f"Warning: Invalid line in log file: {line.strip()}")
                self.statusBar().showMessage(f"Loaded {self.frame_count} frames from {filename}")
            except Exception as e: QMessageBox.critical(self, "Load Error", f"Failed to load log: {e}")
    def update_stats(self): self.frame_count_label.setText(f"Frames: {self.frame_count}")
    def closeEvent(self, event):
        self.disconnect_can()
        if self.log_file: self.log_file.close()
        event.accept()

def main():
    app = QApplication(sys.argv)
    window = CANBusObserver()
    qdarktheme.setup_theme("auto")
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
