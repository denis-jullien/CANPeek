#!/usr/bin/env python3
"""
CAN Bus Observer GUI - Similar to PCAN-View
Features:
- Frame view grouped by ID or chronological trace
- DBC decoding support
- CAN log file saving/loading
- Frame filtering with min/max/mask
- Basic CANopen decoding
- Real-time monitoring
"""

import sys
import time
import json
import struct
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
from functools import partial


from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QTabWidget, QPushButton, QLabel,
    QLineEdit, QCheckBox, QComboBox, QSpinBox, QTextEdit, QSplitter,
    QGroupBox, QFormLayout, QHeaderView, QFileDialog, QMessageBox,
    QProgressBar, QStatusBar, QMenuBar, QMenu, QToolBar, QFrame,
    QTableView
)
from PySide6.QtCore import (
    QThread, QTimer, Signal, QObject, Qt, QAbstractTableModel,
    QModelIndex, QSortFilterProxyModel
)
from PySide6.QtGui import QAction, QFont, QColor, QKeyEvent

import qdarktheme
# Try importing CAN libraries
try:
    import can
    import cantools
    CAN_AVAILABLE = True
except ImportError:
    CAN_AVAILABLE = False
    # Define dummy classes to allow the application to start without crashing.
    # Functionality requiring these libraries will be disabled.
    class can:
        class Message: pass
        class Bus: pass
    class cantools:
        class database:
            @staticmethod
            def load_file(filename):
                raise ImportError("cantools library is not installed.")


@dataclass
class CANFrame:
    """CAN Frame data structure"""
    timestamp: float
    arbitration_id: int
    data: bytes
    dlc: int
    is_extended: bool = False
    is_error: bool = False
    is_remote: bool = False
    channel: str = "CAN1"

class CANFrameFilter:
    """CAN Frame filter configuration"""
    def __init__(self):
        self.enabled = False
        self.min_id = 0x000
        self.max_id = 0x7FF
        self.mask = 0x7FF
        self.accept_extended = True
        self.accept_standard = True
        self.accept_data = True
        self.accept_remote = True

    def matches(self, frame: CANFrame) -> bool:
        if not self.enabled:
            return True
        # Check frame type
        if frame.is_extended and not self.accept_extended: return False
        if not frame.is_extended and not self.accept_standard: return False
        if frame.is_remote and not self.accept_remote: return False
        if not frame.is_remote and not self.accept_data: return False
        # Check ID range and mask
        masked_id = frame.arbitration_id & self.mask
        return self.min_id <= masked_id <= self.max_id

class CANopenDecoder:
    """Basic CANopen protocol decoder"""
    @staticmethod
    def decode_frame(frame: CANFrame) -> Optional[Dict]:
        if frame.arbitration_id == 0x000: return CANopenDecoder._decode_nmt(frame)
        if frame.arbitration_id == 0x080: return CANopenDecoder._decode_sync_emcy(frame)
        if 0x580 <= frame.arbitration_id <= 0x5FF: return CANopenDecoder._decode_sdo_tx(frame)
        if 0x600 <= frame.arbitration_id <= 0x67F: return CANopenDecoder._decode_sdo_rx(frame)
        if 0x180 <= frame.arbitration_id <= 0x4FF: return CANopenDecoder._decode_pdo(frame)
        if 0x700 <= frame.arbitration_id <= 0x77F: return CANopenDecoder._decode_nmt_monitor(frame)
        return None
    @staticmethod
    def _decode_nmt(frame: CANFrame) -> Dict:
        if len(frame.data) >= 2:
            command, node_id = frame.data[0], frame.data[1]
            commands = {1: "Start", 2: "Stop", 128: "Pre-operational", 129: "Reset", 130: "Reset Communication"}
            return {"protocol": "CANopen NMT", "command": commands.get(command, f"Unknown({command})"), "node_id": node_id}
        return {"protocol": "CANopen NMT", "data": "Invalid"}
    @staticmethod
    def _decode_sync_emcy(frame: CANFrame) -> Dict:
        return {"protocol": "CANopen SYNC"} if len(frame.data) == 0 else {"protocol": "CANopen EMERGENCY", "data": frame.data.hex()}
    @staticmethod
    def _decode_sdo_tx(frame: CANFrame) -> Dict:
        return {"protocol": "CANopen SDO TX", "node_id": frame.arbitration_id - 0x580, "data": frame.data.hex()}
    @staticmethod
    def _decode_sdo_rx(frame: CANFrame) -> Dict:
        return {"protocol": "CANopen SDO RX", "node_id": frame.arbitration_id - 0x600, "data": frame.data.hex()}
    @staticmethod
    def _decode_pdo(frame: CANFrame) -> Dict:
        pdo_map = {0x180: "PDO1 TX", 0x200: "PDO1 RX", 0x280: "PDO2 TX", 0x300: "PDO2 RX", 0x380: "PDO3 TX", 0x400: "PDO3 RX", 0x480: "PDO4 TX", 0x500: "PDO4 RX"}
        base = frame.arbitration_id & 0xFF80
        pdo_type = pdo_map.get(base, "PDO Unknown")
        node_id = frame.arbitration_id - base
        return {"protocol": f"CANopen {pdo_type}", "node_id": node_id, "data": frame.data.hex()}
    @staticmethod
    def _decode_nmt_monitor(frame: CANFrame) -> Dict:
        node_id = frame.arbitration_id - 0x700
        if len(frame.data) >= 1:
            state = frame.data[0]
            states = {0: "Boot-up", 4: "Stopped", 5: "Operational", 127: "Pre-operational"}
            return {"protocol": "CANopen NMT Monitor", "node_id": node_id, "state": states.get(state, f"Unknown({state})")}
        return {"protocol": "CANopen NMT Monitor", "node_id": node_id}

class CANTraceModel(QAbstractTableModel):
    """Table model for CAN trace view"""
    def __init__(self):
        super().__init__()
        self.frames: List[CANFrame] = []
        self.headers = ["Timestamp", "ID", "Type", "DLC", "Data", "Decoded"]
        self.dbc_database = None
        self.show_canopen = False
    def set_dbc_database(self, db):
        self.dbc_database = db; self.modelReset.emit()
    def set_canopen_enabled(self, enabled):
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
        frame = self.frames[index.row()]
        col = index.column()
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
        if self.dbc_database and CAN_AVAILABLE:
            try:
                message = self.dbc_database.get_message_by_frame_id(frame.arbitration_id)
                decoded_signals = self.dbc_database.decode_message(frame.arbitration_id, frame.data)
                signal_strs = [f"{name}={value}" for name, value in decoded_signals.items()]
                decoded_parts.append(f"DBC: {message.name} {' '.join(signal_strs)}")
            except KeyError: pass
            except Exception as e: print(f"DBC decoding error for ID 0x{frame.arbitration_id:X}: {e}")
        if self.show_canopen:
            if canopen_data := CANopenDecoder.decode_frame(frame): decoded_parts.append(f"CANopen: {canopen_data}")
        return " | ".join(decoded_parts) if decoded_parts else ""

class CANGroupedModel(QAbstractTableModel):
    """Table model for grouped CAN frames by ID"""
    def __init__(self):
        super().__init__()
        self.grouped_frames: Dict[int, List[CANFrame]] = {}; self.id_order: List[int] = []
        self.headers = ["ID", "Name", "DLC", "Data", "Decoded", "Count", "Cycle Time", "Last"]
        self.dbc_database = None; self.show_canopen = False
    def set_dbc_database(self, db): self.dbc_database = db; self.modelReset.emit()
    def set_canopen_enabled(self, enabled): self.show_canopen = enabled; self.modelReset.emit()
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
    def headerData(self, section, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole: return self.headers[section]
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
            return None
        if role == Qt.DisplayRole:
            if col == 0: return f"0x{can_id:X}"
            if col == 1:
                if self.dbc_database and CAN_AVAILABLE:
                    try: return self.dbc_database.get_message_by_frame_id(can_id).name
                    except KeyError: pass
                return ""
            if col == 2: return str(latest_frame.dlc)
            if col == 3: return " ".join(f"{b:02X}" for b in latest_frame.data)
            if col == 4: return self._decode_frame(latest_frame)
            if col == 5: return str(len(frames))
            if col == 6:
                if len(frames) > 1:
                    relevant = frames[-10:]
                    if len(relevant) > 1:
                        avg_cycle = sum(relevant[i].timestamp - relevant[i-1].timestamp for i in range(1, len(relevant))) / (len(relevant)-1)
                        return f"{avg_cycle*1000:.1f} ms"
                return "-"
            if col == 7: return f"{latest_frame.timestamp:.6f}"
        return None
    def _decode_frame(self, frame: CANFrame) -> str:
        decoded_parts = []
        if self.dbc_database and CAN_AVAILABLE:
            try:
                decoded_signals = self.dbc_database.decode_message(frame.arbitration_id, frame.data)
                signal_strs = [f"{name}={value}" for name, value in decoded_signals.items()]
                decoded_parts.append(" ".join(signal_strs))
            except KeyError: pass
            except Exception as e: print(f"DBC decoding error for ID 0x{frame.arbitration_id:X}: {e}")
        if self.show_canopen:
            if canopen_data := CANopenDecoder.decode_frame(frame):
                parts = [f"{k}={v}" for k,v in canopen_data.items() if k != 'protocol']
                decoded_parts.append(f"{canopen_data.get('protocol','CANopen')}: {' '.join(parts)}")
        return " | ".join(decoded_parts) if decoded_parts else ""

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

class FilterWidget(QWidget):
    """Widget for configuring CAN frame filters"""
    def __init__(self):
        super().__init__(); self.filter = CANFrameFilter(); self.setup_ui()
    def setup_ui(self):
        layout = QVBoxLayout(self); self.enabled_cb = QCheckBox("Enable Filter"); self.enabled_cb.toggled.connect(self.update_filter); layout.addWidget(self.enabled_cb)
        id_group = QGroupBox("ID Range"); id_layout = QFormLayout(id_group); self.min_id_edit = QLineEdit("0x000"); self.max_id_edit = QLineEdit("0x7FF"); self.mask_edit = QLineEdit("0x7FF")
        id_layout.addRow("Min ID:", self.min_id_edit); id_layout.addRow("Max ID:", self.max_id_edit); id_layout.addRow("Mask:", self.mask_edit)
        for edit in [self.min_id_edit, self.max_id_edit, self.mask_edit]: edit.textChanged.connect(self.update_filter)
        layout.addWidget(id_group)
        type_group = QGroupBox("Frame Types"); type_layout = QVBoxLayout(type_group); self.standard_cb = QCheckBox("Standard (11-bit)"); self.extended_cb = QCheckBox("Extended (29-bit)"); self.data_cb = QCheckBox("Data Frames"); self.remote_cb = QCheckBox("Remote Frames")
        for cb in [self.standard_cb, self.extended_cb, self.data_cb, self.remote_cb]: cb.setChecked(True); cb.toggled.connect(self.update_filter); type_layout.addWidget(cb)
        layout.addWidget(type_group)
    def update_filter(self):
        self.filter.enabled = self.enabled_cb.isChecked()
        try: self.filter.min_id = int(self.min_id_edit.text(), 16)
        except ValueError: pass
        try: self.filter.max_id = int(self.max_id_edit.text(), 16)
        except ValueError: pass
        try: self.filter.mask = int(self.mask_edit.text(), 16)
        except ValueError: pass
        self.filter.accept_standard = self.standard_cb.isChecked(); self.filter.accept_extended = self.extended_cb.isChecked(); self.filter.accept_data = self.data_cb.isChecked(); self.filter.accept_remote = self.remote_cb.isChecked()

class TransmitPanel(QGroupBox):
    """Widget for sending multiple CAN frames."""
    frame_to_send = Signal(object)  # can.Message
    def __init__(self):
        super().__init__("Transmit")
        self.timers: Dict[int, QTimer] = {}
        self.setup_ui()
        if not CAN_AVAILABLE: self.setEnabled(False); self.setTitle("Transmit (python-can not available)")
    def setup_ui(self):
        layout = QVBoxLayout(self)
        # Control buttons
        control_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add Frame")
        self.remove_btn = QPushButton("Remove Selected")
        control_layout.addWidget(self.add_btn); control_layout.addWidget(self.remove_btn); control_layout.addStretch()
        layout.addLayout(control_layout)
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(["Enable", "ID (hex)", "Type", "RTR", "DLC", "Data (hex)", "Cycle (ms)", "Send"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)
        # Connect signals
        self.add_btn.clicked.connect(self.add_frame)
        self.remove_btn.clicked.connect(self.remove_selected_frames)
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
        # Enable Checkbox
        enable_cb = QCheckBox(); enable_cb.toggled.connect(partial(self._toggle_periodic, row)); self.table.setCellWidget(row, 0, self._center_widget(enable_cb))
        # ID
        id_edit = QLineEdit("100"); self.table.setCellWidget(row, 1, id_edit)
        # Type ComboBox
        type_combo = QComboBox(); type_combo.addItems(["Standard", "Extended"]); self.table.setCellWidget(row, 2, type_combo)
        # RTR Checkbox
        rtr_cb = QCheckBox(); self.table.setCellWidget(row, 3, self._center_widget(rtr_cb))
        # DLC SpinBox
        dlc_spin = QSpinBox(); dlc_spin.setRange(0, 8); self.table.setCellWidget(row, 4, dlc_spin)
        # Data
        data_edit = QLineEdit(); data_edit.textChanged.connect(lambda text, r=row: self._update_dlc_from_data(r)); self.table.setCellWidget(row, 5, data_edit)
        # Cycle Time
        cycle_edit = QLineEdit("100"); self.table.setCellWidget(row, 6, cycle_edit)
        # Send Button
        send_btn = QPushButton("Send"); send_btn.clicked.connect(partial(self.send_frame, row)); self.table.setCellWidget(row, 7, send_btn)
    def _center_widget(self, widget):
        # Helper to center widgets like checkboxes in cells
        cell_widget = QWidget(); layout = QHBoxLayout(cell_widget); layout.addWidget(widget); layout.setAlignment(Qt.AlignCenter); layout.setContentsMargins(0,0,0,0); return cell_widget
    def _update_dlc_from_data(self, row):
        data_edit = self.table.cellWidget(row, 5)
        dlc_spin = self.table.cellWidget(row, 4)
        try:
            data_len = len(bytes.fromhex(data_edit.text().replace(" ", "")))
            if data_len <= 8: dlc_spin.setValue(data_len)
        except (ValueError, TypeError): pass
    def _toggle_periodic(self, row, state):
        if state:
            try:
                cycle_ms = int(self.table.cellWidget(row, 6).text())
                if cycle_ms <= 0: raise ValueError("Cycle time must be positive")
                timer = QTimer(self)
                timer.timeout.connect(partial(self.send_frame, row))
                timer.start(cycle_ms)
                self.timers[row] = timer
            except (ValueError, TypeError) as e:
                QMessageBox.warning(self, "Invalid Cycle Time", f"Row {row+1}: Please enter a valid positive number for cycle time. Error: {e}")
                self.table.cellWidget(row, 0).findChild(QCheckBox).setChecked(False)
        else: self._stop_timer_for_row(row)
    def _stop_timer_for_row(self, row):
        if row in self.timers: self.timers.pop(row).stop()
    def stop_all_timers(self):
        for timer in self.timers.values(): timer.stop()
        self.timers.clear()
        for r in range(self.table.rowCount()): self.table.cellWidget(r, 0).findChild(QCheckBox).setChecked(False)
    def send_frame(self, row):
        try:
            can_id = int(self.table.cellWidget(row, 1).text(), 16)
            is_extended = self.table.cellWidget(row, 2).currentIndex() == 1
            is_rtr = self.table.cellWidget(row, 3).findChild(QCheckBox).isChecked()
            dlc = self.table.cellWidget(row, 4).value()
            data_str = self.table.cellWidget(row, 5).text().replace(" ", "")
            data_bytes = bytes.fromhex(data_str) if data_str and not is_rtr else b''
            message = can.Message(arbitration_id=can_id, is_extended_id=is_extended, is_remote_frame=is_rtr, dlc=dlc, data=data_bytes)
            self.frame_to_send.emit(message)
        except (ValueError, TypeError) as e:
            QMessageBox.warning(self, "Invalid Transmit Data", f"Row {row+1}: Could not send frame. Please check data format.\nError: {e}")
            self._stop_timer_for_row(row)
            self.table.cellWidget(row, 0).findChild(QCheckBox).setChecked(False)
    def send_selected_frames(self):
        selected_rows = sorted(list(set(index.row() for index in self.table.selectionModel().selectedIndexes())))
        for row in selected_rows: self.send_frame(row)

class CANBusObserver(QMainWindow):
    """Main CAN Bus Observer application"""
    def __init__(self):
        super().__init__(); self.setWindowTitle("CAN Bus Observer"); self.setGeometry(100, 100, 1200, 800)
        self.trace_model = CANTraceModel(); self.grouped_model = CANGroupedModel()
        self.grouped_proxy_model = QSortFilterProxyModel(); self.grouped_proxy_model.setSourceModel(self.grouped_model); self.grouped_proxy_model.setSortRole(Qt.UserRole)
        self.can_reader = None; self.dbc_database = None; self.frame_filter = CANFrameFilter(); self.log_file = None; self.frame_count = 0
        self.setup_ui(); self.setup_menubar(); self.setup_statusbar()
        self.update_timer = QTimer(); self.update_timer.timeout.connect(self.update_stats); self.update_timer.start(1000)
    def setup_ui(self):
        central_widget = QWidget(); self.setCentralWidget(central_widget); layout = QVBoxLayout(central_widget)
        toolbar_layout = QHBoxLayout(); self.connect_btn = QPushButton("Connect"); self.disconnect_btn = QPushButton("Disconnect"); self.disconnect_btn.setEnabled(False)
        self.interface_combo = QComboBox(); self.interface_combo.addItems(["socketcan", "pcan", "kvaser", "vector", "virtual"]); self.channel_edit = QLineEdit("vcan0")
        toolbar_layout.addWidget(QLabel("Interface:")); toolbar_layout.addWidget(self.interface_combo); toolbar_layout.addWidget(QLabel("Channel:")); toolbar_layout.addWidget(self.channel_edit)
        toolbar_layout.addWidget(self.connect_btn); toolbar_layout.addWidget(self.disconnect_btn); toolbar_layout.addStretch(); layout.addLayout(toolbar_layout)
        main_splitter = QSplitter(Qt.Horizontal); layout.addWidget(main_splitter)
        left_widget = QWidget(); left_layout = QVBoxLayout(left_widget)
        control_layout = QHBoxLayout(); self.clear_btn = QPushButton("Clear"); self.save_log_btn = QPushButton("Save Log"); self.load_log_btn = QPushButton("Load Log")
        control_layout.addWidget(self.clear_btn); control_layout.addWidget(self.save_log_btn); control_layout.addWidget(self.load_log_btn); control_layout.addStretch(); left_layout.addLayout(control_layout)
        self.tab_widget = QTabWidget()
        trace_view_widget = QWidget(); trace_layout = QVBoxLayout(trace_view_widget); trace_layout.setContentsMargins(0,0,0,0)
        self.trace_table = QTableView(); self.trace_table.setModel(self.trace_model); self.trace_table.horizontalHeader().setStretchLastSection(True); self.trace_table.setAlternatingRowColors(True); self.trace_table.setSelectionBehavior(QTableView.SelectRows)
        self.autoscroll_cb = QCheckBox("Autoscroll"); self.autoscroll_cb.setChecked(True); trace_layout.addWidget(self.trace_table); trace_layout.addWidget(self.autoscroll_cb); self.tab_widget.addTab(trace_view_widget, "Trace")
        self.grouped_table = QTableView(); self.grouped_table.setModel(self.grouped_proxy_model); self.grouped_table.setSortingEnabled(True); self.grouped_table.horizontalHeader().setStretchLastSection(True); self.grouped_table.setAlternatingRowColors(True); self.grouped_table.setSelectionBehavior(QTableView.SelectRows); self.tab_widget.addTab(self.grouped_table, "Grouped")
        left_layout.addWidget(self.tab_widget)
        self.transmit_panel = TransmitPanel();
        self.transmit_panel.frame_to_send.connect(self.send_can_frame);
        self.transmit_panel.setEnabled(False);
        left_layout.addWidget(self.transmit_panel)
        main_splitter.addWidget(left_widget)
        right_widget = QWidget(); right_layout = QVBoxLayout(right_widget)
        dbc_group = QGroupBox("DBC Database"); dbc_layout = QVBoxLayout(dbc_group); dbc_file_layout = QHBoxLayout()
        self.dbc_file_edit = QLineEdit(); self.dbc_browse_btn = QPushButton("Browse"); self.dbc_load_btn = QPushButton("Load")
        dbc_file_layout.addWidget(self.dbc_file_edit); dbc_file_layout.addWidget(self.dbc_browse_btn); dbc_file_layout.addWidget(self.dbc_load_btn); dbc_layout.addLayout(dbc_file_layout); right_layout.addWidget(dbc_group)
        canopen_group = QGroupBox("CANopen"); canopen_layout = QVBoxLayout(canopen_group); self.canopen_enable_cb = QCheckBox("Enable CANopen Decoding"); canopen_layout.addWidget(self.canopen_enable_cb); right_layout.addWidget(canopen_group)
        self.filter_widget = FilterWidget(); right_layout.addWidget(self.filter_widget); right_layout.addStretch(); main_splitter.addWidget(right_widget)
        main_splitter.setSizes([800, 400])
        self.connect_btn.clicked.connect(self.connect_can); self.disconnect_btn.clicked.connect(self.disconnect_can); self.clear_btn.clicked.connect(self.clear_data); self.save_log_btn.clicked.connect(self.save_log)
        self.load_log_btn.clicked.connect(self.load_log); self.dbc_browse_btn.clicked.connect(self.browse_dbc); self.dbc_load_btn.clicked.connect(self.load_dbc); self.canopen_enable_cb.toggled.connect(self.toggle_canopen)
        self.trace_model.rowsInserted.connect(self.autoscroll_trace_view)
        if not CAN_AVAILABLE:
            self.connect_btn.setEnabled(False); self.connect_btn.setText("Connect (lib missing)"); self.dbc_load_btn.setEnabled(False); self.dbc_browse_btn.setEnabled(False); self.statusBar().showMessage("python-can or cantools not found. Functionality limited.")

    def setup_menubar(self):
        menubar=self.menuBar(); file_menu=menubar.addMenu("File"); load_action=QAction("Load Log...",self); load_action.triggered.connect(self.load_log); file_menu.addAction(load_action); save_action=QAction("Save Log...",self); save_action.triggered.connect(self.save_log); file_menu.addAction(save_action); file_menu.addSeparator(); exit_action=QAction("Exit",self); exit_action.triggered.connect(self.close); file_menu.addAction(exit_action); tools_menu=menubar.addMenu("Tools"); dbc_action=QAction("Load DBC...",self); dbc_action.triggered.connect(self.browse_dbc); tools_menu.addAction(dbc_action)
    def setup_statusbar(self):
        self.statusBar().showMessage("Ready"); self.frame_count_label = QLabel("Frames: 0"); self.connection_label = QLabel("Disconnected"); self.statusBar().addPermanentWidget(self.frame_count_label); self.statusBar().addPermanentWidget(self.connection_label)
    def keyPressEvent(self, event: QKeyEvent):
        if event.key() == Qt.Key_Space and self.transmit_panel.table.hasFocus():
            self.transmit_panel.send_selected_frames()
            event.accept()
        else: super().keyPressEvent(event)
    def connect_can(self):
        interface = self.interface_combo.currentText(); channel = self.channel_edit.text()
        self.can_reader = CANReaderThread(interface, channel); self.can_reader.frame_received.connect(self.on_frame_received); self.can_reader.error_occurred.connect(self.on_can_error)
        if self.can_reader.start_reading():
            self.connect_btn.setEnabled(False); self.disconnect_btn.setEnabled(True); self.transmit_panel.setEnabled(True); self.connection_label.setText(f"Connected ({interface}:{channel})"); self.statusBar().showMessage("CAN bus connected")
        else: self.can_reader = None
    def disconnect_can(self):
        if self.can_reader: self.can_reader.stop_reading(); self.can_reader = None
        self.connect_btn.setEnabled(True);
        self.disconnect_btn.setEnabled(False);
        self.transmit_panel.setEnabled(False);
        self.transmit_panel.stop_all_timers();
        self.connection_label.setText("Disconnected");
        self.statusBar().showMessage("CAN bus disconnected")
    def send_can_frame(self, message: can.Message):
        if self.can_reader and self.can_reader.bus:
            try: self.can_reader.bus.send(message); self.statusBar().showMessage(f"Sent frame ID 0x{message.arbitration_id:X}")
            except Exception as e: QMessageBox.critical(self, "Transmit Error", f"Failed to send frame: {e}")
        else: QMessageBox.warning(self, "Not Connected", "Connect to a CAN bus before sending frames.")
    def autoscroll_trace_view(self):
        if self.autoscroll_cb.isChecked() and self.trace_table.model().rowCount() > 0: self.trace_table.scrollToBottom()
    def on_frame_received(self, frame: CANFrame):
        if not self.filter_widget.filter.matches(frame): return
        self.trace_model.add_frame(frame); self.grouped_model.add_frame(frame)
        if self.log_file: self.write_frame_to_log(frame)
        self.frame_count += 1
    def on_can_error(self, error_message: str):
        QMessageBox.warning(self, "CAN Error", error_message); self.statusBar().showMessage(f"Error: {error_message}"); self.disconnect_can()
    def clear_data(self):
        self.trace_model.clear_frames(); self.grouped_model.clear_frames(); self.frame_count = 0; self.frame_count_label.setText("Frames: 0"); self.statusBar().showMessage("Data cleared")
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
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line.startswith('#') or not line: continue
                        parts = line.split()
                        if len(parts) < 3: continue
                        try:
                            frame = CANFrame(timestamp=float(parts[0]), arbitration_id=int(parts[1], 16), dlc=int(parts[2]), data=bytes.fromhex("".join(parts[3:])))
                            self.trace_model.add_frame(frame); self.grouped_model.add_frame(frame); self.frame_count += 1
                        except (ValueError, IndexError): print(f"Warning: Invalid line {line_num} in log file: {line}")
                self.statusBar().showMessage(f"Loaded {self.frame_count} frames from {filename}")
            except Exception as e: QMessageBox.critical(self, "Load Error", f"Failed to load log: {e}")
    def write_frame_to_log(self, frame: CANFrame):
        if self.log_file:
            try: self.log_file.write(f"{frame.timestamp:.6f} {frame.arbitration_id:X} {frame.dlc} {' '.join(f'{b:02X}' for b in frame.data)}\n"); self.log_file.flush()
            except Exception as e: print(f"Error writing to log file: {e}")
    def browse_dbc(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select DBC File", "", "DBC Files (*.dbc);;All Files (*)")
        if filename: self.dbc_file_edit.setText(filename); self.load_dbc()
    def load_dbc(self):
        filename = self.dbc_file_edit.text()
        if not filename: QMessageBox.warning(self, "No File", "Please select a DBC file first"); return
        if not CAN_AVAILABLE: QMessageBox.warning(self, "Library Missing", "cantools library not installed."); return
        try:
            self.dbc_database = cantools.database.load_file(filename)
            self.trace_model.set_dbc_database(self.dbc_database); self.grouped_model.set_dbc_database(self.dbc_database)
            self.statusBar().showMessage(f"DBC loaded: {len(self.dbc_database.messages)} messages")
        except Exception as e:
            QMessageBox.critical(self, "DBC Load Error", f"Failed to load DBC file: {e}")
            self.dbc_database = None; self.trace_model.set_dbc_database(None); self.grouped_model.set_dbc_database(None)
    def toggle_canopen(self, enabled):
        self.trace_model.set_canopen_enabled(enabled); self.grouped_model.set_canopen_enabled(enabled)
    def update_stats(self): self.frame_count_label.setText(f"Frames: {self.frame_count}")
    def closeEvent(self, event):
        self.disconnect_can()
        if self.log_file: self.log_file.close()
        event.accept()

def main():
    app = QApplication(sys.argv)
    window = CANBusObserver()

    # Apply the complete dark theme to your Qt App.
    qdarktheme.setup_theme("auto")

    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
