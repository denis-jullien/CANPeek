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
from PySide6.QtGui import QAction, QFont, QColor

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
        if frame.is_extended and not self.accept_extended:
            return False
        if not frame.is_extended and not self.accept_standard:
            return False
        if frame.is_remote and not self.accept_remote:
            return False
        if not frame.is_remote and not self.accept_data:
            return False

        # Check ID range and mask
        masked_id = frame.arbitration_id & self.mask
        return self.min_id <= masked_id <= self.max_id

class CANopenDecoder:
    """Basic CANopen protocol decoder"""

    # CANopen function codes
    FUNCTION_CODES = {
        0x000: "NMT",
        0x080: "SYNC/EMCY",
        0x100: "TIME",
        0x180: "PDO1_TX",
        0x200: "PDO1_RX",
        0x280: "PDO2_TX",
        0x300: "PDO2_RX",
        0x380: "PDO3_TX",
        0x400: "PDO3_RX",
        0x480: "PDO4_TX",
        0x500: "PDO4_RX",
        0x580: "SDO_TX",
        0x600: "SDO_RX",
        0x700: "NMT_MONITOR"
    }

    @staticmethod
    def decode_frame(frame: CANFrame) -> Optional[Dict]:
        """Decode CANopen frame"""
        if frame.arbitration_id == 0x000:
            return CANopenDecoder._decode_nmt(frame)
        elif frame.arbitration_id == 0x080:
            return CANopenDecoder._decode_sync_emcy(frame)
        elif 0x580 <= frame.arbitration_id <= 0x5FF:
            return CANopenDecoder._decode_sdo_tx(frame)
        elif 0x600 <= frame.arbitration_id <= 0x67F:
            return CANopenDecoder._decode_sdo_rx(frame)
        elif 0x180 <= frame.arbitration_id <= 0x4FF:
            return CANopenDecoder._decode_pdo(frame)
        elif 0x700 <= frame.arbitration_id <= 0x77F:
            return CANopenDecoder._decode_nmt_monitor(frame)

        return None

    @staticmethod
    def _decode_nmt(frame: CANFrame) -> Dict:
        if len(frame.data) >= 2:
            command = frame.data[0]
            node_id = frame.data[1]
            commands = {1: "Start", 2: "Stop", 128: "Pre-operational", 129: "Reset", 130: "Reset Communication"}
            return {
                "protocol": "CANopen NMT",
                "command": commands.get(command, f"Unknown({command})"),
                "node_id": node_id
            }
        return {"protocol": "CANopen NMT", "data": "Invalid"}

    @staticmethod
    def _decode_sync_emcy(frame: CANFrame) -> Dict:
        if len(frame.data) == 0:
            return {"protocol": "CANopen SYNC"}
        else:
            return {"protocol": "CANopen EMERGENCY", "data": frame.data.hex()}

    @staticmethod
    def _decode_sdo_tx(frame: CANFrame) -> Dict:
        node_id = frame.arbitration_id - 0x580
        return {"protocol": "CANopen SDO TX", "node_id": node_id, "data": frame.data.hex()}

    @staticmethod
    def _decode_sdo_rx(frame: CANFrame) -> Dict:
        node_id = frame.arbitration_id - 0x600
        return {"protocol": "CANopen SDO RX", "node_id": node_id, "data": frame.data.hex()}

    @staticmethod
    def _decode_pdo(frame: CANFrame) -> Dict:
        # Determine PDO type and node
        if 0x180 <= frame.arbitration_id <= 0x1FF:
            pdo_type = "PDO1 TX"
            node_id = frame.arbitration_id - 0x180
        elif 0x200 <= frame.arbitration_id <= 0x27F:
            pdo_type = "PDO1 RX"
            node_id = frame.arbitration_id - 0x200
        elif 0x280 <= frame.arbitration_id <= 0x2FF:
            pdo_type = "PDO2 TX"
            node_id = frame.arbitration_id - 0x280
        elif 0x300 <= frame.arbitration_id <= 0x37F:
            pdo_type = "PDO2 RX"
            node_id = frame.arbitration_id - 0x300
        elif 0x380 <= frame.arbitration_id <= 0x3FF:
            pdo_type = "PDO3 TX"
            node_id = frame.arbitration_id - 0x380
        elif 0x400 <= frame.arbitration_id <= 0x47F:
            pdo_type = "PDO3 RX"
            node_id = frame.arbitration_id - 0x400
        elif 0x480 <= frame.arbitration_id <= 0x4FF:
            pdo_type = "PDO4 TX"
            node_id = frame.arbitration_id - 0x480
        else:
            pdo_type = "PDO RX"
            node_id = frame.arbitration_id - 0x500

        return {"protocol": f"CANopen {pdo_type}", "node_id": node_id, "data": frame.data.hex()}

    @staticmethod
    def _decode_nmt_monitor(frame: CANFrame) -> Dict:
        node_id = frame.arbitration_id - 0x700
        if len(frame.data) >= 1:
            state = frame.data[0]
            states = {0: "Boot-up", 4: "Stopped", 5: "Operational", 127: "Pre-operational"}
            return {
                "protocol": "CANopen NMT Monitor",
                "node_id": node_id,
                "state": states.get(state, f"Unknown({state})")
            }
        return {"protocol": "CANopen NMT Monitor", "node_id": node_id}

class CANTraceModel(QAbstractTableModel):
    """Table model for CAN trace view"""

    def __init__(self):
        super().__init__()
        self.frames: List[CANFrame] = []
        self.headers = ["Timestamp", "ID", "Type", "DLC", "Data", "Decoded", "Count"]
        self.dbc_database = None
        self.show_canopen = False

    def set_dbc_database(self, db):
        self.dbc_database = db
        self.modelReset.emit()

    def set_canopen_enabled(self, enabled):
        self.show_canopen = enabled
        self.modelReset.emit()

    def add_frame(self, frame: CANFrame):
        self.beginInsertRows(QModelIndex(), len(self.frames), len(self.frames))
        self.frames.append(frame)
        self.endInsertRows()

    def clear_frames(self):
        self.beginResetModel()
        self.frames.clear()
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self.frames)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def headerData(self, section, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.headers[section]
        return None

    def data(self, index, role):
        if not index.isValid() or index.row() >= len(self.frames):
            return None

        frame = self.frames[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:  # Timestamp
                return f"{frame.timestamp:.6f}"
            elif col == 1:  # ID
                return f"0x{frame.arbitration_id:X}"
            elif col == 2:  # Type
                type_str = "Ext" if frame.is_extended else "Std"
                if frame.is_remote:
                    type_str += " RTR"
                return type_str
            elif col == 3:  # DLC
                return str(frame.dlc)
            elif col == 4:  # Data
                return " ".join(f"{b:02X}" for b in frame.data)
            elif col == 5:  # Decoded
                return self._decode_frame(frame)
            elif col == 6:  # Count (placeholder for grouped view)
                return "1"

        return None

    def _decode_frame(self, frame: CANFrame) -> str:
        """Decode frame using available decoders"""
        decoded_parts = []

        # DBC decoding
        if self.dbc_database and CAN_AVAILABLE:
            try:
                # Get the message definition from the database
                message = self.dbc_database.get_message_by_frame_id(frame.arbitration_id)
                # Decode the data bytes into physical values
                decoded_signals = self.dbc_database.decode_message(frame.arbitration_id, frame.data)
                # Format the signals into a readable string
                signal_strs = [f"{name}={value}" for name, value in decoded_signals.items()]
                decoded_parts.append(f"DBC: {message.name} {' '.join(signal_strs)}")
            except KeyError:
                # This is expected if the frame ID is not in the DBC file.
                pass
            except Exception as e:
                # Log other, unexpected errors to the console for debugging
                print(f"DBC decoding error for ID 0x{frame.arbitration_id:X}: {e}")
                pass

        # CANopen decoding
        if self.show_canopen:
            canopen_data = CANopenDecoder.decode_frame(frame)
            if canopen_data:
                decoded_parts.append(f"CANopen: {canopen_data}")

        return " | ".join(decoded_parts) if decoded_parts else ""

class CANGroupedModel(QAbstractTableModel):
    """Table model for grouped CAN frames by ID"""

    def __init__(self):
        super().__init__()
        self.grouped_frames: Dict[int, List[CANFrame]] = {}
        self.id_order: List[int] = [] # Maintain insertion order
        self.headers = ["ID", "Name", "DLC", "Data", "Decoded", "Count", "Cycle Time", "Last"]
        self.dbc_database = None
        self.show_canopen = False

    def set_dbc_database(self, db):
        self.dbc_database = db
        self.modelReset.emit()

    def set_canopen_enabled(self, enabled):
        self.show_canopen = enabled
        self.modelReset.emit()

    def add_frame(self, frame: CANFrame):
        if frame.arbitration_id not in self.grouped_frames:
            # New ID - insert new row
            row = len(self.id_order)
            self.beginInsertRows(QModelIndex(), row, row)
            self.grouped_frames[frame.arbitration_id] = [frame]
            self.id_order.append(frame.arbitration_id)
            self.endInsertRows()
        else:
            # Existing ID - update row
            self.grouped_frames[frame.arbitration_id].append(frame)
            row = self.id_order.index(frame.arbitration_id)
            self.dataChanged.emit(self.index(row, 0), self.index(row, self.columnCount()-1))

    def clear_frames(self):
        self.beginResetModel()
        self.grouped_frames.clear()
        self.id_order.clear()
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self.id_order)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def headerData(self, section, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.headers[section]
        return None

    def data(self, index, role):
        if not index.isValid() or index.row() >= len(self.id_order):
            return None

        can_id = self.id_order[index.row()]
        frames = self.grouped_frames[can_id]
        latest_frame = frames[-1]
        col = index.column()

        # Data for sorting (numeric values)
        if role == Qt.UserRole:
            if col == 0: return can_id
            if col == 2: return latest_frame.dlc
            if col == 5: return len(frames)
            if col == 6: # Cycle Time
                if len(frames) > 1:
                    relevant_frames = frames[-10:] # Use last 10 for avg
                    if len(relevant_frames) > 1:
                        deltas = [relevant_frames[i].timestamp - relevant_frames[i-1].timestamp for i in range(1, len(relevant_frames))]
                        return sum(deltas) / len(deltas)
                return 0.0
            if col == 7: return latest_frame.timestamp
            return None

        if role == Qt.DisplayRole:
            if col == 0:  # ID
                return f"0x{can_id:X}"
            elif col == 1:  # Name
                if self.dbc_database and CAN_AVAILABLE:
                    try:
                        message = self.dbc_database.get_message_by_frame_id(can_id)
                        return message.name
                    except KeyError:
                        pass
                return ""
            elif col == 2:  # DLC
                return str(latest_frame.dlc)
            elif col == 3:  # Data
                return " ".join(f"{b:02X}" for b in latest_frame.data)
            elif col == 4:  # Decoded
                return self._decode_frame(latest_frame)
            elif col == 5:  # Count
                return str(len(frames))
            elif col == 6:  # Cycle Time
                if len(frames) > 1:
                    relevant_frames = frames[-10:] # Use last 10 for avg
                    if len(relevant_frames) > 1:
                        deltas = [relevant_frames[i].timestamp - relevant_frames[i-1].timestamp for i in range(1, len(relevant_frames))]
                        avg_cycle = sum(deltas) / len(deltas)
                        return f"{avg_cycle*1000:.1f} ms"
                return "-"
            elif col == 7:  # Last
                return f"{latest_frame.timestamp:.6f}"

        return None

    def _decode_frame(self, frame: CANFrame) -> str:
        """Decode frame using available decoders"""
        decoded_parts = []

        # DBC decoding
        if self.dbc_database and CAN_AVAILABLE:
            try:
                decoded_signals = self.dbc_database.decode_message(frame.arbitration_id, frame.data)
                signal_strs = [f"{name}={value}" for name, value in decoded_signals.items()]
                decoded_parts.append(" ".join(signal_strs))
            except KeyError:
                # This is expected if the frame ID is not in the DBC file.
                pass
            except Exception as e:
                # Log other, unexpected errors to the console for debugging
                print(f"DBC decoding error for ID 0x{frame.arbitration_id:X}: {e}")
                pass

        # CANopen decoding
        if self.show_canopen:
            canopen_data = CANopenDecoder.decode_frame(frame)
            if canopen_data:
                if isinstance(canopen_data, dict):
                    parts = [f"{k}={v}" for k, v in canopen_data.items() if k != 'protocol']
                    decoded_parts.append(f"{canopen_data.get('protocol', 'CANopen')}: {' '.join(parts)}")

        return " | ".join(decoded_parts) if decoded_parts else ""

class CANReaderThread(QThread):
    """Thread for reading CAN frames"""

    frame_received = Signal(CANFrame)
    error_occurred = Signal(str)

    def __init__(self, interface="socketcan", channel="vcan0"):
        super().__init__()
        self.interface = interface
        self.channel = channel
        self.running = False
        self.bus = None

    def start_reading(self):
        if not CAN_AVAILABLE:
            self.error_occurred.emit("python-can library not available")
            return False

        try:
            self.bus = can.Bus(interface=self.interface, channel=self.channel, receive_own_messages=True)
            self.running = True
            self.start()
            return True
        except Exception as e:
            self.error_occurred.emit(f"Failed to connect to CAN bus: {str(e)}")
            return False

    def stop_reading(self):
        self.running = False
        if self.bus:
            self.bus.shutdown()
        self.wait()

    def run(self):
        while self.running and self.bus:
            try:
                message = self.bus.recv(timeout=0.1)
                if message:
                    frame = CANFrame(
                        timestamp=message.timestamp,
                        arbitration_id=message.arbitration_id,
                        data=message.data,
                        dlc=message.dlc,
                        is_extended=message.is_extended_id,
                        is_error=message.is_error_frame,
                        is_remote=message.is_remote_frame
                    )
                    self.frame_received.emit(frame)
            except Exception as e:
                if self.running:  # Only emit error if we're still supposed to be running
                    self.error_occurred.emit(f"CAN read error: {str(e)}")
                break

class FilterWidget(QWidget):
    """Widget for configuring CAN frame filters"""

    def __init__(self):
        super().__init__()
        self.filter = CANFrameFilter()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Filter enable
        self.enabled_cb = QCheckBox("Enable Filter")
        self.enabled_cb.toggled.connect(self.update_filter)
        layout.addWidget(self.enabled_cb)

        # ID range
        id_group = QGroupBox("ID Range")
        id_layout = QFormLayout(id_group)

        self.min_id_edit = QLineEdit("0x000")
        self.max_id_edit = QLineEdit("0x7FF")
        self.mask_edit = QLineEdit("0x7FF")

        id_layout.addRow("Min ID:", self.min_id_edit)
        id_layout.addRow("Max ID:", self.max_id_edit)
        id_layout.addRow("Mask:", self.mask_edit)

        for edit in [self.min_id_edit, self.max_id_edit, self.mask_edit]:
            edit.textChanged.connect(self.update_filter)

        layout.addWidget(id_group)

        # Frame types
        type_group = QGroupBox("Frame Types")
        type_layout = QVBoxLayout(type_group)

        self.standard_cb = QCheckBox("Standard (11-bit)")
        self.extended_cb = QCheckBox("Extended (29-bit)")
        self.data_cb = QCheckBox("Data Frames")
        self.remote_cb = QCheckBox("Remote Frames")

        for cb in [self.standard_cb, self.extended_cb, self.data_cb, self.remote_cb]:
            cb.setChecked(True)
            cb.toggled.connect(self.update_filter)
            type_layout.addWidget(cb)

        layout.addWidget(type_group)

    def update_filter(self):
        self.filter.enabled = self.enabled_cb.isChecked()

        try:
            self.filter.min_id = int(self.min_id_edit.text(), 16)
        except ValueError:
            pass

        try:
            self.filter.max_id = int(self.max_id_edit.text(), 16)
        except ValueError:
            pass

        try:
            self.filter.mask = int(self.mask_edit.text(), 16)
        except ValueError:
            pass

        self.filter.accept_standard = self.standard_cb.isChecked()
        self.filter.accept_extended = self.extended_cb.isChecked()
        self.filter.accept_data = self.data_cb.isChecked()
        self.filter.accept_remote = self.remote_cb.isChecked()

class TransmitWidget(QGroupBox):
    """Widget for sending a single CAN frame"""
    frame_to_send = Signal(object) # Use object for can.Message

    def __init__(self):
        super().__init__("Transmit Frame")
        self.setup_ui()
        if not CAN_AVAILABLE:
            self.setEnabled(False)
            self.setTitle("Transmit Frame (python-can not available)")

    def setup_ui(self):
        layout = QFormLayout(self)

        self.id_edit = QLineEdit("100")
        self.data_edit = QLineEdit("00 11 22 33")
        self.dlc_spin = QSpinBox()
        self.dlc_spin.setRange(0, 8)
        self.dlc_spin.setValue(4)

        self.extended_cb = QCheckBox("Extended (29-bit)")
        self.rtr_cb = QCheckBox("RTR")
        self.send_btn = QPushButton("Send")

        layout.addRow("ID (hex):", self.id_edit)
        layout.addRow("Data (hex):", self.data_edit)
        layout.addRow("DLC:", self.dlc_spin)
        layout.addRow(self.extended_cb)
        layout.addRow(self.rtr_cb)
        layout.addRow(self.send_btn)

        self.send_btn.clicked.connect(self._on_send)
        self.data_edit.textChanged.connect(self._update_dlc_from_data)
        self.rtr_cb.toggled.connect(self._update_ui_for_rtr)

    def _update_dlc_from_data(self, text):
        if self.rtr_cb.isChecked(): return
        try:
            data_bytes = bytes.fromhex(text.replace(" ", ""))
            if len(data_bytes) <= 8:
                self.dlc_spin.setValue(len(data_bytes))
        except ValueError:
            pass

    def _update_ui_for_rtr(self, is_rtr):
        self.data_edit.setEnabled(not is_rtr)
        if is_rtr:
            self.data_edit.clear()
            self.dlc_spin.setValue(0)

    def _on_send(self):
        try:
            can_id = int(self.id_edit.text(), 16)
            is_extended = self.extended_cb.isChecked()
            is_rtr = self.rtr_cb.isChecked()
            dlc = self.dlc_spin.value()
            data_bytes = b''

            if not is_rtr:
                data_str = self.data_edit.text().replace(" ", "")
                data_bytes = bytes.fromhex(data_str)

                if len(data_bytes) != dlc:
                    if len(data_bytes) > dlc:
                        data_bytes = data_bytes[:dlc]
                    else:
                        data_bytes = data_bytes.ljust(dlc, b'\x00')

            if is_extended and can_id > 0x1FFFFFFF:
                raise ValueError("Extended ID (29-bit) exceeds maximum value.")
            if not is_extended and can_id > 0x7FF:
                raise ValueError("Standard ID (11-bit) exceeds maximum value.")

            message = can.Message(
                arbitration_id=can_id, data=data_bytes, is_extended_id=is_extended,
                is_remote_frame=is_rtr, dlc=dlc
            )
            self.frame_to_send.emit(message)
        except ValueError as e:
            QMessageBox.warning(self, "Invalid Input", f"Could not parse frame data: {e}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")


class CANBusObserver(QMainWindow):
    """Main CAN Bus Observer application"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("CAN Bus Observer")
        self.setGeometry(100, 100, 1200, 800)

        # Data
        self.trace_model = CANTraceModel()
        self.grouped_model = CANGroupedModel()
        self.grouped_proxy_model = QSortFilterProxyModel()
        self.grouped_proxy_model.setSourceModel(self.grouped_model)
        self.grouped_proxy_model.setSortRole(Qt.UserRole)

        self.can_reader = None
        self.dbc_database = None
        self.frame_filter = CANFrameFilter()
        self.log_file = None
        self.frame_count = 0

        # Setup UI
        self.setup_ui()
        self.setup_menubar()
        self.setup_statusbar()

        # Timer for periodic updates
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_stats)
        self.update_timer.start(1000)  # Update every second

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Toolbar
        toolbar_layout = QHBoxLayout()
        self.connect_btn = QPushButton("Connect")
        self.disconnect_btn = QPushButton("Disconnect")
        self.disconnect_btn.setEnabled(False)
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(["socketcan", "pcan", "kvaser", "vector", "virtual"])
        self.channel_edit = QLineEdit("vcan0")
        toolbar_layout.addWidget(QLabel("Interface:"))
        toolbar_layout.addWidget(self.interface_combo)
        toolbar_layout.addWidget(QLabel("Channel:"))
        toolbar_layout.addWidget(self.channel_edit)
        toolbar_layout.addWidget(self.connect_btn)
        toolbar_layout.addWidget(self.disconnect_btn)
        toolbar_layout.addStretch()
        layout.addLayout(toolbar_layout)

        # Main splitter
        main_splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(main_splitter)

        # Left side - Tables and Transmit
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)

        control_layout = QHBoxLayout()
        self.clear_btn = QPushButton("Clear")
        self.save_log_btn = QPushButton("Save Log")
        self.load_log_btn = QPushButton("Load Log")
        control_layout.addWidget(self.clear_btn)
        control_layout.addWidget(self.save_log_btn)
        control_layout.addWidget(self.load_log_btn)
        control_layout.addStretch()
        left_layout.addLayout(control_layout)

        self.tab_widget = QTabWidget()

        # Trace view
        trace_view_widget = QWidget()
        trace_layout = QVBoxLayout(trace_view_widget)
        trace_layout.setContentsMargins(0, 0, 0, 0)
        self.trace_table = QTableView()
        self.trace_table.setModel(self.trace_model)
        self.trace_table.horizontalHeader().setStretchLastSection(True)
        self.trace_table.setAlternatingRowColors(True)
        self.trace_table.setSelectionBehavior(QTableView.SelectRows)
        self.autoscroll_cb = QCheckBox("Autoscroll")
        self.autoscroll_cb.setChecked(True)
        trace_layout.addWidget(self.trace_table)
        trace_layout.addWidget(self.autoscroll_cb)
        self.tab_widget.addTab(trace_view_widget, "Trace")

        # Grouped view
        self.grouped_table = QTableView()
        self.grouped_table.setModel(self.grouped_proxy_model)
        self.grouped_table.setSortingEnabled(True)
        self.grouped_table.horizontalHeader().setStretchLastSection(True)
        self.grouped_table.setAlternatingRowColors(True)
        self.grouped_table.setSelectionBehavior(QTableView.SelectRows)
        self.tab_widget.addTab(self.grouped_table, "Grouped")

        left_layout.addWidget(self.tab_widget)

        # Transmit Panel
        self.transmit_widget = TransmitWidget()
        self.transmit_widget.frame_to_send.connect(self.send_can_frame)
        self.transmit_widget.setEnabled(False)
        left_layout.addWidget(self.transmit_widget)

        main_splitter.addWidget(left_widget)

        # Right side - Controls
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)

        dbc_group = QGroupBox("DBC Database")
        dbc_layout = QVBoxLayout(dbc_group)
        dbc_file_layout = QHBoxLayout()
        self.dbc_file_edit = QLineEdit()
        self.dbc_browse_btn = QPushButton("Browse")
        self.dbc_load_btn = QPushButton("Load")
        dbc_file_layout.addWidget(self.dbc_file_edit)
        dbc_file_layout.addWidget(self.dbc_browse_btn)
        dbc_file_layout.addWidget(self.dbc_load_btn)
        dbc_layout.addLayout(dbc_file_layout)
        right_layout.addWidget(dbc_group)

        canopen_group = QGroupBox("CANopen")
        canopen_layout = QVBoxLayout(canopen_group)
        self.canopen_enable_cb = QCheckBox("Enable CANopen Decoding")
        canopen_layout.addWidget(self.canopen_enable_cb)
        right_layout.addWidget(canopen_group)

        self.filter_widget = FilterWidget()
        right_layout.addWidget(self.filter_widget)

        right_layout.addStretch()
        main_splitter.addWidget(right_widget)

        main_splitter.setSizes([800, 400])

        # Connect signals
        self.connect_btn.clicked.connect(self.connect_can)
        self.disconnect_btn.clicked.connect(self.disconnect_can)
        self.clear_btn.clicked.connect(self.clear_data)
        self.save_log_btn.clicked.connect(self.save_log)
        self.load_log_btn.clicked.connect(self.load_log)
        self.dbc_browse_btn.clicked.connect(self.browse_dbc)
        self.dbc_load_btn.clicked.connect(self.load_dbc)
        self.canopen_enable_cb.toggled.connect(self.toggle_canopen)
        self.trace_model.rowsInserted.connect(self.autoscroll_trace_view)

        # Disable features if libraries are missing
        if not CAN_AVAILABLE:
            self.connect_btn.setEnabled(False)
            self.connect_btn.setText("Connect (lib missing)")
            self.dbc_load_btn.setEnabled(False)
            self.dbc_browse_btn.setEnabled(False)
            self.statusBar().showMessage("python-can or cantools not found. Functionality limited.")

    def setup_menubar(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")
        load_action = QAction("Load Log...", self)
        load_action.triggered.connect(self.load_log)
        file_menu.addAction(load_action)
        save_action = QAction("Save Log...", self)
        save_action.triggered.connect(self.save_log)
        file_menu.addAction(save_action)
        file_menu.addSeparator()
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        tools_menu = menubar.addMenu("Tools")
        dbc_action = QAction("Load DBC...", self)
        dbc_action.triggered.connect(self.browse_dbc)
        tools_menu.addAction(dbc_action)

    def setup_statusbar(self):
        self.statusBar().showMessage("Ready")
        self.frame_count_label = QLabel("Frames: 0")
        self.connection_label = QLabel("Disconnected")
        self.statusBar().addPermanentWidget(self.frame_count_label)
        self.statusBar().addPermanentWidget(self.connection_label)

    def connect_can(self):
        interface = self.interface_combo.currentText()
        channel = self.channel_edit.text()
        self.can_reader = CANReaderThread(interface, channel)
        self.can_reader.frame_received.connect(self.on_frame_received)
        self.can_reader.error_occurred.connect(self.on_can_error)

        if self.can_reader.start_reading():
            self.connect_btn.setEnabled(False)
            self.disconnect_btn.setEnabled(True)
            self.transmit_widget.setEnabled(True)
            self.connection_label.setText(f"Connected ({interface}:{channel})")
            self.statusBar().showMessage("CAN bus connected")
        else:
            self.can_reader = None

    def disconnect_can(self):
        if self.can_reader:
            self.can_reader.stop_reading()
            self.can_reader = None
        self.connect_btn.setEnabled(True)
        self.disconnect_btn.setEnabled(False)
        self.transmit_widget.setEnabled(False)
        self.connection_label.setText("Disconnected")
        self.statusBar().showMessage("CAN bus disconnected")

    def send_can_frame(self, message: can.Message):
        if self.can_reader and self.can_reader.bus:
            try:
                self.can_reader.bus.send(message)
                self.statusBar().showMessage(f"Sent frame ID 0x{message.arbitration_id:X}")
            except Exception as e:
                QMessageBox.critical(self, "Transmit Error", f"Failed to send frame: {str(e)}")
        else:
            QMessageBox.warning(self, "Not Connected", "Connect to a CAN bus before sending frames.")

    def autoscroll_trace_view(self):
        if self.autoscroll_cb.isChecked() and self.trace_table.model().rowCount() > 0:
            self.trace_table.scrollToBottom()

    def on_frame_received(self, frame: CANFrame):
        if not self.filter_widget.filter.matches(frame):
            return
        self.trace_model.add_frame(frame)
        self.grouped_model.add_frame(frame)
        if self.log_file:
            self.write_frame_to_log(frame)
        self.frame_count += 1

    def on_can_error(self, error_message: str):
        QMessageBox.warning(self, "CAN Error", error_message)
        self.statusBar().showMessage(f"Error: {error_message}")
        self.disconnect_can()

    def clear_data(self):
        self.trace_model.clear_frames()
        self.grouped_model.clear_frames()
        self.frame_count = 0
        self.frame_count_label.setText("Frames: 0")
        self.statusBar().showMessage("Data cleared")

    def save_log(self):
        if self.trace_model.rowCount() == 0:
            QMessageBox.information(self, "No Data", "No frames to save")
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Save CAN Log", "", "CAN Log Files (*.log);;All Files (*)")
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("# CAN Bus Log File\n")
                    f.write("# Format: timestamp id dlc data\n")
                    for frame in self.trace_model.frames:
                        data_str = " ".join(f"{b:02X}" for b in frame.data)
                        f.write(f"{frame.timestamp:.6f} {frame.arbitration_id:X} {frame.dlc} {data_str}\n")
                self.statusBar().showMessage(f"Log saved to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Save Error", f"Failed to save log: {str(e)}")

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
                            timestamp = float(parts[0])
                            arbitration_id = int(parts[1], 16)
                            dlc = int(parts[2])
                            data_bytes = [int(p, 16) for p in parts[3:3+dlc]]
                            frame = CANFrame(timestamp=timestamp, arbitration_id=arbitration_id, data=bytes(data_bytes), dlc=dlc)
                            self.trace_model.add_frame(frame)
                            self.grouped_model.add_frame(frame)
                            self.frame_count += 1
                        except (ValueError, IndexError):
                            print(f"Warning: Invalid line {line_num} in log file: {line}")
                self.statusBar().showMessage(f"Loaded {self.frame_count} frames from {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Load Error", f"Failed to load log: {str(e)}")

    def write_frame_to_log(self, frame: CANFrame):
        if self.log_file:
            try:
                data_str = " ".join(f"{b:02X}" for b in frame.data)
                self.log_file.write(f"{frame.timestamp:.6f} {frame.arbitration_id:X} {frame.dlc} {data_str}\n")
                self.log_file.flush()
            except Exception as e:
                print(f"Error writing to log file: {e}")

    def browse_dbc(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select DBC File", "", "DBC Files (*.dbc);;All Files (*)")
        if filename:
            self.dbc_file_edit.setText(filename)
            self.load_dbc()

    def load_dbc(self):
        filename = self.dbc_file_edit.text()
        if not filename:
            QMessageBox.warning(self, "No File", "Please select a DBC file first")
            return
        if not CAN_AVAILABLE:
            QMessageBox.warning(self, "Library Missing", "cantools library not installed.")
            return
        try:
            self.dbc_database = cantools.database.load_file(filename)
            self.trace_model.set_dbc_database(self.dbc_database)
            self.grouped_model.set_dbc_database(self.dbc_database)
            message_count = len(self.dbc_database.messages)
            self.statusBar().showMessage(f"DBC loaded: {message_count} messages")
        except Exception as e:
            QMessageBox.critical(self, "DBC Load Error", f"Failed to load DBC file: {str(e)}")
            self.dbc_database = None # Ensure it's cleared on failure
            self.trace_model.set_dbc_database(None)
            self.grouped_model.set_dbc_database(None)

    def toggle_canopen(self, enabled):
        self.trace_model.set_canopen_enabled(enabled)
        self.grouped_model.set_canopen_enabled(enabled)

    def update_stats(self):
        self.frame_count_label.setText(f"Frames: {self.frame_count}")

    def closeEvent(self, event):
        self.disconnect_can()
        if self.log_file:
            self.log_file.close()
        event.accept()

class CANFrameGenerator(QThread):
    """Thread for generating test CAN frames"""
    frame_generated = Signal(CANFrame)
    def __init__(self):
        super().__init__()
        self.running = False
        self.frame_id = 0x100
    def start_generation(self):
        self.running = True
        self.start()
    def stop_generation(self):
        self.running = False
        self.wait()
    def run(self):
        import random
        import time
        while self.running:
            test_ids = [0x100, 0x200, 0x300, 0x181, 0x182, 0x701, 0x702]
            for can_id in test_ids:
                if not self.running: break
                data_length = random.randint(1, 8)
                data = bytes([random.randint(0, 255) for _ in range(data_length)])
                frame = CANFrame(timestamp=time.time(), arbitration_id=can_id, data=data, dlc=data_length, is_extended=can_id > 0x7FF)
                self.frame_generated.emit(frame)
                time.sleep(0.1)
            time.sleep(1)

def main():
    app = QApplication(sys.argv)
    window = CANBusObserver()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
