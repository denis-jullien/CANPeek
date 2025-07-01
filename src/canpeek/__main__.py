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
import json
from typing import Dict, List, Optional, Any, TYPE_CHECKING
from pathlib import Path
from functools import partial
import faulthandler
import qdarktheme
import inspect


import enum
from . import rc_icons

import asyncio
from qasync import QEventLoop, QApplication


__all__ = [
    "rc_icons",  # remove ruff "Remove unused import: `.rc_icons`"
]


from PySide6.QtWidgets import (
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

from PySide6.QtCore import (
    QTimer,
    Signal,
    Qt,
    QObject,
    QSortFilterProxyModel,
    QSettings,
)
from PySide6.QtGui import QAction, QKeyEvent, QIcon, QPixmap


import can
import cantools

from .co.canopen_utils import (
    CANopenNode,
    CANopenNodeEditor,
    CANopenRootEditor,
    PDOEditor,
    PDODatabaseManager,
    ObjectDictionaryViewer,
)

from .data_utils import (
    CANFrame,
    Project,
    CANFrameFilter,
    DBCFile,
    CANInterfaceManager,
)

from .models import CANTraceModel, CANGroupedModel

if TYPE_CHECKING:
    from __main__ import ProjectExplorer, CANBusObserver


faulthandler.enable()


# --- Data Structures ---
TRACE_BUFFER_LIMIT = 5000


# Replace the CANReaderThread class (around line 850)
class CANAsyncReader(QObject):
    frame_received = Signal(object)
    error_occurred = Signal(str)

    def __init__(self, interface: str, config: Dict[str, Any]):
        super().__init__()
        self.interface = interface
        self.config = config
        self.running = False
        self.bus = None
        self.notifier = None
        self.reader = None
        self.read_task = None

    # @property
    # def notifier(self):
    #     """Expose the notifier for canopen-asyncio integration"""
    #     return self._notifier

    async def start_reading(self):
        """Start async CAN reading"""
        try:
            self.bus = can.Bus(
                interface=self.interface, receive_own_messages=True, **self.config
            )

            # Create async reader and notifier
            # self.reader = can.AsyncBufferedReader()

            # Get the current event loop
            loop = asyncio.get_running_loop()

            # Create notifier with the loop
            self.notifier = can.Notifier(self.bus, [self.rx_messages], loop=loop)

            self.running = True

            return True

        except Exception as e:
            self.error_occurred.emit(f"Failed to start CAN reading: {e}")
            return False

    def rx_messages(self, msg: can.Message) -> None:
        """Regular callback function. Can also be a coroutine."""
        # print(msg)
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

    def stop_reading(self):
        """Stop async CAN reading"""
        self.running = False

        if self.read_task and not self.read_task.done():
            self.read_task.cancel()

        if self.notifier:
            self.notifier.stop()
            self.notifier = None

        if self.bus:
            try:
                self.bus.shutdown()
            except Exception as e:
                print(f"Error shutting down CAN bus: {e}")
            finally:
                self.bus = None

        self.reader = None
        self.read_task = None

    def send_frame(self, message: can.Message):
        """Send a CAN frame"""
        if self.bus and self.running:
            try:
                self.bus.send(message)
            except Exception as e:
                self.error_occurred.emit(f"Send error: {e}")


# --- UI Classes ---
class DBCEditor(QWidget):
    message_to_transmit = Signal(object)

    def __init__(self, dbc_file: DBCFile):
        super().__init__()
        self.dbc_file = dbc_file
        self.sorted_messages = []  # Store sorted messages for transmission
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

        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.open_context_menu)

        self.populate_table()
        self.table.resizeColumnsToContents()

    def populate_table(self):
        # Store the sorted list in the instance variable
        self.sorted_messages = sorted(
            self.dbc_file.database.messages, key=lambda m: m.frame_id
        )
        self.table.setRowCount(len(self.sorted_messages))
        for r, m in enumerate(self.sorted_messages):
            self.table.setItem(r, 0, QTableWidgetItem(m.name))
            self.table.setItem(r, 1, QTableWidgetItem(f"0x{m.frame_id:X}"))
            self.table.setItem(r, 2, QTableWidgetItem(str(m.length)))
            self.table.setItem(
                r, 3, QTableWidgetItem(", ".join(s.name for s in m.signals))
            )

    # --- Add these two new methods ---
    def open_context_menu(self, position):
        """Creates and shows the context menu."""
        item = self.table.itemAt(position)
        if not item:
            return

        row = item.row()
        message = self.sorted_messages[row]

        menu = QMenu()
        action = QAction(f"Add '{message.name}' to Transmit Panel", self)
        action.triggered.connect(lambda: self._emit_transmit_signal(row))
        menu.addAction(action)

        menu.exec(self.table.viewport().mapToGlobal(position))

    def _emit_transmit_signal(self, row: int):
        """Emits the signal with the selected message object."""
        message = self.sorted_messages[row]
        self.message_to_transmit.emit(message)


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
        # Initial population based on the project's current state
        self.interface_combo.setCurrentText(self.project.can_interface)
        self._rebuild_dynamic_fields(self.project.can_interface)

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        group = QGroupBox("Connection Properties")
        self.form_layout = QFormLayout(group)
        main_layout.addWidget(group)
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

        # Connect the top-level combo box to its own handler

        # --- Connections and Initial State ---
        self.show_docs_button.clicked.connect(self._show_documentation_window)
        self.interface_combo.currentTextChanged.connect(self._on_interface_changed)

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
        """Called ONLY when the interface dropdown changes."""
        self.project.can_interface = interface_name
        # Do NOT clear the config here. We might want to preserve settings
        # like 'bitrate' if the new interface also has them.
        self._rebuild_dynamic_fields(interface_name)
        # We must emit project_changed here to update the project tree text
        self.project_changed.emit()

    def _rebuild_dynamic_fields(self, interface_name: str):
        # Fetch the parsed docstring data once
        parsed_doc = self.interface_manager.get_interface_docstring(interface_name)
        param_docs = parsed_doc.get("params", {}) if parsed_doc else {}

        has_docs = bool(
            parsed_doc and (parsed_doc.get("description") or parsed_doc.get("params"))
        )
        self.show_docs_button.setVisible(has_docs)

        # Clear old widgets
        while self.dynamic_layout.count():
            item = self.dynamic_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.dynamic_widgets.clear()

        params = self.interface_manager.get_interface_params(interface_name)
        if not params:
            self._update_project_config()  # Ensure config is empty if no params
            return

        for name, info in params.items():
            # Get value from project's config first, fallback to param default
            current_value = self.project.can_config.get(name, info.get("default"))
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

            # --- Widget Creation ---
            if is_enum:
                widget = QComboBox()
                widget.setProperty("enum_class", expected_type)
                widget.addItems([m.name for m in list(expected_type)])
                if isinstance(current_value, enum.Enum):
                    widget.setCurrentText(current_value.name)
                elif isinstance(current_value, str) and current_value in [
                    m.name for m in expected_type
                ]:
                    widget.setCurrentText(current_value)
                widget.currentTextChanged.connect(self._update_project_config)
            elif expected_type is bool:
                widget = QCheckBox()
                widget.setChecked(
                    bool(current_value) if current_value is not None else False
                )
                widget.toggled.connect(self._update_project_config)
            elif name == "bitrate" and expected_type is int:
                widget = QSpinBox()
                widget.setRange(1000, 4000000)
                widget.setSuffix(" bps")
                widget.setValue(
                    int(current_value) if current_value is not None else 125000
                )
                widget.valueChanged.connect(self._update_project_config)
            else:  # Fallback to QLineEdit
                widget = QLineEdit()
                widget.setText(str(current_value) if current_value is not None else "")
                widget.editingFinished.connect(self._update_project_config)

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

        # Perform an initial update to sync the model, just in case
        self._update_project_config()

    def _convert_line_edit_text(self, text: str, param_info: Dict) -> Any:
        text = text.strip()
        expected_type = param_info.get("type")
        if text == "" or text.lower() == "none":
            return None

        try:
            if expected_type is int:
                return int(text) if not text.startswith("0x") else int(text, 16)
            if expected_type is float:
                return float(text)
            if expected_type is bool:
                return text.lower() in ("true", "1", "t", "yes", "y")
        except (ValueError, TypeError):
            # On parsing error, return None or a sensible default.
            # Here we return None, the project will use its last known good value.
            return None

        return text

    def _update_project_config(self):
        """The single point of truth for updating the project's CAN config."""
        # Update the project's interface name from the combo box
        self.project.can_interface = self.interface_combo.currentText()

        params = (
            self.interface_manager.get_interface_params(self.project.can_interface)
            or {}
        )
        new_config = {}

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
                    if enum_class and widget.currentText():
                        value = enum_class[widget.currentText()]
                elif isinstance(widget, QLineEdit):
                    value = self._convert_line_edit_text(widget.text(), param_info)
            except (ValueError, TypeError, KeyError) as e:
                print(f"Warning: Invalid input for '{name}'. Error: {e}")
                # Keep the old value from the project's config if input is bad
                value = self.project.can_config.get(name)

            # Only add non-None values to the config to keep it clean
            if value is not None:
                new_config[name] = value

        # Update the project's config dictionary in-place.
        # This is the key fix!
        self.project.can_config.clear()
        self.project.can_config.update(new_config)

        # Notify the rest of the application that the project has changed.
        self.project_changed.emit()


class PropertiesPanel(QWidget):
    message_to_transmit = Signal(object)

    def __init__(
        self,
        project: Project,
        explorer: "ProjectExplorer",
        interface_manager: CANInterfaceManager,
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
            self.current_widget = editor
        elif isinstance(data, CANopenNode):
            editor = CANopenNodeEditor(data, self.main_window.pdo_manager)
            editor.node_changed.connect(self.explorer.rebuild_tree)
            editor.node_changed.connect(self.explorer.project_changed.emit)
            self.current_widget = editor
        elif isinstance(data, CANFrameFilter):
            editor = FilterEditor(data)
            editor.filter_changed.connect(lambda: item.setText(0, data.name))
            editor.filter_changed.connect(self.explorer.project_changed.emit)
            self.current_widget = editor
        elif isinstance(data, DBCFile):
            editor = DBCEditor(data)
            # Connect the editor's signal to the panel's signal
            editor.message_to_transmit.connect(self.message_to_transmit.emit)
            self.current_widget = editor
        elif isinstance(data, tuple) and len(data) == 2 and data[0] == "pdo_content":
            # PDO content viewer for CANopen node
            node = data[1]
            self.current_widget = PDOEditor(node, self.main_window.pdo_manager)
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

    def expand_all_items(self):
        """Expands all items in the project tree."""
        self.tree.expandAll()

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
    row_selection_changed = Signal(int, str, str)  # row, id_text, data_hex
    config_changed = Signal()

    def __init__(self):
        super().__init__("Transmit")
        self.timers: Dict[int, QTimer] = {}
        self.dbcs: List[object] = []
        self.setup_ui()
        # self.setEnabled(True)

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

    def add_message_frame(self, message: cantools.db.Message):
        """Adds a new row to the transmit table based on a DBC message definition."""
        r = self.table.rowCount()
        self.table.insertRow(r)
        self._setup_row_widgets(r)

        # Now, populate the new row with data from the message object
        self.table.blockSignals(True)

        # ID
        self.table.item(r, 1).setText(f"{message.frame_id:X}")

        # Type (Std/Ext)
        self.table.cellWidget(r, 2).setCurrentIndex(
            1 if message.is_extended_frame else 0
        )

        # DLC
        self.table.item(r, 4).setText(str(message.length))

        # Data (encode with defaults to get initial values)
        try:
            initial_data = message.encode({}, scaling=False, padding=True)
            self.table.item(r, 5).setText(initial_data.hex(" "))
        except Exception as e:
            print(f"Could not encode initial data for {message.name}: {e}")
            self.table.item(r, 5).setText("00 " * message.length)

        self.table.blockSignals(False)
        self.config_changed.emit()  # Mark project as dirty

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
            row = curr.row()
            # Also get the data from the data column (5)
            id_text = self.table.item(row, 1).text()
            data_item = self.table.item(row, 5)
            data_hex = data_item.text() if data_item else ""

            self.row_selection_changed.emit(row, id_text, data_hex)

    def _on_cell_changed(self, r, c):
        self.config_changed.emit()
        # Also update on data change
        if c == 1 or c == 5:
            id_text = self.table.item(r, 1).text()
            data_item = self.table.item(r, 5)
            data_hex = data_item.text() if data_item else ""
            self.row_selection_changed.emit(r, id_text, data_hex)

    def _update_dlc(self, r):
        try:
            self.table.item(r, 4).setText(
                str(len(bytes.fromhex(self.table.item(r, 5).text().replace(" ", ""))))
            )
        except (ValueError, TypeError):
            pass

    def update_row_data(self, r, data):
        # Block signals on the table to prevent re-triggering the change cascade
        self.table.blockSignals(True)

        self.table.item(r, 5).setText(data.hex(" "))
        self.table.item(r, 4).setText(str(len(data)))

        self.table.blockSignals(False)

        # We still want to mark the project as dirty after the change
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
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ["Signal", "Value", "Unit", "Min", "Max", "Status"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)
        self.table.cellChanged.connect(self._validate_and_encode)

    def clear_panel(self):
        self.message = None
        self.table.setRowCount(0)
        self.setTitle("Signal Config")
        self.setVisible(False)

    def _set_status(self, row: int, text: str, is_error: bool):
        """Helper to set the text and color of a status cell."""
        status_item = QTableWidgetItem(text)
        if is_error:
            status_item.setForeground(Qt.red)
            status_item.setToolTip(text)
        else:
            status_item.setForeground(Qt.green)

        status_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        self.table.setItem(row, 5, status_item)

    def populate(self, msg, data_hex: str):
        self.message = msg
        initial_values = {}

        # Try to decode the existing data to pre-fill the values
        if data_hex:
            try:
                data_bytes = bytes.fromhex(data_hex.replace(" ", ""))
                # Use allow_truncated=True to handle cases where data is shorter than expected
                initial_values = msg.decode(
                    data_bytes, decode_choices=False, allow_truncated=True
                )
            except (ValueError, KeyError) as e:
                print(f"Could not decode existing data for signal panel: {e}")
                initial_values = {}  # Fallback to defaults on error

        self.table.blockSignals(True)
        self.table.setRowCount(len(msg.signals))

        for r, s in enumerate(msg.signals):
            # Use the decoded value if available, otherwise use the signal's default initial value
            value = initial_values.get(
                s.name, s.initial if s.initial is not None else 0
            )

            self.table.setItem(r, 0, QTableWidgetItem(s.name))
            self.table.item(r, 0).setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)

            self.table.setItem(r, 1, QTableWidgetItem(str(value)))

            self.table.setItem(r, 2, QTableWidgetItem(str(s.unit or "")))
            self.table.item(r, 2).setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)

            # --- Min (Col 3) - NEW ---
            min_val = s.minimum if s.minimum is not None else "N/A"
            min_item = QTableWidgetItem(str(min_val))
            min_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            min_item.setToolTip(f"Minimum allowed value for {s.name}")
            self.table.setItem(r, 3, min_item)

            # --- Max (Col 4) - NEW ---
            max_val = s.maximum if s.maximum is not None else "N/A"
            max_item = QTableWidgetItem(str(max_val))
            max_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            max_item.setToolTip(f"Maximum allowed value for {s.name}")
            self.table.setItem(r, 4, max_item)

            self.table.setItem(r, 5, QTableWidgetItem(""))

        self.table.blockSignals(False)
        self.setTitle(f"Signal Config: {msg.name}")
        self.setVisible(True)
        # Trigger an initial encode to ensure the data field is up-to-date,
        # especially if we fell back to default values.
        self._validate_and_encode()

    def _validate_and_encode(self):
        """
        Validates the signal values against the DBC, updates the status column
        with any errors, and emits the encoded data if successful.
        """
        if not self.message:
            return

        # --- 1. Build the data dictionary from the table ---
        data_dict = {}
        parse_errors = False

        # We don't need to block signals here as we are just reading
        for r in range(self.table.rowCount()):
            signal_name = self.table.item(r, 0).text()
            value_text = self.table.item(r, 1).text()
            try:
                data_dict[signal_name] = float(value_text)
            except (ValueError, TypeError):
                parse_errors = True
                # We will set the status message for this *after* reading all values

        # --- Temporarily block signals to prevent recursion when updating status ---
        self.table.blockSignals(True)

        # Update status based on initial parsing
        for r in range(self.table.rowCount()):
            signal_name = self.table.item(r, 0).text()
            if signal_name not in data_dict:
                self._set_status(r, "Invalid number", is_error=True)
            else:
                self._set_status(r, "", is_error=False)  # Clear previous parse errors

        self.table.blockSignals(False)
        # --------------------------------------------------------------------------

        if parse_errors:
            return

        # --- 2. Attempt to encode and handle validation errors ---
        try:
            encoded_data = self.message.encode(data_dict, strict=True)

            # Block signals again for the success case
            self.table.blockSignals(True)
            for r in range(self.table.rowCount()):
                self._set_status(r, "OK", is_error=False)
            self.table.blockSignals(False)

            self.data_encoded.emit(encoded_data)

        except (cantools.database.errors.EncodeError, ValueError, KeyError) as e:
            error_str = str(e)

            # Block signals while we update rows with error messages
            self.table.blockSignals(True)
            found_error_signal = False
            for r in range(self.table.rowCount()):
                signal_name = self.table.item(r, 0).text()
                if f'"{signal_name}"' in error_str:
                    self._set_status(r, error_str, is_error=True)
                    found_error_signal = True
                else:
                    self._set_status(r, "OK", is_error=False)

            if not found_error_signal:
                self._set_status(0, error_str, is_error=True)

            self.table.blockSignals(False)


# --- Main Application Window ---
class CANBusObserver(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CANPeek")
        self.setGeometry(100, 100, 1400, 900)
        self.canopen_network = None  # Will be created when connecting
        self.MAX_RECENT_PROJECTS = 10
        self.recent_projects_paths = []
        self.interface_manager = CANInterfaceManager()
        self.pdo_manager = PDODatabaseManager()
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

        icon = QIcon(QPixmap(":/icons/canpeek.png"))
        self.setWindowIcon(icon)

        # Connect project changes to PDO cache invalidation
        self.project_explorer.project_changed.connect(
            self._on_project_structure_changed
        )

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
        self.connect_action.triggered.connect(
            lambda: asyncio.create_task(self.connect_can())
        )
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
        self.object_dictionary_viewer = ObjectDictionaryViewer()
        self.object_dictionary_viewer.frame_to_send.connect(self.send_can_frame)
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
        # self.transmit_panel.setEnabled(False)
        transmit_dock = QDockWidget("Transmit", self)
        transmit_dock.setObjectName("TransmitDock")
        transmit_dock.setWidget(transmit_container)
        self.addDockWidget(Qt.BottomDockWidgetArea, transmit_dock)
        self.docks = {
            "explorer": explorer_dock,
            "properties": properties_dock,
            "transmit": transmit_dock,
        }
        self.properties_panel.message_to_transmit.connect(
            self._add_message_to_transmit_panel
        )
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

    def _add_message_to_transmit_panel(self, message: cantools.db.Message):
        """Slot to handle request to add a DBC message to the transmit panel."""
        self.transmit_panel.add_message_frame(message)

    def keyPressEvent(self, event: QKeyEvent):
        if event.key() == Qt.Key_Space and self.transmit_panel.table.hasFocus():
            self.transmit_panel.send_selected()
            event.accept()
        else:
            super().keyPressEvent(event)

    def _process_frame(self, frame: CANFrame):
        try:
            # if self.project.canopen_enabled:
            #     self.canopen_network.notify(
            #         frame.arbitration_id, frame.data, frame.timestamp
            #     )
            #     if frame.arbitration_id == 0x58C:
            #         print("Received SDO frame:", frame)
            self.frame_batch.append(frame)
            if frame.arbitration_id & 0x580 == 0x580:
                # This is an SDO frame, process it
                self.object_dictionary_viewer.frame_rx_sdo.emit(frame)
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
        """Create PDO databases from enabled CANopen nodes using manager"""
        return self.pdo_manager.get_all_active_databases(self.project.canopen_nodes)

    def on_project_changed(self):
        active_dbcs = self.project.get_active_dbcs()
        pdo_databases = self._create_pdo_databases()

        self.trace_model.set_config(
            active_dbcs, self.project.canopen_enabled, pdo_databases
        )
        self.grouped_model.set_config(
            active_dbcs, self.project.canopen_enabled, pdo_databases
        )

        # If already connected, re-add nodes asynchronously
        if self.canopen_network and self.can_reader and self.can_reader.bus:
            # Schedule async node update
            asyncio.create_task(self._update_canopen_nodes())

        self.transmit_panel.set_dbc_databases(active_dbcs)

        row = self.transmit_panel.table.currentRow()
        id_text = ""
        data_hex = ""
        if row >= 0:
            id_item = self.transmit_panel.table.item(row, 1)
            if id_item:
                id_text = id_item.text()

            data_item = self.transmit_panel.table.item(row, 5)
            if data_item:
                data_hex = data_item.text()

        self.on_transmit_row_selected(row, id_text, data_hex)

        self.properties_panel.project = self.project

        # Update object dictionary viewer
        current_item = self.project_explorer.tree.currentItem()
        if current_item:
            self.on_project_explorer_selection_changed(current_item, None)
        else:
            self.object_dictionary_viewer.clear_node()

    def on_transmit_row_selected(self, row: int, id_text: str, data_hex: str):
        self.signal_transmit_panel.clear_panel()
        if row < 0 or not id_text:
            return
        try:
            can_id = int(id_text, 16)
            message = self.transmit_panel.get_message_from_id(can_id)
            if message:
                # Pass the existing data_hex to the populate method
                self.signal_transmit_panel.populate(message, data_hex)
        except ValueError:
            pass  # Invalid ID text, just clear the panel

    def on_signal_data_encoded(self, data_bytes):
        if (row := self.transmit_panel.table.currentRow()) >= 0:
            self.transmit_panel.update_row_data(row, data_bytes)

    async def _update_canopen_nodes(self):
        """Update CANopen nodes when project changes while connected"""
        if not self.canopen_network:
            return

        # Clear existing nodes
        self.canopen_network.nodes.clear()

        # Re-add nodes if CANopen is enabled
        if self.project.canopen_enabled:
            for node_config in self.project.canopen_nodes:
                if node_config.enabled and node_config.path.exists():
                    try:
                        await self.canopen_network.aadd_node(
                            node_config.node_id, str(node_config.path)
                        )
                        print(f"Updated CANopen node {node_config.node_id}")
                    except Exception as e:
                        print(f"Error updating CANopen node {node_config.node_id}: {e}")

    def on_project_explorer_selection_changed(self, current, previous):
        """Handle project explorer selection changes"""
        if not current:
            self.object_dictionary_viewer.clear_node()
            return

        data = current.data(0, Qt.UserRole)
        if isinstance(data, CANopenNode) and data.enabled:
            # CANopen node selected
            asyncio.create_task(self.object_dictionary_viewer.set_node(data))
        else:
            # Non-CANopen item selected
            self.object_dictionary_viewer.clear_node()

    async def connect_can(self):
        self.can_reader = CANAsyncReader(
            self.project.can_interface, self.project.can_config
        )
        self.can_reader.frame_received.connect(self._process_frame)
        self.can_reader.error_occurred.connect(self.on_can_error)

        if not await self.can_reader.start_reading():
            self.can_reader = None
            self.on_can_error("Failed to establish bus object in reader thread.")
            return

        self.connect_action.setEnabled(False)
        self.disconnect_action.setEnabled(True)
        # self.transmit_panel.setEnabled(True)
        config_str = ", ".join(f"{k}={v}" for k, v in self.project.can_config.items())
        self.connection_label.setText(
            f"Connected ({self.project.can_interface}: {config_str})"
        )
        if current_item := self.project_explorer.tree.currentItem():
            self.properties_panel.show_properties(current_item)

    # Update the disconnect_can method (around line 2715)
    def disconnect_can(self):
        if self.canopen_network:
            # Disconnect nodes
            for node in self.canopen_network.nodes.values():
                if hasattr(node, "pdo"):
                    node.pdo.stop()

            # The network will be cleaned up when we stop the reader
            self.canopen_network = None

        if self.can_reader:
            self.can_reader.stop_reading()
            self.can_reader.deleteLater()
            self.can_reader = None

        self.connect_action.setEnabled(True)
        self.disconnect_action.setEnabled(False)
        # self.transmit_panel.setEnabled(False)
        self.transmit_panel.stop_all_timers()
        self.connection_label.setText("Disconnected")
        if current_item := self.project_explorer.tree.currentItem():
            self.properties_panel.show_properties(current_item)

    # Update the send_can_frame method (around line 2732)
    def send_can_frame(self, message: can.Message):
        if self.can_reader and self.can_reader.running:
            self.can_reader.send_frame(message)
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
        self.pdo_manager.invalidate_cache()  # Clear PDO cache
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
            self.pdo_manager.invalidate_cache()  # Clear PDO cache
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
            self.project_explorer.expand_all_items()  # <--- ADD THIS LINE
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

    def _on_project_structure_changed(self):
        """Handle project structure changes that might affect PDO databases"""
        # This is called when the project structure changes
        # We could be more selective about cache invalidation here
        pass

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

    event_loop = QEventLoop(app)
    asyncio.set_event_loop(event_loop)

    app_close_event = asyncio.Event()
    app.aboutToQuit.connect(app_close_event.set)

    app.setOrganizationName("CANPeek")
    app.setApplicationName("CANPeek")
    window = CANBusObserver()
    qdarktheme.setup_theme("auto")
    window.show()

    with event_loop:
        event_loop.run_until_complete(app_close_event.wait())


if __name__ == "__main__":
    main()
