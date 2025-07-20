from typing import Dict, Any
import inspect
import enum
from canpeek import rc_icons
from typing import TYPE_CHECKING

__all__ = [
    "rc_icons",  # remove ruff "Remove unused import: `.rc_icons`"
]


from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QLabel,
    QLineEdit,
    QCheckBox,
    QComboBox,
    QSpinBox,
    QGroupBox,
    QFormLayout,
    QMenu,
    QTreeWidgetItem,
    QDialog,
    QTextEdit,
)

from PySide6.QtCore import (
    Signal,
    Qt,
)
from PySide6.QtGui import (
    QAction,
)


# Import Polars backend components


from canpeek.co.canopen_utils import (
    CANopenNode,
    CANopenNodeEditor,
    CANopenRootEditor,
    PDOEditor,
)

from canpeek.data_utils import (
    Project,
    CANFrameFilter,
    DBCFile,
    CANInterfaceManager,
    Connection,
)

if TYPE_CHECKING:
    from __main__ import ProjectExplorer, CANBusObserver


# --- UI Classes ---
class DBCEditor(QWidget):
    message_to_transmit = Signal(object)
    project_changed = Signal()

    def __init__(self, dbc_file: DBCFile, project: Project):
        super().__init__()
        self.dbc_file = dbc_file
        self.project = project
        self.sorted_messages = []  # Store sorted messages for transmission
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        group = QGroupBox(f"DBC Content: {self.dbc_file.path.name}")

        form_layout = QFormLayout()

        self.channel_combo = QComboBox()
        self.channel_combo.addItem("All", None)  # "All" option with None as data
        self.connection_map = {conn.name: conn.id for conn in self.project.connections}
        for conn in self.project.connections:
            self.channel_combo.addItem(conn.name, conn.id)

        if self.dbc_file.connection_id:
            if self.dbc_file.connection_id == -1:
                self.channel_combo.setCurrentIndex(-1)
            else:
                # Find the name corresponding to the stored connection_id
                for name, conn_id in self.connection_map.items():
                    if conn_id == self.dbc_file.connection_id:
                        self.channel_combo.setCurrentText(name)
                        break
        else:
            self.channel_combo.setCurrentIndex(0)  # Select "All"

        self.channel_combo.currentTextChanged.connect(self._on_channel_changed)
        form_layout.addRow("Channel:", self.channel_combo)

        layout = QVBoxLayout(group)
        layout.addLayout(form_layout)
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

    def _on_channel_changed(self, text: str):
        selected_id = self.channel_combo.currentData()
        self.dbc_file.connection_id = selected_id
        self.project_changed.emit()

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

    def __init__(self, can_filter: CANFrameFilter, project: Project):
        super().__init__()
        self.filter = can_filter
        self.project = project
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        group = QGroupBox("Filter Properties")
        layout = QFormLayout(group)
        main_layout.addWidget(group)
        self.name_edit = QLineEdit(self.filter.name)
        layout.addRow("Name:", self.name_edit)

        self.channel_combo = QComboBox()
        self.channel_combo.addItem("All", None)  # "All" option with None as data
        self.connection_map = {conn.name: conn.id for conn in self.project.connections}
        for conn in self.project.connections:
            self.channel_combo.addItem(conn.name, conn.id)

        if self.filter.connection_id:
            if self.filter.connection_id == -1:
                self.channel_combo.setCurrentIndex(-1)
            else:
                # Find the name corresponding to the stored connection_id
                for name, conn_id in self.connection_map.items():
                    if conn_id == self.filter.connection_id:
                        self.channel_combo.setCurrentText(name)
                        break
        else:
            self.channel_combo.setCurrentIndex(0)  # Select "All"

        self.channel_combo.currentTextChanged.connect(self._update_filter)
        layout.addRow("Channel:", self.channel_combo)

        id_layout = QHBoxLayout()
        id_layout2 = QHBoxLayout()
        self.min_id_edit = QLineEdit(f"0x{self.filter.min_id:X}")
        self.max_id_edit = QLineEdit(f"0x{self.filter.max_id:X}")
        self.mask_edit = QLineEdit(f"0x{self.filter.mask:X}")
        self.mask_compare_edit = QLineEdit(f"0x{self.filter.mask_compare:X}")
        id_layout.addWidget(QLabel("Min:"))
        id_layout.addWidget(self.min_id_edit)
        id_layout.addWidget(QLabel("Max:"))
        id_layout.addWidget(self.max_id_edit)
        layout.addRow("ID (hex):", id_layout)
        id_layout2.addWidget(QLabel("Mask:"))
        id_layout2.addWidget(self.mask_edit)
        id_layout2.addWidget(QLabel("Mask Compare:"))
        id_layout2.addWidget(self.mask_compare_edit)
        layout.addRow(id_layout2)
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
        selected_id = self.channel_combo.currentData()
        self.filter.connection_id = selected_id
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

    def __init__(self, connection: Connection, interface_manager: CANInterfaceManager):
        super().__init__()
        self.connection = connection
        self.interface_manager = interface_manager
        self.dynamic_widgets = {}
        self.docs_window = DocumentationWindow(self)
        self.setup_ui()
        self.interface_combo.setCurrentText(self.connection.interface)
        self._rebuild_dynamic_fields(self.connection.interface)

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        group = QGroupBox("Connection Properties")
        self.form_layout = QFormLayout(group)
        main_layout.addWidget(group)

        self.name_edit = QLineEdit(self.connection.name)
        self.form_layout.addRow("Name:", self.name_edit)

        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.interface_manager.get_available_interfaces())
        self.form_layout.addRow("Interface:", self.interface_combo)

        self.show_docs_button = QPushButton("Show python-can Documentation...")
        self.form_layout.addRow(self.show_docs_button)

        self.dynamic_fields_container = QWidget()
        self.dynamic_layout = QFormLayout(self.dynamic_fields_container)
        self.dynamic_layout.setContentsMargins(0, 0, 0, 0)
        self.form_layout.addRow(self.dynamic_fields_container)

        self.name_edit.editingFinished.connect(self._on_name_changed)
        self.show_docs_button.clicked.connect(self._show_documentation_window)
        self.interface_combo.currentTextChanged.connect(self._on_interface_changed)

    def set_connected_state(self, connected):
        """Enable/disable interface field and settings based on connection state"""
        # Disable interface selection and name editing when connected
        self.interface_combo.setEnabled(not connected)
        # self.name_edit.setEnabled(not connected)

        # Disable all dynamic interface settings when connected
        for widget in self.dynamic_widgets.values():
            if hasattr(widget, "setEnabled"):
                widget.setEnabled(not connected)

    def _on_name_changed(self):
        self.connection.name = self.name_edit.text()
        self.project_changed.emit()

    def _show_documentation_window(self):
        interface_name = self.interface_combo.currentText()
        docstring = self.interface_manager.get_interface_docstring(interface_name)
        self.docs_window.set_content(interface_name, docstring)
        self.docs_window.show()
        self.docs_window.raise_()
        self.docs_window.activateWindow()

    def _on_interface_changed(self, interface_name: str):
        self._rebuild_dynamic_fields(interface_name)
        self.connection.interface = interface_name
        self.project_changed.emit()

    def _rebuild_dynamic_fields(self, interface_name: str):
        parsed_doc = self.interface_manager.get_interface_docstring(interface_name)
        param_docs = parsed_doc.get("params", {}) if parsed_doc else {}
        has_docs = bool(
            parsed_doc and (parsed_doc.get("description") or parsed_doc.get("params"))
        )
        self.show_docs_button.setVisible(has_docs)

        while self.dynamic_layout.count():
            item = self.dynamic_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.dynamic_widgets.clear()

        params = self.interface_manager.get_interface_params(interface_name)
        if not params:
            self._update_project_config()
            return

        for name, info in params.items():
            # Use the default prameter value from python-can if the interface type changed
            if self.connection.interface != interface_name:
                current_value = info.get("default", self.connection.config.get(name))
            else:
                current_value = self.connection.config.get(name, info.get("default"))

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
            else:
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
            return None

        return text

    def _update_project_config(self):
        self.connection.interface = self.interface_combo.currentText()
        params = (
            self.interface_manager.get_interface_params(self.connection.interface) or {}
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
                value = self.connection.config.get(name)

            if value is not None:
                new_config[name] = value

        self.connection.config.clear()
        self.connection.config.update(new_config)
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
        if isinstance(data, Connection):
            editor = ConnectionEditor(data, self.interface_manager)
            editor.project_changed.connect(self.explorer.rebuild_tree)
            # Set the initial connected state when the editor is shown
            is_connected = data.name in self.main_window.can_readers
            editor.set_connected_state(is_connected)
            self.current_widget = editor
        elif data == "canopen_root":
            editor = CANopenRootEditor(self.project, self.main_window.canopen_network)
            editor.settings_changed.connect(self.explorer.rebuild_tree)
            self.current_widget = editor
        elif isinstance(data, CANopenNode):
            editor = CANopenNodeEditor(data, self.main_window.pdo_manager, self.project)
            editor.node_changed.connect(self.explorer.rebuild_tree)
            editor.node_changed.connect(self.explorer.project_changed.emit)
            self.current_widget = editor
        elif isinstance(data, CANFrameFilter):
            editor = FilterEditor(data, self.project)
            # editor.filter_changed.connect(lambda: item.setText(0, data.name))
            editor.filter_changed.connect(self.explorer.project_changed.emit)
            editor.filter_changed.connect(self.explorer.rebuild_tree)
            self.current_widget = editor
        elif isinstance(data, DBCFile):
            editor = DBCEditor(data, self.project)
            # Connect the editor's signal to the panel's signal
            editor.message_to_transmit.connect(self.message_to_transmit.emit)
            editor.project_changed.connect(self.explorer.rebuild_tree)
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
