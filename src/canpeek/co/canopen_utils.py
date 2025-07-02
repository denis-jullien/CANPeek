"""
CANopen related utilities, widgets, and logic for CANPeek.
"""

import asyncio
import struct
from pathlib import Path
from typing import Dict, List, Optional

import canopen
from .dcf2db import dcf_2_db

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QGroupBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QCheckBox,
    QSpinBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QSplitter,
    QProgressBar,
    QSizePolicy,
    QComboBox,
)
from PySide6.QtCore import Signal, Qt

# Use TYPE_CHECKING to avoid circular import errors at runtime
from ..data_utils import CANFrame, Project, CANopenNode
from .sdo_client import SdoClient, SdoAbortedError


class PDODatabaseManager:
    """Manages PDO databases with caching to avoid duplicate creation"""

    def __init__(self):
        self._cache = {}  # Cache: (path, node_id) -> database

    def get_pdo_database(self, node: CANopenNode):
        """Get or create PDO database for a CANopen node"""
        if not node.pdo_decoding_enabled:
            return None

        cache_key = (str(node.path), node.node_id)

        if cache_key not in self._cache:
            try:
                slave_name = f"{node.path.stem}_Node{node.node_id}"
                self._cache[cache_key] = dcf_2_db(
                    str(node.path), node.node_id, slave_name
                )
                print(f"Created PDO database for node {node.node_id}")
            except Exception as e:
                print(f"Error creating PDO database for node {node.node_id}: {e}")
                return None

        return self._cache[cache_key]

    def invalidate_cache(self, node: CANopenNode = None):
        """Invalidate cache for a specific node or all nodes"""
        if node:
            cache_key = (str(node.path), node.node_id)
            self._cache.pop(cache_key, None)
        else:
            self._cache.clear()

    def get_all_active_databases(self, nodes: List[CANopenNode]) -> List[object]:
        """Get all PDO databases for enabled nodes"""
        databases = []
        for node in nodes:
            if node.enabled and node.pdo_decoding_enabled:
                db = self.get_pdo_database(node)
                if db:
                    databases.append(db)
        return databases


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


class PDOEditor(QWidget):
    def __init__(self, node: CANopenNode, pdo_manager: PDODatabaseManager):
        super().__init__()
        self.node = node
        self.pdo_manager = pdo_manager
        self.pdo_database = None
        self.setup_ui()
        self.load_pdo_database()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        group = QGroupBox(
            f"PDO Content: {self.node.path.name} (Node {self.node.node_id})"
        )
        layout = QVBoxLayout(group)
        main_layout.addWidget(group)

        self.table = QTableWidget()
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Message", "ID (hex)", "DLC", "Signals"])
        layout.addWidget(self.table)

        self.status_label = QLabel("Loading PDO database...")
        layout.addWidget(self.status_label)

    def load_pdo_database(self):
        """Load PDO database using the manager"""
        try:
            self.pdo_database = self.pdo_manager.get_pdo_database(self.node)
            if self.pdo_database:
                self.populate_table()
                self.status_label.setText(
                    f"Loaded {len(self.pdo_database.messages)} PDO messages"
                )
            else:
                self.status_label.setText("PDO decoding not enabled or failed to load")
                self.table.setRowCount(0)
        except Exception as e:
            self.status_label.setText(f"Error loading PDO database: {str(e)}")
            self.table.setRowCount(0)

    def populate_table(self):
        if not self.pdo_database:
            return

        messages = sorted(self.pdo_database.messages, key=lambda m: m.frame_id)
        self.table.setRowCount(len(messages))

        for r, m in enumerate(messages):
            self.table.setItem(r, 0, QTableWidgetItem(m.name))
            self.table.setItem(r, 1, QTableWidgetItem(f"0x{m.frame_id:X}"))
            self.table.setItem(r, 2, QTableWidgetItem(str(m.length)))
            self.table.setItem(
                r, 3, QTableWidgetItem(", ".join(s.name for s in m.signals))
            )

        self.table.resizeColumnsToContents()


class CANopenNodeEditor(QWidget):
    node_changed = Signal()

    def __init__(
        self, node: CANopenNode, pdo_manager: PDODatabaseManager, project: Project
    ):
        super().__init__()
        self.node = node
        self.pdo_manager = pdo_manager
        self.project = project
        self.pdo_editor = None
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Node properties group
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

        self.channel_combo = QComboBox()
        # self.channel_combo.addItem("", None)  # "All" option with None as data
        self.connection_map = {conn.name: conn.id for conn in self.project.connections}
        for conn in self.project.connections:
            self.channel_combo.addItem(conn.name, conn.id)

        self.channel_combo.setCurrentIndex(-1)  # Reset to no selection

        if self.node.connection_id:
            # Find the name corresponding to the stored connection_id
            for name, conn_id in self.connection_map.items():
                if conn_id == self.node.connection_id:
                    self.channel_combo.setCurrentText(name)
                    break

        self.channel_combo.currentTextChanged.connect(self._update_node)
        layout.addRow("Channel:", self.channel_combo)

        # Add PDO decoding checkbox
        self.pdo_decoding_cb = QCheckBox("Enable PDO Decoding")
        self.pdo_decoding_cb.setChecked(self.node.pdo_decoding_enabled)
        self.pdo_decoding_cb.setToolTip("Decode PDO messages using EDS/DCF file")
        layout.addRow(self.pdo_decoding_cb)
        self.pdo_decoding_cb.toggled.connect(self._update_node)
        self.pdo_decoding_cb.toggled.connect(self._toggle_pdo_content)

        # PDO content area (initially hidden)
        self._setup_pdo_content()

    def _setup_pdo_content(self):
        """Setup PDO content viewer"""
        if self.node.pdo_decoding_enabled:
            self.pdo_editor = PDOEditor(self.node, self.pdo_manager)
            self.layout().addWidget(self.pdo_editor)

    def _toggle_pdo_content(self, enabled: bool):
        """Show/hide PDO content based on checkbox state"""
        if enabled and not self.pdo_editor:
            self.pdo_editor = PDOEditor(self.node, self.pdo_manager)
            self.layout().addWidget(self.pdo_editor)
        elif not enabled and self.pdo_editor:
            self.pdo_editor.deleteLater()
            self.pdo_editor = None

    def _update_node(self):
        old_node_id = self.node.node_id
        old_pdo_enabled = self.node.pdo_decoding_enabled

        self.node.node_id = self.node_id_spinbox.value()
        self.node.connection_id = self.channel_combo.currentData()
        self.node.pdo_decoding_enabled = self.pdo_decoding_cb.isChecked()

        # Invalidate cache if node ID changed
        if old_node_id != self.node.node_id:
            # Invalidate old cache entry
            old_node = CANopenNode(
                self.node.path, old_node_id, self.node.enabled, old_pdo_enabled
            )
            self.pdo_manager.invalidate_cache(old_node)

            # Reload PDO content if it's visible
            if self.pdo_editor:
                self.pdo_editor.load_pdo_database()

        self.node_changed.emit()


class CANopenRootEditor(QWidget):
    settings_changed = Signal()

    def __init__(self, project: Project, network: canopen.Network):
        super().__init__()
        self.project = project
        self.network = network
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        group = QGroupBox("CANopen Settings")
        layout = QFormLayout(group)
        main_layout.addWidget(group)
        self.enabled_cb = QCheckBox("Enable generic CANopen processing")
        self.enabled_cb.setChecked(self.project.canopen_enabled)
        layout.addRow(self.enabled_cb)
        self.enabled_cb.toggled.connect(self._update_settings)

    def _update_settings(self):
        self.project.canopen_enabled = self.enabled_cb.isChecked()
        self.settings_changed.emit()


class ObjectDictionaryViewer(QWidget):
    """CANopen Object Dictionary Viewer with SDO read/write capabilities"""

    frame_to_send = Signal(object, object)  # message, connection_id (uuid.UUID)
    frame_rx_sdo = Signal(object)

    def __init__(self):
        super().__init__()
        self.sdo_client: Optional[SdoClient] = None
        self.setup_ui()
        self.frame_rx_sdo.connect(self.on_frame_rx_sdo)

    def on_frame_rx_sdo(self, frame: CANFrame):
        """Handle received SDO frames by placing them in the response queue."""
        if self.sdo_client:
            asyncio.create_task(self.sdo_client.on_frame_rx(frame))

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
        self.tree.setHeaderLabels(
            ["Index", "Sub", "Name", "Type", "Access", "Value", "Hex Value"]
        )
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
        self.read_btn.clicked.connect(lambda: asyncio.create_task(self.read_sdo()))
        self.read_btn.setEnabled(False)
        sdo_layout.addWidget(self.read_btn)

        # Write section
        write_layout = QHBoxLayout()
        write_layout.addWidget(QLabel("New Value:"))
        self.write_value_edit = QLineEdit()
        self.write_btn = QPushButton("Write")
        self.write_btn.clicked.connect(lambda: asyncio.create_task(self.write_sdo()))
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

    async def set_node(self, node_config: CANopenNode):
        """Set the current CANopen node to display"""
        self.sdo_client = SdoClient(
            node_config.node_id, node_config.connection_id, self.frame_to_send.emit
        )
        self.node_info_label.setText(
            f"CANopen Node {node_config.node_id} - {node_config.path.name}"
        )
        try:
            self.load_eds_file(node_config.path)
        except Exception as e:
            self.status_label.setText(f"Error loading EDS file: {e}")
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

    def populate_from_eds(self, object_dictionary):
        """Populate tree from object dictionary"""
        self.tree.clear()

        # Group objects by category
        categories = {
            "Communication Parameters (0x1000-0x1FFF)": [],
            "Manufacturer Specific (0x2000-0x5FFF)": [],
            "Profile Specific (0x6000-0x9FFF)": [],
            "Reserved (0xA000-0xFFFF)": [],
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
            if hasattr(obj, "subindices") and obj.subindices:
                # Array or record with subindices
                obj_item = QTreeWidgetItem(
                    parent_item,
                    [
                        f"0x{index:04X}",
                        "",
                        getattr(obj, "name", f"Object_{index:04X}"),
                        "",
                        "",
                        "",
                        "",
                    ],
                )
                obj_item.setData(
                    0, Qt.UserRole, {"index": index, "subindex": None, "obj": obj}
                )

                # Add subindices
                for subindex, subobj in obj.subindices.items():
                    if isinstance(subindex, int):
                        sub_item = QTreeWidgetItem(
                            obj_item,
                            [
                                f"0x{index:04X}",
                                f"0x{subindex:02X}",
                                getattr(subobj, "name", f"Sub_{subindex:02X}"),
                                str(getattr(subobj, "data_type", "Unknown")),
                                self.get_access_string(
                                    getattr(subobj, "access_type", None)
                                ),
                                "-",
                                "-",
                            ],
                        )
                        sub_item.setData(
                            0,
                            Qt.UserRole,
                            {"index": index, "subindex": subindex, "obj": subobj},
                        )
            else:
                # Simple variable
                obj_item = QTreeWidgetItem(
                    parent_item,
                    [
                        f"0x{index:04X}",
                        "0x00",
                        getattr(obj, "name", f"Object_{index:04X}"),
                        str(getattr(obj, "data_type", "Unknown")),
                        self.get_access_string(getattr(obj, "access_type", None)),
                        "-",
                        "-",
                    ],
                )
                obj_item.setData(
                    0, Qt.UserRole, {"index": index, "subindex": 0, "obj": obj}
                )

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
                    hex_value = raw_value.hex(" ").upper()
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
            "ro": "Read Only",
            "wo": "Write Only",
            "rw": "Read/Write",
            "rww": "Read/Write/Write",
            "rwr": "Read/Write/Read",
            "const": "Constant",
        }

        if hasattr(access_type, "name"):
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

        if not data or "index" not in data:
            self.clear_details()
            return

        self.show_object_details(data)

    def show_object_details(self, data):
        """Show details for selected object"""
        index = data["index"]
        subindex = data["subindex"]
        obj = data["obj"]

        # Update details
        self.index_label.setText(f"0x{index:04X}")
        self.subindex_label.setText(
            f"0x{subindex:02X}" if subindex is not None else "-"
        )
        self.name_label.setText(getattr(obj, "name", "Unknown"))
        self.type_label.setText(str(getattr(obj, "data_type", "Unknown")))
        self.access_label.setText(
            self.get_access_string(getattr(obj, "access_type", None))
        )

        # Enable/disable SDO operations based on access type
        access_type = getattr(obj, "access_type", None)
        can_read = (
            access_type in ["const", "ro", "rw", "rww", "rwr"] if access_type else True
        )
        can_write = access_type in ["wo", "rw", "rww", "rwr"] if access_type else True

        # Only enable if we have a connected node
        has_connection = True

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

    async def read_sdo(self):
        if not self.sdo_client or not hasattr(self, "selected_index"):
            return

        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.status_label.setText("Reading...")
        self.status_label.setStyleSheet("color: blue;")

        try:
            received_data = await self.sdo_client.read(
                self.selected_index, self.selected_subindex
            )
            try:
                display_value = received_data.decode("utf-8").rstrip("\x00")
            except UnicodeDecodeError:
                display_value = received_data.hex(" ").upper()

            self.current_value_label.setText(display_value)
            self.status_label.setText("Read successful")
            self.status_label.setStyleSheet("color: green;")
            self.update_tree_item_value(display_value, received_data)

        except asyncio.TimeoutError:
            self.status_label.setText("Read failed: Timeout")
            self.status_label.setStyleSheet("color: red;")
        except SdoAbortedError as e:
            self.status_label.setText(f"Read aborted by node: {e}")
            self.status_label.setStyleSheet("color: red;")
        except asyncio.CancelledError:
            self.status_label.setText("Read operation cancelled.")
            self.status_label.setStyleSheet("color: orange;")
        except Exception as e:
            self.status_label.setText(f"Read failed: {e}")
            self.status_label.setStyleSheet("color: red;")
        finally:
            self.progress_bar.setVisible(False)

    def _pack_value(self, value_str: str, obj: any) -> bytes:
        """Packs a string value into bytes according to the object's data type."""
        data_type = getattr(obj, "data_type", None)

        # Heuristic parsing of the input string
        try:
            if value_str.lower().startswith("0x"):
                value = int(value_str, 16)
            elif "." in value_str:
                value = float(value_str)
            else:
                value = int(value_str)
        except ValueError:
            value = value_str  # Treat as a string if parsing fails

        # Pack based on CANopen data type
        if data_type == canopen.objectdictionary.BOOLEAN:
            return struct.pack("<B", int(bool(value)))
        if data_type in (
            canopen.objectdictionary.INTEGER8,
            canopen.objectdictionary.UNSIGNED8,
        ):
            return struct.pack("<B", int(value))
        if data_type in (
            canopen.objectdictionary.INTEGER16,
            canopen.objectdictionary.UNSIGNED16,
        ):
            return struct.pack("<H", int(value))
        if data_type in (
            canopen.objectdictionary.INTEGER32,
            canopen.objectdictionary.UNSIGNED32,
        ):
            return struct.pack("<L", int(value))
        if data_type in (
            canopen.objectdictionary.INTEGER64,
            canopen.objectdictionary.UNSIGNED64,
        ):
            return struct.pack("<Q", int(value))
        if data_type == canopen.objectdictionary.REAL32:
            return struct.pack("<f", float(value))
        if data_type == canopen.objectdictionary.REAL64:
            return struct.pack("<d", float(value))

        # For strings, domains, etc., encode as bytes
        if isinstance(value, str):
            return value.encode("utf-8")

        # Fallback for unknown types if we got a number
        if isinstance(value, int):
            # Guess size based on value
            if value.bit_length() <= 8:
                return struct.pack("<B", value)
            if value.bit_length() <= 16:
                return struct.pack("<H", value)
            if value.bit_length() <= 32:
                return struct.pack("<L", value)
            if value.bit_length() <= 64:
                return struct.pack("<Q", value)

        raise TypeError(f"Could not pack value '{value_str}' for data type {data_type}")

    async def write_sdo(self):
        if not self.sdo_client or not hasattr(self, "selected_index"):
            return

        value_text = self.write_value_edit.text().strip()
        if not value_text:
            self.status_label.setText("Please enter a value to write")
            self.status_label.setStyleSheet("color: orange;")
            return

        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.status_label.setText("Writing...")
        self.status_label.setStyleSheet("color: blue;")

        try:
            selected_item = self.tree.currentItem()
            if not selected_item:
                raise ValueError("No item selected.")

            obj_data = selected_item.data(0, Qt.UserRole)
            data_to_send = self._pack_value(value_text, obj_data["obj"])

            await self.sdo_client.write(
                self.selected_index, self.selected_subindex, data_to_send
            )

            self.status_label.setText("Write successful")
            self.status_label.setStyleSheet("color: green;")
            self.write_value_edit.clear()

            await asyncio.sleep(0.1)
            await self.read_sdo()

        except asyncio.TimeoutError:
            self.status_label.setText("Write failed: Timeout")
            self.status_label.setStyleSheet("color: red;")
        except SdoAbortedError as e:
            self.status_label.setText(f"Write aborted by node: {e}")
            self.status_label.setStyleSheet("color: red;")
        except asyncio.CancelledError:
            self.status_label.setText("Write operation cancelled.")
            self.status_label.setStyleSheet("color: orange;")
        except Exception as e:
            self.status_label.setText(f"Write failed: {e}")
            self.status_label.setStyleSheet("color: red;")
        finally:
            self.progress_bar.setVisible(False)

    def clear_node(self):
        """Clear the current node"""
        self.sdo_client = None
        self.node_info_label.setText("No CANopen node selected")
        self.tree.clear()
        self.clear_details()
        self.status_label.setText("Ready")
        self.status_label.setStyleSheet("color: gray;")
