import asyncio
from typing import List, Optional
import uuid

import can

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QGroupBox,
    QFormLayout,
    QLabel,
    QComboBox,
    QPushButton,
    QListWidget,
    QListWidgetItem,
    QRadioButton,
    QLineEdit,
)
from PySide6.QtCore import Signal, Qt

from ..data_utils import CANopenNode, Project

NMT_COMMAND_MAP = {
    "Operational": 0x01,
    "Stopped": 0x02,
    "Pre-operational": 0x80,
    "Reset node": 0x81,
    "Reset communication": 0x82,
}


class NMTSender(QWidget):
    frame_to_send = Signal(object, object)  # message, connection_id (uuid.UUID)
    status_update = Signal(str, str)  # message, color

    def __init__(self, project: Project):
        super().__init__()
        self.project = project
        self.current_connection_id: Optional[uuid.UUID] = None
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        self.connection_label = QLabel("Active Connection: (None)")
        self.connection_label.setStyleSheet("font-weight: bold; padding: 2px;")
        main_layout.addWidget(self.connection_label)

        # NMT Command Group
        self.command_group = QGroupBox("CANopen NMT Command")
        command_layout = QFormLayout(self.command_group)

        self.command_combo = QComboBox()
        self.command_combo.addItems(NMT_COMMAND_MAP.keys())
        command_layout.addRow("Command:", self.command_combo)

        main_layout.addWidget(self.command_group)

        # Node Selection Group
        self.node_group = QGroupBox("Target Nodes")
        node_layout = QVBoxLayout(self.node_group)

        self.all_nodes_radio = QRadioButton("All Nodes (Node ID 0)")
        self.all_nodes_radio.setChecked(True)
        self.specific_nodes_radio = QRadioButton("Specific Nodes from Project")
        self.arbitrary_nodes_radio = QRadioButton("Arbitrary Node(s)")

        node_layout.addWidget(self.all_nodes_radio)
        node_layout.addWidget(self.specific_nodes_radio)

        self.node_list_widget = QListWidget()
        self.node_list_widget.setSelectionMode(QListWidget.MultiSelection)
        self.node_list_widget.setEnabled(False)  # Initially disabled
        node_layout.addWidget(self.node_list_widget)

        node_layout.addWidget(self.arbitrary_nodes_radio)
        self.arbitrary_nodes_edit = QLineEdit()
        self.arbitrary_nodes_edit.setPlaceholderText("e.g., 1, 2, 10-15")
        self.arbitrary_nodes_edit.setEnabled(False)
        node_layout.addWidget(self.arbitrary_nodes_edit)

        self.all_nodes_radio.toggled.connect(self._toggle_node_list)
        self.specific_nodes_radio.toggled.connect(self._toggle_node_list)
        self.arbitrary_nodes_radio.toggled.connect(self._toggle_node_list)

        main_layout.addWidget(self.node_group)

        # Send Button
        self.send_button = QPushButton("Send NMT Command")
        self.send_button.clicked.connect(
            lambda: asyncio.create_task(self._send_nmt_command())
        )
        self.send_button.setEnabled(False)
        main_layout.addWidget(self.send_button)

        self.populate_node_list()
        self._toggle_node_list()  # Set initial state of node list

    def set_connection_context(
        self, connection_id: Optional[uuid.UUID], is_globally_connected: bool
    ):
        """Sets the current connection context and updates the UI display and send button state."""
        self.current_connection_id = connection_id
        self.send_button.setEnabled(is_globally_connected and connection_id is not None)

        if not is_globally_connected:
            self.connection_label.setText("Active Connection: (Disconnected)")
        elif connection_id:
            conn_name = self.project.get_connection_name(connection_id)
            self.connection_label.setText(f"Active Connection: {conn_name}")
        else:
            self.connection_label.setText(
                "Active Connection: (None - Select in Project Explorer)"
            )

        self.update_project_nodes()

    def set_project(self, project: Project):
        """Updates the project reference and refreshes the node list."""
        self.project = project
        self.update_project_nodes()

    def populate_node_list(self):
        self.node_list_widget.clear()
        nodes_to_display = [
            node
            for node in self.project.canopen_nodes
            if not self.current_connection_id
            or node.connection_id == self.current_connection_id
        ]
        for node in nodes_to_display:
            item = QListWidgetItem(f"{node.path.name} (ID: {node.node_id})")
            item.setData(Qt.UserRole, node)  # Store the actual CANopenNode object
            self.node_list_widget.addItem(item)

    def _toggle_node_list(self):
        self.node_list_widget.setEnabled(self.specific_nodes_radio.isChecked())
        self.arbitrary_nodes_edit.setEnabled(self.arbitrary_nodes_radio.isChecked())

    def _parse_arbitrary_nodes(self, text: str) -> List[int]:
        """Parses a comma-separated string of nodes and ranges into a list of integers."""
        nodes = set()
        if not text:
            return []
        parts = text.split(",")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    start, end = map(int, part.split("-"))
                    if start <= end:
                        nodes.update(range(start, end + 1))
                except ValueError:
                    self.status_update.emit(
                        f"Invalid range in arbitrary nodes: '{part}'", "red"
                    )
                    return []  # Return empty list on error
            else:
                try:
                    nodes.add(int(part))
                except ValueError:
                    self.status_update.emit(
                        f"Invalid node ID in arbitrary nodes: '{part}'", "red"
                    )
                    return []  # Return empty list on error
        return sorted(list(nodes))

    async def _send_nmt_command(self):
        command_name = self.command_combo.currentText()
        command_code = NMT_COMMAND_MAP.get(command_name)

        if command_code is None:
            self.status_update.emit("Invalid NMT command selected.", "red")
            return

        target_node_ids = []
        if self.all_nodes_radio.isChecked():
            target_node_ids.append(0)  # Node ID 0 for all nodes
        elif self.specific_nodes_radio.isChecked():
            selected_items = self.node_list_widget.selectedItems()
            if not selected_items:
                self.status_update.emit("No specific nodes selected.", "orange")
                return
            for item in selected_items:
                node: CANopenNode = item.data(Qt.UserRole)
                target_node_ids.append(node.node_id)
        elif self.arbitrary_nodes_radio.isChecked():
            node_text = self.arbitrary_nodes_edit.text()
            target_node_ids = self._parse_arbitrary_nodes(node_text)
            if not target_node_ids and node_text:
                # Error message was already emitted by the parser
                return

        self.status_update.emit("Sending NMT command...", "blue")

        for node_id in target_node_ids:
            # NMT messages are always sent with COB-ID 0x000
            # The data payload is [command, node_id]
            can_message = can.Message(
                arbitration_id=0x000,
                data=[command_code, node_id],
                is_extended_id=False,
            )

            connection_id_to_use = self.current_connection_id

            # If no specific connection is in context, find the first available one
            if not connection_id_to_use:
                for conn in self.project.connections:
                    if conn.enabled:
                        connection_id_to_use = conn.id
                        break

            if connection_id_to_use:
                self.frame_to_send.emit(can_message, connection_id_to_use)
                self.status_update.emit(
                    f"Sent NMT command '{command_name}' to Node ID {node_id}", "green"
                )
            else:
                self.status_update.emit(
                    "No active CAN connection found to send NMT message.", "red"
                )
                return

        self.status_update.emit("NMT command(s) sent successfully.", "green")

    def update_project_nodes(self):
        self.populate_node_list()
        self._toggle_node_list()  # Update enabled state based on radio button
