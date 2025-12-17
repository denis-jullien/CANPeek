"""
Project tree widget for managing connections, filters, and databases.

Provides a hierarchical view of project configuration similar to
PCAN-Explorer's Project Manager.
"""

from __future__ import annotations

from typing import Optional, Any
from uuid import UUID

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QIcon, QColor, QAction
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QTreeWidget,
    QTreeWidgetItem,
    QMenu,
    QStyle,
)

from canpeek.core.types import Connection, BusState
from canpeek.protocols.canopen import CANopenNode, NMTState


class ProjectTree(QWidget):
    """
    Project tree showing connections, filters, databases, and CANopen nodes.

    Structure:
        - Connections
          - Connection 1
          - Connection 2
        - Message Filters
          - Filter 1
        - Databases
          - file.dbc
        - CANopen
          - Node 1

    Signals:
        item_selected: Emitted when an item is selected (type, data)
        item_double_clicked: Emitted on double click
        connection_toggled: Emitted when connection enabled state changes
        project_changed: Emitted when project structure changes
    """

    item_selected = Signal(str, object)  # item_type, item_data
    item_double_clicked = Signal(str, object)
    connection_toggled = Signal(object, bool)  # Connection, enabled
    add_connection_requested = Signal()  # Request to add a new connection
    edit_connection_requested = Signal(object)  # Connection to edit
    remove_connection_requested = Signal(object)  # Connection to remove
    connect_connection_requested = Signal(object)  # Connection to connect
    disconnect_connection_requested = Signal(object)  # Connection to disconnect
    database_loaded = Signal(str)  # path - emitted when database is added
    database_unloaded = Signal(str)  # path - emitted when database is removed
    database_toggled = Signal(str, bool)  # path, enabled - emitted on checkbox toggle
    project_changed = Signal()

    # Item type constants
    TYPE_ROOT = "root"
    TYPE_CONNECTIONS_ROOT = "connections_root"
    TYPE_CONNECTION = "connection"
    TYPE_FILTERS_ROOT = "filters_root"
    TYPE_FILTER = "filter"
    TYPE_DATABASES_ROOT = "databases_root"
    TYPE_DATABASE = "database"
    TYPE_CANOPEN_ROOT = "canopen_root"
    TYPE_CANOPEN_NODE = "canopen_node"

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)

        self._connections: list[Connection] = []
        self._bus_states: dict[UUID, BusState] = {}
        self._canopen_nodes: dict[int, QTreeWidgetItem] = {}  # node_id -> item

        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setRootIsDecorated(True)
        self._tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self._tree.setSelectionMode(QTreeWidget.SingleSelection)

        layout.addWidget(self._tree)

        # Create root items
        self._create_structure()

    def _connect_signals(self) -> None:
        """Connect internal signals."""
        self._tree.itemSelectionChanged.connect(self._on_selection_changed)
        self._tree.itemDoubleClicked.connect(self._on_double_clicked)
        self._tree.itemChanged.connect(self._on_item_changed)
        self._tree.customContextMenuRequested.connect(self._show_context_menu)

    def _create_structure(self) -> None:
        """Create the tree structure."""
        self._tree.clear()

        style = self.style()

        # Connections root
        self._conn_root = QTreeWidgetItem(self._tree, ["Connections"])
        self._conn_root.setData(0, Qt.UserRole, self.TYPE_CONNECTIONS_ROOT)
        self._conn_root.setIcon(0, style.standardIcon(QStyle.SP_DriveNetIcon))
        self._conn_root.setExpanded(True)

        # Filters root
        self._filter_root = QTreeWidgetItem(self._tree, ["Message Filters"])
        self._filter_root.setData(0, Qt.UserRole, self.TYPE_FILTERS_ROOT)
        self._filter_root.setIcon(0, style.standardIcon(QStyle.SP_FileDialogContentsView))
        self._filter_root.setExpanded(True)

        # Databases root
        self._db_root = QTreeWidgetItem(self._tree, ["Databases"])
        self._db_root.setData(0, Qt.UserRole, self.TYPE_DATABASES_ROOT)
        self._db_root.setIcon(0, style.standardIcon(QStyle.SP_DirIcon))
        self._db_root.setExpanded(True)

        # CANopen root
        self._canopen_root = QTreeWidgetItem(self._tree, ["CANopen"])
        self._canopen_root.setData(0, Qt.UserRole, self.TYPE_CANOPEN_ROOT)
        self._canopen_root.setIcon(0, style.standardIcon(QStyle.SP_ComputerIcon))
        self._canopen_root.setExpanded(True)

    def set_connections(self, connections: list[Connection]) -> None:
        """Set the list of connections."""
        self._connections = connections
        self._rebuild_connections()

    def _rebuild_connections(self) -> None:
        """Rebuild the connections subtree."""
        # Block signals during rebuild
        self._tree.blockSignals(True)

        # Clear existing connection items
        while self._conn_root.childCount() > 0:
            self._conn_root.removeChild(self._conn_root.child(0))

        # Add connection items
        for conn in self._connections:
            item = QTreeWidgetItem(self._conn_root)
            item.setText(0, conn.name)
            item.setData(0, Qt.UserRole, self.TYPE_CONNECTION)
            item.setData(0, Qt.UserRole + 1, conn)

            # Checkbox for connected state (unchecked = disconnected)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            state = self._bus_states.get(conn.id, BusState.UNKNOWN)
            is_connected = state not in (BusState.UNKNOWN, BusState.STOPPED, BusState.BUS_OFF)
            item.setCheckState(0, Qt.Checked if is_connected else Qt.Unchecked)

            # Bus state indicator
            self._update_connection_item(item, conn)

        self._tree.blockSignals(False)

    def _update_connection_item(self, item: QTreeWidgetItem, conn: Connection) -> None:
        """Update connection item appearance based on state."""
        state = self._bus_states.get(conn.id, BusState.UNKNOWN)

        # Set icon based on state
        style = self.style()
        if state == BusState.ERROR_ACTIVE:
            # Green - connected and healthy
            item.setForeground(0, QColor("#4CAF50"))
        elif state in (BusState.ERROR_WARNING, BusState.ERROR_PASSIVE):
            # Yellow/orange - warning
            item.setForeground(0, QColor("#FFC107"))
        elif state == BusState.BUS_OFF:
            # Red - error
            item.setForeground(0, QColor("#F44336"))
        else:
            # Default - disconnected
            item.setForeground(0, QColor("#888888"))

        # Update tooltip
        tooltip = f"Interface: {conn.interface}\n"
        tooltip += f"Channel: {conn.channel}\n"
        tooltip += f"Bitrate: {conn.bitrate} bps"
        if conn.fd:
            tooltip += f"\nData Bitrate: {conn.data_bitrate} bps (FD)"
        tooltip += f"\nState: {state.name}"
        item.setToolTip(0, tooltip)

    def update_bus_state(self, connection_id: UUID, state: BusState) -> None:
        """Update the bus state for a connection."""
        self._bus_states[connection_id] = state

        # Find and update the item
        for i in range(self._conn_root.childCount()):
            item = self._conn_root.child(i)
            conn = item.data(0, Qt.UserRole + 1)
            if conn and conn.id == connection_id:
                # Block signals to prevent recursive connect/disconnect
                self._tree.blockSignals(True)

                # Update checkbox based on connection state
                is_connected = state not in (BusState.UNKNOWN, BusState.STOPPED, BusState.BUS_OFF)
                item.setCheckState(0, Qt.Checked if is_connected else Qt.Unchecked)

                self._tree.blockSignals(False)

                # Update visual appearance
                self._update_connection_item(item, conn)
                break

    def add_database(self, path: str, name: str) -> None:
        """Add a database to the tree."""
        item = QTreeWidgetItem(self._db_root)
        item.setText(0, name)
        item.setData(0, Qt.UserRole, self.TYPE_DATABASE)
        item.setData(0, Qt.UserRole + 1, path)
        item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
        item.setCheckState(0, Qt.Checked)

    def add_filter(self, name: str, filter_data: Any) -> None:
        """Add a filter to the tree."""
        item = QTreeWidgetItem(self._filter_root)
        item.setText(0, name)
        item.setData(0, Qt.UserRole, self.TYPE_FILTER)
        item.setData(0, Qt.UserRole + 1, filter_data)
        item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
        item.setCheckState(0, Qt.Checked)

    def _on_selection_changed(self) -> None:
        """Handle selection change."""
        items = self._tree.selectedItems()
        if not items:
            return

        item = items[0]
        item_type = item.data(0, Qt.UserRole)
        item_data = item.data(0, Qt.UserRole + 1)

        self.item_selected.emit(item_type, item_data)

    def _on_double_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        """Handle double click."""
        item_type = item.data(0, Qt.UserRole)
        item_data = item.data(0, Qt.UserRole + 1)

        # Edit connection on double-click
        if item_type == self.TYPE_CONNECTION and item_data:
            self.edit_connection_requested.emit(item_data)
            return

        self.item_double_clicked.emit(item_type, item_data)

    def _on_item_changed(self, item: QTreeWidgetItem, column: int) -> None:
        """Handle item change (checkbox toggle)."""
        item_type = item.data(0, Qt.UserRole)
        item_data = item.data(0, Qt.UserRole + 1)

        if item_type == self.TYPE_CONNECTION and item_data:
            checked = item.checkState(0) == Qt.Checked
            # Checkbox controls connected state
            if checked:
                self.connect_connection_requested.emit(item_data)
            else:
                self.disconnect_connection_requested.emit(item_data)

        elif item_type == self.TYPE_DATABASE and item_data:
            checked = item.checkState(0) == Qt.Checked
            self.database_toggled.emit(item_data, checked)

    def _show_context_menu(self, pos) -> None:
        """Show context menu."""
        item = self._tree.itemAt(pos)
        if not item:
            return

        item_type = item.data(0, Qt.UserRole)
        menu = QMenu(self)

        if item_type == self.TYPE_CONNECTIONS_ROOT:
            add_action = menu.addAction("Add Connection")
            add_action.triggered.connect(self._add_connection)

        elif item_type == self.TYPE_CONNECTION:
            conn = item.data(0, Qt.UserRole + 1)
            connect_action = menu.addAction("Connect")
            connect_action.triggered.connect(lambda: self.connect_connection_requested.emit(conn))
            disconnect_action = menu.addAction("Disconnect")
            disconnect_action.triggered.connect(lambda: self.disconnect_connection_requested.emit(conn))
            menu.addSeparator()
            configure_action = menu.addAction("Configure...")
            configure_action.triggered.connect(lambda: self.edit_connection_requested.emit(conn))
            menu.addSeparator()
            remove_action = menu.addAction("Remove")
            remove_action.triggered.connect(lambda: self.remove_connection_requested.emit(conn))

        elif item_type == self.TYPE_DATABASES_ROOT:
            add_action = menu.addAction("Add Database...")
            add_action.triggered.connect(self._add_database)

        elif item_type == self.TYPE_DATABASE:
            db_path = item.data(0, Qt.UserRole + 1)
            remove_action = menu.addAction("Remove")
            remove_action.triggered.connect(lambda: self.remove_database(db_path))

        elif item_type == self.TYPE_FILTERS_ROOT:
            add_action = menu.addAction("Add Filter")
            add_action.triggered.connect(self._add_filter)

        if menu.actions():
            menu.exec(self._tree.viewport().mapToGlobal(pos))

    def _add_connection(self) -> None:
        """Request to add a new connection."""
        self.add_connection_requested.emit()

    def _add_database(self) -> None:
        """Add a new database file."""
        from PySide6.QtWidgets import QFileDialog

        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Database Files",
            "",
            "CAN Databases (*.dbc *.arxml *.kcd);;All Files (*)"
        )

        for path in paths:
            from pathlib import Path
            name = Path(path).name
            self.add_database(path, name)
            self.database_loaded.emit(path)

        if paths:
            self.project_changed.emit()

    def remove_database(self, path: str) -> None:
        """Remove a database from the tree."""
        for i in range(self._db_root.childCount()):
            item = self._db_root.child(i)
            if item.data(0, Qt.UserRole + 1) == path:
                self._db_root.removeChild(item)
                self.database_unloaded.emit(path)
                self.project_changed.emit()
                break

    def _add_filter(self) -> None:
        """Add a new filter."""
        # TODO: Implement filter dialog
        self.add_filter(f"Filter {self._filter_root.childCount() + 1}", None)
        self.project_changed.emit()

    # --- CANopen node management ---

    def add_canopen_node(self, node: CANopenNode) -> None:
        """Add a discovered CANopen node to the tree."""
        if node.node_id in self._canopen_nodes:
            # Already exists, just update
            self.update_canopen_node(node)
            return

        item = QTreeWidgetItem(self._canopen_root)
        item.setText(0, f"Node {node.node_id}")
        item.setData(0, Qt.UserRole, self.TYPE_CANOPEN_NODE)
        item.setData(0, Qt.UserRole + 1, node)

        self._canopen_nodes[node.node_id] = item
        self._update_canopen_node_item(item, node)

    def update_canopen_node(self, node: CANopenNode) -> None:
        """Update a CANopen node's display."""
        item = self._canopen_nodes.get(node.node_id)
        if item:
            item.setData(0, Qt.UserRole + 1, node)
            self._update_canopen_node_item(item, node)

    def _update_canopen_node_item(self, item: QTreeWidgetItem, node: CANopenNode) -> None:
        """Update CANopen node item appearance based on state."""
        # Update text with state
        state_str = node.state_name
        if node.device_name:
            item.setText(0, f"Node {node.node_id}: {node.device_name} [{state_str}]")
        else:
            item.setText(0, f"Node {node.node_id} [{state_str}]")

        # Color based on state
        if node.state == NMTState.OPERATIONAL:
            item.setForeground(0, QColor("#4CAF50"))  # Green
        elif node.state == NMTState.PRE_OPERATIONAL:
            item.setForeground(0, QColor("#2196F3"))  # Blue
        elif node.state == NMTState.STOPPED:
            item.setForeground(0, QColor("#FFC107"))  # Yellow
        elif node.state == NMTState.BOOT_UP:
            item.setForeground(0, QColor("#9C27B0"))  # Purple
        else:
            item.setForeground(0, QColor("#888888"))  # Gray

        # Tooltip
        tooltip = f"Node ID: {node.node_id}\n"
        tooltip += f"State: {node.state_name}\n"
        tooltip += f"Messages: {node.message_count}\n"
        if node.error_count > 0:
            tooltip += f"Errors: {node.error_count}\n"
        if node.heartbeat_interval_ms:
            tooltip += f"Heartbeat: {node.heartbeat_interval_ms:.0f} ms\n"
        item.setToolTip(0, tooltip)

    def remove_canopen_node(self, node_id: int) -> None:
        """Remove a CANopen node from the tree."""
        item = self._canopen_nodes.pop(node_id, None)
        if item:
            index = self._canopen_root.indexOfChild(item)
            if index >= 0:
                self._canopen_root.takeChild(index)

    def clear_canopen_nodes(self) -> None:
        """Clear all CANopen nodes."""
        while self._canopen_root.childCount() > 0:
            self._canopen_root.removeChild(self._canopen_root.child(0))
        self._canopen_nodes.clear()

    def expand_all(self) -> None:
        """Expand all items."""
        self._tree.expandAll()

    def collapse_all(self) -> None:
        """Collapse all items."""
        self._tree.collapseAll()
