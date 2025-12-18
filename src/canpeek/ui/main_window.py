"""
Main application window with Qt-Advanced-Docking layout.

Provides a professional CAN analyzer interface similar to PCAN-Explorer
with dockable panels for:
- Project tree (connections, filters, databases)
- Grouped receive view
- Trace view
- Transmit panel
- Properties panel
"""

from __future__ import annotations

import asyncio
from typing import Optional
from uuid import UUID

from PySide6.QtCore import Qt, QTimer, QSettings, Signal
from PySide6.QtGui import QAction, QIcon, QCloseEvent
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QLabel,
    QToolBar,
    QMenu,
    QMessageBox,
    QFileDialog,
    QStyle,
    QApplication,
)

import PySide6QtAds as QtAds

from canpeek.core.types import Connection, BusState, CANFrame
from canpeek.core.reader import BusManager
from canpeek.core.decoder import DBCDecoder
from canpeek.protocols.canopen import CANopenNodeManager, CANopenNode, CANopenMessage
from canpeek.project import Project, DatabaseConfig, FilterConfig
from canpeek.ui.widgets.receive_view import ReceiveView
from canpeek.ui.widgets.trace_view import TraceView
from canpeek.ui.widgets.project_tree import ProjectTree
from canpeek.ui.widgets.status_bar import StatusBar
from canpeek.ui.widgets.transmit_panel import TransmitPanel
from canpeek.ui.widgets.properties_panel import PropertiesPanel
from canpeek.ui.dialogs.sudo_dialog import SudoDialog
from canpeek.ui.dialogs.connection_dialog import ConnectionDialog


class MainWindow(QMainWindow):
    """
    Main application window.

    Features:
        - Qt-Advanced-Docking for flexible panel layout
        - Multiple CAN bus connections
        - Real-time frame display
        - Project management
        - Save/restore layout
    """

    # Signals
    frames_received = Signal(list)  # List[CANFrame]

    def __init__(self):
        super().__init__()

        self.setWindowTitle("CANPeek")
        self.setMinimumSize(1200, 800)

        # Core components
        self._bus_manager = BusManager()
        self._canopen_manager = CANopenNodeManager()
        self._dbc_decoder = DBCDecoder()
        self._connections: list[Connection] = []
        self._project = Project()

        # Update timer for GUI refresh
        self._update_timer = QTimer(self)
        self._update_timer.timeout.connect(self._on_update_timer)
        self._frame_count = 0
        self._last_frame_count = 0
        self._message_rate = 0.0

        # Set up UI
        self._setup_docking()
        self._setup_actions()
        self._setup_toolbar()
        self._setup_menubar()
        self._setup_status_bar()
        self._connect_signals()

        # Set up decoder for views
        self._receive_view.set_decoder(self._dbc_decoder)
        self._trace_view.set_decoder(self._dbc_decoder)

        # Add default connection
        self._add_default_connection()

        # Restore layout
        self._restore_settings()

        # Start update timer (20 Hz)
        self._update_timer.start(50)

    def _setup_docking(self) -> None:
        """Set up Qt-Advanced-Docking system."""
        # Configure docking
        QtAds.CDockManager.setConfigFlags(
            QtAds.CDockManager.DefaultOpaqueConfig
        )
        QtAds.CDockManager.setConfigFlag(
            QtAds.CDockManager.FocusHighlighting, True
        )
        QtAds.CDockManager.setConfigFlag(
            QtAds.CDockManager.DockAreaHasTabsMenuButton, True
        )
        QtAds.CDockManager.setConfigFlag(
            QtAds.CDockManager.OpaqueSplitterResize, True
        )

        self._dock_manager = QtAds.CDockManager(self)

        # Create dock widgets

        # --- Central area: Receive views ---
        self._receive_view = ReceiveView()
        receive_dock = QtAds.CDockWidget("Grouped View")
        receive_dock.setWidget(self._receive_view)
        central_area = self._dock_manager.addDockWidget(
            QtAds.CenterDockWidgetArea, receive_dock
        )

        # Trace view (tabbed with grouped view)
        self._trace_view = TraceView()
        trace_dock = QtAds.CDockWidget("Trace View")
        trace_dock.setWidget(self._trace_view)
        self._dock_manager.addDockWidgetTabToArea(trace_dock, central_area)

        # Make grouped view the default
        central_area.setCurrentDockWidget(receive_dock)

        # --- Right side: Project tree ---
        self._project_tree = ProjectTree()
        project_dock = QtAds.CDockWidget("Project Manager")
        project_dock.setWidget(self._project_tree)
        right_area = self._dock_manager.addDockWidget(
            QtAds.RightDockWidgetArea, project_dock
        )

        # Properties panel (below project tree)
        self._properties_panel = PropertiesPanel()
        properties_dock = QtAds.CDockWidget("Properties")
        properties_dock.setWidget(self._properties_panel)
        self._dock_manager.addDockWidget(
            QtAds.BottomDockWidgetArea, properties_dock, right_area
        )

        # --- Bottom: Transmit panel ---
        self._transmit_panel = TransmitPanel()
        transmit_dock = QtAds.CDockWidget("Transmit")
        transmit_dock.setWidget(self._transmit_panel)
        self._dock_manager.addDockWidget(
            QtAds.BottomDockWidgetArea, transmit_dock, central_area
        )

        # Store dock references
        self._docks = {
            'receive': receive_dock,
            'trace': trace_dock,
            'project': project_dock,
            'properties': properties_dock,
            'transmit': transmit_dock,
        }

    def _setup_actions(self) -> None:
        """Create actions for menus and toolbar."""
        style = self.style()

        # File actions
        self._new_action = QAction(
            style.standardIcon(QStyle.SP_FileIcon),
            "&New Project", self
        )
        self._new_action.setShortcut("Ctrl+N")
        self._new_action.triggered.connect(self._on_new_project)

        self._open_action = QAction(
            style.standardIcon(QStyle.SP_DialogOpenButton),
            "&Open Project...", self
        )
        self._open_action.setShortcut("Ctrl+O")
        self._open_action.triggered.connect(self._on_open_project)

        self._save_action = QAction(
            style.standardIcon(QStyle.SP_DialogSaveButton),
            "&Save Project", self
        )
        self._save_action.setShortcut("Ctrl+S")
        self._save_action.triggered.connect(self._on_save_project)

        self._exit_action = QAction("E&xit", self)
        self._exit_action.setShortcut("Ctrl+Q")
        self._exit_action.triggered.connect(self.close)

        # Connection actions
        self._new_connection_action = QAction(
            style.standardIcon(QStyle.SP_DriveNetIcon),
            "&New Connection...", self
        )
        self._new_connection_action.triggered.connect(self._on_new_connection)

        self._connect_action = QAction(
            style.standardIcon(QStyle.SP_MediaPlay),
            "&Connect All", self
        )
        self._connect_action.setShortcut("F5")
        self._connect_action.triggered.connect(self._on_connect)

        self._disconnect_action = QAction(
            style.standardIcon(QStyle.SP_MediaStop),
            "&Disconnect All", self
        )
        self._disconnect_action.setShortcut("F6")
        self._disconnect_action.triggered.connect(self._on_disconnect)
        self._disconnect_action.setEnabled(False)

        # Data actions
        self._clear_action = QAction(
            style.standardIcon(QStyle.SP_TrashIcon),
            "C&lear Data", self
        )
        self._clear_action.setShortcut("Ctrl+L")
        self._clear_action.triggered.connect(self._on_clear_data)

    def _setup_toolbar(self) -> None:
        """Set up the main toolbar."""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setObjectName("MainToolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        toolbar.addAction(self._new_action)
        toolbar.addAction(self._open_action)
        toolbar.addAction(self._save_action)
        toolbar.addSeparator()
        toolbar.addAction(self._new_connection_action)
        toolbar.addAction(self._connect_action)
        toolbar.addAction(self._disconnect_action)
        toolbar.addSeparator()
        toolbar.addAction(self._clear_action)

    def _setup_menubar(self) -> None:
        """Set up the menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")
        file_menu.addAction(self._new_action)
        file_menu.addAction(self._open_action)
        file_menu.addAction(self._save_action)
        file_menu.addSeparator()
        file_menu.addAction(self._exit_action)

        # Connection menu
        conn_menu = menubar.addMenu("&Connection")
        conn_menu.addAction(self._new_connection_action)
        conn_menu.addSeparator()
        conn_menu.addAction(self._connect_action)
        conn_menu.addAction(self._disconnect_action)

        # View menu
        view_menu = menubar.addMenu("&View")
        for dock in self._docks.values():
            view_menu.addAction(dock.toggleViewAction())

        # Help menu
        help_menu = menubar.addMenu("&Help")
        about_action = help_menu.addAction("&About")
        about_action.triggered.connect(self._on_about)

    def _setup_status_bar(self) -> None:
        """Set up the status bar."""
        self._status_bar = StatusBar(self)
        self.setStatusBar(self._status_bar)

    def _connect_signals(self) -> None:
        """Connect internal signals."""
        # Bus manager callbacks
        self._bus_manager.on_bus_state_change = self._on_bus_state_change
        self._bus_manager.on_bus_error = self._on_bus_error

        # Project tree signals
        self._project_tree.connection_toggled.connect(
            self._on_connection_toggled
        )
        self._project_tree.project_changed.connect(
            self._on_project_changed
        )
        self._project_tree.add_connection_requested.connect(
            self._on_new_connection
        )
        self._project_tree.edit_connection_requested.connect(
            self._on_edit_connection
        )
        self._project_tree.remove_connection_requested.connect(
            self._on_remove_connection
        )
        self._project_tree.connect_connection_requested.connect(
            self._on_connect_single
        )
        self._project_tree.disconnect_connection_requested.connect(
            self._on_disconnect_single
        )
        self._project_tree.database_loaded.connect(
            self._on_database_loaded
        )
        self._project_tree.database_unloaded.connect(
            self._on_database_unloaded
        )
        self._project_tree.database_toggled.connect(
            self._on_database_toggled
        )
        self._project_tree.filter_added.connect(
            self._on_filter_added
        )
        self._project_tree.filter_removed.connect(
            self._on_filter_removed
        )
        self._project_tree.filter_toggled.connect(
            self._on_filter_toggled
        )

        # Frame received signal
        self.frames_received.connect(self._on_frames_received)

        # View selection signals -> properties panel
        self._receive_view.frame_selected.connect(self._on_frame_selected)
        self._trace_view.frame_selected.connect(self._on_frame_selected)
        self._project_tree.item_selected.connect(self._on_project_item_selected)

        # CANopen manager callbacks
        self._canopen_manager.on_node_discovered = self._on_canopen_node_discovered
        self._canopen_manager.on_node_state_changed = self._on_canopen_node_state_changed

        # Transmit panel
        self._transmit_panel.send_frame.connect(self._on_transmit_frame)

    def _add_default_connection(self) -> None:
        """Add a default virtual CAN connection."""
        conn = Connection(
            name="Virtual Bus",
            interface="virtual",
            channel="test",
            bitrate=500000,
        )
        self._connections.append(conn)
        self._bus_manager.add_connection(conn)
        self._project_tree.set_connections(self._connections)
        self._transmit_panel.set_connections(self._connections)
        self._status_bar.add_bus(conn.id, conn.name)

    # --- Event handlers ---

    def _on_update_timer(self) -> None:
        """Handle update timer tick."""
        # Get frames from all buses
        frames = self._bus_manager.get_all_frames()

        if frames:
            self._frame_count += len(frames)
            self.frames_received.emit(frames)

        # Update message rate (every second)
        delta = self._frame_count - self._last_frame_count
        self._message_rate = delta * 20  # 20 Hz timer
        self._last_frame_count = self._frame_count

        # Update status bar
        self._status_bar.set_frame_count(self._frame_count)
        self._status_bar.set_message_rate(self._message_rate)

    def _on_frames_received(self, frames: list[CANFrame]) -> None:
        """Handle received frames."""
        self._receive_view.update_frames(frames)
        self._trace_view.add_frames(frames)

        # Process through CANopen decoder
        self._canopen_manager.process_frames(frames)

    def _on_canopen_node_discovered(self, node: CANopenNode) -> None:
        """Handle CANopen node discovery."""
        self._project_tree.add_canopen_node(node)
        self._status_bar.showMessage(f"CANopen node {node.node_id} discovered")

    def _on_canopen_node_state_changed(self, node: CANopenNode) -> None:
        """Handle CANopen node state change."""
        self._project_tree.update_canopen_node(node)

    def _on_transmit_frame(self, connection_id: UUID, frame: CANFrame) -> None:
        """Handle frame transmission request from transmit panel."""
        if connection_id:
            success = self._bus_manager.send_frame(connection_id, frame)
            if not success:
                self._status_bar.showMessage("Failed to send frame", 2000)

    def _on_database_loaded(self, path: str) -> None:
        """Handle database file loaded."""
        success = self._dbc_decoder.load_database(path)
        if success:
            count = self._dbc_decoder.message_count
            self._status_bar.showMessage(f"Loaded database: {path} ({count} messages)")
        else:
            self._status_bar.showMessage(f"Failed to load database: {path}", 3000)

    def _on_database_unloaded(self, path: str) -> None:
        """Handle database file unloaded."""
        success = self._dbc_decoder.unload_database(path)
        if success:
            self._status_bar.showMessage(f"Unloaded database: {path}")

    def _on_database_toggled(self, path: str, enabled: bool) -> None:
        """Handle database enabled/disabled toggle."""
        if enabled:
            success = self._dbc_decoder.load_database(path)
            if success:
                self._status_bar.showMessage(f"Enabled database: {path}")
        else:
            success = self._dbc_decoder.unload_database(path)
            if success:
                self._status_bar.showMessage(f"Disabled database: {path}")

    def _on_filter_added(self, filter_config: FilterConfig) -> None:
        """Handle new filter added."""
        self._apply_filters()
        self._status_bar.showMessage(f"Added filter: {filter_config.name}")

    def _on_filter_removed(self, filter_config: FilterConfig) -> None:
        """Handle filter removed."""
        self._apply_filters()
        self._status_bar.showMessage(f"Removed filter: {filter_config.name}")

    def _on_filter_toggled(self, filter_config: FilterConfig, enabled: bool) -> None:
        """Handle filter enabled/disabled toggle."""
        self._apply_filters()
        state = "enabled" if enabled else "disabled"
        self._status_bar.showMessage(f"Filter {filter_config.name} {state}")

    def _apply_filters(self) -> None:
        """Apply all enabled filters to the views."""
        # Collect all enabled filters
        enabled_filters = self._project_tree.get_enabled_filters()

        if not enabled_filters:
            # No filters - clear filter settings
            self._receive_view.proxy_model.set_id_range(None, None)
            self._trace_view.proxy_model.set_id_range(None, None)
        else:
            # Combine filters - use the union of all ID ranges
            min_id = None
            max_id = None
            for f in enabled_filters:
                if f.min_id is not None:
                    if min_id is None:
                        min_id = f.min_id
                    else:
                        min_id = min(min_id, f.min_id)
                if f.max_id is not None:
                    if max_id is None:
                        max_id = f.max_id
                    else:
                        max_id = max(max_id, f.max_id)

            self._receive_view.proxy_model.set_id_range(min_id, max_id)
            self._trace_view.proxy_model.set_id_range(min_id, max_id)

    def _on_frame_selected(self, frame: CANFrame) -> None:
        """Handle frame selection in views."""
        # Get message info from decoder
        msg_info = self._dbc_decoder.get_message_info(frame.arbitration_id)
        message_name = msg_info.get("name", "") if msg_info else ""

        # Decode signals
        decoded = self._dbc_decoder.decode(frame)

        # Get message from grouped model for stats
        grouped_msg = self._receive_view.model.get_message(
            self._find_message_row(frame)
        )
        cycle_time = grouped_msg.get_cycle_time_ms() if grouped_msg else None
        count = grouped_msg.count if grouped_msg else 0

        self._properties_panel.show_frame(
            frame, decoded, message_name, cycle_time, count
        )

    def _find_message_row(self, frame: CANFrame) -> int:
        """Find the row index for a message in the grouped model."""
        model = self._receive_view.model
        for row in range(model.message_count):
            msg = model.get_message(row)
            if msg and msg.arbitration_id == frame.arbitration_id:
                if msg.connection_id == frame.connection_id:
                    return row
        return -1

    def _on_project_item_selected(self, item_type: str, item_data) -> None:
        """Handle project tree item selection."""
        if item_type == "connection" and item_data:
            state = self._bus_states.get(item_data.id, BusState.UNKNOWN) if hasattr(self, '_bus_states') else BusState.UNKNOWN
            state = self._bus_manager.get_bus_state(item_data.id)
            self._properties_panel.show_connection(item_data, state)
        elif item_type == "canopen_node" and item_data:
            self._properties_panel.show_canopen_node(item_data)
        elif item_type == "database" and item_data:
            # item_data is the database path
            self._properties_panel.clear()
        else:
            self._properties_panel.clear()

    def _on_bus_state_change(self, connection_id: UUID, state: BusState) -> None:
        """Handle bus state change."""
        self._status_bar.update_bus_state(connection_id, state)
        self._project_tree.update_bus_state(connection_id, state)

    def _on_bus_error(self, connection_id: UUID, message: str) -> None:
        """Handle bus error."""
        conn = self._bus_manager.get_connection(connection_id)
        name = conn.name if conn else str(connection_id)[:8]
        self._status_bar.showMessage(f"Error on {name}: {message}", 5000)

    def _on_connection_toggled(self, connection: Connection, enabled: bool) -> None:
        """Handle connection enabled/disabled toggle."""
        connection.enabled = enabled

    def _on_project_changed(self) -> None:
        """Handle project structure change."""
        pass  # TODO: Mark project as dirty

    # --- Actions ---

    def _on_new_connection(self) -> None:
        """Show dialog to create a new connection."""
        dialog = ConnectionDialog(self)
        if dialog.exec() == ConnectionDialog.Accepted:
            conn = dialog.get_connection()
            self.add_connection(conn)
            self._status_bar.showMessage(f"Added connection: {conn.name}")

    def _on_edit_connection(self, connection: Connection) -> None:
        """Show dialog to edit an existing connection."""
        old_name = connection.name
        dialog = ConnectionDialog(self, connection=connection)
        if dialog.exec() == ConnectionDialog.Accepted:
            updated_conn = dialog.get_connection()
            # Update the connection in place
            connection.name = updated_conn.name
            connection.interface = updated_conn.interface
            connection.channel = updated_conn.channel
            connection.bitrate = updated_conn.bitrate
            connection.data_bitrate = updated_conn.data_bitrate
            connection.fd = updated_conn.fd
            connection.extra_config = updated_conn.extra_config

            # Refresh UI components
            self._project_tree.set_connections(self._connections)
            self._transmit_panel.set_connections(self._connections)

            # Update status bar bus name
            self._status_bar.update_bus_name(connection.id, connection.name)

            # Update bus combo boxes in views
            if old_name != connection.name:
                self._receive_view.rename_bus(old_name, connection.name)
                self._trace_view.rename_bus(old_name, connection.name)

            self._status_bar.showMessage(f"Updated connection: {connection.name}")

    def _on_remove_connection(self, connection: Connection) -> None:
        """Remove a connection after confirmation."""
        reply = QMessageBox.question(
            self,
            "Remove Connection",
            f"Remove connection '{connection.name}'?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.remove_connection(connection.id)
            self._status_bar.showMessage(f"Removed connection: {connection.name}")

    def _on_connect_single(self, connection: Connection) -> None:
        """Connect a single bus."""
        success = self._bus_manager.start_connection(connection.id)
        if success:
            self._status_bar.showMessage(f"Connected: {connection.name}")
            # Update state to show connected
            state = self._bus_manager.get_bus_state(connection.id)
            if state == BusState.UNKNOWN:
                state = BusState.ERROR_ACTIVE  # Assume active if unknown
            self._project_tree.update_bus_state(connection.id, state)
            self._status_bar.update_bus_state(connection.id, state)
            self._update_connection_buttons()
        else:
            self._status_bar.showMessage(f"Failed to connect: {connection.name}", 3000)
            # Make sure checkbox reflects failed state
            self._project_tree.update_bus_state(connection.id, BusState.UNKNOWN)

    def _on_disconnect_single(self, connection: Connection) -> None:
        """Disconnect a single bus."""
        self._bus_manager.stop_connection(connection.id)
        self._status_bar.showMessage(f"Disconnected: {connection.name}")
        self._project_tree.update_bus_state(connection.id, BusState.UNKNOWN)
        self._status_bar.update_bus_state(connection.id, BusState.UNKNOWN)
        self._update_connection_buttons()

    def _update_connection_buttons(self) -> None:
        """Update connect/disconnect button states."""
        any_connected = self._bus_manager.has_active_connections()
        self._connect_action.setEnabled(not any_connected or len(self._connections) > self._bus_manager.active_connection_count())
        self._disconnect_action.setEnabled(any_connected)

    def _on_connect(self) -> None:
        """Connect to all enabled buses."""
        results = self._bus_manager.start_all()

        connected = sum(1 for success in results.values() if success)
        failed = len(results) - connected

        # Update states for each connection
        for conn_id, success in results.items():
            if success:
                state = self._bus_manager.get_bus_state(conn_id)
                if state == BusState.UNKNOWN:
                    state = BusState.ERROR_ACTIVE
                self._project_tree.update_bus_state(conn_id, state)
                self._status_bar.update_bus_state(conn_id, state)
            else:
                self._project_tree.update_bus_state(conn_id, BusState.UNKNOWN)

        if connected > 0:
            self._connect_action.setEnabled(False)
            self._disconnect_action.setEnabled(True)
            self._status_bar.showMessage(
                f"Connected to {connected} bus(es)"
                + (f", {failed} failed" if failed else "")
            )
        else:
            self._status_bar.showMessage("Connection failed", 3000)

    def _on_disconnect(self) -> None:
        """Disconnect from all buses."""
        self._bus_manager.stop_all()

        self._connect_action.setEnabled(True)
        self._disconnect_action.setEnabled(False)
        self._status_bar.showMessage("Disconnected")

        # Reset bus states
        for conn in self._connections:
            self._status_bar.update_bus_state(conn.id, BusState.UNKNOWN)
            self._project_tree.update_bus_state(conn.id, BusState.UNKNOWN)

    def _on_clear_data(self) -> None:
        """Clear all received data."""
        self._receive_view.clear()
        self._trace_view.clear()
        self._canopen_manager.clear()
        self._project_tree.clear_canopen_nodes()
        self._frame_count = 0
        self._last_frame_count = 0
        self._status_bar.set_frame_count(0)
        self._status_bar.showMessage("Data cleared")

    def _on_new_project(self) -> None:
        """Create new project."""
        # Check for unsaved changes
        if self._project.connections or self._project.databases:
            reply = QMessageBox.question(
                self,
                "New Project",
                "Discard current project?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return

        # Clear everything
        self._on_disconnect()
        self._on_clear_data()

        # Remove all connections except default
        for conn in self._connections[:]:
            self.remove_connection(conn.id)

        # Clear databases
        self._dbc_decoder.clear()

        # Create new project
        self._project = Project()
        self._add_default_connection()
        self._update_window_title()
        self._status_bar.showMessage("New project created")

    def _on_open_project(self) -> None:
        """Open existing project."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Project",
            "",
            "CANPeek Projects (*.cpeek);;All Files (*)"
        )
        if not path:
            return

        project = Project.load(path)
        if not project:
            QMessageBox.warning(
                self,
                "Open Project",
                f"Failed to load project from {path}"
            )
            return

        # Clear current state
        self._on_disconnect()
        self._on_clear_data()
        for conn in self._connections[:]:
            self.remove_connection(conn.id)
        self._dbc_decoder.clear()

        # Load project
        self._project = project

        # Add connections
        for conn in project.connections:
            self.add_connection(conn)

        # Load databases
        for db in project.databases:
            if db.enabled:
                self._dbc_decoder.load_database(db.path)
            self._project_tree.add_database(db.path, db.path.split('/')[-1])

        self._update_window_title()
        self._status_bar.showMessage(f"Opened {path}")

    def _on_save_project(self) -> None:
        """Save current project."""
        if self._project.path:
            # Save to existing path
            self._save_project_to_path(self._project.path)
        else:
            # Ask for path
            self._on_save_project_as()

    def _on_save_project_as(self) -> None:
        """Save project to new path."""
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Project",
            "",
            "CANPeek Projects (*.cpeek)"
        )
        if path:
            if not path.endswith('.cpeek'):
                path += '.cpeek'
            self._save_project_to_path(path)

    def _save_project_to_path(self, path: str) -> None:
        """Save project to specified path."""
        # Update project with current state
        self._project.connections = list(self._connections)
        self._project.databases = [
            DatabaseConfig(path=db_path, enabled=True)
            for db_path in self._dbc_decoder.loaded_databases
        ]

        if self._project.save(path):
            self._update_window_title()
            self._status_bar.showMessage(f"Saved to {path}")
        else:
            QMessageBox.warning(
                self,
                "Save Project",
                f"Failed to save project to {path}"
            )

    def _update_window_title(self) -> None:
        """Update window title with project name."""
        title = "CANPeek"
        if self._project.path:
            title += f" - {self._project.display_name}"
        self.setWindowTitle(title)

    def _on_about(self) -> None:
        """Show about dialog."""
        QMessageBox.about(
            self,
            "About CANPeek",
            "<h2>CANPeek v2.0</h2>"
            "<p>High-performance CAN/CAN FD bus analyzer</p>"
            "<p>Built with Python, Qt, and python-can</p>"
        )

    # --- Settings persistence ---

    def _save_settings(self) -> None:
        """Save window settings."""
        settings = QSettings("CANPeek", "CANPeek")
        settings.setValue("geometry", self.saveGeometry())
        settings.setValue("windowState", self.saveState())
        settings.setValue("dockState", self._dock_manager.saveState())

    def _restore_settings(self) -> None:
        """Restore window settings."""
        settings = QSettings("CANPeek", "CANPeek")

        geometry = settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)

        state = settings.value("windowState")
        if state:
            self.restoreState(state)

        dock_state = settings.value("dockState")
        if dock_state:
            self._dock_manager.restoreState(dock_state)

    def closeEvent(self, event: QCloseEvent) -> None:
        """Handle window close event."""
        # Stop all connections
        self._bus_manager.stop_all()

        # Save settings
        self._save_settings()

        event.accept()

    # --- Public API ---

    @property
    def bus_manager(self) -> BusManager:
        """Get the bus manager."""
        return self._bus_manager

    def add_connection(self, connection: Connection) -> None:
        """Add a new connection."""
        self._connections.append(connection)
        self._bus_manager.add_connection(connection)
        self._project_tree.set_connections(self._connections)
        self._transmit_panel.set_connections(self._connections)
        self._status_bar.add_bus(connection.id, connection.name)

    def remove_connection(self, connection_id: UUID) -> None:
        """Remove a connection."""
        self._bus_manager.remove_connection(connection_id)
        self._connections = [
            c for c in self._connections if c.id != connection_id
        ]
        self._project_tree.set_connections(self._connections)
        self._transmit_panel.set_connections(self._connections)
        self._status_bar.remove_bus(connection_id)
