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

import os
import queue
import sys
import json
import subprocess

from typing import Dict, List, Optional, TYPE_CHECKING
from pathlib import Path
from functools import partial
from canpeek import rc_icons
import asyncio
from qasync import QEventLoop, QApplication
import uuid


from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QLabel,
    QComboBox,
    QFileDialog,
    QMessageBox,
    QMenu,
    QTreeView,
    QTreeWidget,
    QTreeWidgetItem,
    QTableView,
    QToolBar,
    QStyle,
    QSizePolicy,
    QWidgetAction,
    QInputDialog,
)

from PySide6.QtCore import (
    QTimer,
    Signal,
    Qt,
    QSettings,
)
from PySide6.QtGui import (
    QAction,
    QKeyEvent,
    QIcon,
    QPixmap,
    QColor,
    QActionGroup,
    QFontDatabase,
)

import PySide6QtAds as QtAds
import qt_themes

import can
import cantools


from canpeek.view.frame_processor import CANFrameProcessor
from canpeek.ui.properties_panel import PropertiesPanel, ConnectionEditor

from canpeek.co.canopen_utils import (
    CANopenNode,
    PDODatabaseManager,
    ObjectDictionaryViewer,
)
from canpeek.co.nmt_editor import NMTSender

from canpeek.data_utils import (
    CANFrame,
    Project,
    CANFrameFilter,
    DBCFile,
    CANInterfaceManager,
    Connection,
)


from canpeek.ui.transmit_panels import SignalTransmitPanel, TransmitPanel

from canpeek.can_utils import CANMultiprocessReader
from canpeek.view.trace2_view import CANTableModel, CANBuffer

from src.canpeek.view.trace2_view import Trace2FilterHeaderView

if TYPE_CHECKING:
    from __main__ import ProjectExplorer, CANBusObserver

__all__ = [
    "rc_icons",  # remove ruff "Remove unused import: `.rc_icons`"
]


# Workaround for qt-ads on wayland https://github.com/githubuser0xFFFF/Qt-Advanced-Docking-System/issues/714
if os.environ.get("XDG_SESSION_TYPE") == "wayland":
    print("Workaround for qt-ads on Wayland")
    os.environ["QT_QPA_PLATFORM"] = "xcb"


class ProjectExplorer(QWidget):
    project_changed = Signal()

    def __init__(self, project: Project, main_window: "CANBusObserver"):
        super().__init__()
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

        self.conn_root = self.add_item(None, "Connections", "connections_root")
        for conn in self.project.connections:
            self.add_item(self.conn_root, conn.name, conn, conn.enabled)

        self.dbc_root = self.add_item(None, "Symbol Files (.dbc)", "dbc_root")
        for dbc in self.project.dbcs:
            conn_name = (
                self.project.get_connection_name(dbc.connection_id)
                if dbc.connection_id
                else "Unassigned"
            )
            self.add_item(
                self.dbc_root,
                dbc.path.name,
                dbc,
                dbc.enabled,
                invalid=(dbc.connection_id == -1),
                tooltip=f"Assigned to: {conn_name}"
                if dbc.connection_id
                else "Unassigned",
            )

        self.filter_root = self.add_item(None, "Message Filters", "filter_root")
        for f in self.project.filters:
            conn_name = (
                self.project.get_connection_name(f.connection_id)
                if f.connection_id
                else "Unassigned"
            )
            self.add_item(
                self.filter_root,
                f.name,
                f,
                f.enabled,
                invalid=(f.connection_id == -1),
                tooltip=f"Assigned to: {conn_name}"
                if f.connection_id
                else "Unassigned",
            )

        self.co_root = self.add_item(None, "CANopen", "canopen_root")
        bus_items = {}
        for node in self.project.canopen_nodes:
            conn_name = (
                self.project.get_connection_name(node.connection_id)
                if node.connection_id
                else None
            )

            if node.connection_id not in bus_items:
                bus_items[node.connection_id] = self.add_item(
                    self.co_root,
                    conn_name if conn_name else "Unassigned",
                    f"canopen_bus_{node.connection_id}",
                    invalid=(conn_name is None),
                )
            self.add_item(
                bus_items[node.connection_id],
                f"{node.path.name} [ID: {node.node_id}]",
                node,
                node.enabled,
            )

        self.tree.expandAll()
        self.tree.blockSignals(False)
        self.project_changed.emit()

    def add_item(
        self, parent, text, data=None, checked=None, invalid=False, tooltip=None
    ):
        item = QTreeWidgetItem(parent or self.tree, [text])
        style = self.style()
        icon = None

        if data == "connections_root":
            icon = style.standardIcon(QStyle.SP_DriveNetIcon)
        elif data == "dbc_root" or data == "filter_root":
            icon = style.standardIcon(QStyle.SP_DirIcon)
        elif data == "canopen_root":
            icon = style.standardIcon(QStyle.SP_ComputerIcon)

        if icon:
            item.setIcon(0, icon)

        if data:
            item.setData(0, Qt.UserRole, data)
        if checked is not None:
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(0, Qt.Checked if checked else Qt.Unchecked)

        if invalid:
            item.setBackground(0, QColor(255, 0, 0, 128))
            item.setToolTip(0, tooltip or "This item is invalid and cannot be used.")

        return item

    def on_item_changed(self, item, column):
        if data := item.data(0, Qt.UserRole):
            if isinstance(data, (DBCFile, CANFrameFilter, CANopenNode, Connection)):
                data.enabled = item.checkState(0) == Qt.Checked
            self.project_changed.emit()

    def open_context_menu(self, position):
        menu = QMenu()
        item = self.tree.itemAt(position)
        data = item.data(0, Qt.UserRole) if item else None

        if data in [None, "connections_root"]:
            menu.addAction("Add Connection").triggered.connect(self.add_connection)
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

    def add_connection(self):
        self.project.connections.append(
            Connection(
                name=f"Connection {len(self.project.connections) + 1}",
                config={"channel": f"vcan{len(self.project.connections)}"},
            )
        )
        self.rebuild_tree()

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
            elif isinstance(data, Connection):
                removed_conn_id = data.id
                self.project.connections.remove(data)

                # Clean up references in other project items
                for dbc in self.project.dbcs:
                    if dbc.connection_id == removed_conn_id:
                        dbc.connection_id = -1
                for filt in self.project.filters:
                    if filt.connection_id == removed_conn_id:
                        filt.connection_id = -1
                for node in self.project.canopen_nodes:
                    if node.connection_id == removed_conn_id:
                        node.connection_id = -1

                # Clean up CANMultiprocessReader if it exists
                if removed_conn_id in self.main_window.can_readers:
                    reader = self.main_window.can_readers.pop(removed_conn_id)
                    reader.stop_reading()
                    reader.deleteLater()
                self.main_window.transmit_panel.set_connections(
                    self.main_window.can_readers
                )
            self.rebuild_tree()

    def add_canopen_node(self):
        fns, _ = QFileDialog.getOpenFileNames(
            self,
            "Select EDS/DCF File(s)",
            "",
            "CANopen Object Dictionary (*.eds *.dcf);;All Files (*)",
        )
        if fns:
            default_connection_id = None
            if self.project.connections:
                default_connection_id = self.project.connections[0].id

            for fn in fns:
                self.project.canopen_nodes.append(
                    CANopenNode(
                        path=Path(fn), node_id=1, connection_id=default_connection_id
                    )
                )
            self.rebuild_tree()


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
        self.can_readers: Dict[uuid.UUID, CANMultiprocessReader] = {}
        self.bus_states: Dict[uuid.UUID, can.BusState] = {}

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
        # Get the current event loop
        self.loop = asyncio.get_event_loop()

        self.frame_processor = CANFrameProcessor()
        self.grouped_model = self.frame_processor.get_grouped_model()

        self.all_received_frames_count = 0

        QtAds.CDockManager.setConfigFlag(QtAds.CDockManager.OpaqueSplitterResize, True)
        QtAds.CDockManager.setConfigFlag(
            QtAds.CDockManager.XmlCompressionEnabled, False
        )
        QtAds.CDockManager.setConfigFlag(QtAds.CDockManager.FocusHighlighting, True)
        self.dock_manager = QtAds.CDockManager(self)

        self.trace2_queue = queue.Queue()
        self.trace2_canbuffer = CANBuffer(self.trace2_queue)
        self.trace2_table = QTableView()
        self.trace2_model = CANTableModel(self.trace2_canbuffer)
        self.trace2_table.setModel(self.trace2_model)
        self.trace2_canbuffer.start()

        header_view = Trace2FilterHeaderView(Qt.Horizontal)
        header_view.set_model(self.trace2_model)
        self.trace2_table.setHorizontalHeader(header_view)

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
        self.update_perspectives_menu()

        self.gui_update_timer = QTimer(self)
        self.gui_update_timer.timeout.connect(self.update_views)
        self.gui_update_timer.start(50)

        self._update_window_title()

        icon = QIcon(QPixmap(":/icons/canpeek.png"))
        self.setWindowIcon(icon)

        self.project_explorer.project_changed.connect(
            self._on_project_structure_changed
        )

        # Apply default theme and style
        settings = QSettings()
        saved_theme = settings.value("selectedTheme", "default")
        self._set_theme(saved_theme)

        # Check the corresponding action in the menu
        for action in self.theme_group.actions():
            if action.text() == saved_theme:
                action.setChecked(True)
                break

    def _set_theme(self, theme_name: str):
        if theme_name == "default":
            theme_name = None

        # TODO : theme is partialy applied if run once ....
        qt_themes.set_theme(theme_name)
        qt_themes.set_theme(theme_name)
        qt_themes.set_theme(theme_name)
        settings = QSettings()
        settings.setValue("selectedTheme", theme_name)

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
        # Set monospaced font for grouped and trace views
        monospace_font = QFontDatabase.systemFont(QFontDatabase.FixedFont)

        self.grouped_view = QTreeView()
        self.grouped_view.setModel(self.grouped_model)
        self.grouped_view.setAlternatingRowColors(True)
        self.grouped_view.setSortingEnabled(True)
        self.grouped_view.setFont(monospace_font)

        self.object_dictionary_viewer = ObjectDictionaryViewer()
        self.object_dictionary_viewer.frame_to_send.connect(self.send_can_frame)

        self.nmt_sender = NMTSender(self.project)
        self.nmt_sender.frame_to_send.connect(self.send_can_frame)
        self.nmt_sender.status_update.connect(self.statusBar().showMessage)

    def setup_docks(self):
        # Set central widget
        label = QLabel()
        label.setText(
            "This is a DockArea which is always visible, even if it does not contain any DockWidgets."
        )
        label.setAlignment(Qt.AlignCenter)
        central_dock_widget = QtAds.CDockWidget(self.dock_manager, "CentralWidget")
        central_dock_widget.setWidget(label)
        central_dock_widget.setFeature(QtAds.CDockWidget.NoTab, True)
        central_dock_area = self.dock_manager.setCentralWidget(central_dock_widget)

        self.project_explorer = ProjectExplorer(self.project, self)
        explorer_dock = QtAds.CDockWidget(self.dock_manager, "Project Explorer")
        explorer_dock.setWidget(self.project_explorer)
        project_aera = self.dock_manager.addDockWidget(
            QtAds.DockWidgetArea.LeftDockWidgetArea, explorer_dock
        )

        self.properties_panel = PropertiesPanel(
            self.project, self.project_explorer, self.interface_manager, self
        )
        properties_dock = QtAds.CDockWidget(self.dock_manager, "Properties")
        properties_dock.setWidget(self.properties_panel)
        self.dock_manager.addDockWidget(
            QtAds.DockWidgetArea.BottomDockWidgetArea, properties_dock, project_aera
        )

        # New docks for previously tabbed views
        grouped_dock = QtAds.CDockWidget(self.dock_manager, "Grouped View")
        grouped_dock.setWidget(self.grouped_view)
        self.dock_manager.addDockWidgetTabToArea(grouped_dock, central_dock_area)

        trace2_dock = QtAds.CDockWidget(self.dock_manager, "Trace View")
        trace2_dock.setWidget(self.trace2_table)
        self.dock_manager.addDockWidgetTabToArea(trace2_dock, central_dock_area)

        od_dock = QtAds.CDockWidget(self.dock_manager, "Object Dictionary")
        od_dock.setWidget(self.object_dictionary_viewer)
        self.dock_manager.addDockWidgetTabToArea(od_dock, central_dock_area)

        # Set the Grouped View active
        central_dock_area.setCurrentDockWidget(grouped_dock)

        transmit_container = QWidget()
        transmit_layout = QVBoxLayout(transmit_container)
        transmit_layout.setContentsMargins(0, 0, 0, 0)
        self.transmit_panel = TransmitPanel()
        self.signal_transmit_panel = SignalTransmitPanel()
        transmit_layout.addWidget(self.transmit_panel)
        transmit_layout.addWidget(self.signal_transmit_panel)
        self.signal_transmit_panel.setVisible(False)
        transmit_dock = QtAds.CDockWidget(self.dock_manager, "Transmit")
        transmit_dock.setWidget(transmit_container)
        transmit_aera = self.dock_manager.addDockWidget(
            QtAds.BottomDockWidgetArea, transmit_dock, central_dock_area
        )

        nmt_sender_dock = QtAds.CDockWidget(self.dock_manager, "NMT Sender")
        nmt_sender_dock.setWidget(self.nmt_sender)
        self.dock_manager.addDockWidgetTabToArea(nmt_sender_dock, transmit_aera)

        transmit_aera.setCurrentDockWidget(transmit_dock)

        self.docks = {
            "explorer": explorer_dock,
            "properties": properties_dock,
            "transmit": transmit_dock,
            "grouped": grouped_dock,
            "trace": trace2_dock,
            "object_dictionary": od_dock,
            "nmt_sender": nmt_sender_dock,
        }

        self.properties_panel.message_to_transmit.connect(
            self._add_message_to_transmit_panel
        )
        self.transmit_panel.frame_to_send.connect(self.send_can_frame)
        self.transmit_panel.row_selection_changed.connect(self.on_transmit_row_selected)
        self.signal_transmit_panel.data_encoded.connect(self.on_signal_data_encoded)
        self.project_explorer.project_changed.connect(self.on_project_changed)
        self.project_explorer.project_changed.connect(
            self.nmt_sender.update_project_nodes
        )
        self.project_explorer.tree.currentItemChanged.connect(
            self.properties_panel.show_properties
        )
        self.project_explorer.tree.currentItemChanged.connect(
            self.on_project_explorer_selection_changed
        )

    def save_perspective(self):
        perspective_name, ok = QInputDialog.getText(
            self, "Save Perspective", "Enter a name for the perspective:"
        )
        if ok and perspective_name:
            self.dock_manager.addPerspective(perspective_name)
            self.update_perspectives_menu()

    def load_perspective(self, index):
        perspective_name = self.perspectives_combobox.itemText(index)
        self.dock_manager.openPerspective(perspective_name)

    def update_perspectives_menu(self):
        self.perspectives_combobox.clear()
        self.perspectives_combobox.addItems(self.dock_manager.perspectiveNames())

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

        # Add new instance menu actions
        new_instance_action = QAction("New &Instance", self)
        new_instance_action.setShortcut("Ctrl+Shift+N")
        new_instance_action.setToolTip("Launch a new independent CANPeek window")
        new_instance_action.triggered.connect(self.launch_new_instance)
        file_menu.addAction(new_instance_action)

        open_instance_action = QAction("Open in New &Instance...", self)
        open_instance_action.setShortcut("Ctrl+Shift+O")
        open_instance_action.setToolTip(
            "Open a project file in a new independent CANPeek window"
        )
        open_instance_action.triggered.connect(self.open_in_new_instance)
        file_menu.addAction(open_instance_action)

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
        for dock in self.docks.values():
            view_menu.addAction(dock.toggleViewAction())

        # Add Window menu for instance management
        window_menu = menubar.addMenu("&Window")
        window_menu.addAction(new_instance_action)
        window_menu.addAction(open_instance_action)

        perspectives_menu = menubar.addMenu("&Perspectives")
        save_perspective_action = QAction("Save Perspective...", self)
        save_perspective_action.triggered.connect(self.save_perspective)
        perspectives_menu.addAction(save_perspective_action)

        remove_perspective_action = QAction("Remove Perspective...", self)
        remove_perspective_action.triggered.connect(self._remove_perspective)
        perspectives_menu.addAction(remove_perspective_action)

        self.perspectives_combobox = QComboBox(self)
        self.perspectives_combobox.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.perspectives_combobox.setSizePolicy(
            QSizePolicy.Preferred, QSizePolicy.Preferred
        )
        self.perspectives_combobox.activated.connect(self.load_perspective)

        # Theme and Style menus
        theme_menu = menubar.addMenu("&Themes")
        self.theme_group = QActionGroup(self)
        self.theme_group.setExclusive(True)
        names = ["default"]
        names.extend(sorted(qt_themes.get_themes().keys()))
        for theme_name in names:
            action = QAction(theme_name, self, checkable=True)
            action.triggered.connect(partial(self._set_theme, theme_name))
            self.theme_group.addAction(action)
            theme_menu.addAction(action)

        perspective_list_action = QWidgetAction(self)
        perspective_list_action.setDefaultWidget(self.perspectives_combobox)
        perspectives_menu.addAction(perspective_list_action)

    def setup_statusbar(self):
        self.statusBar().showMessage("Ready")
        self.frame_count_label = QLabel("Frames: 0")
        self.connection_label = QLabel("Disconnected")
        self.bus_state_label = QLabel("Bus States: N/A")
        self.performance_label = QLabel("Performance: Ready")
        self.statusBar().addPermanentWidget(self.performance_label)
        self.statusBar().addPermanentWidget(self.bus_state_label)
        self.statusBar().addPermanentWidget(self.frame_count_label)
        self.statusBar().addPermanentWidget(self.connection_label)

    def _remove_perspective(self):
        perspective_names = self.dock_manager.perspectiveNames()
        if not perspective_names:
            QMessageBox.information(
                self, "Remove Perspective", "No perspectives to remove."
            )
            return

        perspective_name, ok = QInputDialog.getItem(
            self,
            "Remove Perspective",
            "Select a perspective to remove:",
            perspective_names,
            0,
            False,
        )
        if ok and perspective_name:
            self.dock_manager.removePerspective(perspective_name)
            self.update_perspectives_menu()

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
            # # Convert bytearray to bytes for Polars backend compatibility
            # if isinstance(frame.data, bytearray):
            #     frame.data = bytes(frame.data)

            self.all_received_frames_count += 1

            # # Feed frames to frame processor for distribution to both views
            # self.frame_processor.add_frame(frame)

            if frame.arbitration_id & 0x580 == 0x580:
                self.object_dictionary_viewer.frame_rx_sdo.emit(frame)
        except Exception as e:
            print(f"Error processing frame: {e}")

    def update_views(self):
        """Update frame counter and handle autoscroll - Polars backend handles the rest"""

        # if True:  # self.autoscroll_cb.isChecked():
        #     self.trace2_table.scrollToBottom()
        self.frame_count_label.setText(f"Frames: {self.all_received_frames_count}")

    def _create_pdo_databases(self) -> List[object]:
        """Create PDO databases from enabled CANopen nodes using manager"""
        return self.pdo_manager.get_all_active_databases(self.project.canopen_nodes)

    def on_project_changed(self):
        active_dbcs = self.project.get_active_dbcs()
        pdo_databases = self._create_pdo_databases()

        # Update grouped model configuration
        self.grouped_model.set_dbc_config(
            active_dbcs, pdo_databases, self.project.canopen_enabled
        )

        # Update trace2_canbuffer DBC configuration for cached decoding
        self.trace2_canbuffer.dbc_decoder.set_dbc_files(active_dbcs)
        self.trace2_canbuffer.dbc_decoder.set_pdo_databases(pdo_databases)
        self.trace2_canbuffer.dbc_decoder.set_canopen_enabled(
            self.project.canopen_enabled
        )

        if self.can_readers:
            asyncio.create_task(self._update_canopen_nodes())

        self.transmit_panel.set_connections(self.can_readers)
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
                self.signal_transmit_panel.populate(message, data_hex)
        except ValueError:
            pass

    def on_signal_data_encoded(self, data_bytes):
        if (row := self.transmit_panel.table.currentRow()) >= 0:
            self.transmit_panel.update_row_data(row, data_bytes)

    async def _update_canopen_nodes(self):
        """Update CANopen nodes when project changes while connected"""
        if not self.canopen_network:
            return

        self.canopen_network.nodes.clear()

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

        is_connected = bool(self.can_readers)
        data = current.data(0, Qt.UserRole)
        if isinstance(data, CANopenNode) and data.enabled:
            asyncio.create_task(self.object_dictionary_viewer.set_node(data))
            self.nmt_sender.set_connection_context(data.connection_id, is_connected)
        elif isinstance(data, Connection):
            self.nmt_sender.set_connection_context(data.id, is_connected)
        elif isinstance(data, str) and data.startswith("canopen_bus_"):
            connection_id_str = data.replace("canopen_bus_", "")
            try:
                connection_id = uuid.UUID(connection_id_str)
                self.nmt_sender.set_connection_context(connection_id, is_connected)
            except ValueError:
                self.nmt_sender.set_connection_context(None, is_connected)
        else:
            self.object_dictionary_viewer.clear_node()
            self.nmt_sender.set_connection_context(None, is_connected)

    def _update_bus_state(self, state: can.BusState):
        """Updates the status bar with the current CAN bus state."""
        sender_reader = self.sender()
        if not isinstance(sender_reader, CANMultiprocessReader):
            return

        conn_id = sender_reader.connection.id
        self.bus_states[conn_id] = state

        state_strings = []
        for conn_id, s in sorted(
            self.bus_states.items(),
            key=lambda item: self.project.get_connection_name(item[0]),
        ):
            conn_name = self.project.get_connection_name(conn_id)
            state_strings.append(
                f"<span style='color: {self._get_state_color(s)};'>{conn_name}: {s.name.title()}</span>"
            )

        self.bus_state_label.setText("Bus States: " + ", ".join(state_strings))

    def _get_state_color(self, state: can.BusState) -> str:
        if state == can.BusState.ACTIVE:
            return "#4CAF50"  # Green
        elif state == can.BusState.PASSIVE:
            return "#FFC107"  # Amber
        elif state == can.BusState.ERROR:
            return "#F44336"  # Red
        return "#FFFFFF"  # White/Default

    async def connect_can(self):
        active_connections = self.project.get_active_connections()
        if not active_connections:
            QMessageBox.information(
                self, "No Connections", "No active connections to start."
            )
            return

        connect_tasks = [self._connect_single(conn) for conn in active_connections]
        results = await asyncio.gather(*connect_tasks)

        successful_connections = [
            conn for conn, res in zip(active_connections, results) if res
        ]

        if successful_connections:
            self.connect_action.setEnabled(False)
            self.disconnect_action.setEnabled(True)
            self.transmit_panel.set_connections(self.can_readers)

            connected_names = [conn.name for conn in successful_connections]
            self.connection_label.setText(f"Connected to: {', '.join(connected_names)}")
        else:
            self.connection_label.setText("Connection Failed")

        if current_item := self.project_explorer.tree.currentItem():
            self.properties_panel.show_properties(current_item)
            if isinstance(self.properties_panel.current_widget, ConnectionEditor):
                self.properties_panel.current_widget.set_connected_state(True)

        # Update NMT sender context after connection state changes
        self.on_project_explorer_selection_changed(
            self.project_explorer.tree.currentItem(), None
        )

    async def _connect_single(self, connection: Connection) -> bool:
        if connection.id in self.can_readers:
            return True  # Already connected

        reader = CANMultiprocessReader(
            connection,
            [self.frame_processor.grouped_queue, self.trace2_queue],
        )
        reader.frame_received.connect(self._process_frame)
        reader.error_occurred.connect(self.on_can_error)
        reader.bus_state_changed.connect(self._update_bus_state)

        if reader.start_reading():
            self.can_readers[connection.id] = reader
            return True
        else:
            reader.deleteLater()
            return False

    def disconnect_can(self):
        for reader in self.can_readers.values():
            reader.stop_reading()
            reader.deleteLater()
        self.can_readers.clear()
        self.bus_states.clear()

        self.connect_action.setEnabled(True)
        self.disconnect_action.setEnabled(False)
        self.transmit_panel.stop_all_timers()
        self.transmit_panel.set_connections(self.can_readers)
        self.connection_label.setText("Disconnected")
        self.bus_state_label.setText("Bus States: N/A")

        if current_item := self.project_explorer.tree.currentItem():
            self.properties_panel.show_properties(current_item)
            if isinstance(self.properties_panel.current_widget, ConnectionEditor):
                self.properties_panel.current_widget.set_connected_state(False)

        # Update NMT sender context after connection state changes
        self.on_project_explorer_selection_changed(
            self.project_explorer.tree.currentItem(), None
        )

    def send_can_frame(self, message: can.Message, connection_id: uuid.UUID):
        print(f"Sending frame: {message} on connection {connection_id}")
        if reader := self.can_readers.get(connection_id):
            if reader.running:
                reader.send_frame(message)
        else:
            conn_name = self.project.get_connection_name(connection_id)
            QMessageBox.warning(
                self, "Not Connected", f"Connection '{conn_name}' is not active."
            )

    def on_can_error(self, error_message: str):
        QMessageBox.warning(self, "CAN Error", error_message)
        self.statusBar().showMessage(f"Error: {error_message}")
        self.disconnect_can()

    def clear_data(self):
        self.all_received_frames_count = 0
        # Reset frame processor
        self.frame_processor.clear_data()
        self.trace2_canbuffer.clear()
        # Clear DBC decoder caches
        self.trace2_canbuffer.dbc_decoder.clear_caches()
        # self.trace_model = self.frame_processor.get_trace_model()
        # self.grouped_model = self.frame_processor.get_grouped_model()
        #
        # # Update views with new models
        # self.trace_view.setModel(self.trace_model)
        # self.grouped_view.setModel(self.grouped_model)
        #
        # # Update filter header view with new model
        # self.trace_header_view.set_model(self.trace_model)

        # Update configuration for new models
        self.on_project_changed()

        self.frame_count_label.setText("Frames: 0")

    def ask_for_file_path(self, title: str) -> str | None:
        dialog = QFileDialog(self, title, "", self.log_file_filter)
        dialog.setDefaultSuffix("log")
        dialog.setAcceptMode(QFileDialog.AcceptSave)
        if not dialog.exec():
            return None
        return dialog.selectedFiles()[0]

    def save_log(self):
        # Get all frames from CANBuffer (entire buffer content)
        buffer_data = self.trace2_canbuffer.get_polars_data(self.trace2_canbuffer.index)

        if buffer_data.is_empty():
            QMessageBox.information(self, "No Data", "No frames to save.")
            return

        filename = self.ask_for_file_path("Save CAN Log")
        if not filename:
            return

        logger = None
        try:
            logger = can.Logger(filename)
            # Convert Polars DataFrame rows to can.Message objects
            for row in buffer_data.iter_rows(named=True):
                # Convert hex string ID back to int
                arbitration_id = int(row["id"], 16)
                # Convert hex string data back to bytes
                data_bytes = bytes.fromhex(row["data"].replace(" ", ""))

                logger.on_message_received(
                    can.Message(
                        timestamp=row["timestamp"],
                        arbitration_id=arbitration_id,
                        is_extended_id=row["is_extended"],
                        is_remote_frame=row["is_rtr"],
                        is_error_frame=False,  # Not stored in current buffer format
                        dlc=row["dlc"],
                        data=data_bytes,
                        channel=row["bus"],
                    )
                )
            self.statusBar().showMessage(
                f"Log saved to {filename} ({buffer_data.height} frames)"
            )
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
            # self.clear_data()
            frames_to_add = []
            for msg in can.LogReader(filename):
                try:
                    # Ensure arbitration_id is an integer
                    arbitration_id = msg.arbitration_id
                    if not isinstance(arbitration_id, int):
                        raise ValueError(
                            f"Arbitration ID is not an integer: {arbitration_id}"
                        )

                    # Ensure dlc is an integer
                    dlc = msg.dlc
                    if not isinstance(dlc, int):
                        raise ValueError(f"DLC is not an integer: {dlc}")

                    # Ensure data is bytes or bytearray, convert to bytes if bytearray
                    data = msg.data
                    if isinstance(data, bytearray):
                        data = bytes(data)
                    if not isinstance(data, bytes):
                        raise ValueError(f"Data is not bytes: {data}")

                    frames_to_add.append(
                        CANFrame(
                            timestamp=msg.timestamp,
                            arbitration_id=arbitration_id,
                            data=data,
                            dlc=dlc,
                            is_extended=msg.is_extended_id,
                            is_error=msg.is_error_frame,
                            is_remote=msg.is_remote_frame,
                            bus=msg.channel or "CAN1",
                        )
                    )
                except Exception as frame_error:
                    QMessageBox.warning(
                        self,
                        "Log Parse Warning",
                        f"Skipping malformed frame: {frame_error}. Original message: {msg}",
                    )
                    continue
            # Add frames to frame processor
            if frames_to_add:
                # self.frame_processor.add_frames(frames_to_add)
                self.all_received_frames_count += len(frames_to_add)
                for frame in frames_to_add:
                    self.grouped_model.add_frame(frame)
                    self.trace2_queue.put(frame)

            self.statusBar().showMessage(
                f"Loaded {self.all_received_frames_count} frames from {filename}"
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
        if self._prompt_save_if_dirty():
            self.disconnect_can()  # Stop any active CAN connections and timers
            self.clear_data()
            self.project = Project()
            # Add a default connection when a new project is created
            self.project.connections.append(Connection())
            self.current_project_path = None
            self.pdo_manager.invalidate_cache()  # Clear PDO cache
            self.project_explorer.set_project(self.project)
            self.transmit_panel.set_config([])
            self.nmt_sender.set_project(self.project)
            self._set_dirty(False)
            self._update_window_title()

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
            self.pdo_manager.invalidate_cache()
            self.project = Project.from_dict(data, self.interface_manager)
            self.current_project_path = Path(path)
            self.project_explorer.set_project(self.project)
            self.transmit_panel.set_config(data.get("transmit_config", []))
            self._add_to_recent_projects(self.current_project_path)
            self._set_dirty(False)
            self.statusBar().showMessage(
                f"Project {self.current_project_path.name} loaded"
            )
            self.nmt_sender.set_project(self.project)
        except Exception as e:
            QMessageBox.critical(
                self, "Project Load Error", f"Failed to load project: {e}"
            )
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
        if not self.current_project_path:
            return self._save_project_as()
        return self._save_project_to_path(self.current_project_path)

    def _save_project_as(self) -> bool:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Project As", "", "CANPeek Project (*.cpeek);;All Files (*)"
        )
        # TODO : add dialog.setDefaultSuffix("cpeek")
        if not path:
            return False
        self.current_project_path = Path(path)
        self._add_to_recent_projects(self.current_project_path)
        return self._save_project_to_path(self.current_project_path)

    def _save_project_to_path(self, path: Path) -> bool:
        try:
            data = self.project.to_dict()
            data["transmit_config"] = self.transmit_panel.get_config()
            with open(path, "w") as f:
                json.dump(data, f, indent=4)
            self._set_dirty(False)
            self.statusBar().showMessage(f"Project saved to {path.name}")
            return True
        except Exception as e:
            QMessageBox.critical(
                self, "Project Save Error", f"Failed to save project: {e}"
            )
            return False
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
        settings.setValue("dockState", self.dock_manager.saveState())
        self.dock_manager.savePerspectives(settings)
        if self.current_project_path:
            settings.setValue("lastProjectPath", str(self.current_project_path))

    def restore_layout(self):
        settings = QSettings()
        geometry = settings.value("geometry")
        state = settings.value("windowState")
        dock_state = settings.value("dockState")
        last_project = settings.value("lastProjectPath")
        if geometry:
            self.restoreGeometry(geometry)
        if state:
            self.restoreState(state)
        if dock_state:
            self.dock_manager.restoreState(dock_state)
        if last_project and Path(last_project).exists():
            self._open_project(last_project)
        self.dock_manager.loadPerspectives(settings)

    def _on_project_structure_changed(self):
        """Handle project structure changes that might affect PDO databases"""
        # This is called when the project structure changes
        # We could be more selective about cache invalidation here
        pass

    def closeEvent(self, event):
        if not self._prompt_save_if_dirty():
            event.ignore()
            return

        self.frame_processor.shutdown()

        self.save_layout()
        self.disconnect_can()
        QApplication.processEvents()
        event.accept()

    def get_current_executable(self):
        """Get the current executable path for launching new instances"""
        if getattr(sys, "frozen", False):
            # Running as Nuitka/PyInstaller executable
            return [sys.executable]
        else:
            # Development mode - try different approaches
            if __name__ == "__main__":
                # Running as script directly
                return [sys.executable, sys.argv[0]]
            else:
                # Running as module
                return [sys.executable, "-m", "canpeek"]

    def launch_new_canpeek_instance(self, project_path=None):
        """Launch a completely independent CANPeek instance"""
        cmd = self.get_current_executable()

        # Validate project path if specified
        if project_path:
            if not Path(project_path).exists():
                QMessageBox.warning(
                    self,
                    "File Not Found",
                    f"Project file does not exist:\n{project_path}",
                )
                return None
            cmd.extend(["--project", project_path])

        # Platform-specific process creation
        kwargs = {
            "cwd": os.getcwd(),
        }

        # Add platform-specific flags for process isolation
        if os.name == "nt":  # Windows
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:  # Unix-like (Linux, macOS)
            kwargs["start_new_session"] = True

        try:
            # Launch the process
            process = subprocess.Popen(cmd, **kwargs)

            # Show success message
            if project_path:
                filename = Path(project_path).name
                message = f"Opened '{filename}' in new instance (PID: {process.pid})"
            else:
                message = f"Launched new CANPeek instance (PID: {process.pid})"

            self.statusBar().showMessage(message)
            print(f"Command executed: {' '.join(cmd)}")
            return process

        except FileNotFoundError:
            QMessageBox.critical(
                self,
                "Launch Error",
                f"Could not find executable. Command attempted:\n{' '.join(cmd)}\n\n"
                "Make sure CANPeek is properly installed or running from the correct directory.",
            )
            return None
        except Exception as e:
            QMessageBox.critical(
                self,
                "Launch Error",
                f"Failed to launch new CANPeek instance:\n{e}\n\n"
                f"Command attempted: {' '.join(cmd)}",
            )
            return None

    def launch_new_instance(self):
        """Launch new empty CANPeek instance"""
        self.launch_new_canpeek_instance()

    def open_in_new_instance(self):
        """Open project file dialog and launch in new instance"""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Project in New Instance",
            "",
            "CANPeek Project (*.cpeek);;All Files (*)",
        )
        if path:
            self.launch_new_canpeek_instance(path)


def main():
    import argparse

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="CANPeek - CAN Bus Analyzer")
    parser.add_argument("--project", type=str, help="Project file to open on startup")
    args = parser.parse_args()

    app = QApplication(sys.argv)

    # qt_themes.set_theme("catppuccin_mocha")

    event_loop = QEventLoop(app)
    asyncio.set_event_loop(event_loop)

    app_close_event = asyncio.Event()
    app.aboutToQuit.connect(app_close_event.set)

    app.setOrganizationName("CANPeek")
    app.setApplicationName("CANPeek")
    window = CANBusObserver()

    # Open project if specified via command line
    if args.project:
        window._open_project(args.project)

    window.show()

    with event_loop:
        event_loop.run_until_complete(app_close_event.wait())


if __name__ == "__main__":
    main()
