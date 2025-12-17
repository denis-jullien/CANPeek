"""
Grouped receive view widget.

Displays CAN messages grouped by ID with expandable signals,
similar to PCAN-Explorer's receive view.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont, QFontDatabase, QAction
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTreeView,
    QHeaderView,
    QComboBox,
    QLineEdit,
    QPushButton,
    QLabel,
    QCheckBox,
    QMenu,
    QToolBar,
    QStyle,
)

from canpeek.models.grouped_model import GroupedModel, GroupedColumn, MessageFilterProxyModel
from canpeek.core.types import CANFrame


class ReceiveView(QWidget):
    """
    Grouped receive view showing CAN messages by ID.

    Features:
        - Messages grouped by CAN ID
        - Expandable signals from DBC decoding
        - Real-time updates with cycle time
        - Filtering by ID, bus, or pattern
        - Column sorting
        - Context menu for actions

    Signals:
        frame_selected: Emitted when a frame is selected
        message_double_clicked: Emitted when a message is double-clicked
    """

    frame_selected = Signal(object)  # CANFrame
    message_double_clicked = Signal(int, str)  # arbitration_id, bus_name

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)

        self._model = GroupedModel()
        self._proxy_model = MessageFilterProxyModel()
        self._proxy_model.setSourceModel(self._model)

        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Tree view (created first so toolbar can reference it)
        self._tree_view = QTreeView()
        self._tree_view.setModel(self._proxy_model)
        self._tree_view.setRootIsDecorated(True)
        self._tree_view.setAlternatingRowColors(True)
        self._tree_view.setSortingEnabled(True)
        self._tree_view.setSelectionBehavior(QTreeView.SelectRows)
        self._tree_view.setSelectionMode(QTreeView.SingleSelection)
        self._tree_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self._tree_view.setExpandsOnDoubleClick(True)

        # Set monospace font
        mono_font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        self._tree_view.setFont(mono_font)

        # Configure header
        header = self._tree_view.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(GroupedColumn.ID, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(GroupedColumn.BUS, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(GroupedColumn.SYMBOL, QHeaderView.Stretch)
        header.setSectionResizeMode(GroupedColumn.DLC, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(GroupedColumn.DATA, QHeaderView.Stretch)
        header.setSectionResizeMode(GroupedColumn.CYCLE, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(GroupedColumn.COUNT, QHeaderView.ResizeToContents)

        # Default sort by ID
        self._tree_view.sortByColumn(GroupedColumn.ID, Qt.AscendingOrder)

        # Toolbar (created after tree view so it can reference it)
        toolbar = self._create_toolbar()
        layout.addWidget(toolbar)
        layout.addWidget(self._tree_view)

        # Status bar
        status_layout = QHBoxLayout()
        status_layout.setContentsMargins(4, 2, 4, 2)

        self._message_count_label = QLabel("Messages: 0")
        status_layout.addWidget(self._message_count_label)

        status_layout.addStretch()

        self._update_rate_label = QLabel("0 msg/s")
        status_layout.addWidget(self._update_rate_label)

        layout.addLayout(status_layout)

    def _create_toolbar(self) -> QToolBar:
        """Create the toolbar."""
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFloatable(False)

        # Bus filter combo
        toolbar.addWidget(QLabel(" Bus: "))
        self._bus_combo = QComboBox()
        self._bus_combo.setMinimumWidth(100)
        self._bus_combo.addItem("All", None)
        self._bus_combo.currentIndexChanged.connect(self._on_bus_filter_changed)
        toolbar.addWidget(self._bus_combo)

        toolbar.addSeparator()

        # ID filter
        toolbar.addWidget(QLabel(" Filter: "))
        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("ID or name filter...")
        self._filter_edit.setMaximumWidth(200)
        self._filter_edit.textChanged.connect(self._on_filter_changed)
        toolbar.addWidget(self._filter_edit)

        # Clear filter button
        style = self.style()
        clear_action = QAction(
            style.standardIcon(QStyle.SP_LineEditClearButton),
            "Clear Filter",
            self
        )
        clear_action.triggered.connect(self._clear_filter)
        toolbar.addAction(clear_action)

        toolbar.addSeparator()

        # Expand/collapse buttons
        expand_action = QAction("Expand All", self)
        expand_action.triggered.connect(self._tree_view.expandAll)
        toolbar.addAction(expand_action)

        collapse_action = QAction("Collapse All", self)
        collapse_action.triggered.connect(self._tree_view.collapseAll)
        toolbar.addAction(collapse_action)

        toolbar.addSeparator()

        # Clear data button
        clear_data_action = QAction(
            style.standardIcon(QStyle.SP_TrashIcon),
            "Clear",
            self
        )
        clear_data_action.triggered.connect(self.clear)
        toolbar.addAction(clear_data_action)

        # Pause checkbox
        self._pause_checkbox = QCheckBox("Pause")
        self._pause_checkbox.setChecked(False)
        toolbar.addWidget(self._pause_checkbox)

        return toolbar

    def _connect_signals(self) -> None:
        """Connect internal signals."""
        self._tree_view.selectionModel().selectionChanged.connect(
            self._on_selection_changed
        )
        self._tree_view.doubleClicked.connect(self._on_double_clicked)
        self._tree_view.customContextMenuRequested.connect(
            self._show_context_menu
        )

    def set_decoder(self, decoder) -> None:
        """Set the DBC decoder for signal decoding."""
        self._model.set_decoder(decoder)

    def update_frames(self, frames: list[CANFrame]) -> None:
        """
        Update with new frames.

        This is the main method to add received frames.
        """
        if self._pause_checkbox.isChecked():
            return

        self._model.update_frames(frames)
        self._update_status()

        # Update bus filter combo if needed
        self._update_bus_combo(frames)

    def clear(self) -> None:
        """Clear all messages."""
        self._model.clear()
        self._update_status()

    def add_bus(self, bus_name: str, bus_id: int = 0) -> None:
        """Add a bus to the filter combo."""
        # Check if already exists
        for i in range(self._bus_combo.count()):
            if self._bus_combo.itemData(i) == bus_name:
                return

        self._bus_combo.addItem(bus_name, bus_name)

    def remove_bus(self, bus_name: str) -> None:
        """Remove a bus from the filter combo."""
        for i in range(self._bus_combo.count()):
            if self._bus_combo.itemData(i) == bus_name:
                self._bus_combo.removeItem(i)
                break

    def _update_status(self) -> None:
        """Update status labels."""
        count = self._model.message_count
        self._message_count_label.setText(f"Messages: {count}")

    def _update_bus_combo(self, frames: list[CANFrame]) -> None:
        """Update bus combo with new bus names."""
        existing_buses = set()
        for i in range(self._bus_combo.count()):
            data = self._bus_combo.itemData(i)
            if data is not None:
                existing_buses.add(data)

        for frame in frames:
            if frame.bus_name and frame.bus_name not in existing_buses:
                self._bus_combo.addItem(frame.bus_name, frame.bus_name)
                existing_buses.add(frame.bus_name)

    def _on_bus_filter_changed(self, index: int) -> None:
        """Handle bus filter change."""
        bus_name = self._bus_combo.currentData()
        self._proxy_model.set_bus_filter(bus_name)

    def _on_filter_changed(self, text: str) -> None:
        """Handle filter text change."""
        self._proxy_model.set_id_pattern(text)

    def _clear_filter(self) -> None:
        """Clear all filters."""
        self._filter_edit.clear()
        self._bus_combo.setCurrentIndex(0)

    def _on_selection_changed(self) -> None:
        """Handle selection change."""
        indexes = self._tree_view.selectionModel().selectedRows()
        if not indexes:
            return

        index = self._proxy_model.mapToSource(indexes[0])
        frame = self._model.get_frame(index.row())
        if frame:
            self.frame_selected.emit(frame)

    def _on_double_clicked(self, index) -> None:
        """Handle double click."""
        source_index = self._proxy_model.mapToSource(index)
        msg = self._model.get_message(source_index.row())
        if msg:
            self.message_double_clicked.emit(msg.arbitration_id, msg.bus_name)

    def _show_context_menu(self, pos) -> None:
        """Show context menu."""
        index = self._tree_view.indexAt(pos)
        if not index.isValid():
            return

        menu = QMenu(self)

        # Copy actions
        copy_id_action = menu.addAction("Copy ID")
        copy_data_action = menu.addAction("Copy Data")
        menu.addSeparator()

        # Add to transmit
        add_tx_action = menu.addAction("Add to Transmit Panel")
        menu.addSeparator()

        # Filter actions
        filter_action = menu.addAction("Filter by this ID")

        # Execute menu
        action = menu.exec(self._tree_view.viewport().mapToGlobal(pos))

        if action == copy_id_action:
            self._copy_id(index)
        elif action == copy_data_action:
            self._copy_data(index)
        elif action == filter_action:
            self._filter_by_id(index)

    def _copy_id(self, index) -> None:
        """Copy CAN ID to clipboard."""
        source_index = self._proxy_model.mapToSource(index)
        msg = self._model.get_message(source_index.row())
        if msg:
            from PySide6.QtWidgets import QApplication
            QApplication.clipboard().setText(f"0x{msg.arbitration_id:X}")

    def _copy_data(self, index) -> None:
        """Copy data to clipboard."""
        source_index = self._proxy_model.mapToSource(index)
        msg = self._model.get_message(source_index.row())
        if msg:
            from PySide6.QtWidgets import QApplication
            QApplication.clipboard().setText(msg.data.hex(' ').upper())

    def _filter_by_id(self, index) -> None:
        """Set filter to specific ID."""
        source_index = self._proxy_model.mapToSource(index)
        msg = self._model.get_message(source_index.row())
        if msg:
            self._filter_edit.setText(f"0x{msg.arbitration_id:X}")

    @property
    def model(self) -> GroupedModel:
        """Get the underlying model."""
        return self._model

    @property
    def is_paused(self) -> bool:
        """Check if view is paused."""
        return self._pause_checkbox.isChecked()

    def set_paused(self, paused: bool) -> None:
        """Set pause state."""
        self._pause_checkbox.setChecked(paused)
