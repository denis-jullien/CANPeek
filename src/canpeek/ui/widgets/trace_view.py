"""
Trace view widget for displaying raw CAN frames.

Shows all CAN frames in chronological order with
timestamp, ID, data, and decoded information.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableView,
    QHeaderView,
    QCheckBox,
    QLabel,
    QPushButton,
    QToolBar,
    QStyle,
    QLineEdit,
    QComboBox,
)
from PySide6.QtGui import QAction

from canpeek.models.trace_model import TraceModel, TraceColumn, TraceFilterProxyModel
from canpeek.core.types import CANFrame


class TraceView(QWidget):
    """
    Trace view showing all CAN frames chronologically.

    Features:
        - High-performance virtual scrolling
        - Autoscroll to latest frames
        - Configurable maximum frame count
        - Timestamp display modes
        - Column sorting

    Signals:
        frame_selected: Emitted when a frame is selected
    """

    frame_selected = Signal(object)  # CANFrame

    def __init__(
        self,
        max_frames: int = 50_000,
        parent: Optional[QWidget] = None
    ):
        super().__init__(parent)

        self._model = TraceModel(max_frames=max_frames)
        self._proxy_model = TraceFilterProxyModel()
        self._proxy_model.setSourceModel(self._model)
        self._autoscroll = True

        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Toolbar
        toolbar = self._create_toolbar()
        layout.addWidget(toolbar)

        # Table view
        self._table_view = QTableView()
        self._table_view.setModel(self._proxy_model)
        self._table_view.setAlternatingRowColors(True)
        self._table_view.setSelectionBehavior(QTableView.SelectRows)
        self._table_view.setSelectionMode(QTableView.SingleSelection)
        self._table_view.verticalHeader().setVisible(False)

        # Set monospace font
        mono_font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        self._table_view.setFont(mono_font)

        # Configure header
        header = self._table_view.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(TraceColumn.INDEX, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(TraceColumn.TIMESTAMP, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(TraceColumn.BUS, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(TraceColumn.DIRECTION, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(TraceColumn.ID, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(TraceColumn.TYPE, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(TraceColumn.DLC, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(TraceColumn.DATA, QHeaderView.Interactive)
        header.setSectionResizeMode(TraceColumn.DECODED, QHeaderView.Stretch)

        # Set initial column widths
        self._table_view.setColumnWidth(TraceColumn.DATA, 200)

        layout.addWidget(self._table_view)

        # Bottom controls
        controls_layout = QHBoxLayout()
        controls_layout.setContentsMargins(4, 2, 4, 2)

        self._frame_count_label = QLabel("Frames: 0 / 50000")
        controls_layout.addWidget(self._frame_count_label)

        controls_layout.addStretch()

        self._autoscroll_checkbox = QCheckBox("Autoscroll")
        self._autoscroll_checkbox.setChecked(True)
        self._autoscroll_checkbox.toggled.connect(self._on_autoscroll_toggled)
        controls_layout.addWidget(self._autoscroll_checkbox)

        self._pause_checkbox = QCheckBox("Pause")
        self._pause_checkbox.setChecked(False)
        controls_layout.addWidget(self._pause_checkbox)

        layout.addLayout(controls_layout)

    def _create_toolbar(self) -> QToolBar:
        """Create the toolbar."""
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFloatable(False)

        style = self.style()

        # Clear button
        clear_action = QAction(
            style.standardIcon(QStyle.SP_TrashIcon),
            "Clear",
            self
        )
        clear_action.triggered.connect(self.clear)
        toolbar.addAction(clear_action)

        toolbar.addSeparator()

        # Bus filter
        toolbar.addWidget(QLabel(" Bus: "))
        self._bus_combo = QComboBox()
        self._bus_combo.setMinimumWidth(80)
        self._bus_combo.addItem("All", None)
        self._bus_combo.currentIndexChanged.connect(self._on_bus_filter_changed)
        toolbar.addWidget(self._bus_combo)

        # Direction filter
        toolbar.addWidget(QLabel(" Dir: "))
        self._direction_combo = QComboBox()
        self._direction_combo.setMinimumWidth(60)
        self._direction_combo.addItem("All", None)
        self._direction_combo.addItem("RX", True)
        self._direction_combo.addItem("TX", False)
        self._direction_combo.currentIndexChanged.connect(self._on_direction_filter_changed)
        toolbar.addWidget(self._direction_combo)

        # ID filter
        toolbar.addWidget(QLabel(" ID: "))
        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("0x...")
        self._filter_edit.setMaximumWidth(100)
        self._filter_edit.textChanged.connect(self._on_id_filter_changed)
        toolbar.addWidget(self._filter_edit)

        # Clear filter button
        clear_filter_action = QAction(
            style.standardIcon(QStyle.SP_LineEditClearButton),
            "Clear Filter",
            self
        )
        clear_filter_action.triggered.connect(self._clear_filter)
        toolbar.addAction(clear_filter_action)

        toolbar.addSeparator()

        # Time display mode
        toolbar.addWidget(QLabel(" Time: "))
        self._relative_time_checkbox = QCheckBox("Relative")
        self._relative_time_checkbox.setChecked(True)
        self._relative_time_checkbox.toggled.connect(self._on_time_mode_changed)
        toolbar.addWidget(self._relative_time_checkbox)

        toolbar.addSeparator()

        # Scroll to top/bottom
        scroll_top_action = QAction("Scroll to Top", self)
        scroll_top_action.triggered.connect(
            lambda: self._table_view.scrollToTop()
        )
        toolbar.addAction(scroll_top_action)

        scroll_bottom_action = QAction("Scroll to Bottom", self)
        scroll_bottom_action.triggered.connect(
            lambda: self._table_view.scrollToBottom()
        )
        toolbar.addAction(scroll_bottom_action)

        return toolbar

    def _connect_signals(self) -> None:
        """Connect internal signals."""
        self._table_view.selectionModel().selectionChanged.connect(
            self._on_selection_changed
        )

    def set_decoder(self, decoder) -> None:
        """Set the DBC decoder for signal decoding."""
        self._model.set_decoder(decoder)

    def add_frame(self, frame: CANFrame) -> None:
        """Add a single frame."""
        if self._pause_checkbox.isChecked():
            return

        self._model.add_frame(frame)
        self._update_status()
        self._maybe_autoscroll()

    def add_frames(self, frames: list[CANFrame]) -> None:
        """Add multiple frames."""
        if self._pause_checkbox.isChecked():
            return

        self._model.add_frames(frames)
        self._update_status()
        self._update_bus_combo(frames)
        self._maybe_autoscroll()

    def clear(self) -> None:
        """Clear all frames."""
        self._model.clear()
        self._update_status()

    def set_frames(self, frames: list[CANFrame]) -> None:
        """Replace all frames (for loading traces)."""
        self._model.set_frames(frames)
        self._update_status()

    def _update_status(self) -> None:
        """Update status labels."""
        count = self._model.frame_count
        max_count = self._model.max_frames
        self._frame_count_label.setText(f"Frames: {count} / {max_count}")

    def _maybe_autoscroll(self) -> None:
        """Scroll to bottom if autoscroll is enabled."""
        if self._autoscroll and not self._pause_checkbox.isChecked():
            self._table_view.scrollToBottom()

    def _on_autoscroll_toggled(self, checked: bool) -> None:
        """Handle autoscroll toggle."""
        self._autoscroll = checked
        if checked:
            self._table_view.scrollToBottom()

    def _on_time_mode_changed(self, relative: bool) -> None:
        """Handle time display mode change."""
        self._model.set_relative_time(relative)

    def _on_bus_filter_changed(self, index: int) -> None:
        """Handle bus filter change."""
        bus_name = self._bus_combo.currentData()
        self._proxy_model.set_bus_filter(bus_name)

    def _on_direction_filter_changed(self, index: int) -> None:
        """Handle direction filter change."""
        direction = self._direction_combo.currentData()
        self._proxy_model.set_direction_filter(direction)

    def _on_id_filter_changed(self, text: str) -> None:
        """Handle ID filter text change."""
        self._proxy_model.set_id_pattern(text)

    def _clear_filter(self) -> None:
        """Clear all filters."""
        self._filter_edit.clear()
        self._bus_combo.setCurrentIndex(0)
        self._direction_combo.setCurrentIndex(0)

    def _on_selection_changed(self) -> None:
        """Handle selection change."""
        indexes = self._table_view.selectionModel().selectedRows()
        if not indexes:
            return

        source_index = self._proxy_model.mapToSource(indexes[0])
        frame = self._model.get_frame(source_index.row())
        if frame:
            self.frame_selected.emit(frame)

    def add_bus(self, bus_name: str) -> None:
        """Add a bus to the filter combo."""
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

    @property
    def model(self) -> TraceModel:
        """Get the underlying model."""
        return self._model

    @property
    def is_paused(self) -> bool:
        """Check if view is paused."""
        return self._pause_checkbox.isChecked()

    def set_paused(self, paused: bool) -> None:
        """Set pause state."""
        self._pause_checkbox.setChecked(paused)

    def get_all_frames(self) -> list[CANFrame]:
        """Get all frames for saving."""
        return self._model.get_all_frames()
