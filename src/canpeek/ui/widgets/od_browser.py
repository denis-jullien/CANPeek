"""
Object Dictionary Browser widget.

Combines a tree view of the OD with a details panel for viewing/editing entries.
"""

from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from canpeek.models.od_tree_model import ODTreeModel
from canpeek.protocols.canopen.object_dictionary import (
    ODEntry,
    ODIndex,
    ObjectDictionaryWrapper,
)
from canpeek.ui.widgets.od_details_panel import ODDetailsPanel


class ODBrowser(QWidget):
    """
    Object Dictionary browser widget.

    Displays an OD tree and details panel side-by-side.
    Emits signals for SDO read/write operations.
    """

    # Signals
    sdo_read_requested = Signal(int, int, int)  # node_id, index, subindex
    sdo_write_requested = Signal(int, int, int, bytes)  # node_id, index, subindex, data
    scan_requested = Signal(int)  # node_id - read all entries

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_node_id: Optional[int] = None
        self._current_od: Optional[ObjectDictionaryWrapper] = None
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Header with node selector and scan button
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(4, 4, 4, 4)

        self._node_label = QLabel("No node selected")
        self._node_label.setStyleSheet("font-weight: bold;")
        header_layout.addWidget(self._node_label)

        header_layout.addStretch()

        self._scan_btn = QPushButton("Scan All")
        self._scan_btn.setToolTip("Read all readable values from device")
        self._scan_btn.setEnabled(False)
        self._scan_btn.clicked.connect(self._on_scan_clicked)
        header_layout.addWidget(self._scan_btn)

        layout.addWidget(header)

        # Progress bar (hidden by default)
        self._progress = QProgressBar()
        self._progress.setVisible(False)
        layout.addWidget(self._progress)

        # Main content: splitter with tree and details
        splitter = QSplitter(Qt.Horizontal)

        # Left: Tree view
        self._tree = QTreeView()
        self._model = ODTreeModel()
        self._tree.setModel(self._model)
        self._tree.setAlternatingRowColors(True)
        self._tree.setSelectionMode(QTreeView.SingleSelection)
        self._tree.setExpandsOnDoubleClick(True)

        # Configure columns
        header_view = self._tree.header()
        header_view.setStretchLastSection(True)
        header_view.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Index
        header_view.setSectionResizeMode(1, QHeaderView.Stretch)  # Name
        header_view.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Type
        header_view.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Access

        splitter.addWidget(self._tree)

        # Right: Details panel
        self._details = ODDetailsPanel()
        splitter.addWidget(self._details)

        # Set initial splitter sizes (60% tree, 40% details)
        splitter.setSizes([400, 250])

        layout.addWidget(splitter)

        # Status bar
        self._status_label = QLabel()
        self._status_label.setStyleSheet("color: #666; padding: 2px;")
        layout.addWidget(self._status_label)

    def _connect_signals(self) -> None:
        """Connect internal signals."""
        # Tree selection -> details panel
        self._tree.selectionModel().currentChanged.connect(self._on_selection_changed)

        # Details panel read/write -> emit signals
        self._details.read_requested.connect(self._on_read_requested)
        self._details.write_requested.connect(self._on_write_requested)

    def set_node(self, node_id: int, od: ObjectDictionaryWrapper) -> None:
        """
        Display the OD for a node.

        Args:
            node_id: CANopen node ID
            od: Loaded ObjectDictionaryWrapper
        """
        self._current_node_id = node_id
        self._current_od = od

        self._node_label.setText(f"Node {node_id} - {od.path.name}")
        self._model.load_od(od)
        self._scan_btn.setEnabled(True)

        # Expand first few items
        for i in range(min(5, self._model.rowCount())):
            self._tree.expand(self._model.index(i, 0))

        self._update_status()

    def clear(self) -> None:
        """Clear the browser."""
        self._current_node_id = None
        self._current_od = None
        self._node_label.setText("No node selected")
        self._model.clear()
        self._details.clear()
        self._scan_btn.setEnabled(False)
        self._status_label.clear()

    def update_value(self, index: int, subindex: int, value, raw: bytes = None) -> None:
        """
        Update the displayed value for an entry.

        Called after a successful SDO read.
        """
        # Update in model
        self._model.update_value(index, subindex, value)

        # Update details panel if this entry is selected
        selected = self._tree.currentIndex()
        if selected.isValid():
            entry = self._model.get_entry(selected)
            if entry and entry.index == index and entry.subindex == subindex:
                raw_hex = raw.hex() if raw else ""
                self._details.set_value(str(value), raw_hex)

    def set_progress(self, current: int, total: int) -> None:
        """Update the progress bar during scan operations."""
        if total > 0:
            self._progress.setMaximum(total)
            self._progress.setValue(current)
            self._progress.setVisible(True)
        else:
            self._progress.setVisible(False)

    def show_status(self, message: str, is_error: bool = False) -> None:
        """Show a status message."""
        if is_error:
            self._status_label.setStyleSheet("color: #c00; padding: 2px;")
        else:
            self._status_label.setStyleSheet("color: #060; padding: 2px;")
        self._status_label.setText(message)

    def show_error(self, message: str) -> None:
        """Show an error message."""
        self.show_status(message, is_error=True)
        self._details.set_status(message, is_error=True)

    def _update_status(self) -> None:
        """Update the status bar with OD info."""
        if self._current_od:
            count = len(self._current_od.indices)
            self._status_label.setText(f"{count} objects loaded")
            self._status_label.setStyleSheet("color: #666; padding: 2px;")

    def _on_selection_changed(self, current, previous) -> None:
        """Handle tree selection change."""
        if not current.isValid():
            self._details.clear()
            return

        # Get the data from the model
        entry = self._model.get_entry(current)
        od_index = self._model.get_od_index(current)

        if entry:
            self._details.show_entry(entry)
        elif od_index:
            self._details.show_index(od_index)
        else:
            self._details.clear()

    def _on_read_requested(self) -> None:
        """Handle read request from details panel."""
        if self._current_node_id is None:
            return

        selected = self._tree.currentIndex()
        if not selected.isValid():
            return

        entry = self._model.get_entry(selected)
        if entry:
            self.sdo_read_requested.emit(
                self._current_node_id, entry.index, entry.subindex
            )

    def _on_write_requested(self) -> None:
        """Handle write request from details panel."""
        if self._current_node_id is None:
            return

        selected = self._tree.currentIndex()
        if not selected.isValid():
            return

        entry = self._model.get_entry(selected)
        if entry:
            # The actual data is passed through the signal from ODDetailsPanel
            pass

    def _on_scan_clicked(self) -> None:
        """Handle scan button click."""
        if self._current_node_id is not None:
            self.scan_requested.emit(self._current_node_id)

    @property
    def current_node_id(self) -> Optional[int]:
        """Get the current node ID."""
        return self._current_node_id

    @property
    def current_od(self) -> Optional[ObjectDictionaryWrapper]:
        """Get the current ObjectDictionary."""
        return self._current_od
