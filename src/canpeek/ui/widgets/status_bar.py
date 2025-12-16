"""
Custom status bar with bus state indicators.
"""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QStatusBar,
    QLabel,
    QWidget,
    QHBoxLayout,
)
from PySide6.QtGui import QColor

from canpeek.core.types import BusState


class BusStateWidget(QWidget):
    """Widget showing bus state with colored indicator."""

    STATE_COLORS = {
        BusState.UNKNOWN: "#888888",
        BusState.ERROR_ACTIVE: "#4CAF50",  # Green
        BusState.ERROR_WARNING: "#FFC107",  # Amber
        BusState.ERROR_PASSIVE: "#FF9800",  # Orange
        BusState.BUS_OFF: "#F44336",        # Red
        BusState.STOPPED: "#888888",        # Gray
        BusState.SLEEPING: "#9C27B0",       # Purple
    }

    def __init__(self, name: str, parent: Optional[QWidget] = None):
        super().__init__(parent)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 0, 4, 0)
        layout.setSpacing(4)

        # State indicator (colored circle)
        self._indicator = QLabel("\u25CF")  # Filled circle
        self._indicator.setStyleSheet(f"color: {self.STATE_COLORS[BusState.UNKNOWN]};")
        layout.addWidget(self._indicator)

        # Bus name
        self._name_label = QLabel(name)
        layout.addWidget(self._name_label)

        # State text
        self._state_label = QLabel("")
        self._state_label.setStyleSheet("color: #888888;")
        layout.addWidget(self._state_label)

        self._state = BusState.UNKNOWN

    def set_state(self, state: BusState) -> None:
        """Update the bus state."""
        self._state = state
        color = self.STATE_COLORS.get(state, "#888888")
        self._indicator.setStyleSheet(f"color: {color}; font-size: 12px;")

        state_text = state.name.replace("_", " ").title()
        self._state_label.setText(f"({state_text})")

    def set_name(self, name: str) -> None:
        """Update the bus name."""
        self._name_label.setText(name)


class StatusBar(QStatusBar):
    """
    Enhanced status bar with bus state indicators.

    Shows:
        - Connection states for each bus
        - Total frame count
        - Current message rate
        - Error count
    """

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)

        self._bus_widgets: dict[UUID, BusStateWidget] = {}

        # Create permanent widgets

        # Bus states container
        self._bus_container = QWidget()
        self._bus_layout = QHBoxLayout(self._bus_container)
        self._bus_layout.setContentsMargins(0, 0, 0, 0)
        self._bus_layout.setSpacing(8)
        self.addPermanentWidget(self._bus_container)

        # Separator
        separator = QLabel("|")
        separator.setStyleSheet("color: #555555;")
        self.addPermanentWidget(separator)

        # Frame count
        self._frame_count_label = QLabel("Frames: 0")
        self.addPermanentWidget(self._frame_count_label)

        # Message rate
        self._rate_label = QLabel("0 msg/s")
        self.addPermanentWidget(self._rate_label)

        # Error count
        self._error_label = QLabel("Errors: 0")
        self._error_label.setStyleSheet("color: #F44336;")
        self._error_label.setVisible(False)
        self.addPermanentWidget(self._error_label)

        # Initial message
        self.showMessage("Ready")

    def add_bus(self, connection_id: UUID, name: str) -> None:
        """Add a bus state indicator."""
        if connection_id not in self._bus_widgets:
            widget = BusStateWidget(name)
            self._bus_widgets[connection_id] = widget
            self._bus_layout.addWidget(widget)

    def remove_bus(self, connection_id: UUID) -> None:
        """Remove a bus state indicator."""
        if connection_id in self._bus_widgets:
            widget = self._bus_widgets.pop(connection_id)
            self._bus_layout.removeWidget(widget)
            widget.deleteLater()

    def update_bus_state(self, connection_id: UUID, state: BusState) -> None:
        """Update the state of a bus."""
        if connection_id in self._bus_widgets:
            self._bus_widgets[connection_id].set_state(state)

    def update_bus_name(self, connection_id: UUID, name: str) -> None:
        """Update the name of a bus."""
        if connection_id in self._bus_widgets:
            self._bus_widgets[connection_id].set_name(name)

    def set_frame_count(self, count: int) -> None:
        """Update the frame count display."""
        self._frame_count_label.setText(f"Frames: {count:,}")

    def set_message_rate(self, rate: float) -> None:
        """Update the message rate display."""
        if rate < 1000:
            self._rate_label.setText(f"{rate:.0f} msg/s")
        else:
            self._rate_label.setText(f"{rate/1000:.1f}k msg/s")

    def set_error_count(self, count: int) -> None:
        """Update the error count display."""
        self._error_label.setText(f"Errors: {count}")
        self._error_label.setVisible(count > 0)

    def clear_buses(self) -> None:
        """Remove all bus indicators."""
        for connection_id in list(self._bus_widgets.keys()):
            self.remove_bus(connection_id)
