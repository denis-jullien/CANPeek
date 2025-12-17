"""
Reusable UI widgets for CANPeek.
"""

from canpeek.ui.widgets.receive_view import ReceiveView
from canpeek.ui.widgets.trace_view import TraceView
from canpeek.ui.widgets.project_tree import ProjectTree
from canpeek.ui.widgets.status_bar import StatusBar
from canpeek.ui.widgets.transmit_panel import TransmitPanel
from canpeek.ui.widgets.properties_panel import PropertiesPanel

__all__ = [
    "ReceiveView",
    "TraceView",
    "ProjectTree",
    "StatusBar",
    "TransmitPanel",
    "PropertiesPanel",
]
