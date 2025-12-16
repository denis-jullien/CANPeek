#!/usr/bin/env python3
"""
CANPeek v2 - High-Performance CAN/CAN FD Bus Analyzer

Entry point for the application.
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    """Main entry point."""
    # Wayland workaround for Qt-Advanced-Docking
    if os.environ.get("XDG_SESSION_TYPE") == "wayland":
        os.environ["QT_QPA_PLATFORM"] = "xcb"

    # Import Qt after environment setup
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import QCoreApplication

    # Set application metadata
    QCoreApplication.setOrganizationName("CANPeek")
    QCoreApplication.setApplicationName("CANPeek")
    QCoreApplication.setApplicationVersion("2.0.0-dev")

    # Create application
    app = QApplication(sys.argv)

    # Import and create main window
    from canpeek.ui.main_window import MainWindow

    window = MainWindow()
    window.show()

    # Run event loop
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
