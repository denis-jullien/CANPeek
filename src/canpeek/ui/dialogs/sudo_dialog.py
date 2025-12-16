"""
Sudo authentication dialog.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QCheckBox,
)
from PySide6.QtGui import QIcon


class SudoDialog(QDialog):
    """
    Dialog to request sudo password for privileged operations.

    Used when CANPeek needs to perform operations that require
    root privileges, such as:
    - Bringing CAN interfaces up/down
    - Configuring interface bitrate
    - Creating virtual CAN interfaces
    """

    def __init__(
        self,
        parent=None,
        operation: str = "perform this operation",
        remember: bool = True,
    ):
        """
        Initialize the dialog.

        Args:
            parent: Parent widget
            operation: Description of the operation requiring sudo
            remember: Whether to show "remember" checkbox
        """
        super().__init__(parent)

        self.setWindowTitle("Authentication Required")
        self.setModal(True)
        self.setMinimumWidth(400)
        self.setWindowFlags(
            self.windowFlags() & ~Qt.WindowContextHelpButtonHint
        )

        self._password: Optional[str] = None
        self._remember = False

        self._setup_ui(operation, remember)

    def _setup_ui(self, operation: str, show_remember: bool) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Icon and info
        info_layout = QHBoxLayout()

        # Lock icon
        icon_label = QLabel()
        icon_label.setPixmap(
            self.style().standardIcon(
                self.style().SP_MessageBoxWarning
            ).pixmap(48, 48)
        )
        info_layout.addWidget(icon_label)

        # Info text
        info_text = QLabel(
            f"<b>Administrator privileges required</b><br><br>"
            f"CANPeek needs elevated privileges to {operation}.<br><br>"
            f"Please enter your password to continue:"
        )
        info_text.setWordWrap(True)
        info_layout.addWidget(info_text, 1)

        layout.addLayout(info_layout)

        # Password field
        self._password_edit = QLineEdit()
        self._password_edit.setEchoMode(QLineEdit.Password)
        self._password_edit.setPlaceholderText("Password")
        self._password_edit.returnPressed.connect(self._on_ok)
        layout.addWidget(self._password_edit)

        # Remember checkbox
        if show_remember:
            self._remember_checkbox = QCheckBox(
                "Remember for this session"
            )
            self._remember_checkbox.setChecked(True)
            layout.addWidget(self._remember_checkbox)
        else:
            self._remember_checkbox = None

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)

        ok_btn = QPushButton("Authenticate")
        ok_btn.setDefault(True)
        ok_btn.clicked.connect(self._on_ok)
        button_layout.addWidget(ok_btn)

        layout.addLayout(button_layout)

        # Focus password field
        self._password_edit.setFocus()

    def _on_ok(self) -> None:
        """Handle OK button click."""
        self._password = self._password_edit.text()
        self._remember = (
            self._remember_checkbox.isChecked()
            if self._remember_checkbox else False
        )
        self.accept()

    def get_password(self) -> Optional[str]:
        """
        Show dialog and return password.

        Returns:
            Password if dialog accepted, None otherwise
        """
        if self.exec() == QDialog.Accepted:
            return self._password
        return None

    @property
    def remember(self) -> bool:
        """Whether to remember the password."""
        return self._remember

    @classmethod
    def request_password(
        cls,
        parent=None,
        operation: str = "perform this operation",
    ) -> Optional[str]:
        """
        Convenience method to show dialog and get password.

        Args:
            parent: Parent widget
            operation: Description of the operation

        Returns:
            Password if provided, None if cancelled
        """
        dialog = cls(parent, operation)
        return dialog.get_password()
