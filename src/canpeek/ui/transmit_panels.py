from typing import Dict, List
from functools import partial
import enum
import uuid


from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QLabel,
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHeaderView,
    QMessageBox,
)

from PySide6.QtCore import (
    QTimer,
    Signal,
    Qt,
)


import can
import cantools


from canpeek.can_utils import CANMultiprocessReader


class TransmitViewColumn(enum.IntEnum):
    """Defines the columns for the TransmitPanel."""

    ON = 0
    ID = 1
    TYPE = 2
    RTR = 3
    DLC = 4
    DATA = 5
    CYCLE = 6
    SEND = 7
    SENT = 8


class TransmitPanel(QWidget):
    frame_to_send = Signal(object, object)  # message, connection_id (uuid.UUID)
    row_selection_changed = Signal(int, str, str)  # row, id_text, data_hex
    config_changed = Signal()

    def __init__(self):
        super().__init__()
        self.timers: Dict[int, QTimer] = {}
        self.dbcs: List[object] = []
        self.connections: Dict[str, CANMultiprocessReader] = {}
        self.setup_ui()

    def set_dbc_databases(self, dbs):
        self.dbcs = dbs

    def set_connections(self, connections: Dict[uuid.UUID, CANMultiprocessReader]):
        """Updates the connection list in the combo box, preserving selection."""
        self.connections = connections
        current_id = self.connection_combo.currentData()
        self.connection_combo.clear()

        if connections:
            sorted_connections = sorted(
                connections.values(), key=lambda r: r.connection.name
            )
            for reader in sorted_connections:
                self.connection_combo.addItem(
                    reader.connection.name, reader.connection.id
                )

            # Restore selection if possible
            if current_id and current_id in connections:
                index = self.connection_combo.findData(current_id)
                if index != -1:
                    self.connection_combo.setCurrentIndex(index)

            self.connection_combo.setEnabled(True)
        else:
            self.connection_combo.setEnabled(False)

    def get_message_from_id(self, can_id):
        for db_file in self.dbcs:
            try:
                return db_file.database.get_message_by_frame_id(can_id)
            except KeyError:
                continue

    def setup_ui(self):
        layout = QVBoxLayout(self)
        ctrl_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add")
        self.rem_btn = QPushButton("Remove")
        self.connection_combo = QComboBox()
        self.connection_combo.setEnabled(False)
        self.connection_combo.setToolTip("Select the connection for sending frames")

        ctrl_layout.addWidget(self.add_btn)
        ctrl_layout.addWidget(self.rem_btn)
        ctrl_layout.addStretch()
        ctrl_layout.addWidget(QLabel("Send on:"))
        ctrl_layout.addWidget(self.connection_combo)
        layout.addLayout(ctrl_layout)

        self.table = QTableWidget()
        self.table.setColumnCount(9)
        headers = [col.name.replace("_", " ").title() for col in TransmitViewColumn]
        headers[TransmitViewColumn.ID] = "ID(hex)"
        headers[TransmitViewColumn.DATA] = "Data(hex)"
        self.table.setHorizontalHeaderLabels(headers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.table)
        self.add_btn.clicked.connect(self.add_frame)
        self.rem_btn.clicked.connect(self.remove_frames)
        self.table.currentItemChanged.connect(self._on_item_changed)
        self.table.cellChanged.connect(self._on_cell_changed)

    def add_frame(self):
        r = self.table.rowCount()
        self.table.insertRow(r)
        self._setup_row_widgets(r)
        self.config_changed.emit()

    def add_message_frame(self, message: cantools.db.Message):
        """Adds a new row to the transmit table based on a DBC message definition."""
        r = self.table.rowCount()
        self.table.insertRow(r)
        self._setup_row_widgets(r)

        # Now, populate the new row with data from the message object
        self.table.blockSignals(True)

        # ID
        self.table.item(r, 1).setText(f"{message.frame_id:X}")

        # Type (Std/Ext)
        self.table.cellWidget(r, 2).setCurrentIndex(
            1 if message.is_extended_frame else 0
        )

        # DLC
        self.table.item(r, 4).setText(str(message.length))

        # Data (encode with defaults to get initial values)
        try:
            initial_data = message.encode({}, scaling=False, padding=True)
            self.table.item(r, 5).setText(initial_data.hex(" "))
        except Exception as e:
            print(f"Could not encode initial data for {message.name}: {e}")
            self.table.item(r, 5).setText("00 " * message.length)

        self.table.blockSignals(False)
        self.config_changed.emit()  # Mark project as dirty

    def remove_frames(self):
        if self.table.selectionModel().selectedRows():
            [
                self.table.removeRow(r)
                for r in sorted(
                    [i.row() for i in self.table.selectionModel().selectedRows()],
                    reverse=True,
                )
            ]
            self.config_changed.emit()

    def _setup_row_widgets(self, r):
        # ID
        self.table.setItem(r, TransmitViewColumn.ID, QTableWidgetItem("100"))

        # TYPE
        combo = QComboBox()
        combo.addItems(["Std", "Ext"])
        self.table.setCellWidget(r, TransmitViewColumn.TYPE, combo)
        combo.currentIndexChanged.connect(self.config_changed.emit)

        # RTR
        cb_rtr = QCheckBox()
        self.table.setCellWidget(r, TransmitViewColumn.RTR, self._center(cb_rtr))
        cb_rtr.toggled.connect(self.config_changed.emit)

        # DLC
        self.table.setItem(r, TransmitViewColumn.DLC, QTableWidgetItem("0"))

        # DATA
        self.table.setItem(r, TransmitViewColumn.DATA, QTableWidgetItem(""))

        # CYCLE
        self.table.setItem(r, TransmitViewColumn.CYCLE, QTableWidgetItem("100"))

        # SEND
        btn = QPushButton("Send")
        btn.clicked.connect(partial(self.send_from_row, r))
        self.table.setCellWidget(r, TransmitViewColumn.SEND, btn)

        # SENT
        sent_item = QTableWidgetItem("0")
        sent_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        self.table.setItem(r, TransmitViewColumn.SENT, sent_item)

        # ON
        cb_on = QCheckBox()
        cb_on.toggled.connect(partial(self._toggle_periodic, r))
        self.table.setCellWidget(r, TransmitViewColumn.ON, self._center(cb_on))

    def _center(self, w):
        c = QWidget()
        layout = QHBoxLayout(c)
        layout.addWidget(w)
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(0, 0, 0, 0)
        return c

    def _on_item_changed(self, curr, prev):
        if curr and (not prev or curr.row() != prev.row()):
            row = curr.row()
            id_text = self.table.item(row, TransmitViewColumn.ID).text()
            data_item = self.table.item(row, TransmitViewColumn.DATA)
            data_hex = data_item.text() if data_item else ""
            self.row_selection_changed.emit(row, id_text, data_hex)

    def _on_cell_changed(self, r, c):
        self.config_changed.emit()
        if c == TransmitViewColumn.ID or c == TransmitViewColumn.DATA:
            id_text = self.table.item(r, TransmitViewColumn.ID).text()
            data_item = self.table.item(r, TransmitViewColumn.DATA)
            data_hex = data_item.text() if data_item else ""
            self.row_selection_changed.emit(r, id_text, data_hex)
        elif c == TransmitViewColumn.DATA:
            self._update_dlc(r)

    def _update_dlc(self, r):
        try:
            data_len = len(
                bytes.fromhex(
                    self.table.item(r, TransmitViewColumn.DATA).text().replace(" ", "")
                )
            )
            self.table.item(r, TransmitViewColumn.DLC).setText(str(data_len))
        except (ValueError, TypeError):
            pass

    def update_row_data(self, r, data):
        self.table.blockSignals(True)
        self.table.item(r, TransmitViewColumn.DATA).setText(data.hex(" "))
        self.table.item(r, TransmitViewColumn.DLC).setText(str(len(data)))
        self.table.blockSignals(False)
        self.config_changed.emit()

    def _toggle_periodic(self, r, state):
        self.config_changed.emit()
        if state:
            try:
                cycle = int(self.table.item(r, TransmitViewColumn.CYCLE).text())
                t = QTimer(self)
                t.timeout.connect(partial(self.send_from_row, r))
                t.start(cycle)
                self.timers[r] = t
            except (ValueError, TypeError):
                QMessageBox.warning(self, "Bad Cycle", f"Row {r + 1}: bad cycle time.")
                self.table.cellWidget(r, TransmitViewColumn.ON).findChild(
                    QCheckBox
                ).setChecked(False)
        elif r in self.timers:
            self.timers.pop(r).stop()

    def stop_all_timers(self):
        [t.stop() for t in self.timers.values()]
        self.timers.clear()
        [
            self.table.cellWidget(r, 0).findChild(QCheckBox).setChecked(False)
            for r in range(self.table.rowCount())
        ]

    def send_from_row(self, r):
        connection_id = self.connection_combo.currentData()
        if not connection_id:
            QMessageBox.warning(
                self, "No Connection", "Please select a connection to send from."
            )
            return
        try:
            message_to_send = can.Message(
                arbitration_id=int(
                    self.table.item(r, TransmitViewColumn.ID).text(), 16
                ),
                is_extended_id=self.table.cellWidget(
                    r, TransmitViewColumn.TYPE
                ).currentIndex()
                == 1,
                is_remote_frame=self.table.cellWidget(r, TransmitViewColumn.RTR)
                .findChild(QCheckBox)
                .isChecked(),
                dlc=int(self.table.item(r, TransmitViewColumn.DLC).text()),
                data=bytes.fromhex(
                    self.table.item(r, TransmitViewColumn.DATA).text().replace(" ", "")
                ),
            )
            self.frame_to_send.emit(message_to_send, connection_id)

            sent_item = self.table.item(r, TransmitViewColumn.SENT)
            current_count = int(sent_item.text())
            sent_item.setText(str(current_count + 1))

        except (ValueError, TypeError) as e:
            QMessageBox.warning(self, "Bad Tx Data", f"Row {r + 1}: {e}")
            self._toggle_periodic(r, False)

    def send_selected(self):
        [
            self.send_from_row(r)
            for r in sorted(
                {i.row() for i in self.table.selectionModel().selectedIndexes()}
            )
        ]

    def get_config(self) -> List[Dict]:
        return [
            {
                "on": self.table.cellWidget(r, TransmitViewColumn.ON)
                .findChild(QCheckBox)
                .isChecked(),
                "id": self.table.item(r, TransmitViewColumn.ID).text(),
                "type_idx": self.table.cellWidget(
                    r, TransmitViewColumn.TYPE
                ).currentIndex(),
                "rtr": self.table.cellWidget(r, TransmitViewColumn.RTR)
                .findChild(QCheckBox)
                .isChecked(),
                "dlc": self.table.item(r, TransmitViewColumn.DLC).text(),
                "data": self.table.item(r, TransmitViewColumn.DATA).text(),
                "cycle": self.table.item(r, TransmitViewColumn.CYCLE).text(),
            }
            for r in range(self.table.rowCount())
        ]

    def set_config(self, config: List[Dict]):
        self.stop_all_timers()
        self.table.clearContents()
        self.table.setRowCount(0)
        self.table.setRowCount(len(config))
        self.table.blockSignals(True)
        for r, row_data in enumerate(config):
            self._setup_row_widgets(r)
            self.table.cellWidget(r, TransmitViewColumn.ON).findChild(
                QCheckBox
            ).setChecked(row_data.get("on", False))
            self.table.item(r, TransmitViewColumn.ID).setText(row_data.get("id", "0"))
            self.table.cellWidget(r, TransmitViewColumn.TYPE).setCurrentIndex(
                row_data.get("type_idx", 0)
            )
            self.table.cellWidget(r, TransmitViewColumn.RTR).findChild(
                QCheckBox
            ).setChecked(row_data.get("rtr", False))
            self.table.item(r, TransmitViewColumn.DLC).setText(row_data.get("dlc", "0"))
            self.table.item(r, TransmitViewColumn.DATA).setText(
                row_data.get("data", "")
            )
            self.table.item(r, TransmitViewColumn.CYCLE).setText(
                row_data.get("cycle", "100")
            )
        self.table.blockSignals(False)
        self.config_changed.emit()


class SignalTransmitPanel(QGroupBox):
    data_encoded = Signal(bytes)

    def __init__(self):
        super().__init__("Signal Config")
        self.message = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ["Signal", "Value", "Unit", "Min", "Max", "Status"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)
        self.table.cellChanged.connect(self._validate_and_encode)

    def clear_panel(self):
        self.message = None
        self.table.setRowCount(0)
        self.setTitle("Signal Config")
        self.setVisible(False)

    def _set_status(self, row: int, text: str, is_error: bool):
        """Helper to set the text and color of a status cell."""
        status_item = QTableWidgetItem(text)
        if is_error:
            status_item.setForeground(Qt.red)
            status_item.setToolTip(text)
        else:
            status_item.setForeground(Qt.green)

        status_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        self.table.setItem(row, 5, status_item)

    def populate(self, msg, data_hex: str):
        self.message = msg
        initial_values = {}

        # Try to decode the existing data to pre-fill the values
        if data_hex:
            try:
                data_bytes = bytes.fromhex(data_hex.replace(" ", ""))
                # Use allow_truncated=True to handle cases where data is shorter than expected
                initial_values = msg.decode(
                    data_bytes, decode_choices=False, allow_truncated=True
                )
            except (ValueError, KeyError) as e:
                print(f"Could not decode existing data for signal panel: {e}")
                initial_values = {}  # Fallback to defaults on error

        self.table.blockSignals(True)
        self.table.setRowCount(len(msg.signals))

        for r, s in enumerate(msg.signals):
            # Use the decoded value if available, otherwise use the signal's default initial value
            value = initial_values.get(
                s.name, s.initial if s.initial is not None else 0
            )

            self.table.setItem(r, 0, QTableWidgetItem(s.name))
            self.table.item(r, 0).setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)

            self.table.setItem(r, 1, QTableWidgetItem(str(value)))

            self.table.setItem(r, 2, QTableWidgetItem(str(s.unit or "")))
            self.table.item(r, 2).setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)

            # --- Min (Col 3) - NEW ---
            min_val = s.minimum if s.minimum is not None else "N/A"
            min_item = QTableWidgetItem(str(min_val))
            min_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            min_item.setToolTip(f"Minimum allowed value for {s.name}")
            self.table.setItem(r, 3, min_item)

            # --- Max (Col 4) - NEW ---
            max_val = s.maximum if s.maximum is not None else "N/A"
            max_item = QTableWidgetItem(str(max_val))
            max_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            max_item.setToolTip(f"Maximum allowed value for {s.name}")
            self.table.setItem(r, 4, max_item)

            self.table.setItem(r, 5, QTableWidgetItem(""))

        self.table.blockSignals(False)
        self.setTitle(f"Signal Config: {msg.name}")
        self.setVisible(True)
        # Trigger an initial encode to ensure the data field is up-to-date,
        # especially if we fell back to default values.
        self._validate_and_encode()

    def _validate_and_encode(self):
        """
        Validates the signal values against the DBC, updates the status column
        with any errors, and emits the encoded data if successful.
        """
        if not self.message:
            return

        # --- 1. Build the data dictionary from the table ---
        data_dict = {}
        parse_errors = False

        # We don't need to block signals here as we are just reading
        for r in range(self.table.rowCount()):
            signal_name = self.table.item(r, 0).text()
            value_text = self.table.item(r, 1).text()
            try:
                data_dict[signal_name] = float(value_text)
            except (ValueError, TypeError):
                parse_errors = True
                # We will set the status message for this *after* reading all values

        # --- Temporarily block signals to prevent recursion when updating status ---
        self.table.blockSignals(True)

        # Update status based on initial parsing
        for r in range(self.table.rowCount()):
            signal_name = self.table.item(r, 0).text()
            if signal_name not in data_dict:
                self._set_status(r, "Invalid number", is_error=True)
            else:
                self._set_status(r, "", is_error=False)  # Clear previous parse errors

        self.table.blockSignals(False)
        # --------------------------------------------------------------------------

        if parse_errors:
            return

        # --- 2. Attempt to encode and handle validation errors ---
        try:
            encoded_data = self.message.encode(data_dict, strict=True)

            # Block signals again for the success case
            self.table.blockSignals(True)
            for r in range(self.table.rowCount()):
                self._set_status(r, "OK", is_error=False)
            self.table.blockSignals(False)

            self.data_encoded.emit(encoded_data)

        except (cantools.database.errors.EncodeError, ValueError, KeyError) as e:
            error_str = str(e)

            # Block signals while we update rows with error messages
            self.table.blockSignals(True)
            found_error_signal = False
            for r in range(self.table.rowCount()):
                signal_name = self.table.item(r, 0).text()
                if f'"{signal_name}"' in error_str:
                    self._set_status(r, error_str, is_error=True)
                    found_error_signal = True
                else:
                    self._set_status(r, "OK", is_error=False)

            if not found_error_signal:
                self._set_status(0, error_str, is_error=True)

            self.table.blockSignals(False)
