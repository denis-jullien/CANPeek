# tests/test_main.py

import sys

# import json
import pytest
from pathlib import Path
# from unittest.mock import MagicMock, patch

# Make the app's code importable
# We'll import it as 'canpeek_app' to avoid confusion with the __main__ block
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.canpeek import __main__ as canpeek_app

from PySide6.QtCore import Qt  # , QTimer
# from PySide6.QtWidgets import QCheckBox, QLineEdit, QPushButton

# --- Fixtures ---


@pytest.fixture
def sample_can_frame():
    """Provides a standard CANFrame for tests."""
    return canpeek_app.CANFrame(
        timestamp=12345.678, arbitration_id=0x123, data=b"\x11\x22\x33\x44", dlc=4
    )


@pytest.fixture
def sample_dbc_content():
    """Returns a string representing a minimal, valid DBC file."""
    return """
VERSION ""
BO_ 257 MSG_STATUS: 8 Vector__XXX
 SG_ Sig1 : 0|8@1+ (1,0) [0|255] "" Vector__XXX
 SG_ Sig2 : 8|16@1+ (1,0) [0|0] "" Vector__XXX
"""


@pytest.fixture
def sample_project(tmp_path, sample_dbc_content):
    """Creates a sample Project with a temporary DBC file."""
    dbc_path = tmp_path / "test.dbc"
    dbc_path.write_text(sample_dbc_content)

    project = canpeek_app.Project()
    project.dbcs.append(
        canpeek_app.DBCFile(
            path=dbc_path, database=canpeek_app.cantools.database.load_file(dbc_path)
        )
    )
    project.filters.append(canpeek_app.CANFrameFilter(name="Test Filter"))
    project.can_interface = "virtual"
    project.can_channel = "vcan0"
    return project


@pytest.fixture
def main_window(qtbot):
    """Creates an instance of the main application window."""
    window = canpeek_app.CANBusObserver()
    qtbot.addWidget(window)
    # Prevent the window from showing during tests, which can be slow
    window.show()
    yield window
    # Cleanup after test
    window.close()


# --- Test Classes ---


class TestDataStructures:
    """Tests for the data classes and their serialization."""

    # def test_project_serialization(self, sample_project, tmp_path):
    #     """Test the round-trip serialization/deserialization of a Project."""
    #     project_dict = sample_project.to_dict()

    #     # Check basic structure of the dictionary
    #     assert "dbcs" in project_dict
    #     assert "filters" in project_dict
    #     assert project_dict["can_interface"] == "virtual"
    #     assert Path(project_dict["dbcs"][0]["path"]).name == "test.dbc"

    #     # Test deserialization
    #     new_project = canpeek_app.Project.from_dict(project_dict)
    #     assert new_project.can_interface == sample_project.can_interface
    #     assert len(new_project.dbcs) == 1
    #     assert len(new_project.filters) == 1
    #     assert new_project.dbcs[0].path == sample_project.dbcs[0].path
    #     assert new_project.filters[0].name == "Test Filter"

    def test_filter_matches(self):
        """Test the CANFrameFilter logic."""
        f = canpeek_app.CANFrameFilter(min_id=0x100, max_id=0x1FF, mask=0x7FF)
        frame_match = canpeek_app.CANFrame(0, 0x150, b"", 0)
        frame_no_match = canpeek_app.CANFrame(0, 0x250, b"", 0)
        frame_ext = canpeek_app.CANFrame(0, 0x12345, b"", 0, is_extended=True)

        assert f.matches(frame_match)
        assert not f.matches(frame_no_match)
        f.accept_standard = False
        assert not f.matches(frame_match)
        f.accept_standard = True
        f.accept_extended = False
        assert not f.matches(frame_ext)


class TestDecoders:
    """Tests for the CANopen decoder logic."""

    @pytest.mark.parametrize(
        "frame_id, data, expected_type, expected_node",
        [
            (0x701, b"\x05", "Heartbeat", 1),
            (0x181, b"\x01\x02", "PDO1 TX", 1),
            (0x581, b"\x40\x21\x10\x00", "SDO TX", 1),
            (0x81, b"\x01\x00\x02\x00\x00\x00\x00\x00", "EMCY", 1),
            (0x000, b"\x01\x00", "NMT", None),  # NMT is broadcast
        ],
    )
    def test_canopen_decode(self, frame_id, data, expected_type, expected_node):
        """Test various CANopen message decodings."""
        frame = canpeek_app.CANFrame(0, frame_id, data, len(data))
        decoded = canpeek_app.CANopenDecoder.decode(frame)
        assert decoded is not None
        assert decoded["CANopen Type"] == expected_type
        if expected_node:
            assert decoded["CANopen Node"] == expected_node


class TestUIModels:
    """Tests for the Qt Abstract Models."""

    def test_trace_model(self, sample_can_frame):
        """Test data retrieval from the CANTraceModel."""
        model = canpeek_app.CANTraceModel()
        model.set_data([sample_can_frame])

        assert model.rowCount() == 1
        assert model.columnCount() == 6

        # Check data formatting
        assert model.data(model.index(0, 0), Qt.DisplayRole) == "12345.678000"
        assert model.data(model.index(0, 1), Qt.DisplayRole) == "0x123"
        assert model.data(model.index(0, 4), Qt.DisplayRole) == "11 22 33 44"

    def test_grouped_model_update(self, sample_can_frame):
        """Test that the Grouped Model correctly aggregates frames."""
        model = canpeek_app.CANGroupedModel()
        model.update_frames([sample_can_frame, sample_can_frame])

        assert model.rowCount() == 1  # Only one unique ID
        top_level_index = model.index(0, 0)
        assert model.data(top_level_index, Qt.DisplayRole) == "0x123"

        # Check the count column
        count_index = model.index(0, 2)
        assert model.data(count_index, Qt.DisplayRole) == "2"


class TestUIWidgets:
    """Tests for individual UI widgets, driven by qtbot."""

    def test_filter_editor_updates_data(self, qtbot):
        """Test that editing a field in FilterEditor updates the underlying filter object."""
        can_filter = canpeek_app.CANFrameFilter()
        editor = canpeek_app.FilterEditor(can_filter)
        qtbot.addWidget(editor)

        # Change the name
        editor.name_edit.setText("My New Filter")
        editor.name_edit.editingFinished.emit()  # Manually emit signal for test
        assert can_filter.name == "My New Filter"

        # Change an ID
        editor.min_id_edit.setText("0x200")
        editor.min_id_edit.editingFinished.emit()
        assert can_filter.min_id == 0x200

        # Toggle a checkbox
        qtbot.mouseClick(editor.standard_cb, Qt.LeftButton)
        assert can_filter.accept_standard == editor.standard_cb.isChecked()

    # def test_transmit_panel_send(self, qtbot):
    #     """Test adding a frame to the transmit panel and clicking send."""
    #     panel = canpeek_app.TransmitPanel()
    #     qtbot.addWidget(panel)

    #     # Add a row
    #     qtbot.mouseClick(panel.add_btn, Qt.LeftButton)
    #     assert panel.table.rowCount() == 1

    #     # Set values for the frame
    #     panel.table.item(0, 1).setText("3FF") # ID
    #     panel.table.item(0, 5).setText("AA BB CC") # Data

    #     # Check that the send button emits the correct signal
    #     send_button = panel.table.cellWidget(0, 7)
    #     with qtbot.wait_signal(panel.frame_to_send, timeout=1000) as blocker:
    #         qtbot.mouseClick(send_button, Qt.LeftButton)

    #     # blocker.args will contain the arguments of the emitted signal
    #     sent_message = blocker.args[0]
    #     assert sent_message.arbitration_id == 0x3FF
    #     assert sent_message.data == b'\xAA\xBB\xCC'
    #     assert not sent_message.is_extended_id


class TestMainWindow:
    """Integration-style tests for the main application window."""

    # def test_project_save_and_load(self, main_window, qtbot, tmp_path):
    #     """Test saving and loading a project file."""
    #     # Setup the project
    #     main_window.project.can_interface = "kvaser"
    #     main_window.project.can_bitrate = 125000
    #     main_window.transmit_panel.add_frame()

    #     project_path = tmp_path / "test.cpeek"

    #     # Mock the file dialog to return our temp path
    #     with patch('PySide6.QtWidgets.QFileDialog.getSaveFileName', return_value=(str(project_path), '')):
    #         assert main_window._save_project() == True

    #     # Check that the file was created and has content
    #     assert project_path.exists()
    #     content = json.loads(project_path.read_text())
    #     assert content["project"]["can_interface"] == "kvaser"
    #     assert len(content["transmit_config"]) == 1

    #     # Now, load the project back
    #     with patch('PySide6.QtWidgets.QFileDialog.getOpenFileName', return_value=(str(project_path), '')):
    #         main_window._open_project()

    #     # Check that the app state was restored
    #     assert main_window.project.can_interface == "kvaser"
    #     assert main_window.project.can_bitrate == 125000
    #     assert main_window.transmit_panel.table.rowCount() == 1
    #     assert main_window.current_project_path == project_path

    # def test_connect_disconnect_logic(self, main_window, qtbot, mocker):
    #     """Test the connect/disconnect actions and UI state changes."""
    #     # Mock the CAN reader thread to avoid real hardware interaction
    #     mock_reader_thread = mocker.patch('__main__.CANReaderThread')
    #     mock_reader_thread.return_value.start_reading.return_value = True

    #     # Initial state: Disconnected
    #     assert not main_window.connect_action.isEnabled()
    #     assert main_window.disconnect_action.isEnabled()

    #     # Click connect
    #     main_window.connect_can()

    #     # Check that the thread was created and started
    #     mock_reader_thread.assert_called_once_with("socketcan", "can0", 500000)
    #     mock_reader_thread.return_value.start_reading.assert_called_once()

    #     # Check UI state: Connected
    #     assert not main_window.connect_action.isEnabled()
    #     assert main_window.disconnect_action.isEnabled()
    #     assert "Connected" in main_window.connection_label.text()
    #     assert main_window.transmit_panel.isEnabled()

    #     # Click disconnect
    #     main_window.disconnect_can()
    #     mock_reader_thread.return_value.stop_reading.assert_called_once()

    #     # Check UI state: Disconnected
    #     assert main_window.connect_action.isEnabled()
    #     assert not main_window.disconnect_action.isEnabled()
    #     assert "Disconnected" in main_window.connection_label.text()
    #     assert not main_window.transmit_panel.isEnabled()
