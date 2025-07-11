# tests/test_ui.py

import sys
import pytest
from pathlib import Path
from unittest.mock import patch, mock_open, ANY

# Make the app's code importable
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.canpeek import __main__ as canpeek_app
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog


@pytest.fixture
def main_window(qtbot):
    """Creates an instance of the main application window."""
    with patch("src.canpeek.__main__.CANBusObserver.restore_layout"):
        window = canpeek_app.CANBusObserver()
        qtbot.addWidget(window)
        window.show()
        yield window
        window.close()


class TestUI:
    def test_load_log_action(self, main_window, qtbot):
        """Test the load log action."""
        log_content = "(12345.678) vcan0 123#11223344"
        with patch.object(
            QFileDialog,
            "getOpenFileName",
            return_value=("/fake/path.log", "Canutils Log (*.log)"),
        ):
            with patch("builtins.open", mock_open(read_data=log_content)) as mock_file:
                main_window.load_log_action.trigger()

                qtbot.wait(100)  # Let the UI event loop process

                mock_file.assert_called_once_with("/fake/path.log", "r", encoding=ANY)
                assert main_window.trace_model.rowCount() == 1
                assert (
                    main_window.trace_model.data(
                        main_window.trace_model.index(0, 3), Qt.DisplayRole
                    )
                    == "0x123"
                )
                assert (
                    main_window.trace_model.data(
                        main_window.trace_model.index(0, 0), Qt.DisplayRole
                    )
                    == "04:25:45.678000"
                )

    def test_save_log_action(self, main_window, qtbot):
        """Test the save log action based on user feedback."""
        frame = canpeek_app.CANFrame(12345.678, 0x123, b"\x11\x22\x33\x44", 4)
        main_window.trace_model.add_data([frame])

        fake_log_path = "/fake/test_output.log"

        with patch.object(
            main_window, "ask_for_file_path", return_value=fake_log_path
        ) as mock_ask_for_file_path:
            with patch("builtins.open", mock_open()) as mock_file:
                main_window.save_log_action.trigger()

                mock_ask_for_file_path.assert_called_once_with("Save CAN Log")

                mock_file.assert_called_once_with(fake_log_path, "w", encoding=ANY)
                handle = mock_file()
                handle.write.assert_called()
                written_content = handle.write.call_args[0][0]
                assert "(12345.678000)" in written_content
                assert " 123#" in written_content
                assert "11223344" in written_content
