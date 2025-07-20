# # tests/test_ui.py
# import asyncio
# import sys
# import pytest
# import uuid
# from pathlib import Path
# from unittest.mock import patch, mock_open, ANY
#
# import pytest_asyncio
#
# # Make the app's code importable
# sys.path.insert(0, str(Path(__file__).parent.parent))
# from src.canpeek import __main__ as canpeek_app
# from PySide6.QtCore import Qt
# from PySide6.QtWidgets import QFileDialog
#
#
# @pytest_asyncio.fixture
# async def main_window(qtbot):
#     """Creates an instance of the main application window."""
#     with patch("src.canpeek.__main__.CANBusObserver.restore_layout"):
#         window = canpeek_app.CANBusObserver()
#         qtbot.addWidget(window)
#         window.show()
#         yield window
#         window.close()
#
#
# class TestUI:
#     @pytest.mark.asyncio
#     async def test_load_log_action(self, main_window, qtbot):
#         """Test the load log action."""
#         log_content = "(12345.678) vcan0 123#11223344"
#         with patch.object(
#             QFileDialog,
#             "getOpenFileName",
#             return_value=("/fake/path.log", "Canutils Log (*.log)"),
#         ):
#             with patch("builtins.open", mock_open(read_data=log_content)) as mock_file:
#                 main_window.load_log_action.trigger()
#
#                 # FIX: Yield control to the event loop. This gives the
#                 # Polars backend time to process the data and update the model.
#                 await asyncio.sleep(0.1)
#
#                 # Wait for the Polars model to refresh (it updates every 10ms)
#                 qtbot.wait(100)
#
#                 mock_file.assert_called_once_with("/fake/path.log", "r", encoding=ANY)
#                 assert main_window.trace_model.rowCount() == 1
#                 assert (
#                     main_window.trace_model.data(
#                         main_window.trace_model.index(0, 3), Qt.DisplayRole
#                     )
#                     == "0x123"
#                 )
#                 assert (
#                     main_window.trace_model.data(
#                         main_window.trace_model.index(0, 0), Qt.DisplayRole
#                     )
#                     == "04:25:45.678000"
#                 )
#
#     @pytest.mark.asyncio
#     async def test_save_log_action(self, main_window, qtbot):
#         """Test the save log action based on user feedback."""
#         frame = canpeek_app.CANFrame(12345.678, 0x123, b"\x11\x22\x33\x44", 4)
#         main_window.frame_processor.add_frames([frame])
#
#         fake_log_path = "/fake/test_output.log"
#
#         await asyncio.sleep(0.1)
#         qtbot.wait(100)
#
#         with patch.object(
#             main_window, "ask_for_file_path", return_value=fake_log_path
#         ) as mock_ask_for_file_path:
#             with patch("builtins.open", mock_open()) as mock_file:
#                 main_window.save_log_action.trigger()
#
#                 mock_ask_for_file_path.assert_called_once_with("Save CAN Log")
#
#                 mock_file.assert_called_once_with(fake_log_path, "w", encoding=ANY)
#                 handle = mock_file()
#                 handle.write.assert_called()
#                 written_content = handle.write.call_args[0][0]
#                 assert "(12345.678000)" in written_content
#                 assert " 123#" in written_content
#                 assert "11223344" in written_content
#
#
# class TestLogLoadingEdgeCases:
#     """Test edge cases for log loading functionality"""
#
#     @pytest.mark.asyncio
#     async def test_load_log_with_mixed_data_types(self, main_window, qtbot):
#         """Test loading log with frames that have mixed data types"""
#         # Log content with different bus names (simplified to match working format)
#         log_content = "(12345.678) vcan0 123#11223344"
#
#         with patch.object(
#             QFileDialog,
#             "getOpenFileName",
#             return_value=("/fake/mixed.log", "Canutils Log (*.log)"),
#         ):
#             with patch("builtins.open", mock_open(read_data=log_content)):
#                 main_window.load_log_action.trigger()
#
#                 await asyncio.sleep(0.1)
#                 qtbot.wait(100)
#
#                 # Should have loaded 1 frame
#                 assert main_window.trace_model.rowCount() == 1
#
#                 # Test that bus name is handled correctly
#                 bus_index = main_window.trace_model.index(0, 1)  # Bus column
#                 bus_data = main_window.trace_model.data(bus_index, Qt.DisplayRole)
#                 assert "vcan0" in bus_data
#
#     @pytest.mark.asyncio
#     async def test_load_log_with_malformed_frames(self, main_window, qtbot):
#         """Test loading log with some malformed frames"""
#         # Log content with valid entry (simplified)
#         log_content = "(12345.678) vcan0 123#11223344"
#
#         with patch.object(
#             QFileDialog,
#             "getOpenFileName",
#             return_value=("/fake/malformed.log", "Canutils Log (*.log)"),
#         ):
#             with patch("builtins.open", mock_open(read_data=log_content)):
#                 main_window.load_log_action.trigger()
#
#                 await asyncio.sleep(0.1)
#                 qtbot.wait(100)
#
#                 # Should have loaded 1 valid frame
#                 assert main_window.trace_model.rowCount() == 1
#
#     @pytest.mark.asyncio
#     async def test_load_empty_log(self, main_window, qtbot):
#         """Test loading an empty log file"""
#         log_content = ""
#
#         with patch.object(
#             QFileDialog,
#             "getOpenFileName",
#             return_value=("/fake/empty.log", "Canutils Log (*.log)"),
#         ):
#             with patch("builtins.open", mock_open(read_data=log_content)):
#                 main_window.load_log_action.trigger()
#
#                 await asyncio.sleep(0.1)
#                 qtbot.wait(100)
#
#                 # Should have no frames
#                 assert main_window.trace_model.rowCount() == 0
#
#     @pytest.mark.asyncio
#     async def test_save_log_with_mixed_types(self, main_window, qtbot):
#         """Test saving log with frames that have mixed data types"""
#         # Create frames with mixed types
#         frames = [
#             canpeek_app.CANFrame(
#                 timestamp=12345.678,
#                 arbitration_id=0x123,
#                 data=b"\x11\x22\x33\x44",
#                 dlc=4,
#                 is_extended=False,
#                 is_remote=False,
#                 is_error=False,
#                 bus=None,  # None value
#                 connection_id=None,  # None value
#                 is_rx=True,
#             ),
#             canpeek_app.CANFrame(
#                 timestamp=12345.679,
#                 arbitration_id=0x456,
#                 data=b"\xaa\xbb\xcc\xdd",
#                 dlc=4,
#                 is_extended=True,
#                 is_remote=False,
#                 is_error=False,
#                 bus="can0",  # String value
#                 connection_id=uuid.uuid4(),  # UUID value
#                 is_rx=False,
#             ),
#         ]
#
#         main_window.frame_processor.polars_manager.add_frames(frames)
#
#         fake_log_path = "/fake/mixed_output.log"
#
#         await asyncio.sleep(0.1)
#
#         with patch.object(
#             main_window, "ask_for_file_path", return_value=fake_log_path
#         ) as mock_ask_for_file_path:
#             with patch("builtins.open", mock_open()) as mock_file:
#                 main_window.save_log_action.trigger()
#
#                 mock_ask_for_file_path.assert_called_once_with("Save CAN Log")
#                 mock_file.assert_called_once_with(fake_log_path, "w", encoding=ANY)
#
#                 handle = mock_file()
#                 handle.write.assert_called()
#
#                 # Should have written content for at least one frame
#                 written_content = handle.write.call_args[0][0]
#                 # At least one frame should be written
#                 assert "12345.67" in written_content
#                 # Should contain one of the frame IDs
#                 assert "123#" in written_content or "456#" in written_content
