# """
# Tests for the threaded CAN reader implementation.
# """
#
# import pytest
# import time
# import uuid
# from unittest.mock import Mock, patch
# import can
#
# from canpeek.can_utils import CANMultiprocessReader
# from canpeek.data_utils import Connection
#
#
# class TestCANMultiprocessReader:
#     """Test the threaded CAN reader"""
#
#     def test_reader_initialization(self, qtbot):
#         """Test reader initialization"""
#         connection = Connection(
#             id=uuid.uuid4(),
#             name="test_can",
#             interface="virtual",
#             config={"channel": "test"},
#         )
#
#         reader = CANMultiprocessReader(connection)
#
#         assert reader.connection == connection
#         assert not reader.running
#         assert reader.bus is None
#         assert reader.reader_thread is None
#         assert reader._stop_event is None
#
#     def test_reader_signals(self, qtbot):
#         """Test that reader has proper Qt signals"""
#         connection = Connection(
#             id=uuid.uuid4(),
#             name="test_can",
#             interface="virtual",
#             config={"channel": "test"},
#         )
#
#         reader = CANMultiprocessReader(connection)
#
#         # Check signals exist
#         assert hasattr(reader, "frame_received")
#         assert hasattr(reader, "error_occurred")
#         assert hasattr(reader, "bus_state_changed")
#
#     @patch("can.Bus")
#     def test_start_reading_success(self, mock_bus_class, qtbot):
#         """Test successful start of reading"""
#         # Mock the CAN bus
#         mock_bus = Mock()
#         mock_bus.state = can.BusState.ACTIVE
#         mock_bus_class.return_value = mock_bus
#
#         connection = Connection(
#             id=uuid.uuid4(),
#             name="test_can",
#             interface="virtual",
#             config={"channel": "test"},
#         )
#
#         reader = CANMultiprocessReader(connection)
#
#         # Start reading
#         result = reader.start_reading()
#
#         assert result is True
#         assert reader.running is True
#         assert reader.bus is mock_bus
#         assert reader.reader_thread is not None
#         assert reader._stop_event is not None
#
#         # Clean up
#         reader.stop_reading()
#
#     # @patch("can.Bus")
#     # def test_start_reading_failure(self, mock_bus_class, qtbot):
#     #     """Test failure to start reading"""
#     #     # Mock bus creation to fail
#     #     mock_bus_class.side_effect = Exception("Bus creation failed")
#     #
#     #     connection = Connection(
#     #         id=uuid.uuid4(),
#     #         name="test_can",
#     #         interface="virtual",
#     #         config={"channel": "test"},
#     #     )
#     #
#     #     reader = CANMultiprocessReader(connection)
#     #
#     #     # Capture error signal
#     #     errors = []
#     #     reader.error_occurred.connect(lambda msg: errors.append(msg))
#     #
#     #     # Start reading should fail
#     #     result = reader.start_reading()
#     #
#     #     assert result is False
#     #     assert reader.running is False
#     #     assert len(errors) == 1
#     #     assert "Failed to start threaded CAN reading" in errors[0]
#
#     # @patch("can.Bus")
#     # def test_stop_reading(self, mock_bus_class, qtbot):
#     #     """Test stopping the reader"""
#     #     # Mock the CAN bus
#     #     mock_bus = Mock()
#     #     mock_bus.state = can.BusState.ACTIVE
#     #     mock_bus_class.return_value = mock_bus
#     #
#     #     connection = Connection(
#     #         id=uuid.uuid4(),
#     #         name="test_can",
#     #         interface="virtual",
#     #         config={"channel": "test"},
#     #     )
#     #
#     #     reader = CANMultiprocessReader(connection)
#     #
#     #     # Start and then stop
#     #     reader.start_reading()
#     #     time.sleep(0.1)  # Let thread start
#     #
#     #     reader.stop_reading()
#     #
#     #     assert reader.running is False
#     #     # Thread should have stopped
#     #     if reader.reader_thread:
#     #         assert not reader.reader_thread.is_alive()
#     #
#     #     # Bus should be shut down
#     #     mock_bus.shutdown.assert_called_once()
#
#     # def test_process_message(self, qtbot):
#     #     """Test message processing"""
#     #     connection = Connection(
#     #         id=uuid.uuid4(),
#     #         name="test_can",
#     #         interface="virtual",
#     #         config={"channel": "test"},
#     #     )
#     #
#     #     reader = CANMultiprocessReader(connection)
#     #
#     #     # Capture frame signals
#     #     frames = []
#     #     reader.frame_received.connect(lambda frame: frames.append(frame))
#     #
#     #     # Create a mock CAN message
#     #     mock_msg = Mock()
#     #     mock_msg.is_error_frame = False
#     #     mock_msg.timestamp = 12345.678
#     #     mock_msg.arbitration_id = 0x123
#     #     mock_msg.data = b"\x01\x02\x03\x04"
#     #     mock_msg.dlc = 4
#     #     mock_msg.is_extended_id = False
#     #     mock_msg.is_remote_frame = False
#     #     mock_msg.is_rx = True
#     #
#     #     # Process the message
#     #     reader._process_message(mock_msg)
#     #
#     #     # Check that frame was emitted
#     #     assert len(frames) == 1
#     #     frame = frames[0]
#     #     assert frame.timestamp == 12345.678
#     #     assert frame.arbitration_id == 0x123
#     #     assert frame.data == b"\x01\x02\x03\x04"
#     #     assert frame.dlc == 4
#     #     assert frame.bus == "test_can"
#     #     assert frame.connection_id == connection.id
#     #
#     # def test_process_error_frame(self, qtbot):
#     #     """Test processing of error frames"""
#     #     connection = Connection(
#     #         id=uuid.uuid4(),
#     #         name="test_can",
#     #         interface="virtual",
#     #         config={"channel": "test"},
#     #     )
#     #
#     #     reader = CANMultiprocessReader(connection)
#     #     reader.bus = Mock()
#     #     reader.bus.state = can.BusState.ERROR
#     #
#     #     # Capture bus state signals
#     #     states = []
#     #     reader.bus_state_changed.connect(lambda state: states.append(state))
#     #
#     #     # Create error frame
#     #     mock_msg = Mock()
#     #     mock_msg.is_error_frame = True
#     #
#     #     # Process error frame
#     #     reader._process_message(mock_msg)
#     #
#     #     # Should emit bus state change
#     #     assert len(states) == 1
#     #     assert states[0] == can.BusState.ERROR
#
#
# if __name__ == "__main__":
#     pytest.main([__file__, "-v"])
