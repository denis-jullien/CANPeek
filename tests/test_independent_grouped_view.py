"""
Tests for the independent grouped view implementation.
"""

import pytest


class TestFastCANGroupedModel:
    """Test the fast independent grouped model"""

    # def test_model_initialization(self, qtbot):
    #     """Test model initialization"""
    #     model = FastCANGroupedModel()
    #
    #     assert len(model.grouped_data) == 0
    #     assert len(model.sorted_ids) == 0
    #     assert model.rowCount() == 0
    #     assert model.columnCount() == 7

    # def test_add_single_frame(self, qtbot):
    #     """Test adding a single frame"""
    #     model = FastCANGroupedModel()
    #
    #     frame = CANFrame(
    #         timestamp=time.time(),
    #         arbitration_id=0x123,
    #         data=b"\x01\x02\x03\x04",
    #         dlc=4,
    #         is_extended=False,
    #         is_remote=False,
    #         is_error=False,
    #         bus="can0",
    #         connection_id=uuid.uuid4(),
    #         is_rx=True,
    #     )
    #
    #     model.add_frame(frame)
    #
    #     assert len(model.grouped_data) == 1
    #     assert len(model.sorted_ids) == 1
    #     assert model.rowCount() == 1
    #     assert 0x123 in model.grouped_data
    #
    #     # Test frame info
    #     info = model.grouped_data[0x123]
    #     assert info.arbitration_id == 0x123
    #     assert info.count == 1
    #     assert info.cycle_time_ms == 0.0  # First frame has no cycle time
    #
    # def test_add_multiple_frames_same_id(self, qtbot):
    #     """Test adding multiple frames with the same ID"""
    #     model = FastCANGroupedModel()
    #
    #     base_time = time.time()
    #
    #     # Add first frame
    #     frame1 = CANFrame(
    #         timestamp=base_time,
    #         arbitration_id=0x123,
    #         data=b"\x01\x02\x03\x04",
    #         dlc=4,
    #         is_extended=False,
    #         is_remote=False,
    #         is_error=False,
    #         bus="can0",
    #         is_rx=True,
    #     )
    #     model.add_frame(frame1)
    #
    #     # Add second frame 100ms later
    #     frame2 = CANFrame(
    #         timestamp=base_time + 0.1,  # 100ms later
    #         arbitration_id=0x123,
    #         data=b"\x05\x06\x07\x08",
    #         dlc=4,
    #         is_extended=False,
    #         is_remote=False,
    #         is_error=False,
    #         bus="can0",
    #         is_rx=True,
    #     )
    #     model.add_frame(frame2)
    #
    #     # Should still have only one entry
    #     assert len(model.grouped_data) == 1
    #     assert model.rowCount() == 1
    #
    #     # Test updated frame info
    #     info = model.grouped_data[0x123]
    #     assert info.count == 2
    #     assert abs(info.cycle_time_ms - 100.0) < 1.0  # ~100ms cycle time
    #     assert info.latest_data == b"\x05\x06\x07\x08"
    #
    # def test_add_frames_different_ids(self, qtbot):
    #     """Test adding frames with different IDs"""
    #     model = FastCANGroupedModel()
    #
    #     frames = []
    #     for i in range(5):
    #         frame = CANFrame(
    #             timestamp=time.time() + i * 0.001,
    #             arbitration_id=0x100 + i,
    #             data=bytes([i] * 4),
    #             dlc=4,
    #             is_extended=False,
    #             is_remote=False,
    #             is_error=False,
    #             bus="can0",
    #             is_rx=True,
    #         )
    #         frames.append(frame)
    #
    #     model.add_frames_batch(frames)
    #
    #     assert len(model.grouped_data) == 5
    #     assert model.rowCount() == 5
    #
    #     # Check all IDs are present
    #     for i in range(5):
    #         assert (0x100 + i) in model.grouped_data
    #
    # def test_sorting(self, qtbot):
    #     """Test sorting functionality"""
    #     model = FastCANGroupedModel()
    #
    #     # Add frames in reverse ID order
    #     for i in range(5, 0, -1):
    #         frame = CANFrame(
    #             timestamp=time.time(),
    #             arbitration_id=0x100 + i,
    #             data=bytes([i] * 4),
    #             dlc=4,
    #             is_extended=False,
    #             is_remote=False,
    #             is_error=False,
    #             bus="can0",
    #             is_rx=True,
    #         )
    #         model.add_frame(frame)
    #
    #     # Should be sorted in ascending order by default
    #     assert model.sorted_ids == [0x101, 0x102, 0x103, 0x104, 0x105]
    #
    #     # Test descending sort
    #     from PySide6.QtCore import Qt
    #
    #     model.sort(0, Qt.DescendingOrder)  # Sort by ID, descending
    #     assert model.sorted_ids == [0x105, 0x104, 0x103, 0x102, 0x101]
    #
    # def test_data_access(self, qtbot):
    #     """Test Qt model data access"""
    #     model = FastCANGroupedModel()
    #
    #     frame = CANFrame(
    #         timestamp=time.time(),
    #         arbitration_id=0x123,
    #         data=b"\x01\x02\x03\x04",
    #         dlc=4,
    #         is_extended=False,
    #         is_remote=False,
    #         is_error=False,
    #         bus="can0",
    #         is_rx=True,
    #     )
    #     model.add_frame(frame)
    #
    #     # Test data access through Qt interface
    #     index = model.index(0, 0)  # First row, ID column
    #     id_data = model.data(index, 0)  # DisplayRole
    #     assert id_data == "0x123"
    #
    #     # Test DLC column
    #     dlc_index = model.index(0, 3)
    #     dlc_data = model.data(dlc_index, 0)
    #     assert dlc_data == "4"
    #
    #     # Test data column
    #     data_index = model.index(0, 4)
    #     data_value = model.data(data_index, 0)
    #     assert data_value == "01 02 03 04"
    #
    # def test_clear_data(self, qtbot):
    #     """Test clearing all data"""
    #     model = FastCANGroupedModel()
    #
    #     # Add some frames
    #     for i in range(3):
    #         frame = CANFrame(
    #             timestamp=time.time(),
    #             arbitration_id=0x100 + i,
    #             data=bytes([i] * 4),
    #             dlc=4,
    #             is_extended=False,
    #             is_remote=False,
    #             is_error=False,
    #             bus="can0",
    #             is_rx=True,
    #         )
    #         model.add_frame(frame)
    #
    #     assert model.rowCount() == 3
    #
    #     # Clear data
    #     model.clear_data()
    #
    #     assert model.rowCount() == 0
    #     assert len(model.grouped_data) == 0
    #     assert len(model.sorted_ids) == 0


class TestCANFrameProcessor:
    """Test the frame processor that coordinates both views"""

    # def test_processor_initialization(self, qtbot):
    #     """Test processor initialization"""
    #     processor = CANFrameProcessor()
    #
    #     assert processor.total_frames_processed == 0
    #     assert processor.polars_manager is not None
    #     assert processor.grouped_model is not None
    #
    #     # Cleanup
    #     processor.shutdown()

    # def test_frame_distribution(self, qtbot):
    #     """Test that frames are distributed to both views"""
    #     processor = CANFrameProcessor()
    #
    #     frame = CANFrame(
    #         timestamp=time.time(),
    #         arbitration_id=0x123,
    #         data=b"\x01\x02\x03\x04",
    #         dlc=4,
    #         is_extended=False,
    #         is_remote=False,
    #         is_error=False,
    #         bus="can0",
    #         is_rx=True,
    #     )
    #
    #     # Wait for the signal to be emitted
    #     with qtbot.wait_signal(processor.grouped_frames_ready, timeout=1000):
    #         processor.add_frame(frame)
    #
    #     # Additional wait for processing
    #     qtbot.wait(50)  # 50ms for processing
    #
    #     # Check that both models received the frame
    #     trace_model = processor.get_trace_model()
    #     grouped_model = processor.get_grouped_model()
    #
    #     # Note: trace model might need refresh to show data
    #     assert grouped_model.rowCount() == 1
    #     assert processor.total_frames_processed == 1
    #
    #     # Cleanup
    #     processor.shutdown()
    #
    # def test_batch_processing(self, qtbot):
    #     """Test batch frame processing"""
    #     processor = CANFrameProcessor()
    #
    #     frames = []
    #     for i in range(10):
    #         frame = CANFrame(
    #             timestamp=time.time() + i * 0.001,
    #             arbitration_id=0x100 + (i % 3),  # 3 unique IDs
    #             data=bytes([i] * 4),
    #             dlc=4,
    #             is_extended=False,
    #             is_remote=False,
    #             is_error=False,
    #             bus="can0",
    #             is_rx=True,
    #         )
    #         frames.append(frame)
    #
    #     # Wait for at least one signal emission (batches of 10)
    #     with qtbot.wait_signal(processor.grouped_frames_ready, timeout=1000):
    #         processor.add_frames(frames)
    #
    #     # Additional wait for processing
    #     qtbot.wait(50)  # 50ms for processing
    #
    #     # Check that grouped model has 3 unique IDs
    #     grouped_model = processor.get_grouped_model()
    #     assert grouped_model.rowCount() == 3
    #     assert processor.total_frames_processed == 10
    #
    #     # Cleanup
    #     processor.shutdown()
    #
    # def test_clear_data(self, qtbot):
    #     """Test clearing data from processor"""
    #     processor = CANFrameProcessor()
    #
    #     # Add some frames
    #     frame = CANFrame(
    #         timestamp=time.time(),
    #         arbitration_id=0x123,
    #         data=b"\x01\x02\x03\x04",
    #         dlc=4,
    #         is_extended=False,
    #         is_remote=False,
    #         is_error=False,
    #         bus="can0",
    #         is_rx=True,
    #     )
    #
    #     # Wait for initial frame processing
    #     with qtbot.wait_signal(processor.grouped_frames_ready, timeout=1000):
    #         processor.add_frame(frame)
    #
    #     qtbot.wait(50)  # Additional processing time
    #     assert processor.total_frames_processed == 1
    #
    #     # Clear data and wait for the signal
    #     with qtbot.wait_signal(processor.clear_data_requested, timeout=1000):
    #         processor.clear_data()
    #
    #     qtbot.wait(50)  # Wait for clear to process
    #
    #     assert processor.total_frames_processed == 0
    #     grouped_model = processor.get_grouped_model()
    #     assert grouped_model.rowCount() == 0
    #
    #     # Cleanup
    #     processor.shutdown()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
