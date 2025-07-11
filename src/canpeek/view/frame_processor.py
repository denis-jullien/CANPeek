"""
Central frame processor that handles decoding and distributes frames to grouped view.

This module provides a grouped view processing pipeline that:
1. Receives raw CAN frames
2. Performs DBC/CANopen decoding
3. Distributes processed frames to grouped view
"""

from queue import Queue, Empty

from PySide6.QtCore import QObject, Signal, QThread, QMutex, QMutexLocker

from canpeek.view.grouped_view import FastCANGroupedModel


class GroupedWorkerThread(QThread):
    """QThread worker for processing grouped view frames"""

    def __init__(self, grouped_queue: Queue, grouped_frames_ready_signal):
        super().__init__()
        self.grouped_queue = grouped_queue
        self.grouped_frames_ready = grouped_frames_ready_signal
        self.shutdown_mutex = None

    def set_shutdown_mutex(self, mutex: QMutex):
        """Set shared shutdown mutex"""
        self.shutdown_mutex = mutex

    def _check_shutdown(self):
        """Check if shutdown has been requested"""
        if self.shutdown_mutex:
            with QMutexLocker(self.shutdown_mutex):
                # Check parent's shutdown flag
                return self.parent().shutdown_requested if self.parent() else False
        return False

    def run(self):
        """Main thread execution for grouped processing"""
        print("Grouped worker thread started")
        batch = []

        while not self._check_shutdown():
            try:
                # Collect frames in batch to minimize Qt thread crossings
                frame = self.grouped_queue.get(timeout=0.01)  # 10ms timeout
                batch.append(frame)

                # Process batch when it reaches size or on timeout
                if len(batch) >= 10:  # Process in small batches
                    self.grouped_frames_ready.emit(batch.copy())
                    batch.clear()

            except Empty:
                # Process any remaining frames on timeout
                if batch:
                    self.grouped_frames_ready.emit(batch.copy())
                    batch.clear()
                continue

        # Process final batch
        if batch:
            self.grouped_frames_ready.emit(batch.copy())

        print("Grouped worker thread stopped")


class CANFrameProcessor(QObject):
    """Central processor for CAN frames with threaded view distribution"""

    # Signals for thread-safe communication
    grouped_frames_ready = Signal(list)
    clear_data_requested = Signal()

    def __init__(self):
        super().__init__()

        # Initialize grouped view backend
        self.grouped_model = FastCANGroupedModel()

        # Connect signals to slots for safe Qt thread communication
        self.grouped_frames_ready.connect(self._process_grouped_frames_main_thread)
        self.clear_data_requested.connect(self._clear_data_main_thread)

        # DBC configuration
        self.dbc_files = []
        self.pdo_databases = []
        self.canopen_enabled = True

        # Threading for independent processing
        self.grouped_queue = Queue(maxsize=10000)  # Queue for grouped view
        self.shutdown_requested = False
        self.shutdown_mutex = QMutex()

        # Worker threads using QThread
        self.grouped_thread = GroupedWorkerThread(
            self.grouped_queue, self.grouped_frames_ready
        )

        # Set parent relationships for proper shutdown handling
        self.grouped_thread.setParent(self)

        # Connect shutdown signals
        self.grouped_thread.set_shutdown_mutex(self.shutdown_mutex)

        # Start worker threads
        self.grouped_thread.start()

        print("Frame processor initialized with threaded grouped backend")

    def _check_shutdown(self):
        """Check if shutdown has been requested"""
        with QMutexLocker(self.shutdown_mutex):
            return self.shutdown_requested

    def _set_shutdown_requested(self):
        """Set shutdown flag thread-safely"""
        with QMutexLocker(self.shutdown_mutex):
            self.shutdown_requested = True

    def _process_grouped_frames_main_thread(self, frames):
        """Process grouped frames in the main thread (Qt slot)"""
        try:
            for frame in frames:
                self.grouped_model.add_frame(frame)

        except Exception as e:
            print(f"Error in grouped frame processing: {e}")

    def _clear_data_main_thread(self):
        """Clear all data from grouped view in the main thread (Qt slot)"""
        try:
            # Clear grouped model
            self.grouped_model.clear_data()

            # Clear worker queues
            try:
                while True:
                    self.grouped_queue.get_nowait()
            except Empty:
                pass

            print("Data cleared successfully from main thread")
        except Exception as e:
            print(f"Error in clearing data: {e}")

    def clear_data(self):
        """Clear all data from grouped view (thread-safe)"""
        # Emit signal to handle clearing in main thread
        self.clear_data_requested.emit()

    def get_grouped_model(self):
        """Get the grouped model (fast independent)"""
        return self.grouped_model

    def shutdown(self):
        """Shutdown the processor and cleanup resources"""
        print("Shutting down frame processor...")

        # Signal worker threads to stop
        self._set_shutdown_requested()

        if self.grouped_thread.isRunning():
            self.grouped_thread.quit()
            if not self.grouped_thread.wait(2000):  # 2 seconds timeout
                print("Warning: Grouped thread did not stop cleanly")

        # Grouped model doesn't need explicit shutdown
        print("Frame processor shutdown complete")
