"""
High-performance ring buffer for CAN frame handling.

This module provides thread-safe ring buffers optimized for
single-producer, single-consumer (SPSC) patterns common in
CAN frame reception.
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Generic, TypeVar, List, Optional, Callable
import time

from canpeek.core.types import CANFrame

T = TypeVar('T')


@dataclass
class BufferStats:
    """Statistics for buffer performance monitoring."""
    total_pushed: int = 0
    total_popped: int = 0
    overflow_count: int = 0
    max_size_reached: int = 0
    last_push_ns: int = 0
    last_pop_ns: int = 0


class RingBuffer(Generic[T]):
    """
    Thread-safe ring buffer with overflow handling.

    Optimized for single-producer, single-consumer patterns but
    safe for multi-producer/multi-consumer use.

    Features:
        - Configurable capacity with overflow handling
        - Batch push/pop operations for efficiency
        - Performance statistics tracking
        - Optional overflow callback

    Example:
        >>> buffer = RingBuffer[CANFrame](capacity=10000)
        >>> buffer.push(frame)
        >>> frames = buffer.pop_batch(100)
    """

    def __init__(
        self,
        capacity: int = 100_000,
        overflow_callback: Optional[Callable[[int], None]] = None,
    ):
        """
        Initialize ring buffer.

        Args:
            capacity: Maximum number of items to store
            overflow_callback: Called with overflow count when buffer is full
        """
        self._capacity = capacity
        self._buffer: deque[T] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._overflow_callback = overflow_callback
        self._stats = BufferStats()
        self._not_empty = threading.Condition(self._lock)

    @property
    def capacity(self) -> int:
        """Maximum buffer capacity."""
        return self._capacity

    @property
    def stats(self) -> BufferStats:
        """Get buffer statistics (read-only copy)."""
        with self._lock:
            return BufferStats(
                total_pushed=self._stats.total_pushed,
                total_popped=self._stats.total_popped,
                overflow_count=self._stats.overflow_count,
                max_size_reached=self._stats.max_size_reached,
                last_push_ns=self._stats.last_push_ns,
                last_pop_ns=self._stats.last_pop_ns,
            )

    def __len__(self) -> int:
        """Current number of items in buffer."""
        with self._lock:
            return len(self._buffer)

    def is_empty(self) -> bool:
        """Check if buffer is empty."""
        with self._lock:
            return len(self._buffer) == 0

    def is_full(self) -> bool:
        """Check if buffer is at capacity."""
        with self._lock:
            return len(self._buffer) >= self._capacity

    def clear(self) -> int:
        """
        Clear all items from buffer.

        Returns:
            Number of items cleared
        """
        with self._lock:
            count = len(self._buffer)
            self._buffer.clear()
            return count

    def push(self, item: T) -> bool:
        """
        Add single item to buffer.

        Args:
            item: Item to add

        Returns:
            True if added, False if buffer was full (item still added,
            oldest item dropped due to maxlen)
        """
        with self._lock:
            was_full = len(self._buffer) >= self._capacity
            self._buffer.append(item)

            self._stats.total_pushed += 1
            self._stats.last_push_ns = time.time_ns()
            self._stats.max_size_reached = max(
                self._stats.max_size_reached, len(self._buffer)
            )

            if was_full:
                self._stats.overflow_count += 1
                if self._overflow_callback:
                    self._overflow_callback(1)

            self._not_empty.notify()
            return not was_full

    def push_batch(self, items: List[T]) -> int:
        """
        Add multiple items to buffer efficiently.

        Args:
            items: Items to add

        Returns:
            Number of items that caused overflow (oldest items dropped)
        """
        if not items:
            return 0

        with self._lock:
            space_before = self._capacity - len(self._buffer)
            overflow = max(0, len(items) - space_before)

            self._buffer.extend(items)

            self._stats.total_pushed += len(items)
            self._stats.last_push_ns = time.time_ns()
            self._stats.max_size_reached = max(
                self._stats.max_size_reached, len(self._buffer)
            )

            if overflow > 0:
                self._stats.overflow_count += overflow
                if self._overflow_callback:
                    self._overflow_callback(overflow)

            self._not_empty.notify_all()
            return overflow

    def pop(self) -> Optional[T]:
        """
        Remove and return oldest item.

        Returns:
            Oldest item, or None if buffer is empty
        """
        with self._lock:
            if not self._buffer:
                return None

            item = self._buffer.popleft()
            self._stats.total_popped += 1
            self._stats.last_pop_ns = time.time_ns()
            return item

    def pop_batch(self, max_count: int) -> List[T]:
        """
        Remove and return up to max_count oldest items.

        Args:
            max_count: Maximum number of items to return

        Returns:
            List of items (may be shorter than max_count)
        """
        with self._lock:
            count = min(len(self._buffer), max_count)
            if count == 0:
                return []

            items = [self._buffer.popleft() for _ in range(count)]
            self._stats.total_popped += count
            self._stats.last_pop_ns = time.time_ns()
            return items

    def pop_all(self) -> List[T]:
        """
        Remove and return all items atomically.

        Returns:
            List of all items in order (oldest first)
        """
        with self._lock:
            items = list(self._buffer)
            self._buffer.clear()
            self._stats.total_popped += len(items)
            self._stats.last_pop_ns = time.time_ns()
            return items

    def pop_wait(self, timeout: Optional[float] = None) -> Optional[T]:
        """
        Wait for and return an item.

        Args:
            timeout: Maximum time to wait in seconds (None = forever)

        Returns:
            Item, or None if timeout elapsed
        """
        with self._not_empty:
            if not self._buffer:
                self._not_empty.wait(timeout)

            if self._buffer:
                item = self._buffer.popleft()
                self._stats.total_popped += 1
                self._stats.last_pop_ns = time.time_ns()
                return item
            return None

    def peek(self) -> Optional[T]:
        """
        Return oldest item without removing it.

        Returns:
            Oldest item, or None if buffer is empty
        """
        with self._lock:
            return self._buffer[0] if self._buffer else None

    def peek_batch(self, max_count: int) -> List[T]:
        """
        Return up to max_count oldest items without removing them.

        Args:
            max_count: Maximum number of items to return

        Returns:
            List of items (may be shorter than max_count)
        """
        with self._lock:
            count = min(len(self._buffer), max_count)
            return list(self._buffer)[:count]


class MultiBufferAggregator:
    """
    Aggregates frames from multiple ring buffers.

    Used to collect frames from multiple CAN buses into a single
    stream for processing.
    """

    def __init__(self):
        self._buffers: dict[int, RingBuffer[CANFrame]] = {}
        self._lock = threading.Lock()

    def add_buffer(self, bus_id: int, buffer: RingBuffer[CANFrame]) -> None:
        """Register a buffer for a bus."""
        with self._lock:
            self._buffers[bus_id] = buffer

    def remove_buffer(self, bus_id: int) -> None:
        """Unregister a buffer."""
        with self._lock:
            self._buffers.pop(bus_id, None)

    def pop_all_merged(self) -> List[CANFrame]:
        """
        Pop all frames from all buffers, sorted by timestamp.

        Returns:
            All frames from all buses, sorted by timestamp
        """
        all_frames: List[CANFrame] = []

        with self._lock:
            for buffer in self._buffers.values():
                all_frames.extend(buffer.pop_all())

        # Sort by timestamp for proper ordering
        all_frames.sort(key=lambda f: f.timestamp_ns)
        return all_frames

    def pop_batch_merged(self, max_per_buffer: int = 1000) -> List[CANFrame]:
        """
        Pop batch from each buffer, merged and sorted.

        Args:
            max_per_buffer: Maximum frames to pop from each buffer

        Returns:
            Merged frames sorted by timestamp
        """
        all_frames: List[CANFrame] = []

        with self._lock:
            for buffer in self._buffers.values():
                all_frames.extend(buffer.pop_batch(max_per_buffer))

        all_frames.sort(key=lambda f: f.timestamp_ns)
        return all_frames

    def total_pending(self) -> int:
        """Get total number of pending frames across all buffers."""
        with self._lock:
            return sum(len(b) for b in self._buffers.values())

    def get_stats(self) -> dict[int, BufferStats]:
        """Get statistics for all buffers."""
        with self._lock:
            return {bus_id: buf.stats for bus_id, buf in self._buffers.items()}
