"""
DBC decoder with caching for efficient signal decoding.

Uses cantools for DBC parsing and provides cached decoding
for high-performance real-time signal display.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional, Any
import threading

import cantools
from cantools.database import Database, Message

from canpeek.core.types import CANFrame


@dataclass
class SignalInfo:
    """Information about a signal."""
    name: str
    start_bit: int
    length: int
    byte_order: str
    is_signed: bool
    scale: float
    offset: float
    minimum: Optional[float]
    maximum: Optional[float]
    unit: str
    choices: Optional[dict[int, str]]


@dataclass
class MessageInfo:
    """Information about a message."""
    name: str
    arbitration_id: int
    length: int
    is_extended_id: bool
    signals: list[SignalInfo]
    comment: str


class DBCDecoder:
    """
    DBC decoder with caching for high-performance decoding.

    Features:
        - Loads multiple DBC files
        - Caches decoded signals per message ID
        - Thread-safe
        - Provides message and signal metadata

    Example:
        >>> decoder = DBCDecoder()
        >>> decoder.load_database("/path/to/file.dbc")
        >>> signals = decoder.decode(frame)
        >>> print(signals)  # {'EngineRPM': 3500, 'EngineTemp': 92}
    """

    def __init__(self, decode_cache_size: int = 10000):
        self._databases: list[Database] = []
        self._db_paths: list[str] = []
        self._message_cache: dict[int, Message] = {}
        self._lock = threading.Lock()

        # LRU cache for decoded values: (arb_id, data_bytes) -> decoded dict
        self._decode_cache_size = decode_cache_size
        self._decode_cache: dict[tuple[int, bytes], dict[str, Any]] = {}
        self._decode_cache_order: list[tuple[int, bytes]] = []

    def load_database(self, path: str) -> bool:
        """
        Load a DBC database file.

        Args:
            path: Path to .dbc, .arxml, or .kcd file

        Returns:
            True if loaded successfully
        """
        try:
            db = cantools.database.load_file(path)
            with self._lock:
                self._databases.append(db)
                self._db_paths.append(path)
                # Update message cache
                for msg in db.messages:
                    # Don't override existing messages (first loaded wins)
                    if msg.frame_id not in self._message_cache:
                        self._message_cache[msg.frame_id] = msg
            return True
        except Exception as e:
            print(f"Failed to load database {path}: {e}")
            return False

    def unload_database(self, path: str) -> bool:
        """Unload a database file."""
        with self._lock:
            try:
                idx = self._db_paths.index(path)
                db = self._databases[idx]

                # Remove messages from this database
                for msg in db.messages:
                    if self._message_cache.get(msg.frame_id) == msg:
                        del self._message_cache[msg.frame_id]

                del self._databases[idx]
                del self._db_paths[idx]

                # Rebuild cache from remaining databases
                self._rebuild_cache()
                return True
            except ValueError:
                return False

    def _rebuild_cache(self) -> None:
        """Rebuild message cache from all databases."""
        self._message_cache.clear()
        for db in self._databases:
            for msg in db.messages:
                if msg.frame_id not in self._message_cache:
                    self._message_cache[msg.frame_id] = msg

    def clear(self) -> None:
        """Unload all databases."""
        with self._lock:
            self._databases.clear()
            self._db_paths.clear()
            self._message_cache.clear()

    @property
    def loaded_databases(self) -> list[str]:
        """Get list of loaded database paths."""
        with self._lock:
            return list(self._db_paths)

    @property
    def message_count(self) -> int:
        """Get total number of known messages."""
        with self._lock:
            return len(self._message_cache)

    def get_message(self, arbitration_id: int) -> Optional[Message]:
        """Get message definition by ID."""
        with self._lock:
            return self._message_cache.get(arbitration_id)

    def get_message_info(self, arbitration_id: int) -> Optional[dict[str, Any]]:
        """Get message metadata."""
        msg = self.get_message(arbitration_id)
        if msg is None:
            return None

        return {
            "name": msg.name,
            "id": msg.frame_id,
            "length": msg.length,
            "is_extended_id": msg.is_extended_frame,
            "comment": msg.comment or "",
            "signals": [s.name for s in msg.signals],
        }

    def get_signal_info(self, arbitration_id: int, signal_name: str) -> Optional[dict[str, Any]]:
        """Get signal metadata."""
        msg = self.get_message(arbitration_id)
        if msg is None:
            return None

        for sig in msg.signals:
            if sig.name == signal_name:
                return {
                    "name": sig.name,
                    "start_bit": sig.start,
                    "length": sig.length,
                    "byte_order": sig.byte_order,
                    "is_signed": sig.is_signed,
                    "scale": sig.scale,
                    "offset": sig.offset,
                    "minimum": sig.minimum,
                    "maximum": sig.maximum,
                    "unit": sig.unit or "",
                    "choices": sig.choices,
                }
        return None

    def decode(self, frame: CANFrame) -> Optional[dict[str, Any]]:
        """
        Decode a CAN frame to signal values.

        Uses LRU cache for performance - same data returns cached result.

        Args:
            frame: CAN frame to decode

        Returns:
            Dictionary of signal_name -> value, or None if unknown message
        """
        cache_key = (frame.arbitration_id, frame.data)

        # Check cache first (fast path)
        if cache_key in self._decode_cache:
            return self._decode_cache[cache_key]

        msg = self.get_message(frame.arbitration_id)
        if msg is None:
            return None

        try:
            # Decode using cantools
            result = msg.decode(frame.data, decode_choices=True)

            # Add to cache with LRU eviction
            self._cache_put(cache_key, result)

            return result
        except Exception:
            return None

    def _cache_put(self, key: tuple[int, bytes], value: dict[str, Any]) -> None:
        """Add entry to decode cache with LRU eviction."""
        if key in self._decode_cache:
            # Move to end (most recent)
            self._decode_cache_order.remove(key)
            self._decode_cache_order.append(key)
            return

        # Evict oldest if at capacity
        while len(self._decode_cache) >= self._decode_cache_size:
            oldest = self._decode_cache_order.pop(0)
            del self._decode_cache[oldest]

        self._decode_cache[key] = value
        self._decode_cache_order.append(key)

    def clear_decode_cache(self) -> None:
        """Clear the decode cache."""
        self._decode_cache.clear()
        self._decode_cache_order.clear()

    def decode_with_units(self, frame: CANFrame) -> Optional[dict[str, tuple[Any, str]]]:
        """
        Decode a CAN frame to signal values with units.

        Returns:
            Dictionary of signal_name -> (value, unit)
        """
        msg = self.get_message(frame.arbitration_id)
        if msg is None:
            return None

        try:
            decoded = msg.decode(frame.data, decode_choices=True)
            result = {}
            for sig in msg.signals:
                if sig.name in decoded:
                    result[sig.name] = (decoded[sig.name], sig.unit or "")
            return result
        except Exception:
            return None

    def encode(self, arbitration_id: int, signals: dict[str, Any]) -> Optional[bytes]:
        """
        Encode signal values to CAN data bytes.

        Args:
            arbitration_id: Message ID
            signals: Dictionary of signal_name -> value

        Returns:
            Encoded data bytes, or None if unknown message
        """
        msg = self.get_message(arbitration_id)
        if msg is None:
            return None

        try:
            return msg.encode(signals)
        except Exception:
            return None

    def get_all_messages(self) -> list[dict[str, Any]]:
        """Get info for all known messages."""
        with self._lock:
            result = []
            for msg in self._message_cache.values():
                result.append({
                    "name": msg.name,
                    "id": msg.frame_id,
                    "length": msg.length,
                    "is_extended_id": msg.is_extended_frame,
                    "signal_count": len(msg.signals),
                })
            return sorted(result, key=lambda m: m["id"])

    def format_decoded(self, decoded: dict[str, Any], arbitration_id: int) -> str:
        """Format decoded signals as a string."""
        if not decoded:
            return ""

        msg = self.get_message(arbitration_id)
        if msg is None:
            return " ".join(f"{k}={v}" for k, v in decoded.items())

        parts = []
        for sig in msg.signals:
            if sig.name in decoded:
                value = decoded[sig.name]
                if sig.unit:
                    parts.append(f"{sig.name}={value}{sig.unit}")
                else:
                    parts.append(f"{sig.name}={value}")

        return " ".join(parts)
