import threading

from typing import Dict, Optional

from dataclasses import dataclass
from canpeek.data_utils import CANFrame, DBCFile
from typing import List, Any
import cantools
import hashlib

# --- Data Structures ---


@dataclass
class SignalInfo:
    """Represents a single decoded signal or field."""

    name: str
    value: Any
    unit: str


@dataclass
class DecodingResult:
    """Represents the complete decoding of a message from a single source."""

    source: str  # e.g., "DBC", "PDO", "CANopen"
    name: str  # e.g., "EngineStatus", "TPDO1_Node5", "NMT"
    signals: List[SignalInfo]


class CachedDBCDecoder:
    """DBC decoder with message and decoding caching to avoid repeated database lookups."""

    def __init__(self):
        self.dbc_files: List[DBCFile] = []
        self.pdo_databases: List[cantools.db.Database] = []
        self.canopen_enabled = False

        # Message cache: (frame_id, dbc_file_id) -> cantools.db.Message
        self._message_cache: Dict[tuple, cantools.db.Message] = {}
        self._message_cache_lock = threading.Lock()

        # Decoding cache: (frame_id, data_hash) -> List[DecodingResult]
        self._decoding_cache: Dict[tuple, List[DecodingResult]] = {}
        self._decoding_cache_lock = threading.Lock()

        # Cache size limits to prevent unbounded growth
        self._max_message_cache_size = 10000
        self._max_decoding_cache_size = 5000

    def set_dbc_files(self, dbc_files: List[DBCFile]):
        """Set DBC files and clear message cache."""
        self.dbc_files = dbc_files
        with self._message_cache_lock:
            self._message_cache.clear()
        with self._decoding_cache_lock:
            self._decoding_cache.clear()

    def set_pdo_databases(self, pdo_databases: List[cantools.db.Database]):
        """Set PDO databases and clear message cache."""
        self.pdo_databases = pdo_databases
        with self._message_cache_lock:
            self._message_cache.clear()
        with self._decoding_cache_lock:
            self._decoding_cache.clear()

    def set_canopen_enabled(self, enabled: bool):
        """Enable/disable CANopen decoding."""
        self.canopen_enabled = enabled
        if not enabled:
            # Clear decoding cache when disabling CANopen
            with self._decoding_cache_lock:
                self._decoding_cache.clear()

    def _get_cached_message(
        self, frame_id: int, database: cantools.db.Database, db_id: str
    ) -> Optional[cantools.db.Message]:
        """Get cached message or fetch and cache it."""
        cache_key = (frame_id, db_id)

        with self._message_cache_lock:
            if cache_key in self._message_cache:
                return self._message_cache[cache_key]

            # Fetch message from database
            try:
                message = database.get_message_by_frame_id(frame_id)

                # Cache the message if we haven't exceeded the limit
                if len(self._message_cache) < self._max_message_cache_size:
                    self._message_cache[cache_key] = message
                else:
                    # Remove oldest entries to make room (simple FIFO)
                    oldest_key = next(iter(self._message_cache))
                    del self._message_cache[oldest_key]
                    self._message_cache[cache_key] = message

                return message
            except (KeyError, ValueError):
                return None

    def _get_data_hash(self, data: bytes) -> str:
        """Generate hash for data payload."""
        return hashlib.md5(data).hexdigest()

    def decode_frame(self, frame: CANFrame) -> List[DecodingResult]:
        """Decode a CAN frame using cached DBC lookups."""
        frame_id = frame.arbitration_id
        data_hash = self._get_data_hash(frame.data)
        cache_key = (frame_id, data_hash)

        # Check decoding cache first
        with self._decoding_cache_lock:
            if cache_key in self._decoding_cache:
                return self._decoding_cache[cache_key]

        # Perform actual decoding
        results = self._decode_frame_uncached(frame)

        # Cache the results
        with self._decoding_cache_lock:
            if len(self._decoding_cache) < self._max_decoding_cache_size:
                self._decoding_cache[cache_key] = results
            else:
                # Remove oldest entries to make room (simple FIFO)
                oldest_key = next(iter(self._decoding_cache))
                del self._decoding_cache[oldest_key]
                self._decoding_cache[cache_key] = results

        return results

    def _decode_frame_uncached(self, frame: CANFrame) -> List[DecodingResult]:
        """Perform actual decoding without caching."""
        results: List[DecodingResult] = []

        # 1. Process regular DBCs
        for dbc in self.dbc_files:
            if dbc.connection_id is None or dbc.connection_id == frame.connection_id:
                db_id = f"dbc_{id(dbc.database)}"
                message = self._get_cached_message(
                    frame.arbitration_id, dbc.database, db_id
                )
                if message:
                    try:
                        decoded_signals = dbc.database.decode_message(
                            frame.arbitration_id, frame.data, decode_choices=False
                        )

                        signal_infos = [
                            SignalInfo(
                                name=s.name,
                                value=decoded_signals.get(s.name, "N/A"),
                                unit=s.unit or "",
                            )
                            for s in message.signals
                        ]

                        results.append(
                            DecodingResult(
                                source="DBC", name=message.name, signals=signal_infos
                            )
                        )
                    except (ValueError, Exception):
                        pass  # Decoding failed

        # 2. Process CANopen PDO databases
        for db in self.pdo_databases:
            db_id = f"pdo_{id(db)}"
            message = self._get_cached_message(frame.arbitration_id, db, db_id)
            if message:
                try:
                    decoded_signals = db.decode_message(
                        frame.arbitration_id, frame.data, decode_choices=False
                    )

                    signal_infos = [
                        SignalInfo(
                            name=s.name,
                            value=decoded_signals.get(s.name, "N/A"),
                            unit=s.unit or "",
                        )
                        for s in message.signals
                    ]

                    results.append(
                        DecodingResult(
                            source="PDO", name=message.name, signals=signal_infos
                        )
                    )
                except (ValueError, Exception):
                    pass  # Decoding failed

        # 3. Process generic CANopen
        if self.canopen_enabled:
            try:
                from .co.canopen_utils import CANopenDecoder

                if co_info := CANopenDecoder.decode(frame):
                    canopen_type = co_info.pop("CANopen Type", "Unknown")
                    signal_infos = [
                        SignalInfo(name=k, value=v, unit="") for k, v in co_info.items()
                    ]
                    results.append(
                        DecodingResult(
                            source="CANopen", name=canopen_type, signals=signal_infos
                        )
                    )
            except (ImportError, Exception):
                pass  # CANopen decoding failed

        return results

    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics for monitoring."""
        with self._message_cache_lock:
            message_cache_size = len(self._message_cache)
        with self._decoding_cache_lock:
            decoding_cache_size = len(self._decoding_cache)

        return {
            "message_cache_size": message_cache_size,
            "decoding_cache_size": decoding_cache_size,
            "max_message_cache_size": self._max_message_cache_size,
            "max_decoding_cache_size": self._max_decoding_cache_size,
        }

    def clear_caches(self):
        """Clear both message and decoding caches."""
        with self._message_cache_lock:
            self._message_cache.clear()
        with self._decoding_cache_lock:
            self._decoding_cache.clear()
