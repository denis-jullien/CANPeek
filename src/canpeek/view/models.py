from __future__ import annotations

from typing import List
import cantools


from canpeek.data_utils import CANFrame, DBCFile
from canpeek.co.canopen_utils import CANopenDecoder
from canpeek.view.decoders import DecodingResult, SignalInfo


# --- Helper Function for Decoding ---


def get_structured_decodings(
    frame: CANFrame,
    dbc_files: List[DBCFile],
    pdo_databases: List[cantools.db.Database],
    canopen_enabled: bool,
) -> List[DecodingResult]:
    """
    Decodes a CAN frame from all available sources and returns structured results.

    This is the centralized decoding function.
    """
    results: List[DecodingResult] = []

    def _process_database(db: cantools.db.Database, source_name: str) -> None:
        """Helper to decode from a cantools database and append to results."""
        try:
            message = db.get_message_by_frame_id(frame.arbitration_id)
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
                    source=source_name, name=message.name, signals=signal_infos
                )
            )
        except (KeyError, ValueError):
            pass  # Frame not in this database

    # 1. Process regular DBCs
    for dbc in dbc_files:
        if dbc.connection_id is None or dbc.connection_id == frame.connection_id:
            _process_database(dbc.database, "DBC")

    # 2. Process CANopen PDO databases
    for db in pdo_databases:
        _process_database(db, "PDO")

    # 3. Process generic CANopen
    if canopen_enabled:
        if co_info := CANopenDecoder.decode(frame):
            # The 'CANopen Type' becomes the name, the rest are signals
            canopen_type = co_info.pop("CANopen Type", "Unknown")
            signal_infos = [
                SignalInfo(name=k, value=v, unit="") for k, v in co_info.items()
            ]
            results.append(
                DecodingResult(
                    source="CANopen", name=canopen_type, signals=signal_infos
                )
            )

    return results
