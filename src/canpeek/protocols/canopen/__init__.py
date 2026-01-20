"""
CANopen protocol support.

Provides CANopen message decoding and node management.
"""

from canpeek.protocols.canopen.decoder import (
    CANopenFunction,
    CANopenMessage,
    NMTCommand,
    NMTState,
    SDOCommand,
    decode_frame,
    is_canopen_frame,
    get_node_id,
    get_function_code,
    format_canopen_short,
    format_canopen_full,
)
from canpeek.protocols.canopen.nodes import (
    CANopenNode,
    CANopenNodeManager,
)
from canpeek.protocols.canopen.object_dictionary import (
    ObjectDictionaryWrapper,
    ODEntry,
    ODIndex,
)
from canpeek.protocols.canopen.sdo_client import (
    SdoClient,
    SdoAbortError,
    SdoTimeoutError,
)

__all__ = [
    # Decoder
    "CANopenFunction",
    "CANopenMessage",
    "NMTCommand",
    "NMTState",
    "SDOCommand",
    "decode_frame",
    "is_canopen_frame",
    "get_node_id",
    "get_function_code",
    "format_canopen_short",
    "format_canopen_full",
    # Nodes
    "CANopenNode",
    "CANopenNodeManager",
    # Object Dictionary
    "ObjectDictionaryWrapper",
    "ODEntry",
    "ODIndex",
    # SDO Client
    "SdoClient",
    "SdoAbortError",
    "SdoTimeoutError",
]
