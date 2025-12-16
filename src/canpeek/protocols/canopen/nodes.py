"""
CANopen node manager.

Tracks discovered CANopen nodes and their states.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Callable
from uuid import UUID
import time

from canpeek.core.types import CANFrame
from canpeek.protocols.canopen.decoder import (
    decode_frame,
    CANopenMessage,
    NMTState,
    get_node_id,
    is_canopen_frame,
)


@dataclass
class CANopenNode:
    """Represents a discovered CANopen node."""
    node_id: int
    connection_id: Optional[UUID] = None

    # State tracking
    state: NMTState = NMTState.PRE_OPERATIONAL
    last_heartbeat_time: float = 0.0
    heartbeat_interval_ms: Optional[float] = None

    # Statistics
    message_count: int = 0
    error_count: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # Device info (from EDS or SDO)
    vendor_id: Optional[int] = None
    product_code: Optional[int] = None
    device_name: str = ""

    def update_heartbeat(self, nmt_state: NMTState) -> None:
        """Update from heartbeat message."""
        now = time.time()

        # Calculate heartbeat interval
        if self.last_heartbeat_time > 0:
            delta = now - self.last_heartbeat_time
            self.heartbeat_interval_ms = delta * 1000

        self.last_heartbeat_time = now
        self.last_seen = now
        self.state = nmt_state
        self.message_count += 1

    def update_message(self) -> None:
        """Update from any message."""
        self.last_seen = time.time()
        self.message_count += 1

    def update_error(self) -> None:
        """Update from emergency message."""
        self.last_seen = time.time()
        self.error_count += 1
        self.message_count += 1

    @property
    def state_name(self) -> str:
        """Get human-readable state name."""
        state_names = {
            NMTState.BOOT_UP: "Boot-up",
            NMTState.STOPPED: "Stopped",
            NMTState.OPERATIONAL: "Operational",
            NMTState.PRE_OPERATIONAL: "Pre-operational",
        }
        return state_names.get(self.state, f"Unknown (0x{self.state:02X})")

    @property
    def display_name(self) -> str:
        """Get display name for the node."""
        if self.device_name:
            return f"Node {self.node_id}: {self.device_name}"
        return f"Node {self.node_id}"

    @property
    def is_alive(self) -> bool:
        """Check if node has been seen recently (within 5 seconds)."""
        return (time.time() - self.last_seen) < 5.0


class CANopenNodeManager:
    """
    Manages discovered CANopen nodes.

    Processes CAN frames to discover and track CANopen nodes,
    maintaining their state and statistics.
    """

    def __init__(self):
        # Nodes by (connection_id, node_id)
        self._nodes: dict[tuple[Optional[UUID], int], CANopenNode] = {}

        # Callbacks
        self.on_node_discovered: Optional[Callable[[CANopenNode], None]] = None
        self.on_node_state_changed: Optional[Callable[[CANopenNode], None]] = None
        self.on_node_error: Optional[Callable[[CANopenNode, CANopenMessage], None]] = None

    def process_frame(self, frame: CANFrame) -> Optional[CANopenMessage]:
        """
        Process a CAN frame and update node tracking.

        Returns decoded CANopen message if applicable.
        """
        if not is_canopen_frame(frame):
            return None

        msg = decode_frame(frame)
        if msg is None:
            return None

        # Track node if message has a node ID
        if msg.node_id is not None:
            self._update_node(frame.connection_id, msg)

        return msg

    def process_frames(self, frames: list[CANFrame]) -> list[CANopenMessage]:
        """Process multiple frames, returning decoded messages."""
        messages = []
        for frame in frames:
            msg = self.process_frame(frame)
            if msg is not None:
                messages.append(msg)
        return messages

    def _update_node(self, connection_id: Optional[UUID], msg: CANopenMessage) -> None:
        """Update or create node from message."""
        key = (connection_id, msg.node_id)

        # Get or create node
        if key not in self._nodes:
            node = CANopenNode(
                node_id=msg.node_id,
                connection_id=connection_id,
            )
            self._nodes[key] = node

            # Notify discovery
            if self.on_node_discovered:
                self.on_node_discovered(node)
        else:
            node = self._nodes[key]

        # Update based on message type
        old_state = node.state

        if msg.function == "HEARTBEAT" and msg.nmt_state is not None:
            node.update_heartbeat(msg.nmt_state)

            # Notify state change
            if old_state != node.state and self.on_node_state_changed:
                self.on_node_state_changed(node)

        elif msg.function == "EMCY":
            node.update_error()

            # Notify error
            if self.on_node_error:
                self.on_node_error(node, msg)

        else:
            node.update_message()

    def get_node(self, connection_id: Optional[UUID], node_id: int) -> Optional[CANopenNode]:
        """Get a specific node."""
        return self._nodes.get((connection_id, node_id))

    def get_all_nodes(self) -> list[CANopenNode]:
        """Get all discovered nodes."""
        return list(self._nodes.values())

    def get_nodes_for_connection(self, connection_id: Optional[UUID]) -> list[CANopenNode]:
        """Get all nodes for a specific connection."""
        return [
            node for (cid, _), node in self._nodes.items()
            if cid == connection_id
        ]

    def get_alive_nodes(self) -> list[CANopenNode]:
        """Get all nodes that are still alive."""
        return [node for node in self._nodes.values() if node.is_alive]

    def clear(self) -> None:
        """Clear all discovered nodes."""
        self._nodes.clear()

    def clear_connection(self, connection_id: Optional[UUID]) -> None:
        """Clear nodes for a specific connection."""
        keys_to_remove = [
            key for key in self._nodes.keys()
            if key[0] == connection_id
        ]
        for key in keys_to_remove:
            del self._nodes[key]

    @property
    def node_count(self) -> int:
        """Get total number of discovered nodes."""
        return len(self._nodes)
