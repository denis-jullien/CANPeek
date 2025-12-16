# CANPeek v2 - High-Performance CAN/CAN FD Analyzer

## Project Overview

A professional-grade CAN bus analyzer with high-performance multi-bus support, inspired by PCAN-Explorer's UI layout while maintaining cross-platform compatibility.

### Goals
- Handle 3+ CAN FD buses simultaneously at full load (~30k msg/sec total)
- Professional UI with PCAN-Explorer-style project tree and docking
- Advanced SocketCAN integration with bus management
- Real-time signal decoding with minimal latency

---

## 1. Architecture Overview

### 1.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CANPeek v2 Architecture                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    CAN Reception Layer                           │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐                       │   │
│  │  │ Bus 1    │  │ Bus 2    │  │ Bus 3+   │   Dedicated threads   │   │
│  │  │ Reader   │  │ Reader   │  │ Reader   │   per interface       │   │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘                       │   │
│  │       │             │             │                              │   │
│  │       └─────────────┼─────────────┘                              │   │
│  │                     ▼                                            │   │
│  │         ┌───────────────────────┐                               │   │
│  │         │   Lock-free Queues    │   Per-bus ring buffers        │   │
│  │         │   (Multi-producer)    │   ~100k frame capacity        │   │
│  │         └───────────┬───────────┘                               │   │
│  └─────────────────────┼───────────────────────────────────────────┘   │
│                        │                                                │
│  ┌─────────────────────┼───────────────────────────────────────────┐   │
│  │                     ▼                                            │   │
│  │         ┌───────────────────────┐                               │   │
│  │         │   Processing Layer    │   Background thread           │   │
│  │         │   - Filtering         │   - Batch processing          │   │
│  │         │   - Grouping          │   - Decode caching            │   │
│  │         │   - Statistics        │   - Worker pool               │   │
│  │         └───────────┬───────────┘                               │   │
│  └─────────────────────┼───────────────────────────────────────────┘   │
│                        │                                                │
│  ┌─────────────────────┼───────────────────────────────────────────┐   │
│  │                     ▼                                            │   │
│  │         ┌───────────────────────┐                               │   │
│  │         │   GUI Layer (Qt)      │   Main thread only            │   │
│  │         │   - View updates      │   - Pre-computed data         │   │
│  │         │   - User interaction  │   - Rate-limited refresh      │   │
│  │         └───────────────────────┘                               │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Threading Model

| Thread | Responsibility | Communication |
|--------|---------------|---------------|
| **Main (GUI)** | Qt event loop, UI updates | Receives processed data via signals |
| **Reader N** | CAN frame reception per bus | Writes to lock-free ring buffer |
| **Processor** | Filtering, grouping, decode | Reads buffers, emits to GUI |
| **Decoder Pool** | DBC signal decoding | Thread pool for parallel decode |
| **File I/O** | Log save/load | Background async operations |

---

## 2. Core Data Structures

### 2.1 CAN Frame

```python
from dataclasses import dataclass
from typing import Optional
import struct

# Flag bit positions
FLAG_EXTENDED_ID = 1 << 0
FLAG_FD_FRAME = 1 << 1
FLAG_BITRATE_SWITCH = 1 << 2
FLAG_ERROR_STATE_IND = 1 << 3
FLAG_REMOTE_FRAME = 1 << 4
FLAG_ERROR_FRAME = 1 << 5
FLAG_IS_RX = 1 << 6

@dataclass(slots=True, frozen=True)
class CANFrame:
    """Immutable CAN frame with efficient memory layout."""
    timestamp_ns: int       # Nanosecond precision timestamp
    arbitration_id: int     # 11-bit or 29-bit CAN ID
    data: bytes             # Up to 64 bytes for CAN FD
    dlc: int                # Data Length Code (0-15 for FD)
    flags: int              # Bit flags (see FLAG_* constants)
    bus_id: int             # Numeric bus identifier

    @property
    def is_extended_id(self) -> bool:
        return bool(self.flags & FLAG_EXTENDED_ID)

    @property
    def is_fd(self) -> bool:
        return bool(self.flags & FLAG_FD_FRAME)

    @property
    def is_brs(self) -> bool:
        return bool(self.flags & FLAG_BITRATE_SWITCH)

    @property
    def is_rx(self) -> bool:
        return bool(self.flags & FLAG_IS_RX)

    @property
    def timestamp(self) -> float:
        """Timestamp in seconds (for compatibility)."""
        return self.timestamp_ns / 1_000_000_000

    def to_bytes(self) -> bytes:
        """Serialize frame for storage/transmission."""
        header = struct.pack('<QIBBBxxx',  # 20 bytes header, padded
            self.timestamp_ns,
            self.arbitration_id,
            self.dlc,
            self.flags,
            self.bus_id
        )
        return header + self.data

    @classmethod
    def from_bytes(cls, data: bytes) -> 'CANFrame':
        """Deserialize frame from bytes."""
        ts, arb_id, dlc, flags, bus_id = struct.unpack('<QIBBBxxx', data[:20])
        return cls(ts, arb_id, data[20:20+dlc], dlc, flags, bus_id)
```

### 2.2 Ring Buffer

```python
import threading
from collections import deque
from typing import List, Optional

class LockFreeRingBuffer:
    """
    Thread-safe ring buffer for CAN frames.
    Single-producer, single-consumer optimized.
    """

    def __init__(self, capacity: int = 100_000):
        self.capacity = capacity
        self._buffer: deque[CANFrame] = deque(maxlen=capacity)
        self._lock = threading.Lock()  # Fallback for multi-consumer
        self._overflow_count = 0

    def push(self, frame: CANFrame) -> bool:
        """Add frame to buffer. Returns False if overflow."""
        if len(self._buffer) >= self.capacity:
            self._overflow_count += 1
            return False
        self._buffer.append(frame)
        return True

    def push_batch(self, frames: List[CANFrame]) -> int:
        """Add multiple frames. Returns count of dropped frames."""
        dropped = 0
        for frame in frames:
            if not self.push(frame):
                dropped += 1
        return dropped

    def pop_all(self) -> List[CANFrame]:
        """Atomically drain all frames from buffer."""
        with self._lock:
            frames = list(self._buffer)
            self._buffer.clear()
            return frames

    def pop_batch(self, max_count: int) -> List[CANFrame]:
        """Pop up to max_count frames."""
        with self._lock:
            count = min(len(self._buffer), max_count)
            return [self._buffer.popleft() for _ in range(count)]

    @property
    def overflow_count(self) -> int:
        return self._overflow_count

    def __len__(self) -> int:
        return len(self._buffer)
```

---

## 3. SocketCAN Integration

### 3.1 Features

| Feature | Description | Requires Sudo |
|---------|-------------|---------------|
| Interface discovery | List available CAN interfaces | No |
| Bus up/down | Bring interface up or down | Yes |
| Bitrate config | Set nominal bitrate | Yes |
| FD config | Set data bitrate, enable FD | Yes |
| Error frames | Receive error frames | No (if enabled) |
| Bus statistics | Read TX/RX counters, errors | No |
| Bus state | Active/Passive/Bus-off | No |
| Loopback | Enable local loopback | Yes |
| Listen-only | Receive without ACK | Yes |

### 3.2 SocketCAN Manager

```python
import subprocess
import os
import re
from dataclasses import dataclass
from typing import List, Optional, Dict
from enum import Enum
from pathlib import Path

class BusState(Enum):
    UNKNOWN = 0
    ERROR_ACTIVE = 1
    ERROR_WARNING = 2
    ERROR_PASSIVE = 3
    BUS_OFF = 4
    STOPPED = 5
    SLEEPING = 6

@dataclass
class CANInterfaceStats:
    """Statistics from /sys/class/net/<iface>/statistics/"""
    tx_packets: int = 0
    rx_packets: int = 0
    tx_bytes: int = 0
    rx_bytes: int = 0
    tx_errors: int = 0
    rx_errors: int = 0
    tx_dropped: int = 0
    rx_dropped: int = 0
    rx_overrun_errors: int = 0

@dataclass
class CANInterfaceInfo:
    """Complete CAN interface information."""
    name: str
    is_up: bool
    is_can_fd: bool
    bitrate: Optional[int]
    data_bitrate: Optional[int]  # For CAN FD
    state: BusState
    restart_ms: int
    txqueuelen: int
    stats: CANInterfaceStats
    driver: str
    hw_type: str

class SocketCANManager:
    """
    Manages SocketCAN interfaces with optional sudo elevation.
    """

    SYSFS_NET = Path("/sys/class/net")

    def __init__(self):
        self._sudo_password: Optional[str] = None
        self._sudo_validated = False

    def discover_interfaces(self) -> List[str]:
        """Find all CAN interfaces on the system."""
        interfaces = []
        for iface_path in self.SYSFS_NET.iterdir():
            type_file = iface_path / "type"
            if type_file.exists():
                try:
                    iface_type = int(type_file.read_text().strip())
                    # ARPHRD_CAN = 280
                    if iface_type == 280:
                        interfaces.append(iface_path.name)
                except (ValueError, PermissionError):
                    pass
        return sorted(interfaces)

    def get_interface_info(self, iface: str) -> Optional[CANInterfaceInfo]:
        """Get detailed information about a CAN interface."""
        try:
            result = subprocess.run(
                ['ip', '-details', 'link', 'show', iface],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return None

            output = result.stdout

            # Parse interface state
            is_up = 'state UP' in output or ',UP,' in output

            # Parse CAN-specific details
            is_fd = 'fd on' in output.lower()

            # Extract bitrate
            bitrate_match = re.search(r'bitrate\s+(\d+)', output)
            bitrate = int(bitrate_match.group(1)) if bitrate_match else None

            # Extract data bitrate (FD)
            dbitrate_match = re.search(r'dbitrate\s+(\d+)', output)
            data_bitrate = int(dbitrate_match.group(1)) if dbitrate_match else None

            # Extract state
            state = BusState.UNKNOWN
            state_match = re.search(r'state\s+(ERROR-ACTIVE|ERROR-WARNING|ERROR-PASSIVE|BUS-OFF|STOPPED|SLEEPING)', output)
            if state_match:
                state_map = {
                    'ERROR-ACTIVE': BusState.ERROR_ACTIVE,
                    'ERROR-WARNING': BusState.ERROR_WARNING,
                    'ERROR-PASSIVE': BusState.ERROR_PASSIVE,
                    'BUS-OFF': BusState.BUS_OFF,
                    'STOPPED': BusState.STOPPED,
                    'SLEEPING': BusState.SLEEPING,
                }
                state = state_map.get(state_match.group(1), BusState.UNKNOWN)

            # Extract restart-ms
            restart_match = re.search(r'restart-ms\s+(\d+)', output)
            restart_ms = int(restart_match.group(1)) if restart_match else 0

            # Get statistics
            stats = self._read_statistics(iface)

            return CANInterfaceInfo(
                name=iface,
                is_up=is_up,
                is_can_fd=is_fd,
                bitrate=bitrate,
                data_bitrate=data_bitrate,
                state=state,
                restart_ms=restart_ms,
                txqueuelen=1000,  # Default
                stats=stats,
                driver=self._get_driver(iface),
                hw_type=self._get_hw_type(iface),
            )
        except Exception as e:
            print(f"Error getting interface info for {iface}: {e}")
            return None

    def _read_statistics(self, iface: str) -> CANInterfaceStats:
        """Read interface statistics from sysfs."""
        stats_path = self.SYSFS_NET / iface / "statistics"
        stats = CANInterfaceStats()

        stat_files = [
            ('tx_packets', 'tx_packets'),
            ('rx_packets', 'rx_packets'),
            ('tx_bytes', 'tx_bytes'),
            ('rx_bytes', 'rx_bytes'),
            ('tx_errors', 'tx_errors'),
            ('rx_errors', 'rx_errors'),
            ('tx_dropped', 'tx_dropped'),
            ('rx_dropped', 'rx_dropped'),
            ('rx_over_errors', 'rx_overrun_errors'),
        ]

        for file_name, attr_name in stat_files:
            try:
                value = int((stats_path / file_name).read_text().strip())
                setattr(stats, attr_name, value)
            except (FileNotFoundError, ValueError, PermissionError):
                pass

        return stats

    def _get_driver(self, iface: str) -> str:
        """Get the driver name for the interface."""
        driver_link = self.SYSFS_NET / iface / "device" / "driver"
        try:
            return driver_link.resolve().name
        except (FileNotFoundError, PermissionError):
            return "unknown"

    def _get_hw_type(self, iface: str) -> str:
        """Determine hardware type (virtual, USB, PCI, etc.)."""
        device_path = self.SYSFS_NET / iface / "device"
        if not device_path.exists():
            return "virtual"

        # Check for USB
        if (device_path / "..").resolve().name.startswith("usb"):
            return "usb"

        # Check for PCI
        try:
            subsystem = (device_path / "subsystem").resolve().name
            return subsystem
        except:
            return "unknown"

    # --- Sudo operations ---

    def request_sudo(self, password: str) -> bool:
        """Validate sudo password."""
        try:
            result = subprocess.run(
                ['sudo', '-S', '-v'],
                input=password + '\n',
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                self._sudo_password = password
                self._sudo_validated = True
                return True
        except Exception:
            pass
        return False

    def _run_sudo(self, cmd: List[str]) -> subprocess.CompletedProcess:
        """Run a command with sudo."""
        if not self._sudo_validated:
            raise PermissionError("Sudo not validated. Call request_sudo() first.")

        full_cmd = ['sudo', '-S'] + cmd
        return subprocess.run(
            full_cmd,
            input=self._sudo_password + '\n',
            capture_output=True,
            text=True,
            timeout=30
        )

    def set_interface_up(self, iface: str) -> bool:
        """Bring interface up."""
        result = self._run_sudo(['ip', 'link', 'set', iface, 'up'])
        return result.returncode == 0

    def set_interface_down(self, iface: str) -> bool:
        """Bring interface down."""
        result = self._run_sudo(['ip', 'link', 'set', iface, 'down'])
        return result.returncode == 0

    def configure_interface(
        self,
        iface: str,
        bitrate: int,
        data_bitrate: Optional[int] = None,
        fd: bool = False,
        listen_only: bool = False,
        loopback: bool = False,
        restart_ms: int = 100,
    ) -> bool:
        """Configure CAN interface parameters."""
        # Must be down to configure
        self.set_interface_down(iface)

        cmd = ['ip', 'link', 'set', iface, 'type', 'can', 'bitrate', str(bitrate)]

        if fd and data_bitrate:
            cmd.extend(['dbitrate', str(data_bitrate), 'fd', 'on'])

        if listen_only:
            cmd.extend(['listen-only', 'on'])

        if loopback:
            cmd.extend(['loopback', 'on'])

        cmd.extend(['restart-ms', str(restart_ms)])

        result = self._run_sudo(cmd)
        return result.returncode == 0

    def create_vcan(self, name: str = "vcan0") -> bool:
        """Create a virtual CAN interface."""
        # Load vcan module
        self._run_sudo(['modprobe', 'vcan'])

        # Create interface
        result = self._run_sudo([
            'ip', 'link', 'add', 'dev', name, 'type', 'vcan'
        ])

        if result.returncode != 0 and 'exists' not in result.stderr:
            return False

        # Bring up
        return self.set_interface_up(name)

    def delete_vcan(self, name: str) -> bool:
        """Delete a virtual CAN interface."""
        self.set_interface_down(name)
        result = self._run_sudo(['ip', 'link', 'delete', name])
        return result.returncode == 0
```

### 3.3 Sudo Dialog

```python
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QMessageBox
)
from PySide6.QtCore import Qt

class SudoDialog(QDialog):
    """Dialog to request sudo password for privileged operations."""

    def __init__(self, parent=None, operation: str = "configure CAN interfaces"):
        super().__init__(parent)
        self.setWindowTitle("Administrator Privileges Required")
        self.setModal(True)
        self.setMinimumWidth(400)

        layout = QVBoxLayout(self)

        # Info label
        info = QLabel(
            f"CANPeek needs administrator privileges to {operation}.\n\n"
            "Please enter your password:"
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        # Password field
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Password")
        self.password_edit.returnPressed.connect(self.accept)
        layout.addWidget(self.password_edit)

        # Buttons
        btn_layout = QHBoxLayout()
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        self.ok_btn = QPushButton("Authenticate")
        self.ok_btn.setDefault(True)
        self.ok_btn.clicked.connect(self.accept)
        btn_layout.addStretch()
        btn_layout.addWidget(self.cancel_btn)
        btn_layout.addWidget(self.ok_btn)
        layout.addLayout(btn_layout)

    def get_password(self) -> Optional[str]:
        """Show dialog and return password if accepted."""
        if self.exec() == QDialog.Accepted:
            return self.password_edit.text()
        return None
```

---

## 4. UI Layout (PCAN-Explorer Style)

### 4.1 Main Window Structure

```
┌────────────────────────────────────────────────────────────────────────────┐
│ File  Connections  Edit  Transmit  View  Project  Trace  Tools  Window Help│
├────────────────────────────────────────────────────────────────────────────┤
│ [🔌 Connect][⏹ Stop][🗑️ Clear][💾 Save][📂 Load][⚙️]     [🔍 Filter    ] │
├──────────────────────────────────────────────────────┬─────────────────────┤
│ ┌────────────────────────────────────────────────┐   │ Project Manager     │
│ │ 📊 Receive  [can0 ▼][can1][All][+]            │   │ ─────────────────── │
│ ├────────────────────────────────────────────────┤   │ 📁 Connections      │
│ │▼│ ID    │ Symbol      │ Data        │ Cycle   │   │   ├─ ✓ can0 (500k) │
│ │─┼───────┼─────────────┼─────────────┼─────────│   │   └─ ✓ can1 (1M)   │
│ │▼│ 0x100 │EngineStatus │ 12 34 56 78 │ 10.0 ms │   │ 📁 Message Filters  │
│ │ │       │EngineRPM    │ 3500 rpm    │         │   │   └─ Powertrain    │
│ │ │       │EngineTemp   │ 92 °C       │         │   │ 📁 Databases        │
│ │ │       │ThrottlePos  │ 45.2 %      │         │   │   └─ Engine.dbc    │
│ │▶│ 0x200 │VehicleSpeed │ AA BB       │ 20.0 ms │   │ 📁 Signals          │
│ │ │ 0x7DF │UDS_Request  │ 02 10 01    │ -       │   │   ├─ EngineRPM     │
│ └────────────────────────────────────────────────┘   │   └─ Speed         │
├──────────────────────────────────────────────────────┤ ─────────────────── │
│ ┌────────────────────────────────────────────────┐   │ Properties          │
│ │ 📜 Trace                      [⏸ Pause][Auto ✓]│   │ ─────────────────── │
│ ├────────────────────────────────────────────────┤   │ Name: EngineRPM     │
│ │ Time     │Bus │ ID  │DLC│ Data          │Decode│   │ Message: 0x100      │
│ │ 0.001234 │can0│0x100│ 8 │12 34 56 78 9A │...   │   │ Start: 0            │
│ │ 0.001456 │can1│0x200│ 2 │AA BB          │...   │   │ Length: 16          │
│ │ 0.002100 │can0│0x100│ 8 │12 35 56 78 9A │...   │   │ Factor: 0.25        │
│ └────────────────────────────────────────────────┘   │ Unit: rpm           │
├──────────────────────────────────────────────────────┴─────────────────────┤
│ ┌─ Transmit ─────────────────────────────────────────────────────────────┐ │
│ │ On│ ID    │ Symbol      │ DLC│ Data           │ Cycle│ Send │ Sent     │ │
│ │ ☐ │ 0x123 │ TestMsg     │ 8  │ 00 00 00 00... │ 100  │ [▶]  │ 0        │ │
│ └────────────────────────────────────────────────────────────────────────┘ │
├────────────────────────────────────────────────────────────────────────────┤
│ 🟢 can0: Active 500k/2M │ 🟢 can1: Active 1M │ Frames: 12,456 │ 0 errors  │
└────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Project Tree Structure

```
📁 Project: MyProject.cpeek
├── 🔌 Connections
│   ├── ✓ can0 - PCAN-USB Pro FD
│   │     ├── Bitrate: 500 kbit/s
│   │     ├── Data Rate: 2 Mbit/s (FD)
│   │     ├── State: 🟢 Error-Active
│   │     └── Mode: Normal
│   ├── ✓ can1 - SocketCAN (vcan0)
│   │     └── State: 🟢 Active
│   └── ○ can2 - Kvaser Leaf (Disabled)
│
├── 🔍 Message Filters
│   ├── ✓ Powertrain (0x100-0x1FF) → can0
│   ├── ✓ Chassis (0x200-0x2FF) → can1
│   └── ○ Diagnostics (0x700-0x7FF) [Disabled]
│
├── 📚 Databases
│   ├── 📄 Powertrain.dbc → can0
│   │     ├── EngineStatus (0x100)
│   │     ├── TransmissionStatus (0x120)
│   │     └── ... (15 messages)
│   ├── 📄 Chassis.dbc → can1
│   └── 📄 Body.dbc → All buses
│
├── 📊 Signals (Live Values)
│   ├── 📁 Powertrain.dbc
│   │   ├── EngineRPM: 3500 rpm
│   │   ├── EngineTemp: 92 °C
│   │   └── ThrottlePos: 45.2 %
│   └── 📁 Chassis.dbc
│       └── VehicleSpeed: 120 km/h
│
└── 🔧 CANopen
    ├── 📁 can0
    │   ├── Node 1: Motor.eds
    │   │     ├── State: Operational
    │   │     └── Heartbeat: 100 ms
    │   └── Node 5: IO.dcf
    └── 📁 can1
        └── Node 2: Sensor.eds
```

### 4.3 Grouped Receive View Columns

| Column | Description | Width | Sortable |
|--------|-------------|-------|----------|
| Expand | +/- for signals | 20px | No |
| Type | Icon (Msg/Signal/FD) | 30px | No |
| ID | CAN ID (hex) | 70px | Yes |
| Bus | Interface name | 60px | Yes |
| Symbol | Message/Signal name | 150px | Yes |
| DLC | Data length | 40px | Yes |
| Data/Value | Raw hex or decoded | 200px | No |
| Unit | Signal unit | 60px | No |
| Cycle | Measured cycle time | 70px | Yes |
| Count | Reception count | 60px | Yes |

---

## 5. Performance Requirements

### 5.1 Throughput Targets

| Scenario | Requirement |
|----------|-------------|
| Single CAN 2.0 @ 500kbit/s | 8,000 msg/sec |
| Single CAN FD @ 1M/4M | 15,000 msg/sec |
| 3x CAN FD @ 1M/8M | 30,000 msg/sec total |
| Peak burst (100ms) | 50,000 msg/sec |

### 5.2 Latency Targets

| Metric | Target |
|--------|--------|
| Frame reception to buffer | < 100 µs |
| Buffer to GUI update | < 50 ms |
| Filter evaluation | < 1 µs per frame |
| DBC decode (cached) | < 10 µs per frame |
| DBC decode (cold) | < 100 µs per frame |

### 5.3 Memory Targets

| Component | Target |
|-----------|--------|
| Per-frame overhead | < 100 bytes |
| 1M frames in memory | < 500 MB |
| DBC with 1000 signals | < 10 MB |
| Idle application | < 100 MB |

### 5.4 CPU Targets (4-core system)

| State | Target |
|-------|--------|
| Idle (connected, no traffic) | < 5% |
| Low traffic (1k msg/sec) | < 15% |
| High traffic (30k msg/sec) | < 50% |
| Peak burst handling | < 80% |

---

## 6. Technology Stack

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Language | Python 3.11+ | Type hints, performance |
| GUI Framework | PySide6 | Qt 6, official binding |
| Docking | Qt-Advanced-Docking | Flexible layout |
| CAN Library | python-can 4.5+ | Wide hardware support |
| Async | asyncio + threading | Hybrid approach |
| DBC Parsing | cantools | Robust, maintained |
| CANopen | canopen library | Protocol support |
| Data Storage | NumPy (optional) | Vectorized ops |
| Caching | functools.lru_cache | Built-in, simple |
| Config | JSON | Human-readable |

---

## 7. Directory Structure

```
canpeek2/
├── src/
│   └── canpeek/
│       ├── __init__.py
│       ├── __main__.py              # Entry point
│       ├── app.py                   # QApplication setup
│       │
│       ├── core/                    # High-performance backend
│       │   ├── __init__.py
│       │   ├── types.py             # CANFrame, enums, constants
│       │   ├── buffer.py            # Ring buffer implementation
│       │   ├── bus_manager.py       # Multi-bus manager
│       │   ├── reader.py            # Async CAN reader
│       │   ├── decoder.py           # Cached DBC decoder
│       │   ├── filter.py            # Frame filtering
│       │   └── processor.py         # Background processor
│       │
│       ├── socketcan/               # SocketCAN integration
│       │   ├── __init__.py
│       │   ├── manager.py           # SocketCAN manager
│       │   ├── netlink.py           # Netlink interface (optional)
│       │   └── statistics.py        # Stats monitoring
│       │
│       ├── models/                  # Qt Models
│       │   ├── __init__.py
│       │   ├── trace_model.py       # Trace view model
│       │   ├── grouped_model.py     # Grouped view model
│       │   ├── project_model.py     # Project tree model
│       │   └── connection_model.py  # Connection list model
│       │
│       ├── ui/                      # UI Components
│       │   ├── __init__.py
│       │   ├── main_window.py       # Main window
│       │   ├── widgets/
│       │   │   ├── __init__.py
│       │   │   ├── receive_view.py  # Grouped receive widget
│       │   │   ├── trace_view.py    # Trace table widget
│       │   │   ├── project_tree.py  # Project manager
│       │   │   ├── properties.py    # Properties panel
│       │   │   ├── transmit.py      # Transmit panel
│       │   │   └── hardware.py      # Hardware panel
│       │   └── dialogs/
│       │       ├── __init__.py
│       │       ├── sudo_dialog.py   # Sudo authentication
│       │       ├── connection.py    # Connection config
│       │       └── about.py         # About dialog
│       │
│       ├── protocols/               # Protocol handlers
│       │   ├── __init__.py
│       │   └── canopen/
│       │       ├── __init__.py
│       │       ├── decoder.py
│       │       ├── sdo_client.py
│       │       └── nmt.py
│       │
│       ├── project/                 # Project management
│       │   ├── __init__.py
│       │   ├── project.py           # Project dataclass
│       │   ├── serialization.py     # Save/load
│       │   └── recent.py            # Recent projects
│       │
│       └── resources/
│           ├── __init__.py
│           ├── icons/               # Icon files
│           └── icons.qrc            # Qt resources
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_core/
│   ├── test_models/
│   └── test_ui/
│
├── pyproject.toml
├── README.md
└── REQUIREMENTS.md                  # This file
```

---

## 8. Implementation Phases

### Phase 1: Core Infrastructure ✅ COMPLETE
- [x] Requirements document
- [x] Project structure setup
- [x] Core types (CANFrame, etc.)
- [x] Ring buffer implementation
- [x] Basic CAN reader (single bus)
- [x] SocketCAN manager (discovery, sudo)

### Phase 2: Basic UI ✅ COMPLETE
- [x] Main window with docking
- [x] Project tree (dynamic with connection editing)
- [x] Grouped receive view
- [x] Trace view
- [x] Basic connection dialog

### Phase 3: Multi-bus & Performance (In Progress)
- [x] Multi-bus reader
- [ ] Background processor
- [ ] DBC decoder with caching
- [ ] Frame filtering
- [ ] Performance optimization

### Phase 4: Full Features (Partial)
- [ ] Project save/load
- [ ] Transmit panel
- [ ] Properties panel
- [x] Hardware configuration (via connection dialog)
- [x] CANopen support (decoding + node discovery)

### Phase 5: Polish
- [ ] Themes and styling
- [ ] Keyboard shortcuts
- [ ] Error handling
- [ ] Documentation
- [ ] Testing

---

## 9. Testing Strategy

### Unit Tests
- Core types serialization
- Ring buffer thread safety
- Filter matching
- DBC decoding

### Integration Tests
- Virtual CAN (vcan) operations
- Multi-bus reception
- Project save/load

### Performance Tests
- Throughput benchmarks
- Memory leak detection
- CPU profiling

### Manual Tests
- Hardware interfaces
- UI responsiveness
- Edge cases

---

## 10. References

- [python-can Documentation](https://python-can.readthedocs.io/)
- [SocketCAN Documentation](https://www.kernel.org/doc/html/latest/networking/can.html)
- [Qt-Advanced-Docking](https://github.com/githubuser0xFFFF/Qt-Advanced-Docking-System)
- [cantools Documentation](https://cantools.readthedocs.io/)
- [PCAN-Explorer User Manual](https://www.peak-system.com/)