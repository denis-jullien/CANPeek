# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Run Commands

```bash
# Install dependencies (using uv)
uv sync

# Run the application
uv run canpeek

# Run tests
uv run pytest

# Run single test
uv run pytest tests/test_file.py::test_function

# Type checking
uv run mypy src/canpeek

# Linting
uv run ruff check src/canpeek
uv run ruff format src/canpeek
```

## Architecture Overview

CANPeek is a high-performance CAN/CAN FD bus analyzer for Linux. Key performance target: 30k+ messages/second across 3+ buses simultaneously.

### Threading Model

```
Reader Threads (per bus)  →  Lock-free Ring Buffers  →  GUI Thread (Qt)
       ↓                            ↓                        ↓
  python-can Notifier         100k capacity           20Hz update timer
```

- **Reader threads**: One per CAN bus using python-can's `Notifier` class
- **Ring buffers**: Lock-free `collections.deque` for thread-safe frame passing (`core/buffer.py`)
- **GUI thread**: Polls buffers at 20Hz, batch-updates Qt models

### Package Structure

```
src/canpeek/
├── core/           # Core data types and CAN infrastructure
│   ├── types.py    # CANFrame (slots dataclass), BusState, Connection
│   ├── buffer.py   # Lock-free RingBuffer for inter-thread communication
│   └── reader.py   # CANBusReader (Listener), BusManager
├── socketcan/      # Linux SocketCAN management (sudo, ip link, bitrate config)
├── models/         # Qt models for views
│   ├── trace_model.py    # Chronological frame list (QAbstractTableModel)
│   └── grouped_model.py  # Messages grouped by ID (QAbstractItemModel tree)
├── ui/
│   ├── main_window.py    # Main window with Qt-Advanced-Docking (PySide6-QtAds)
│   ├── widgets/          # Receive view, trace view, project tree, status bar
│   └── dialogs/          # Sudo dialog, connection dialogs
├── protocols/      # Protocol decoders (CANopen)
└── project/        # Project file persistence (.cpeek)
```

### Key Design Decisions

- **CANFrame**: Uses `@dataclass(slots=True)` for memory efficiency; flags stored as single int with bit operations
- **Qt-Advanced-Docking**: Professional docking UI (PCAN-Explorer style) via `PySide6-QtAds`
- **python-can**: Hardware abstraction for CAN interfaces (SocketCAN, PCAN, Kvaser, Vector)
- **Incremental model updates**: Avoids `beginResetModel()`; uses row insert/data change signals
- **Wayland workaround**: Forces XCB platform for Qt-Advanced-Docking compatibility

### Dependencies

- `PySide6>=6.9.0` - Qt bindings
- `PySide6-QtAds>=4.4.0` - Advanced docking system
- `python-can>=4.5.0` - CAN hardware abstraction
- `cantools>=40.2.3` - DBC file parsing and signal decoding
- `canopen>=2.3.0` - CANopen protocol support

## Performance Considerations

- Never call `beginResetModel()`/`endResetModel()` during streaming
- Batch frame updates (process multiple frames per GUI tick)
- Use `QSortFilterProxyModel` sparingly on large datasets
- DBC decoding should be cached per message ID
