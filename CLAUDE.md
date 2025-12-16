# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CANPeek is a high-performance CAN/CAN FD bus analyzer for Linux built with Python and Qt. It handles 30k+ messages/second across multiple buses with a PCAN-Explorer-style dockable UI.

## Build & Development Commands

```bash
# Install for development
uv sync --all-extras

# Run the application
uv run canpeek
# or
uv run python -m canpeek

# Run all tests
uv run pytest

# Run a specific test file
uv run pytest tests/test_core/test_buffer.py

# Run tests with coverage
uv run pytest --cov=canpeek

# Linting
uv run ruff check src/

# Type checking
uv run mypy src/
```

## Architecture

### Threading Model

The application uses a multi-threaded architecture:
- **Main (GUI) thread**: Qt event loop, UI updates via signals
- **Reader threads**: One per CAN bus, writes to lock-free ring buffers
- **Processor thread**: Filtering, grouping, DBC decoding

### Key Components

**Core Layer** (`src/canpeek/core/`):
- `types.py`: `CANFrame` dataclass (slots-based for performance), `Connection`, `BusState` enums
- `buffer.py`: Thread-safe ring buffer using `deque(maxlen=N)`
- `reader.py`: `BusManager` coordinates multiple `BusReader` threads using python-can

**UI Layer** (`src/canpeek/ui/`):
- `main_window.py`: Uses PySide6-QtAds for dockable panels (Grouped View, Trace View, Project Manager, Properties, Transmit)
- Update timer runs at 20 Hz to batch GUI updates

**Models** (`src/canpeek/models/`):
- `trace_model.py`: Chronological frame list for trace view
- `grouped_model.py`: Groups frames by CAN ID with expandable signals

### Data Flow

1. `BusReader` receives frames via python-can
2. Converts to `CANFrame.from_python_can()` with nanosecond timestamps
3. Pushes to ring buffer (lock-free single-producer)
4. Main window timer polls `bus_manager.get_all_frames()`
5. Emits `frames_received` signal to update views

## Technology Stack

- **Python 3.11+** with type hints
- **PySide6** (Qt 6) + **PySide6-QtAds** for advanced docking
- **python-can** for CAN hardware abstraction
- **cantools** for DBC file parsing
- **canopen** for CANopen protocol support

## Platform Notes

- Linux with SocketCAN is the primary target
- Wayland workaround: Application forces XCB platform for Qt-Advanced-Docking compatibility (see `__main__.py`)
- SocketCAN interface configuration requires sudo (handled via `SudoDialog`)
