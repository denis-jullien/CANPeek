# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CANPeek is a Python Qt-based CAN bus analyzer and monitoring tool with DBC support and CANopen functionality. The project uses:

- **Language**: Python 3.10+
- **GUI Framework**: PySide6 (Qt6)
- **Package Manager**: uv (modern Python package manager)
- **Testing**: pytest with Qt support
- **Linting**: ruff

## Development Commands

### Running the Application
```bash
# Run with all optional interfaces
uv run canpeek --extra interfaces

# Run from source (development)
uv run canpeek
```

### Testing
```bash
# Run all tests
uv run pytest

# Run specific test file
uv run pytest tests/test_main.py

# Run with verbose output
uv run pytest -v

# Run specific test by name
uv run pytest -k "test_name"
```

### Code Quality
```bash
# Run linter (check only)
uv run ruff check

# Run formatter
uv run ruff format

# Run both linter and formatter
uv run ruff check && uv run ruff format
```

### Dependencies
```bash
# Install dependencies
uv sync

# Install with optional interfaces
uv sync --extra interfaces

# Add new dependency
uv add package_name

# Add development dependency
uv add --dev package_name
```

## Architecture Overview

### Core Structure
- **`__main__.py`**: Main application entry point (~27k lines, monolithic GUI implementation)
- **`polars_qt_bridge.py`**: High-performance Qt models using Polars DataFrames (`PolarsCANTraceModel`, `PolarsCANGroupedModel`)
- **`polars_backend.py`**: Polars-based CAN data processing and filtering engine
- **`frame_processor.py`**: Central frame processing with threaded view distribution
- **`grouped_view.py`**: Fast independent grouped view implementation
- **`can_utils.py`**: CAN communication utilities (`CANThreadedReader`, `SafeNotifier`)
- **`data_utils.py`**: Core data structures (`CANFrame`, `DBCFile`, `CANFrameFilter`)
- **`interfaces_utils.py`**: CAN interface management and discovery
- **`co/`**: CANopen specific functionality (SDO client, NMT, PDO management)

### Key Components

#### Data Models
- `CANFrame`: Core CAN message representation with timestamp, ID, data, and metadata
- `DBCFile`: DBC database wrapper with connection association
- `CANFrameFilter`: Message filtering with ID ranges, masks, and frame type filtering
- `Connection`: CAN interface connection configuration

#### Views
- **Trace View**: Real-time chronological message display using Polars DataFrames (`PolarsCANTraceModel`)
- **Grouped View**: High-performance frame grouping by ID with fast cycle time calculation (`FastCANGroupedModel`)
- Both views support threaded processing and fixed 60 FPS updates

#### CAN Communication
- `CANThreadedReader`: Dedicated thread CAN message reception using python-can (prevents UI blocking)
- `CANFrameProcessor`: Central frame distribution to trace and grouped views via worker threads
- `SafeNotifier`: Error-resilient CAN message notification
- Multi-interface support: socketcan, pcan, kvaser, vector, etc.

#### CANopen Support
- `CANopenDecoder`: Generic CANopen message decoding (NMT, PDO, SDO, Heartbeat)
- `CANopenNode`: Node state management and object dictionary
- `SDOClient`: SDO read/write operations
- `NMTSender`: Network management functions

### Project Structure
```
src/canpeek/
├── __main__.py             # Main GUI application (monolithic)
├── polars_qt_bridge.py     # High-performance Polars-based Qt models
├── polars_backend.py       # Polars data processing and filtering
├── frame_processor.py      # Central frame processing with threading
├── grouped_view.py         # Fast independent grouped view
├── models.py               # Legacy Qt models (FilterHeaderView, etc.)
├── can_utils.py            # CAN communication layer (threaded reader)
├── data_utils.py           # Core data structures
├── interfaces_utils.py     # Interface discovery and management
├── co/                     # CANopen functionality
│   ├── canopen_utils.py    # CANopen decoding and node management
│   ├── sdo_client.py       # SDO client implementation
│   ├── nmt_editor.py       # NMT operations
│   └── dcf2db.py           # DCF to DBC conversion
├── ui/                     # UI panels and widgets
│   ├── transmit_panels.py  # CAN transmission panels
│   └── properties_panel.py # Connection and project properties
└── icons/                  # Application icons
```

## Key Design Patterns

### High-Performance Data Processing
- **Polars DataFrames**: Used for trace view storage and filtering (10-100x performance improvement)
- **Threaded Architecture**: Separate worker threads for trace and grouped view processing
- **Fixed 60 FPS Updates**: All views maintain consistent 60 FPS refresh rate
- **Thread-Safe Communication**: Qt signals for safe cross-thread data transfer

### Threading Architecture
CANPeek uses a hybrid threading approach combining Python's `threading.Thread` for hardware-level operations and Qt's `QThread` for data processing:

#### **Hardware Layer** (`threading.Thread`)
- **CANThreadedReader**: Dedicated `threading.Thread` for CAN reception (prevents UI blocking)
- **Low-level CAN Interface**: Hardware-level communication uses Python threads for minimal overhead
- **Performance Critical**: CAN reading must be as fast as possible to avoid message loss

#### **Processing Layer** (`QThread`)
- **CANFrameProcessor**: Central coordinator with `QThread` worker threads for each view
- **TraceWorkerThread**: `QThread` for trace view processing (100 frame batches, 60 FPS)
- **GroupedWorkerThread**: `QThread` for grouped view processing (10 frame batches)
- **PolarsCANProcessor**: Background Polars operations in separate `QThread` instances
- **FilterWorker**: `QThread` for expensive filtering operations
- **DataWorker**: `QThread` for frame processing and decode operations

#### **UI Layer** (Main Qt Thread)
- **Fixed 60 FPS Updates**: All views maintain consistent 60 FPS refresh rate
- **Qt Signal/Slot Communication**: Thread-safe communication between layers
- **Async Processing**: Heavy operations don't block UI thread
- **Zero Message Loss**: CAN reading continues uninterrupted during heavy UI operations

#### **Threading Flow**
```
Hardware Layer → Processing Layer → UI Layer
threading.Thread → QThread → Main Qt Thread
can_utils.py → frame_processor.py → polars_qt_bridge.py
             → polars_backend.py →
```

### Multi-Database Support
- Supports multiple DBC files simultaneously
- Each DBC can be associated with specific connections
- Unified decoding pipeline in `get_structured_decodings()`
- Decode caching for performance optimization

### Plugin Architecture
- Interface discovery is dynamic based on installed python-can backends
- CANopen functionality is modular and optional

## Testing Notes

- Tests use `pytest-qt` for Qt application testing
- `pytest-asyncio` for async test support
- Test configuration in `pyproject.toml` specifies PySide6 as Qt API
- Key test files: 
  - `test_main.py`: Core application functionality
  - `test_ui.py`: UI components and integration
  - `test_sdo_client.py`: CANopen SDO client
  - `test_polars_backend.py`: High-performance data processing
  - `test_polars_qt_bridge.py`: Qt model integration
  - `test_independent_grouped_view.py`: Grouped view and frame processor
  - `test_threaded_can_reader.py`: Threaded CAN reader functionality

## Common Development Tasks

### Adding New CAN Interface
1. Ensure python-can backend is installed
2. Interface will be auto-discovered via `interfaces_utils.py`
3. Add any backend-specific configuration in `Connection` class

### Extending CANopen Support
1. Add new message types to `CANopenDecoder` in `co/canopen_utils.py`
2. Update decoding logic in `get_structured_decodings()`
3. Consider adding UI components in the main application

### Performance Optimization
- Focus on `PolarsCANTraceModel` and `PolarsCANGroupedModel` for view performance
- Batch updates are critical for high-throughput scenarios (100 frames for trace, 10 for grouped)
- Use `QTimer` for periodic UI updates (fixed 60 FPS) rather than immediate updates
- Leverage async processing with `get_filtered_data_async()` for non-blocking operations
- Monitor performance with built-in FPS counters and performance metrics

## High-Frequency Performance Requirements

### Critical Performance Challenges
**✅ RESOLVED**: Previous performance issues have been addressed with the new architecture:

1. **✅ Message Loss**: Optimized queue limits (10k messages) with efficient `QThread` processing
2. **✅ UI Responsiveness**: Fixed 60 FPS updates with 16ms batching window
3. **✅ DBC Decoding Bottleneck**: Hierarchical caching and lazy decoding minimize redundant calls
4. **✅ Filter-Decode Interaction**: Staged filtering applies fast filters before expensive decode filters
5. **✅ Memory Efficiency**: Polars DataFrames provide efficient storage and vectorized operations for millions of frames

### Performance Optimization Strategy
**✅ IMPLEMENTED**: The following optimizations are now in place:

1. **✅ Polars-Based Data Pipeline**: Full implementation with Polars DataFrames for 10-100x performance gains
2. **✅ Hierarchical Caching**: Multi-level decode caching (message lookup → basic info → full decoding)
3. **✅ Lazy Decoding**: Only decode signals when actually needed by UI
4. **✅ Staged Filtering**: Apply fast filters before expensive decode filters
5. **✅ Batch Processing**: Group identical payloads to minimize redundant decoding
6. **✅ Qt Threading**: Background processing using `QThread` for non-blocking operations
7. **✅ Async Filtering**: Heavy filtering operations run in background threads

### Recommended Libraries
- **✅ Polars**: Currently used for high-performance data processing and filtering
- **✅ NumPy**: Currently used for optimized data operations and vectorized processing
- **PyArrow** (optional): Available for efficient Qt model integration with >1M frames

### Critical Requirements
**✅ ACHIEVED**: All critical requirements are now met:

- **✅ Zero Message Loss**: All CAN frames are preserved in trace with optimized threading
- **✅ Accurate Timing**: Precise timestamps and cycle time calculations maintained
- **✅ Real-time Updates**: UI responsiveness maintained during high-frequency bursts with 60 FPS updates
- **✅ Memory Efficiency**: Polars DataFrames handle millions of frames with minimal memory usage

The current implementation prioritizes message integrity and timing accuracy while delivering high performance.

## Development Notes

The codebase includes AI-generated code with some structural challenges:
- `__main__.py` is monolithic (~27k lines) and could benefit from modularization
- Some repetitive patterns exist that could be refactored
- Core functionality is solid but architecture could be improved

When making changes, follow existing patterns and maintain compatibility with the Qt threading architecture and multi-connection support.

## Threading Implementation Notes

### Threading Best Practices
- **Hardware Layer**: Use `threading.Thread` for CAN interface operations (minimal overhead, hardware-level)
- **Processing Layer**: Use `QThread` for data processing, filtering, and heavy operations
- **UI Layer**: Keep all UI updates in the main Qt thread using signals/slots
- **Thread Safety**: Use `QMutex` and `QMutexLocker` for shared resource access
- **Shutdown**: Properly handle thread lifecycle with `quit()` and `wait()` methods

### Performance Monitoring
- Built-in FPS counters track UI performance (target: 60 FPS)
- Performance metrics monitor operation timings and cache hit rates
- Frame processing statistics available via `get_performance_stats()`
- Threading overhead is minimized through efficient batching and caching