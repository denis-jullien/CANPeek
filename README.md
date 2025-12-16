# CANPeek

A high-performance CAN bus observer and analyzer for Linux, built with Python and Qt.

## Features

- **High Performance**: Multi-threaded architecture handling 30k+ messages/second across multiple buses
- **CAN FD Support**: Full support for CAN FD frames with up to 64 bytes payload
- **SocketCAN Integration**: Advanced SocketCAN management with interface configuration
- **DBC Decoding**: Real-time signal decoding from DBC database files
- **Professional UI**: PCAN-Explorer style interface with Qt-Advanced-Docking
- **Multiple Views**: Trace view (chronological) and grouped receive view
- **Project Management**: Save and load workspace configurations

## Requirements

- Python 3.11+
- Linux with SocketCAN support
- PySide6

## Installation

```bash
pip install -e .
```

## Usage

```bash
canpeek
```

Or run as a module:

```bash
python -m canpeek
```

## Development

Install development dependencies:

```bash
pip install -e ".[dev]"
```

Run tests:

```bash
pytest
```

## License

MIT License
