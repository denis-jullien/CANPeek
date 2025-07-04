# CANpeek

**CANpeek** is a graphical CAN bus observer and analyzer for Linux and Windows based on Python and Qt with can databases (DBC) support and some CANopen functionality.

![screenshot](https://raw.githubusercontent.com/denis-jullien/CANPeek/refs/heads/master/screenshot.png)

## Features

- 🧩 **Project-based configuration** with filters, DBC files, and persistent decoding options
- 🌐 **Multi-interface support**: socketcan, pcan, kvaser, vector and other interfaces based on [python-can](https://python-can.readthedocs.io/en/stable/configuration.html#interface-names)
- 📊 **Dual View**: Real-time **Trace View** and hierarchical **Grouped View** with signal expansion
- 📁 **Multi-DBC support** with signal decoding from [cantools](https://github.com/cantools/cantools)
- 🧠 **Generic CANopen decoder** with support for NMT, PDO, SDO, Heartbeat, and more
- 🗃️ **CANopen Object Dictionary** with an SDO client for read/write operations
- 📦 **CAN frame transmitter**, supporting both raw and signal-based (DBC) messages 
- 📜 **Log support**: Save/load CAN logs in all [python-can IO formats](https://python-can.readthedocs.io/en/stable/file_io.html)
- 🔌 **Connections Management**: Handling of multiple simultaneous CAN connections

## Getting Started

Ready to dive in? Head over to the [Getting Started](user_guide/getting_started.md) guide to install and configure CANpeek.

## About the Project

CANpeek was developed to provide a simple, cross-platform, and intuitive tool for CAN bus analysis. The project was rapidly prototyped with the help of large language models (LLMs), which allowed for a feature-rich application to be developed in a short amount of time.

While the application is fully functional, the codebase may not always follow best practices. Contributions to improve the code, add features, or fix bugs are always welcome. Please see the project's [GitHub repository](https://github.com/denis-jullien/CANPeek) for more information.