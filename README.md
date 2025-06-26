# CANpeek

**CANpeek** is a graphical CAN bus observer and analyzer for Linux and Windows (untested) based on Python and Qt.

## 🤖 About the Code (aka “AI Slop” Warning)

This project includes code — and this very README — that were generated almost entirely with large language models (LLMs). Yes, the term “AI slop” was insisted upon.

While the app works and provides a full-featured CAN bus GUI, you may find:

* Some awkward structure and bloated chunks of logic
* Repetitive patterns that could use refactoring
* Giant all-in-one files (yes, `main.py`, we’re looking at you)
* Documentation (including this README) was AI-generated too — so if it sounds polished but slightly overconfident, that’s why.

The goal was rapid prototyping, not pristine architecture. Use it, improve it, rewrite parts of it — all contributions are welcome.

## Features

- 🧩 **Project-based configuration** with filters, DBC files, and persistent decoding options
- 🌐 **Multi-interface support**: socketcan, pcan, kvaser, vector, and virtual based on [python-can](https://python-can.readthedocs.io/en/stable/configuration.html#interface-names)
- 📊 **Dual View**: Real-time **Trace View** and hierarchical **Grouped View** with signal expansion
- 📁 **Multi-DBC support** with signal decoding from [cantools](https://github.com/cantools/cantools)
- 🧠 **CANopen basic decoder** with support for NMT, PDO, SDO, Heartbeat, and more
- 📦 **CAN frame transmitter**, supporting both raw and signal-based (DBC) messages 
- 📜 **Log support**: Save/load CAN logs in all [python-can IO formats](https://python-can.readthedocs.io/en/stable/file_io.html)

## Screenshots

![screenshot](https://raw.githubusercontent.com/denis-jullien/CANPeek/refs/heads/master/screenshot.png)

## Installation

### With pip

The interfaces avaibility depends on modules and drivers available on your system. Use the extra [interfaces] to install optionals python modules.


```bash
pip install canpeek[interfaces]
canpeek
```

### From source

1. Install [uv](https://github.com/astral-sh/uv)
2. Run `uv run canpeek --extra interfaces`

## Usage

1. **Connect to a CAN interface**:

   * Select backend (`socketcan`, `pcan`, `kvaser`, etc.)
   * Enter the channel (e.g., `can0`)
   * Click **Connect**

2. **Load DBC files** via the "Project Explorer" to decode signals.

3. **Create Filters** to limit visible traffic.

4. **Send CAN messages**:

   * Manually from the **Transmit** tab
   * If the message id is in the DBC, a dedicated panel is available to edit signals values

5. **Save / Load** CAN logs in multiples formats.

## Other tools 

CANPeek is designed to be quick & simple, you might find those intersesting:

 * [cangaroo](https://github.com/normaldotcom/cangaroo) : rather similar
 * [SavvyCAN](https://github.com/collin80/SavvyCAN) : a much more complete canbus tool
