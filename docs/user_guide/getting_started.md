# Getting Started

This guide will walk you through the installation and initial setup of CANpeek.

## Installation

CANpeek can be installed using pip or from source.

### With pip

To install CANpeek and all optional interface dependencies, run the following command:

```bash
pip install canpeek[interfaces]
```

Then, to run the application, simply execute:

```bash
canpeek
```

### From source

To install from source, you will need to have [uv](https://github.com/astral-sh/uv) installed.

1. Clone the repository:

   ```bash
   git clone https://github.com/denis-jullien/CANPeek.git
   cd CANPeek
   ```

2. Install the dependencies and run the application:

   ```bash
   uv run canpeek --extra interfaces
   ```

## Connecting to a CAN Interface

Once CANpeek is running, you can connect to a CAN interface:

1.  **Select the backend** for your CAN interface (e.g., `socketcan`, `pcan`, `kvaser`).
2.  **Enter the channel** for your interface (e.g., `can0`).
3.  Click the **Connect** button.

For detailed instructions on setting up specific CAN interfaces, please refer to the **CAN Interface Setup** section of the documentation.
