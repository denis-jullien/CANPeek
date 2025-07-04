# PCAN Setup

PCAN is a family of CAN interfaces from PEAK-System.

## Installation

### Linux

To use PCAN interfaces on Linux, you need to install the `pcan` kernel driver.

1.  Download the driver from the [PEAK-System website](https://www.peak-system.com/Drivers.76.0.html?&L=1).
2.  Follow the instructions in the downloaded package to compile and install the driver.

### Windows

On Windows, you need to install the PCAN driver for your hardware.

1.  Download the driver from the [PEAK-System website](https://www.peak-system.com/Drivers.76.0.html?&L=1).
2.  Follow the instructions to install the driver.

## Using with CANpeek

In CANpeek:

1.  Select the `pcan` backend.
2.  Enter the name of your PCAN interface (e.g., `PCAN_USBBUS1`) in the **Channel** field.
3.  Click **Connect**.
