# SocketCAN Setup

SocketCAN is the standard CAN interface for Linux. It provides a generic interface to various CAN hardware, including virtual CAN interfaces.

## Installation

On most modern Linux distributions, the `can-utils` package provides the necessary tools for working with SocketCAN.

**Debian/Ubuntu:**

```bash
sudo apt-get install can-utils
```

**Fedora/CentOS:**

```bash
sudo yum install can-utils
```

## Configuration

### Virtual CAN Interface

For testing purposes, you can create a virtual CAN interface:

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

### Physical CAN Interface

To use a physical CAN interface, you will need to load the appropriate kernel module for your hardware and configure the interface.

For example, to configure a CAN interface with a bitrate of 250 kbit/s:

```bash
sudo ip link set can0 type can bitrate 250000
sudo ip link set up can0
```

## Using with CANpeek

In CANpeek:

1.  Select the `socketcan` backend.
2.  Enter the name of your CAN interface (e.g., `vcan0`, `can0`) in the **Channel** field.
3.  Click **Connect**.
