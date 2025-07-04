# Other Interfaces

CANpeek uses the [python-can](https://python-can.readthedocs.io/en/stable/index.html) library for CAN communication, so it supports any interface that is supported by `python-can`.

## Supported Interfaces

A list of supported interfaces can be found in the [python-can documentation](https://python-can.readthedocs.io/en/stable/configuration.html#interface-names).

Some of the other supported interfaces include:

-   **IXXAT**
-   **NI-CAN**
-   **Serial**
-   **UDP Multicast**

## Configuration

To use an interface that is not explicitly listed in the CANpeek interface dropdown, you can select the `virtual` backend and specify the `interface` and `channel` in the configuration file.

For detailed instructions on how to configure a specific interface, please refer to the [python-can documentation](https://python-can.readthedocs.io/en/stable/configuration.html).
