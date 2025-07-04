# Vector Setup

Vector provides a wide range of CAN/CAN-FD interfaces and software tools.

## Installation

To use Vector interfaces, you need to install the Vector XL Driver Library.

1.  Download the driver library from the [Vector website](https://www.vector.com/int/en/download/).
2.  Follow the instructions to install the library.

## Using with CANpeek

In CANpeek:

1.  Select the `vector` backend.
2.  Enter the channel number of your Vector interface (e.g., `0`, `1`) in the **Channel** field.
3.  Click **Connect**.

**Note:** You may also need to specify the `app_name` parameter in the configuration to identify your application to the Vector driver.
