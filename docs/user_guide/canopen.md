# CANopen

CANpeek includes a generic CANopen decoder and an SDO client for interacting with CANopen devices.

## CANopen Decoder

The CANopen decoder automatically decodes the following CANopen protocols:

-   **NMT (Network Management)**: Monitors the state of CANopen devices.
-   **PDO (Process Data Object)**: Transmits real-time process data.
-   **SDO (Service Data Object)**: Provides access to the Object Dictionary.
-   **Heartbeat**: Monitors the status of network nodes.
-   **EMCY (Emergency)**: Reports errors.

Decoded CANopen messages are displayed in the Trace and Grouped Views with their protocol and relevant information.

## SDO Client

CANpeek includes an SDO client that allows you to read from and write to the Object Dictionary of a CANopen device.

To use the SDO client:

1.  Go to the **CANopen** tab.
2.  Enter the **Node ID** of the device you want to communicate with.
3.  Enter the **Index** and **Sub-index** of the Object Dictionary entry you want to access.
4.  To read a value, click the **Read** button.
5.  To write a value, enter the value in the **Data** field and click the **Write** button.
