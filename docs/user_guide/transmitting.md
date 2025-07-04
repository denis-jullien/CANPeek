# Transmitting Frames

CANpeek provides a flexible interface for transmitting CAN frames.

## Transmit Tab

The **Transmit** tab is located in the bottom panel of the main window. From here, you can send CAN frames manually or by using signals from a loaded DBC file.

### Manual Transmission

To send a frame manually:

1.  Enter the **ID** of the frame.
2.  Enter the **Data** payload in hexadecimal format.
3.  Click the **Send** button.

### Signal-Based Transmission

If you have a DBC file loaded, you can transmit frames by setting the values of their signals:

1.  Select the message you want to transmit from the dropdown list.
2.  A panel will appear with controls for each of the message's signals.
3.  Set the desired signal values.
4.  Click the **Send** button.

## Cyclic Transmission

You can also configure frames to be sent cyclically:

1.  Enter the frame's ID and data (or select a message and set its signal values).
2.  Check the **Cyclic** box.
3.  Enter the desired transmission period in milliseconds.
4.  Click the **Start** button to begin cyclic transmission.
