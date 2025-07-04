# Main Window

This section provides an overview of the main window and its components.

![screenshot](https://raw.githubusercontent.com/denis-jullien/CANPeek/refs/heads/master/screenshot.png)

## Components

1.  **Menu Bar**: Provides access to file operations, settings, and help.
2.  **Tool Bar**: Contains shortcuts for common actions like connecting/disconnecting, saving, and clearing the view.
3.  **Project Explorer**: Manage project files, including DBC files and filters.
4.  **Trace View**: Displays a real-time log of all incoming CAN frames.
5.  **Grouped View**: Organizes CAN frames by their ID and displays the latest message with decoded signal values.
6.  **Transmit Tab**: Allows you to send CAN frames, either manually or by using signals from a loaded DBC file.
7.  **Status Bar**: Shows the current connection status and other information.

## Trace View

The Trace View provides a chronological list of all CAN frames received on the bus. Each row displays the following information:

-   **Timestamp**: The time the frame was received.
-   **ID**: The CAN identifier of the frame.
-   **DLC**: The data length code (number of bytes in the data payload).
-   **Data**: The data payload of the frame.

## Grouped View

The Grouped View provides a more structured way to view CAN data. It groups frames by their ID and displays the most recent frame for each ID. If a DBC file is loaded, the Grouped View will also show the decoded signal values for each frame.

You can expand each message to see the individual signals and their values.
