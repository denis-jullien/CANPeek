# Logging

CANpeek supports saving and loading CAN logs in various formats.

## Saving a Log

To save the current contents of the Trace View to a log file:

1.  Go to **File > Save Log**.
2.  Choose a file name and location.
3.  Select the desired log format.

CANpeek supports all the log formats supported by the [python-can](https://python-can.readthedocs.io/en/stable/file_io.html) library, including:

-   **ASC**: The popular format used by Vector tools.
-   **BLF**: The binary logging format used by Vector tools.
-   **CSV**: Comma-separated values.
-   **TRC**: The format used by PEAK-System tools.

## Loading a Log

To load a log file:

1.  Go to **File > Load Log**.
2.  Select the log file you want to load.

The contents of the log file will be displayed in the Trace View.
