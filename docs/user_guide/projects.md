# Projects

CANpeek uses a project-based workflow to help you manage your CAN bus analysis sessions. A project file (`.canpeek`) stores your configuration, including loaded DBC files, filters, and other settings.

## Creating a New Project

To create a new project, go to **File > New Project**. This will create a new, empty project.

## Opening a Project

To open an existing project, go to **File > Open Project** and select the `.canpeek` file.

## Saving a Project

To save the current project, go to **File > Save Project**. If the project has not been saved before, you will be prompted to choose a location and file name.

## Project Explorer

The Project Explorer is located on the left side of the main window and shows the files associated with the current project.

### DBC Files

To add a DBC file to your project, right-click on the **DBC Files** item in the Project Explorer and select **Add DBC File**. You can also drag and drop DBC files from your file manager onto the Project Explorer.

Once a DBC file is loaded, CANpeek will automatically use it to decode CAN frames.

### Filters

To add a filter to your project, right-click on the **Filters** item in the Project Explorer and select **Add Filter**. See the [Filtering](filtering.md) page for more information.
