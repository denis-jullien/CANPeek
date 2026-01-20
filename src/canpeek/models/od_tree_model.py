"""
Qt model for displaying CANopen Object Dictionary in a tree view.
"""

from typing import Any, Optional

from PySide6.QtCore import QAbstractItemModel, QModelIndex, Qt

from canpeek.protocols.canopen.object_dictionary import (
    ODEntry,
    ODIndex,
    ObjectDictionaryWrapper,
)


class ODTreeItem:
    """Internal tree item for the OD model."""

    def __init__(
        self,
        data: ODIndex | ODEntry | None = None,
        parent: Optional["ODTreeItem"] = None,
    ):
        self.item_data = data
        self.parent_item = parent
        self.children: list[ODTreeItem] = []

    def append_child(self, child: "ODTreeItem") -> None:
        child.parent_item = self
        self.children.append(child)

    def child(self, row: int) -> Optional["ODTreeItem"]:
        if 0 <= row < len(self.children):
            return self.children[row]
        return None

    def child_count(self) -> int:
        return len(self.children)

    def row(self) -> int:
        if self.parent_item:
            return self.parent_item.children.index(self)
        return 0

    def parent(self) -> Optional["ODTreeItem"]:
        return self.parent_item

    @property
    def is_index(self) -> bool:
        return isinstance(self.item_data, ODIndex)

    @property
    def is_entry(self) -> bool:
        return isinstance(self.item_data, ODEntry)


class ODTreeModel(QAbstractItemModel):
    """
    Qt model for displaying Object Dictionary in a tree view.

    Structure:
    - Root
      - ODIndex (e.g., 0x1000 Device Type)
        - ODEntry (subindex 0)
        - ODEntry (subindex 1)
        - ...
      - ODIndex (e.g., 0x1001 Error Register)
        - ODEntry (subindex 0)
      - ...
    """

    # Column definitions
    COL_INDEX = 0
    COL_NAME = 1
    COL_TYPE = 2
    COL_ACCESS = 3
    COL_VALUE = 4

    COLUMNS = ["Index", "Name", "Type", "Access", "Value"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._root = ODTreeItem()
        self._od: Optional[ObjectDictionaryWrapper] = None

    def load_od(self, od: ObjectDictionaryWrapper) -> None:
        """Load an object dictionary into the model."""
        self.beginResetModel()
        self._od = od
        self._root = ODTreeItem()
        self._build_tree()
        self.endResetModel()

    def clear(self) -> None:
        """Clear the model."""
        self.beginResetModel()
        self._od = None
        self._root = ODTreeItem()
        self.endResetModel()

    def _build_tree(self) -> None:
        """Build the tree structure from the OD."""
        if not self._od:
            return

        for od_index in self._od.indices:
            index_item = ODTreeItem(od_index)
            self._root.append_child(index_item)

            # Add sub-entries
            for entry in od_index.subentries:
                entry_item = ODTreeItem(entry)
                index_item.append_child(entry_item)

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.column() > 0:
            return 0

        if not parent.isValid():
            return self._root.child_count()

        parent_item = parent.internalPointer()
        return parent_item.child_count()

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self.COLUMNS)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid():
            return None

        item: ODTreeItem = index.internalPointer()
        col = index.column()

        if role == Qt.DisplayRole:
            return self._get_display_data(item, col)
        elif role == Qt.ToolTipRole:
            return self._get_tooltip(item)
        elif role == Qt.UserRole:
            # Return the actual data object
            return item.item_data

        return None

    def _get_display_data(self, item: ODTreeItem, col: int) -> str:
        if item.is_index:
            od_index: ODIndex = item.item_data
            if col == self.COL_INDEX:
                return od_index.index_str
            elif col == self.COL_NAME:
                return od_index.name
            elif col == self.COL_TYPE:
                return od_index.object_type_name
            elif col == self.COL_ACCESS:
                return ""
            elif col == self.COL_VALUE:
                return ""

        elif item.is_entry:
            entry: ODEntry = item.item_data
            if col == self.COL_INDEX:
                return f":{entry.subindex:02X}"
            elif col == self.COL_NAME:
                return entry.name
            elif col == self.COL_TYPE:
                return entry.data_type_name
            elif col == self.COL_ACCESS:
                return entry.access_type.upper()
            elif col == self.COL_VALUE:
                if entry.current_value is not None:
                    return str(entry.current_value)
                return ""

        return ""

    def _get_tooltip(self, item: ODTreeItem) -> str:
        if item.is_index:
            od_index: ODIndex = item.item_data
            tooltip = f"Index: {od_index.index_str}\n"
            tooltip += f"Name: {od_index.name}\n"
            tooltip += f"Type: {od_index.object_type_name}"
            if od_index.description:
                tooltip += f"\n\n{od_index.description}"
            return tooltip

        elif item.is_entry:
            entry: ODEntry = item.item_data
            tooltip = f"Index: {entry.index:04X}:{entry.subindex:02X}\n"
            tooltip += f"Name: {entry.name}\n"
            tooltip += f"Type: {entry.data_type_name}\n"
            tooltip += f"Access: {entry.access_type}"
            if entry.default is not None:
                tooltip += f"\nDefault: {entry.default}"
            if entry.min_value is not None:
                tooltip += f"\nMin: {entry.min_value}"
            if entry.max_value is not None:
                tooltip += f"\nMax: {entry.max_value}"
            if entry.description:
                tooltip += f"\n\n{entry.description}"
            return tooltip

        return ""

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole
    ) -> Any:
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            if 0 <= section < len(self.COLUMNS):
                return self.COLUMNS[section]
        return None

    def index(
        self, row: int, column: int, parent: QModelIndex = QModelIndex()
    ) -> QModelIndex:
        if not self.hasIndex(row, column, parent):
            return QModelIndex()

        if not parent.isValid():
            parent_item = self._root
        else:
            parent_item = parent.internalPointer()

        child_item = parent_item.child(row)
        if child_item:
            return self.createIndex(row, column, child_item)
        return QModelIndex()

    def parent(self, index: QModelIndex) -> QModelIndex:
        if not index.isValid():
            return QModelIndex()

        child_item: ODTreeItem = index.internalPointer()
        parent_item = child_item.parent()

        if parent_item is None or parent_item == self._root:
            return QModelIndex()

        return self.createIndex(parent_item.row(), 0, parent_item)

    def flags(self, index: QModelIndex) -> Qt.ItemFlags:
        if not index.isValid():
            return Qt.NoItemFlags
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable

    def get_entry(self, index: QModelIndex) -> Optional[ODEntry]:
        """Get the ODEntry for a given model index."""
        if not index.isValid():
            return None

        item: ODTreeItem = index.internalPointer()
        if item.is_entry:
            return item.item_data
        return None

    def get_od_index(self, index: QModelIndex) -> Optional[ODIndex]:
        """Get the ODIndex for a given model index."""
        if not index.isValid():
            return None

        item: ODTreeItem = index.internalPointer()
        if item.is_index:
            return item.item_data
        return None

    def update_value(self, od_index: int, subindex: int, value: Any) -> None:
        """Update the displayed value for an entry."""
        # Find the item and update it
        for row, index_item in enumerate(self._root.children):
            if index_item.is_index and index_item.item_data.index == od_index:
                for sub_row, entry_item in enumerate(index_item.children):
                    if entry_item.is_entry and entry_item.item_data.subindex == subindex:
                        entry_item.item_data.current_value = value
                        # Emit dataChanged for the value column
                        idx = self.createIndex(sub_row, self.COL_VALUE, entry_item)
                        self.dataChanged.emit(idx, idx, [Qt.DisplayRole])
                        return

    @property
    def od(self) -> Optional[ObjectDictionaryWrapper]:
        """Get the current ObjectDictionary."""
        return self._od
