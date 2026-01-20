"""
CANopen Object Dictionary wrapper for EDS/DCF files.

Provides a clean interface around the canopen library's ObjectDictionary.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import canopen
import canopen.objectdictionary


# Data type mapping for human-readable names
DATA_TYPE_NAMES = {
    0x0001: "BOOLEAN",
    0x0002: "INTEGER8",
    0x0003: "INTEGER16",
    0x0004: "INTEGER32",
    0x0005: "UNSIGNED8",
    0x0006: "UNSIGNED16",
    0x0007: "UNSIGNED32",
    0x0008: "REAL32",
    0x0009: "VISIBLE_STRING",
    0x000A: "OCTET_STRING",
    0x000B: "UNICODE_STRING",
    0x000C: "TIME_OF_DAY",
    0x000D: "TIME_DIFFERENCE",
    0x000F: "DOMAIN",
    0x0010: "INTEGER24",
    0x0011: "REAL64",
    0x0012: "INTEGER40",
    0x0013: "INTEGER48",
    0x0014: "INTEGER56",
    0x0015: "INTEGER64",
    0x0016: "UNSIGNED24",
    0x0018: "UNSIGNED40",
    0x0019: "UNSIGNED48",
    0x001A: "UNSIGNED56",
    0x001B: "UNSIGNED64",
}

# Object type names
OBJECT_TYPE_NAMES = {
    0x00: "NULL",
    0x02: "DOMAIN",
    0x05: "DEFTYPE",
    0x06: "DEFSTRUCT",
    0x07: "VAR",
    0x08: "ARRAY",
    0x09: "RECORD",
}


@dataclass
class ODEntry:
    """Represents a single OD entry (variable or sub-entry)."""

    index: int
    subindex: int
    name: str
    data_type: int
    data_type_name: str
    access_type: str
    default: Any = None
    min_value: Any = None
    max_value: Any = None
    description: str = ""
    unit: str = ""
    # Runtime value from SDO read
    current_value: Any = None
    current_value_raw: Optional[bytes] = None

    @property
    def is_readable(self) -> bool:
        """Check if entry can be read via SDO."""
        return self.access_type in ("ro", "rw", "const")

    @property
    def is_writable(self) -> bool:
        """Check if entry can be written via SDO."""
        return self.access_type in ("rw", "wo")

    @property
    def index_str(self) -> str:
        """Return formatted index string."""
        return f"0x{self.index:04X}"

    @property
    def subindex_str(self) -> str:
        """Return formatted subindex string."""
        return f"0x{self.subindex:02X}"

    @property
    def full_index_str(self) -> str:
        """Return formatted index:subindex string."""
        return f"0x{self.index:04X}:{self.subindex:02X}"


@dataclass
class ODIndex:
    """Represents an OD index entry (may contain sub-entries)."""

    index: int
    name: str
    object_type: int
    object_type_name: str
    description: str = ""
    subentries: list[ODEntry] = field(default_factory=list)

    @property
    def index_str(self) -> str:
        """Return formatted index string."""
        return f"0x{self.index:04X}"

    @property
    def has_subentries(self) -> bool:
        """Check if this index has sub-entries."""
        return len(self.subentries) > 0

    @property
    def is_variable(self) -> bool:
        """Check if this is a simple variable (no sub-entries)."""
        return self.object_type == 0x07  # VAR

    @property
    def is_array(self) -> bool:
        """Check if this is an array."""
        return self.object_type == 0x08

    @property
    def is_record(self) -> bool:
        """Check if this is a record."""
        return self.object_type == 0x09


class ObjectDictionaryWrapper:
    """
    Wrapper around canopen.ObjectDictionary for easier access.

    Loads EDS/DCF files and provides a clean interface to browse
    the object dictionary structure.
    """

    def __init__(self, path: Path):
        """
        Load an EDS/DCF file.

        Args:
            path: Path to the EDS or DCF file
        """
        self.path = path
        self._indices: list[ODIndex] = []
        self._entries_by_index: dict[tuple[int, int], ODEntry] = {}
        self._load()

    def _load(self) -> None:
        """Load and parse the EDS/DCF file."""
        # Use canopen's RemoteNode to parse the file
        # Node ID 1 is arbitrary - we just need to load the OD
        temp_node = canopen.RemoteNode(1, str(self.path))
        self._parse_od(temp_node.object_dictionary)

    def _parse_od(self, od: canopen.ObjectDictionary) -> None:
        """Parse the canopen ObjectDictionary into our data structures."""
        self._indices.clear()
        self._entries_by_index.clear()

        for index_key in sorted(od.keys()):
            if not isinstance(index_key, int):
                continue

            obj = od[index_key]
            od_index = self._parse_index(index_key, obj)
            self._indices.append(od_index)

    def _parse_index(self, index: int, obj: Any) -> ODIndex:
        """Parse a single OD index entry."""
        name = getattr(obj, "name", f"Object_{index:04X}")
        object_type = getattr(obj, "object_type", 0x07)  # Default to VAR
        object_type_name = OBJECT_TYPE_NAMES.get(object_type, f"Unknown({object_type})")
        description = getattr(obj, "description", "")

        od_index = ODIndex(
            index=index,
            name=name,
            object_type=object_type,
            object_type_name=object_type_name,
            description=description,
        )

        # Check for sub-entries (arrays/records)
        if hasattr(obj, "subindices") and obj.subindices:
            for subindex in sorted(obj.subindices.keys()):
                if isinstance(subindex, int):
                    subobj = obj.subindices[subindex]
                    entry = self._parse_entry(index, subindex, subobj)
                    od_index.subentries.append(entry)
                    self._entries_by_index[(index, subindex)] = entry
        else:
            # Simple variable - create a single entry at subindex 0
            entry = self._parse_entry(index, 0, obj)
            od_index.subentries.append(entry)
            self._entries_by_index[(index, 0)] = entry

        return od_index

    def _parse_entry(self, index: int, subindex: int, obj: Any) -> ODEntry:
        """Parse a single OD entry (variable or sub-entry)."""
        name = getattr(obj, "name", f"Sub_{subindex:02X}")
        data_type = getattr(obj, "data_type", 0)
        data_type_name = DATA_TYPE_NAMES.get(data_type, f"Unknown({data_type})")
        access_type = getattr(obj, "access_type", "ro")
        default = getattr(obj, "default", None)
        min_value = getattr(obj, "min", None)
        max_value = getattr(obj, "max", None)
        description = getattr(obj, "description", "")
        unit = getattr(obj, "unit", "")

        return ODEntry(
            index=index,
            subindex=subindex,
            name=name,
            data_type=data_type,
            data_type_name=data_type_name,
            access_type=access_type,
            default=default,
            min_value=min_value,
            max_value=max_value,
            description=description,
            unit=unit,
        )

    @property
    def indices(self) -> list[ODIndex]:
        """Get all OD indices."""
        return self._indices

    def get_index(self, index: int) -> Optional[ODIndex]:
        """Get an OD index by its index number."""
        for od_index in self._indices:
            if od_index.index == index:
                return od_index
        return None

    def get_entry(self, index: int, subindex: int = 0) -> Optional[ODEntry]:
        """Get a specific OD entry by index and subindex."""
        return self._entries_by_index.get((index, subindex))

    def get_readable_entries(self) -> list[ODEntry]:
        """Get all readable entries (for scan operation)."""
        return [e for e in self._entries_by_index.values() if e.is_readable]

    def get_writable_entries(self) -> list[ODEntry]:
        """Get all writable entries."""
        return [e for e in self._entries_by_index.values() if e.is_writable]

    def get_category(self, index: int) -> str:
        """Get the category name for an index."""
        if 0x1000 <= index <= 0x1FFF:
            return "Communication"
        elif 0x2000 <= index <= 0x5FFF:
            return "Manufacturer"
        elif 0x6000 <= index <= 0x9FFF:
            return "Profile"
        else:
            return "Other"

    def get_indices_by_category(self) -> dict[str, list[ODIndex]]:
        """Get indices grouped by category."""
        categories: dict[str, list[ODIndex]] = {
            "Communication": [],
            "Manufacturer": [],
            "Profile": [],
            "Other": [],
        }
        for od_index in self._indices:
            category = self.get_category(od_index.index)
            categories[category].append(od_index)
        return categories

    def update_entry_value(
        self, index: int, subindex: int, value: Any, raw: Optional[bytes] = None
    ) -> None:
        """Update the current value of an entry (after SDO read)."""
        entry = self.get_entry(index, subindex)
        if entry:
            entry.current_value = value
            entry.current_value_raw = raw

    def __len__(self) -> int:
        """Return the number of indices."""
        return len(self._indices)

    def __iter__(self):
        """Iterate over indices."""
        return iter(self._indices)
