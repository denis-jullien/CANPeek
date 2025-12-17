"""
Project data structure for CANPeek.

A project contains all configuration needed to restore a CANPeek session:
- Connections (CAN interfaces)
- Database files (DBC, ARXML)
- Filters
- Window layout

Project files use YAML format (.cpeek extension).
"""

from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Any
from uuid import UUID

from canpeek.core.types import Connection


@dataclass
class DatabaseConfig:
    """Configuration for a loaded database file."""
    path: str
    enabled: bool = True
    bus_filter: Optional[str] = None  # Specific bus, or None for all


@dataclass
class FilterConfig:
    """Configuration for a message filter."""
    name: str
    enabled: bool = True
    min_id: Optional[int] = None
    max_id: Optional[int] = None
    bus_filter: Optional[str] = None
    id_pattern: str = ""


@dataclass
class Project:
    """
    CANPeek project containing all session configuration.

    Attributes:
        name: Project name
        path: Path to project file (None if not saved)
        connections: List of CAN connections
        databases: List of database configurations
        filters: List of filter configurations
        window_state: Serialized window layout state
    """
    name: str = "Untitled"
    path: Optional[str] = None
    connections: list[Connection] = field(default_factory=list)
    databases: list[DatabaseConfig] = field(default_factory=list)
    filters: list[FilterConfig] = field(default_factory=list)
    window_state: Optional[bytes] = None
    dock_state: Optional[bytes] = None

    @property
    def is_saved(self) -> bool:
        """Check if project has been saved to disk."""
        return self.path is not None

    @property
    def display_name(self) -> str:
        """Get display name for project."""
        if self.path:
            return Path(self.path).stem
        return self.name

    def to_dict(self) -> dict[str, Any]:
        """Convert project to dictionary for JSON serialization."""
        return {
            "version": 1,
            "name": self.name,
            "connections": [
                {
                    "id": str(conn.id),
                    "name": conn.name,
                    "interface": conn.interface,
                    "channel": conn.channel,
                    "bitrate": conn.bitrate,
                    "data_bitrate": conn.data_bitrate,
                    "fd": conn.fd,
                    "enabled": conn.enabled,
                    "extra_config": conn.extra_config,
                }
                for conn in self.connections
            ],
            "databases": [
                {
                    "path": db.path,
                    "enabled": db.enabled,
                    "bus_filter": db.bus_filter,
                }
                for db in self.databases
            ],
            "filters": [
                {
                    "name": f.name,
                    "enabled": f.enabled,
                    "min_id": f.min_id,
                    "max_id": f.max_id,
                    "bus_filter": f.bus_filter,
                    "id_pattern": f.id_pattern,
                }
                for f in self.filters
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Project:
        """Create project from dictionary."""
        version = data.get("version", 1)

        connections = []
        for conn_data in data.get("connections", []):
            conn = Connection(
                id=UUID(conn_data["id"]) if "id" in conn_data else None,
                name=conn_data.get("name", ""),
                interface=conn_data.get("interface", "socketcan"),
                channel=conn_data.get("channel", ""),
                bitrate=conn_data.get("bitrate", 500000),
                data_bitrate=conn_data.get("data_bitrate", 2000000),
                fd=conn_data.get("fd", False),
                enabled=conn_data.get("enabled", True),
                extra_config=conn_data.get("extra_config", {}),
            )
            connections.append(conn)

        databases = []
        for db_data in data.get("databases", []):
            db = DatabaseConfig(
                path=db_data.get("path", ""),
                enabled=db_data.get("enabled", True),
                bus_filter=db_data.get("bus_filter"),
            )
            databases.append(db)

        filters = []
        for filter_data in data.get("filters", []):
            f = FilterConfig(
                name=filter_data.get("name", ""),
                enabled=filter_data.get("enabled", True),
                min_id=filter_data.get("min_id"),
                max_id=filter_data.get("max_id"),
                bus_filter=filter_data.get("bus_filter"),
                id_pattern=filter_data.get("id_pattern", ""),
            )
            filters.append(f)

        return cls(
            name=data.get("name", "Untitled"),
            connections=connections,
            databases=databases,
            filters=filters,
        )

    def save(self, path: Optional[str] = None) -> bool:
        """
        Save project to YAML file.

        Args:
            path: Path to save to (uses self.path if None)

        Returns:
            True if saved successfully
        """
        save_path = path or self.path
        if not save_path:
            return False

        try:
            data = self.to_dict()
            with open(save_path, 'w') as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            self.path = save_path
            return True
        except Exception as e:
            print(f"Failed to save project: {e}")
            return False

    @classmethod
    def load(cls, path: str) -> Optional[Project]:
        """
        Load project from YAML file.

        Args:
            path: Path to project file

        Returns:
            Project instance or None if loading failed
        """
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
            project = cls.from_dict(data)
            project.path = path
            return project
        except Exception as e:
            print(f"Failed to load project: {e}")
            return None
