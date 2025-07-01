from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from pathlib import Path
import enum
import inspect
import cantools
import uuid

from .interfaces_utils import CANInterfaceManager


@dataclass
class CANFrame:
    timestamp: float
    arbitration_id: int
    data: bytes
    dlc: int
    is_extended: bool = False
    is_error: bool = False
    is_remote: bool = False
    bus: str | None = None
    connection_id: Optional[uuid.UUID] = None
    is_rx: bool = True


@dataclass
class DBCFile:
    path: Path
    database: object
    enabled: bool = True
    connection_id: Optional[uuid.UUID] = None


@dataclass
class CANFrameFilter:
    name: str = "New Filter"
    enabled: bool = True
    connection_id: Optional[uuid.UUID] = None
    min_id: int = 0x000
    max_id: int = 0x7FF
    mask: int = 0x7FF
    accept_extended: bool = True
    accept_standard: bool = True
    accept_data: bool = True
    accept_remote: bool = True

    def matches(self, frame: CANFrame) -> bool:
        # This will need to be updated to use connection_id from frame
        # For now, keeping it as channel for compatibility until frame is updated
        if self.connection_id is not None and self.connection_id != frame.connection_id:
            return False
        if frame.is_extended and not self.accept_extended:
            return False
        if not frame.is_extended and not self.accept_standard:
            return False
        if frame.is_remote and not self.accept_remote:
            return False
        if not frame.is_remote and not self.accept_data:
            return False
        return self.min_id <= (frame.arbitration_id & self.mask) <= self.max_id


@dataclass
class CANopenNode:
    path: Path
    node_id: int
    enabled: bool = True
    connection_id: Optional[uuid.UUID] = None
    pdo_decoding_enabled: bool = True

    def to_dict(self) -> Dict:
        return {
            "path": str(self.path),
            "node_id": self.node_id,
            "enabled": self.enabled,
            "connection_id": str(self.connection_id) if self.connection_id else None,
            "pdo_decoding_enabled": self.pdo_decoding_enabled,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "CANopenNode":
        path = Path(data["path"])
        if not path.exists():
            raise FileNotFoundError(f"EDS/DCF file not found: {path}")
        return cls(
            path=path,
            node_id=data["node_id"],
            enabled=data["enabled"],
            connection_id=uuid.UUID(data["connection_id"])
            if data.get("connection_id")
            else None,
            pdo_decoding_enabled=data.get("pdo_decoding_enabled", True),
        )


@dataclass
class Connection:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    name: str = ""
    interface: str = "virtual"
    config: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

    def __post_init__(self):
        if not self.name:
            self.name = "vcan0"
        if not self.config:
            if self.interface == "virtual":
                self.config["channel"] = self.name

    def to_dict(self) -> Dict:
        serializable_config = {
            k: v.name if isinstance(v, enum.Enum) else v for k, v in self.config.items()
        }
        return {
            "id": str(self.id),
            "name": self.name,
            "interface": self.interface,
            "config": serializable_config,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(
        cls, data: Dict, interface_manager: CANInterfaceManager
    ) -> "Connection":
        interface = data.get("interface", "virtual")
        config_from_file = data.get("config", {})
        hydrated_config = {}
        param_defs = interface_manager.get_interface_params(interface)

        if param_defs:
            for key, value in config_from_file.items():
                if key not in param_defs:
                    hydrated_config[key] = value
                    continue

                param_info = param_defs[key]
                expected_type = param_info.get("type")
                is_enum = False
                try:
                    if inspect.isclass(expected_type) and issubclass(
                        expected_type, enum.Enum
                    ):
                        is_enum = True
                except TypeError:
                    pass

                if is_enum and isinstance(value, str):
                    try:
                        hydrated_config[key] = expected_type[value]
                    except KeyError:
                        hydrated_config[key] = param_info.get("default")
                else:
                    hydrated_config[key] = value
        else:
            hydrated_config = config_from_file

        return cls(
            id=uuid.UUID(data["id"]) if data.get("id") else uuid.uuid4(),
            name=data.get("name", "default"),
            interface=interface,
            config=hydrated_config,
            enabled=data.get("enabled", True),
        )


@dataclass
class Project:
    connections: List[Connection] = field(default_factory=list)
    dbcs: List[DBCFile] = field(default_factory=list)
    filters: List[CANFrameFilter] = field(default_factory=list)
    canopen_enabled: bool = False
    canopen_nodes: List[CANopenNode] = field(default_factory=list)

    def get_active_dbcs(self) -> List[DBCFile]:
        return [dbc for dbc in self.dbcs if dbc.enabled]

    def get_active_filters(self) -> List[CANFrameFilter]:
        return [f for f in self.filters if f.enabled and f.connection_id is not None]

    def get_active_connections(self) -> List[Connection]:
        return [c for c in self.connections if c.enabled]

    def get_connection_name(self, connection_id: uuid.UUID) -> str:
        for conn in self.connections:
            if conn.id == connection_id:
                return conn.name
        return None

    def to_dict(self) -> Dict:
        return {
            "connections": [c.to_dict() for c in self.connections],
            "dbcs": [
                {
                    "path": str(dbc.path),
                    "enabled": dbc.enabled,
                    "connection_id": str(dbc.connection_id)
                    if dbc.connection_id
                    else None,
                }
                for dbc in self.dbcs
            ],
            "filters": [asdict(f) for f in self.filters],
            "canopen_enabled": self.canopen_enabled,
            "canopen_nodes": [node.to_dict() for node in self.canopen_nodes],
        }

    @classmethod
    def from_dict(cls, data: Dict, interface_manager: CANInterfaceManager) -> "Project":
        project = cls()

        if "can_interface" in data:
            # This part handles legacy project files where connections were not
            # explicitly defined but inferred from 'can_interface' and 'can_config'.
            # We create a new Connection object with a UUID for these.
            conn = Connection.from_dict(
                {
                    "name": data["can_interface"],
                    "interface": data["can_interface"],
                    "config": data.get("can_config", {}),
                    "enabled": True,
                    "id": str(uuid.uuid4()),  # Assign a new UUID for legacy connections
                },
                interface_manager,
            )
            project.connections.append(conn)

        for conn_data in data.get("connections", []):
            try:
                project.connections.append(
                    Connection.from_dict(conn_data, interface_manager)
                )
            except Exception as e:
                print(f"Warning: Could not load connection from project: {e}")

        if not project.connections:
            project.connections.append(Connection())

        project.canopen_enabled = data.get("canopen_enabled", False)

        for node_data in data.get("canopen_nodes", []):
            try:
                project.canopen_nodes.append(CANopenNode.from_dict(node_data))
            except Exception as e:
                print(f"Warning: Could not load CANopen node from project: {e}")

        project.filters = [
            CANFrameFilter(**f_data) for f_data in data.get("filters", [])
        ]
        for dbc_data in data.get("dbcs", []):
            try:
                path = Path(dbc_data["path"])
                if not path.exists():
                    raise FileNotFoundError(f"DBC file not found: {path}")
                db = cantools.database.load_file(path)
                project.dbcs.append(
                    DBCFile(
                        path,
                        db,
                        dbc_data.get("enabled", True),
                        uuid.UUID(dbc_data["connection_id"])
                        if dbc_data.get("connection_id")
                        else None,
                    )
                )
            except Exception as e:
                print(f"Warning: Could not load DBC from project file: {e}")
        return project
