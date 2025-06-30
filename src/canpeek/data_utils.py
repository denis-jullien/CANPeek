from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any
from pathlib import Path
import enum
import inspect
import cantools

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
    channel: str = "CAN1"


@dataclass
class DBCFile:
    path: Path
    database: object
    enabled: bool = True


@dataclass
class CANFrameFilter:
    name: str = "New Filter"
    enabled: bool = True
    min_id: int = 0x000
    max_id: int = 0x7FF
    mask: int = 0x7FF
    accept_extended: bool = True
    accept_standard: bool = True
    accept_data: bool = True
    accept_remote: bool = True

    def matches(self, frame: CANFrame) -> bool:
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
    pdo_decoding_enabled: bool = True  # Add PDO decoding option

    def to_dict(self) -> Dict:
        return {
            "path": str(self.path),
            "node_id": self.node_id,
            "enabled": self.enabled,
            "pdo_decoding_enabled": self.pdo_decoding_enabled,  # Add to serialization
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
            pdo_decoding_enabled=data.get(
                "pdo_decoding_enabled", True
            ),  # Add with default
        )


@dataclass
class Project:
    dbcs: List[DBCFile] = field(default_factory=list)
    filters: List[CANFrameFilter] = field(default_factory=list)
    canopen_enabled: bool = False
    canopen_nodes: List[CANopenNode] = field(default_factory=list)
    can_interface: str = "virtual"
    can_config: Dict[str, Any] = field(default_factory=lambda: {"channel": "vcan0"})

    def get_active_dbcs(self) -> List[object]:
        return [dbc.database for dbc in self.dbcs if dbc.enabled]

    def get_active_filters(self) -> List[CANFrameFilter]:
        return [f for f in self.filters if f.enabled]

    def to_dict(self) -> Dict:
        serializable_can_config = {
            k: v.name if isinstance(v, enum.Enum) else v
            for k, v in self.can_config.items()
        }
        return {
            "dbcs": [
                {"path": str(dbc.path), "enabled": dbc.enabled} for dbc in self.dbcs
            ],
            "filters": [asdict(f) for f in self.filters],
            "canopen_enabled": self.canopen_enabled,
            "canopen_nodes": [node.to_dict() for node in self.canopen_nodes],
            "can_interface": self.can_interface,
            "can_config": serializable_can_config,
        }

    @classmethod
    def from_dict(cls, data: Dict, interface_manager: CANInterfaceManager) -> "Project":
        project = cls()
        project.canopen_enabled = data.get("canopen_enabled", False)
        project.can_interface = data.get("can_interface", "virtual")

        for node_data in data.get("canopen_nodes", []):
            try:
                project.canopen_nodes.append(CANopenNode.from_dict(node_data))
            except Exception as e:
                print(f"Warning: Could not load CANopen node from project: {e}")

        config_from_file = data.get("can_config", {})
        hydrated_config = {}
        param_defs = interface_manager.get_interface_params(project.can_interface)

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

        project.can_config = hydrated_config
        project.filters = [
            CANFrameFilter(**f_data) for f_data in data.get("filters", [])
        ]
        for dbc_data in data.get("dbcs", []):
            try:
                path = Path(dbc_data["path"])
                if not path.exists():
                    raise FileNotFoundError(f"DBC file not found: {path}")
                db = cantools.database.load_file(path)
                project.dbcs.append(DBCFile(path, db, dbc_data.get("enabled", True)))
            except Exception as e:
                print(f"Warning: Could not load DBC from project file: {e}")
        return project
