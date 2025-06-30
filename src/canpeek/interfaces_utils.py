from typing import Dict, List, Optional
import inspect
import importlib
import can
from contextlib import contextmanager
import logging


class LogCaptureHandler(logging.Handler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []

    def emit(self, record):
        self.records.append(record)


@contextmanager
def capture_logs(logger_name: str):
    log_handler = LogCaptureHandler()
    target_logger = logging.getLogger(logger_name)
    original_handlers = target_logger.handlers[:]
    original_level = target_logger.level
    try:
        target_logger.handlers.clear()
        target_logger.addHandler(log_handler)
        target_logger.setLevel(logging.WARNING)
        yield log_handler
    finally:
        target_logger.handlers = original_handlers
        target_logger.setLevel(original_level)


class CANInterfaceManager:
    def __init__(self):
        self._interfaces = self._discover_interfaces()

    def _discover_interfaces(self):
        interfaces = {}
        for name, (module_name, class_name) in can.interfaces.BACKENDS.items():
            try:
                with capture_logs("can") as log_handler:
                    module = importlib.import_module(module_name)
                    bus_class = getattr(module, class_name)
                    if log_handler.records:
                        continue
                sig = inspect.signature(bus_class.__init__)
                params = {}
                for param in sig.parameters.values():
                    if param.name in ["self", "args", "kwargs", "receive_own_messages"]:
                        continue
                    param_info = {
                        "default": param.default
                        if param.default is not inspect.Parameter.empty
                        else None,
                        "type": param.annotation
                        if param.annotation is not inspect.Parameter.empty
                        else type(param.default),
                    }
                    params[param.name] = param_info
                interfaces[name] = {"class": bus_class, "params": params}
            except (ImportError, AttributeError, OSError, TypeError) as e:
                print(f"Info: Skipping interface '{name}' due to error on load: {e}")
            except Exception as e:
                print(f"Warning: Could not load or inspect CAN interface '{name}': {e}")

        return dict(sorted(interfaces.items()))

    def get_available_interfaces(self) -> List[str]:
        return list(self._interfaces.keys())

    def get_interface_params(self, name: str) -> Optional[Dict]:
        return self._interfaces.get(name, {}).get("params")
