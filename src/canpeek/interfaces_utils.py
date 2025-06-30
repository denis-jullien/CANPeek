from typing import Dict, List, Optional
import inspect
import importlib
import can
from contextlib import contextmanager
import logging
from docstring_parser import parse


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
    """
    Dynamically discovers available python-can interfaces. It uses the
    'docstring-parser' library to parse their docstrings, finds their
    configuration parameters, and filters out any interfaces that produce
    warnings or errors during discovery.
    """

    def __init__(self):
        self._interfaces = self._discover_interfaces()

    def _discover_interfaces(self):
        interfaces = {}
        for name, (module_name, class_name) in can.interfaces.BACKENDS.items():
            try:
                parsed_doc_dict = {}
                with capture_logs("can") as log_handler:
                    module = importlib.import_module(module_name)
                    bus_class = getattr(module, class_name)

                    init_doc = inspect.getdoc(bus_class.__init__)
                    raw_doc = init_doc if init_doc else inspect.getdoc(bus_class)

                    if raw_doc:
                        parsed = parse(raw_doc)

                        desc_parts = []
                        if parsed.short_description:
                            desc_parts.append(parsed.short_description)
                        if parsed.long_description:
                            desc_parts.append(parsed.long_description)
                        description = "\n\n".join(desc_parts)

                        params_dict = {
                            param.arg_name: {
                                "type_name": param.type_name,
                                "description": param.description or "",
                            }
                            for param in parsed.params
                        }

                        parsed_doc_dict = {
                            "description": description,
                            "params": params_dict,
                        }
                    else:
                        parsed_doc_dict = {"description": "", "params": {}}

                    if log_handler.records:
                        first_warning = log_handler.records[0].getMessage()
                        print(
                            f"Info: Skipping interface '{name}' due to warning: {first_warning}"
                        )
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

                interfaces[name] = {
                    "class": bus_class,
                    "params": params,
                    "docstring": parsed_doc_dict,
                }

            except (ImportError, AttributeError, OSError, TypeError) as e:
                print(f"Info: Skipping interface '{name}' due to error on load: {e}")
            except Exception as e:
                print(f"Warning: Could not load or inspect CAN interface '{name}': {e}")

        return dict(sorted(interfaces.items()))

    def get_available_interfaces(self) -> List[str]:
        return list(self._interfaces.keys())

    def get_interface_params(self, name: str) -> Optional[Dict]:
        return self._interfaces.get(name, {}).get("params")

    def get_interface_docstring(self, name: str) -> Optional[Dict]:
        """Returns the parsed docstring for the given interface name."""
        return self._interfaces.get(name, {}).get("docstring")
