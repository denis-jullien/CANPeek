"""
SocketCAN interface manager.

Provides comprehensive SocketCAN management with optional sudo elevation
for privileged operations like bringing interfaces up/down.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional, Callable
import shutil


class InterfaceState(IntEnum):
    """SocketCAN interface state."""
    UNKNOWN = 0
    ERROR_ACTIVE = 1
    ERROR_WARNING = 2
    ERROR_PASSIVE = 3
    BUS_OFF = 4
    STOPPED = 5
    SLEEPING = 6


@dataclass
class CANInterfaceStats:
    """Interface statistics from /sys/class/net/<iface>/statistics/."""
    tx_packets: int = 0
    rx_packets: int = 0
    tx_bytes: int = 0
    rx_bytes: int = 0
    tx_errors: int = 0
    rx_errors: int = 0
    tx_dropped: int = 0
    rx_dropped: int = 0
    rx_over_errors: int = 0
    rx_crc_errors: int = 0
    rx_frame_errors: int = 0
    rx_fifo_errors: int = 0
    tx_fifo_errors: int = 0
    collisions: int = 0


@dataclass
class CANInterfaceInfo:
    """Complete CAN interface information."""
    name: str
    is_up: bool = False
    is_can_fd: bool = False
    bitrate: Optional[int] = None
    data_bitrate: Optional[int] = None
    sample_point: Optional[float] = None
    data_sample_point: Optional[float] = None
    state: InterfaceState = InterfaceState.UNKNOWN
    restart_ms: int = 0
    txqueuelen: int = 10
    mtu: int = 16  # 16 for classic CAN, 72 for CAN FD

    # Error counters
    tx_error_counter: int = 0
    rx_error_counter: int = 0

    # Hardware info
    driver: str = "unknown"
    hw_type: str = "unknown"  # virtual, usb, pci, etc.
    device_path: str = ""

    # Statistics
    stats: CANInterfaceStats = field(default_factory=CANInterfaceStats)

    # Capabilities
    listen_only: bool = False
    loopback: bool = False
    one_shot: bool = False
    triple_sampling: bool = False
    berr_reporting: bool = False


class SudoError(Exception):
    """Raised when sudo operation fails."""
    pass


class SocketCANManager:
    """
    Manages SocketCAN interfaces with optional sudo elevation.

    This class provides methods to discover, configure, and control
    SocketCAN interfaces. Operations that require root privileges
    (like bringing interfaces up/down) use sudo with password caching.

    Example:
        >>> manager = SocketCANManager()
        >>> interfaces = manager.discover_interfaces()
        >>> print(interfaces)
        ['can0', 'vcan0']

        >>> # For privileged operations
        >>> if manager.request_sudo("mypassword"):
        ...     manager.set_interface_up("can0")
    """

    SYSFS_NET = Path("/sys/class/net")

    def __init__(self):
        self._sudo_password: Optional[str] = None
        self._sudo_validated = False
        self._sudo_timestamp = 0.0
        self._on_sudo_required: Optional[Callable[[], Optional[str]]] = None

    def set_sudo_callback(self, callback: Callable[[], Optional[str]]) -> None:
        """
        Set callback to request sudo password from user.

        The callback should return the password or None if cancelled.
        """
        self._on_sudo_required = callback

    def is_linux(self) -> bool:
        """Check if running on Linux."""
        return sys.platform.startswith('linux')

    def discover_interfaces(self) -> list[str]:
        """
        Find all CAN interfaces on the system.

        Returns:
            List of CAN interface names (e.g., ['can0', 'vcan0'])
        """
        if not self.is_linux():
            return []

        interfaces = []
        try:
            for iface_path in self.SYSFS_NET.iterdir():
                if not iface_path.is_dir():
                    continue

                type_file = iface_path / "type"
                if not type_file.exists():
                    continue

                try:
                    iface_type = int(type_file.read_text().strip())
                    # ARPHRD_CAN = 280 (from linux/if_arp.h)
                    if iface_type == 280:
                        interfaces.append(iface_path.name)
                except (ValueError, PermissionError, OSError):
                    pass
        except (PermissionError, OSError):
            pass

        return sorted(interfaces)

    def get_interface_info(self, iface: str) -> Optional[CANInterfaceInfo]:
        """
        Get detailed information about a CAN interface.

        Args:
            iface: Interface name (e.g., 'can0')

        Returns:
            CANInterfaceInfo or None if interface not found
        """
        if not self.is_linux():
            return None

        iface_path = self.SYSFS_NET / iface
        if not iface_path.exists():
            return None

        info = CANInterfaceInfo(name=iface)

        # Get detailed info from 'ip' command
        try:
            result = subprocess.run(
                ['ip', '-details', '-statistics', 'link', 'show', iface],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                self._parse_ip_output(info, result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        # Get additional stats from sysfs
        info.stats = self._read_statistics(iface)

        # Get driver info
        info.driver = self._get_driver(iface)
        info.hw_type = self._get_hw_type(iface)
        info.device_path = self._get_device_path(iface)

        # Get MTU for FD detection
        try:
            mtu = int((iface_path / "mtu").read_text().strip())
            info.mtu = mtu
            info.is_can_fd = mtu == 72  # CAN FD MTU
        except (ValueError, FileNotFoundError, PermissionError):
            pass

        return info

    def _parse_ip_output(self, info: CANInterfaceInfo, output: str) -> None:
        """Parse output from 'ip -details link show'."""
        lines = output.lower()

        # Interface state
        info.is_up = 'state up' in lines or ',up,' in lines

        # CAN state
        state_match = re.search(
            r'state\s+(error-active|error-warning|error-passive|bus-off|stopped|sleeping)',
            lines
        )
        if state_match:
            state_map = {
                'error-active': InterfaceState.ERROR_ACTIVE,
                'error-warning': InterfaceState.ERROR_WARNING,
                'error-passive': InterfaceState.ERROR_PASSIVE,
                'bus-off': InterfaceState.BUS_OFF,
                'stopped': InterfaceState.STOPPED,
                'sleeping': InterfaceState.SLEEPING,
            }
            info.state = state_map.get(state_match.group(1), InterfaceState.UNKNOWN)

        # Bitrate
        bitrate_match = re.search(r'bitrate\s+(\d+)', output)
        if bitrate_match:
            info.bitrate = int(bitrate_match.group(1))

        # Sample point
        sp_match = re.search(r'sample-point\s+([\d.]+)', output)
        if sp_match:
            info.sample_point = float(sp_match.group(1))

        # Data bitrate (CAN FD)
        dbitrate_match = re.search(r'dbitrate\s+(\d+)', output)
        if dbitrate_match:
            info.data_bitrate = int(dbitrate_match.group(1))
            info.is_can_fd = True

        # Data sample point
        dsp_match = re.search(r'dsample-point\s+([\d.]+)', output)
        if dsp_match:
            info.data_sample_point = float(dsp_match.group(1))

        # FD mode
        if 'fd on' in lines or 'fd-non-iso on' in lines:
            info.is_can_fd = True

        # Restart-ms
        restart_match = re.search(r'restart-ms\s+(\d+)', output)
        if restart_match:
            info.restart_ms = int(restart_match.group(1))

        # Error counters
        tec_match = re.search(r'tec\s+(\d+)', lines)
        if tec_match:
            info.tx_error_counter = int(tec_match.group(1))

        rec_match = re.search(r'rec\s+(\d+)', lines)
        if rec_match:
            info.rx_error_counter = int(rec_match.group(1))

        # Capabilities/modes
        info.listen_only = 'listen-only on' in lines
        info.loopback = 'loopback on' in lines
        info.one_shot = 'one-shot on' in lines
        info.triple_sampling = 'triple-sampling on' in lines
        info.berr_reporting = 'berr-reporting on' in lines

        # txqueuelen
        txq_match = re.search(r'txqueuelen\s+(\d+)', output)
        if txq_match:
            info.txqueuelen = int(txq_match.group(1))

    def _read_statistics(self, iface: str) -> CANInterfaceStats:
        """Read interface statistics from sysfs."""
        stats_path = self.SYSFS_NET / iface / "statistics"
        stats = CANInterfaceStats()

        stat_mapping = [
            ('tx_packets', 'tx_packets'),
            ('rx_packets', 'rx_packets'),
            ('tx_bytes', 'tx_bytes'),
            ('rx_bytes', 'rx_bytes'),
            ('tx_errors', 'tx_errors'),
            ('rx_errors', 'rx_errors'),
            ('tx_dropped', 'tx_dropped'),
            ('rx_dropped', 'rx_dropped'),
            ('rx_over_errors', 'rx_over_errors'),
            ('rx_crc_errors', 'rx_crc_errors'),
            ('rx_frame_errors', 'rx_frame_errors'),
            ('rx_fifo_errors', 'rx_fifo_errors'),
            ('tx_fifo_errors', 'tx_fifo_errors'),
            ('collisions', 'collisions'),
        ]

        for file_name, attr_name in stat_mapping:
            try:
                value = int((stats_path / file_name).read_text().strip())
                setattr(stats, attr_name, value)
            except (FileNotFoundError, ValueError, PermissionError, OSError):
                pass

        return stats

    def _get_driver(self, iface: str) -> str:
        """Get the driver name for the interface."""
        driver_link = self.SYSFS_NET / iface / "device" / "driver"
        try:
            return driver_link.resolve().name
        except (FileNotFoundError, PermissionError, OSError):
            return "unknown"

    def _get_hw_type(self, iface: str) -> str:
        """Determine hardware type (virtual, USB, PCI, etc.)."""
        device_path = self.SYSFS_NET / iface / "device"

        if not device_path.exists():
            return "virtual"

        try:
            # Follow the device symlink
            resolved = device_path.resolve()

            # Check for USB
            if '/usb' in str(resolved):
                return "usb"

            # Check subsystem
            subsystem_link = device_path / "subsystem"
            if subsystem_link.exists():
                subsystem = subsystem_link.resolve().name
                if subsystem in ('pci', 'usb', 'platform', 'spi'):
                    return subsystem

            return "unknown"
        except (PermissionError, OSError):
            return "unknown"

    def _get_device_path(self, iface: str) -> str:
        """Get the sysfs device path."""
        device_path = self.SYSFS_NET / iface / "device"
        try:
            return str(device_path.resolve())
        except (FileNotFoundError, PermissionError, OSError):
            return ""

    # --- Sudo operations ---

    def request_sudo(self, password: str) -> bool:
        """
        Validate sudo password.

        Args:
            password: User's sudo password

        Returns:
            True if password is valid
        """
        if not self.is_linux():
            return False

        try:
            result = subprocess.run(
                ['sudo', '-S', '-v'],
                input=password + '\n',
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                self._sudo_password = password
                self._sudo_validated = True
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return False

    def clear_sudo(self) -> None:
        """Clear cached sudo credentials."""
        self._sudo_password = None
        self._sudo_validated = False
        # Invalidate sudo timestamp
        try:
            subprocess.run(['sudo', '-k'], capture_output=True, timeout=5)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    def _run_sudo(self, cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
        """
        Run a command with sudo.

        Raises:
            SudoError: If sudo not validated or command fails
        """
        if not self._sudo_validated:
            # Try callback if available
            if self._on_sudo_required:
                password = self._on_sudo_required()
                if password and self.request_sudo(password):
                    pass  # Continue with the command
                else:
                    raise SudoError("Sudo authentication required but not provided")
            else:
                raise SudoError("Sudo not validated. Call request_sudo() first.")

        full_cmd = ['sudo', '-S'] + cmd
        try:
            result = subprocess.run(
                full_cmd,
                input=self._sudo_password + '\n',
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result
        except subprocess.TimeoutExpired as e:
            raise SudoError(f"Command timed out: {' '.join(cmd)}") from e

    def set_interface_up(self, iface: str) -> bool:
        """
        Bring interface up.

        Args:
            iface: Interface name

        Returns:
            True if successful

        Raises:
            SudoError: If sudo not available
        """
        result = self._run_sudo(['ip', 'link', 'set', iface, 'up'])
        return result.returncode == 0

    def set_interface_down(self, iface: str) -> bool:
        """
        Bring interface down.

        Args:
            iface: Interface name

        Returns:
            True if successful

        Raises:
            SudoError: If sudo not available
        """
        result = self._run_sudo(['ip', 'link', 'set', iface, 'down'])
        return result.returncode == 0

    def configure_interface(
        self,
        iface: str,
        bitrate: int,
        *,
        data_bitrate: Optional[int] = None,
        fd: bool = False,
        sample_point: Optional[float] = None,
        data_sample_point: Optional[float] = None,
        listen_only: bool = False,
        loopback: bool = False,
        one_shot: bool = False,
        triple_sampling: bool = False,
        berr_reporting: bool = False,
        restart_ms: int = 100,
    ) -> tuple[bool, str]:
        """
        Configure CAN interface parameters.

        The interface will be brought down, configured, and brought back up.

        Args:
            iface: Interface name
            bitrate: Nominal bitrate in bit/s
            data_bitrate: Data bitrate for CAN FD
            fd: Enable CAN FD mode
            sample_point: Sample point (0.0-1.0)
            data_sample_point: Data sample point for FD
            listen_only: Enable listen-only mode
            loopback: Enable loopback mode
            one_shot: Enable one-shot mode
            triple_sampling: Enable triple sampling
            berr_reporting: Enable bus error reporting
            restart_ms: Auto-restart delay (0 to disable)

        Returns:
            Tuple of (success: bool, error_message: str)

        Raises:
            SudoError: If sudo not available
        """
        # Must be down to configure
        self.set_interface_down(iface)

        # Build configuration command
        cmd = ['ip', 'link', 'set', iface, 'type', 'can']

        # Bitrate
        cmd.extend(['bitrate', str(bitrate)])

        if sample_point is not None:
            cmd.extend(['sample-point', str(sample_point)])

        # CAN FD
        if fd:
            if data_bitrate:
                cmd.extend(['dbitrate', str(data_bitrate)])
                if data_sample_point is not None:
                    cmd.extend(['dsample-point', str(data_sample_point)])
            cmd.extend(['fd', 'on'])

        # Modes
        if listen_only:
            cmd.extend(['listen-only', 'on'])
        if loopback:
            cmd.extend(['loopback', 'on'])
        if one_shot:
            cmd.extend(['one-shot', 'on'])
        if triple_sampling:
            cmd.extend(['triple-sampling', 'on'])
        if berr_reporting:
            cmd.extend(['berr-reporting', 'on'])

        # Restart
        cmd.extend(['restart-ms', str(restart_ms)])

        result = self._run_sudo(cmd)

        if result.returncode != 0:
            error = result.stderr.strip() or "Unknown error"
            return False, error

        return True, ""

    def restart_interface(self, iface: str) -> bool:
        """
        Restart a CAN interface (useful after bus-off).

        Args:
            iface: Interface name

        Returns:
            True if successful
        """
        result = self._run_sudo(['ip', 'link', 'set', iface, 'type', 'can', 'restart'])
        return result.returncode == 0

    def set_txqueuelen(self, iface: str, length: int) -> bool:
        """
        Set the transmit queue length.

        Args:
            iface: Interface name
            length: Queue length

        Returns:
            True if successful
        """
        result = self._run_sudo(['ip', 'link', 'set', iface, 'txqueuelen', str(length)])
        return result.returncode == 0

    # --- Virtual CAN ---

    def create_vcan(self, name: str = "vcan0") -> tuple[bool, str]:
        """
        Create a virtual CAN interface.

        Args:
            name: Interface name

        Returns:
            Tuple of (success: bool, error_message: str)
        """
        # Load vcan module
        result = self._run_sudo(['modprobe', 'vcan'])
        if result.returncode != 0:
            return False, f"Failed to load vcan module: {result.stderr}"

        # Check if interface already exists
        if (self.SYSFS_NET / name).exists():
            # Just bring it up
            if self.set_interface_up(name):
                return True, ""
            return False, "Interface exists but could not be brought up"

        # Create interface
        result = self._run_sudo(['ip', 'link', 'add', 'dev', name, 'type', 'vcan'])
        if result.returncode != 0:
            if 'exists' in result.stderr.lower():
                # Already exists, try to bring up
                if self.set_interface_up(name):
                    return True, ""
            return False, f"Failed to create vcan: {result.stderr}"

        # Bring up
        if self.set_interface_up(name):
            return True, ""

        return False, "Created but failed to bring up"

    def delete_vcan(self, name: str) -> bool:
        """
        Delete a virtual CAN interface.

        Args:
            name: Interface name

        Returns:
            True if successful
        """
        self.set_interface_down(name)
        result = self._run_sudo(['ip', 'link', 'delete', name])
        return result.returncode == 0

    # --- CAN FD virtual interface ---

    def create_vcan_fd(self, name: str = "vcan0") -> tuple[bool, str]:
        """
        Create a virtual CAN FD interface.

        Args:
            name: Interface name

        Returns:
            Tuple of (success: bool, error_message: str)
        """
        # Load vcan module
        result = self._run_sudo(['modprobe', 'vcan'])
        if result.returncode != 0:
            return False, f"Failed to load vcan module: {result.stderr}"

        # Check if interface already exists
        if (self.SYSFS_NET / name).exists():
            self.delete_vcan(name)

        # Create interface with FD MTU
        result = self._run_sudo([
            'ip', 'link', 'add', 'dev', name, 'type', 'vcan'
        ])
        if result.returncode != 0 and 'exists' not in result.stderr.lower():
            return False, f"Failed to create vcan: {result.stderr}"

        # Set MTU for CAN FD (72 bytes)
        result = self._run_sudo(['ip', 'link', 'set', name, 'mtu', '72'])
        if result.returncode != 0:
            return False, f"Failed to set FD MTU: {result.stderr}"

        # Bring up
        if self.set_interface_up(name):
            return True, ""

        return False, "Created but failed to bring up"

    # --- Utility methods ---

    def get_all_interface_info(self) -> dict[str, CANInterfaceInfo]:
        """
        Get info for all discovered CAN interfaces.

        Returns:
            Dict mapping interface name to info
        """
        result = {}
        for iface in self.discover_interfaces():
            info = self.get_interface_info(iface)
            if info:
                result[iface] = info
        return result

    def is_can_utils_available(self) -> bool:
        """Check if can-utils package is installed."""
        return shutil.which('candump') is not None

    def is_ip_available(self) -> bool:
        """Check if iproute2 (ip command) is available."""
        return shutil.which('ip') is not None
