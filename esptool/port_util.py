# SPDX-FileCopyrightText: 2014-2025 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import sys
from collections.abc import Iterable

from .loader import ListPortInfo, list_ports
from .util import FatalError


def get_port_list(
    vids: list[int] = [],
    pids: list[int] = [],
    names: list[str] = [],
    serials: list[str] = [],
) -> list[str]:
    """Get the list of serial ports names with optional filters.

    For backwards compatibility, this function returns a list of port names.
    """
    return [port.device for port in _get_port_list(vids, pids, names, serials)]


def _get_port_list(
    vids: list[int] = [],
    pids: list[int] = [],
    names: list[str] = [],
    serials: list[str] = [],
) -> list[ListPortInfo]:
    if list_ports is None:
        raise FatalError(
            "Listing all serial ports is currently not available. "
            "Please try to specify the port when running esptool or update "
            "the pyserial package to the latest version."
        )
    ports = []
    for port in list_ports.comports():
        if sys.platform == "darwin" and port.device.endswith(
            ("Bluetooth-Incoming-Port", "wlan-debug", "cu.debug-console")
        ):
            continue
        if vids and (port.vid is None or port.vid not in vids):
            continue
        if pids and (port.pid is None or port.pid not in pids):
            continue
        if names and (
            port.name is None or all(name not in port.name for name in names)
        ):
            continue
        if serials and (
            port.serial_number is None
            or all(serial not in port.serial_number for serial in serials)
        ):
            continue
        ports.append(port)

    # Constants for sorting optimization
    ESPRESSIF_VID = 0x303A
    LINUX_DEVICE_PATTERNS = ("ttyUSB", "ttyACM")
    MACOS_DEVICE_PATTERNS = ("usbserial", "usbmodem")

    def _port_sort_key_linux(port_info: ListPortInfo) -> tuple[int, str]:
        if port_info.vid == ESPRESSIF_VID:
            return (3, port_info.device)

        if any(pattern in port_info.device for pattern in LINUX_DEVICE_PATTERNS):
            return (2, port_info.device)

        return (1, port_info.device)

    def _port_sort_key_macos(port_info: ListPortInfo) -> tuple[int, str]:
        if port_info.vid == ESPRESSIF_VID:
            return (3, port_info.device)

        if any(pattern in port_info.device for pattern in MACOS_DEVICE_PATTERNS):
            return (2, port_info.device)

        return (1, port_info.device)

    def _port_sort_key_windows(port_info: ListPortInfo) -> tuple[int, str]:
        if port_info.vid == ESPRESSIF_VID:
            return (2, port_info.device)

        return (1, port_info.device)

    if sys.platform == "win32":
        key_func = _port_sort_key_windows
    elif sys.platform == "darwin":
        key_func = _port_sort_key_macos
    else:
        key_func = _port_sort_key_linux

    sorted_port_info = sorted(ports, key=key_func)
    return sorted_port_info


def parse_port_filters(
    value: Iterable[str],
) -> tuple[list[int], list[int], list[str], list[str]]:
    """Parse port filter arguments into separate lists for each filter type"""
    filterVids = []
    filterPids = []
    filterNames = []
    filterSerials = []
    for f in value:
        kvp = f.split("=")
        if len(kvp) != 2:
            raise FatalError("Option --port-filter argument must consist of key=value.")
        if kvp[0] == "vid":
            filterVids.append(int(kvp[1], 0))
        elif kvp[0] == "pid":
            filterPids.append(int(kvp[1], 0))
        elif kvp[0] == "name":
            filterNames.append(kvp[1])
        elif kvp[0] == "serial":
            filterSerials.append(kvp[1])
        else:
            raise FatalError("Option --port-filter argument key not recognized.")
    return filterVids, filterPids, filterNames, filterSerials
