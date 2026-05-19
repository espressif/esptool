# SPDX-FileCopyrightText: 2014-2025 Espressif Systems (Shanghai) CO LTD,
# other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from esp_pylib.config import ToolConfig

from .logger import log

CONFIG_OPTIONS = [
    "timeout",
    "chip_erase_timeout",
    "max_timeout",
    "sync_timeout",
    "md5_timeout_per_mb",
    "erase_region_timeout_per_mb",
    "erase_write_timeout_per_mb",
    "mem_end_rom_timeout",
    "serial_write_timeout",
    "connect_attempts",
    "write_block_attempts",
    "reset_delay",
    "open_port_attempts",
    "custom_reset_sequence",
    "custom_hard_reset_sequence",
]

# Module-level ToolConfig instance: ``load_config_file`` is called
# at module-import time from ``esptool.loader`` (to seed the timeout / retry
# constants) *and* again at CLI start-up with ``verbose=True`` (to surface
# the "Loaded custom configuration from ..." line). Sharing one instance
# means both call sites observe the same cached parser, and the second
# verbose call still emits the user-facing messages because the first call
# did not.
#
# ``permissive_env_var=True`` matches the historical behaviour: the env-var
# override silently falls through to the directory search when the file is
# missing or has no ``[esptool]`` section, instead of crashing module-level
# imports of ``esptool.loader``.
_CONFIG = ToolConfig(
    section_name="esptool",
    config_filenames=["esptool.cfg", "setup.cfg", "tox.ini"],
    env_var="ESPTOOL_CFGFILE",
    valid_options=CONFIG_OPTIONS,
    permissive_env_var=True,
    logger=log,
)


def load_config_file(verbose=False):
    """Return the parsed esptool configuration.

    Kept for backward compatibility with external consumers (notably
    `esp_rfc2217_server`). The first call decides whether to emit the
    "Loaded custom configuration from ..." line by flipping the shared
    ToolConfig's ``verbose`` flag — verbose CLI starts upgrade the
    quiet module-import-time load, but never the other way around.
    """
    if verbose and not _CONFIG.verbose:
        _CONFIG.verbose = True
        # Drop the cached parser so the next ``load()`` re-emits the user-
        # facing messages now that ``verbose`` is on.
        _CONFIG.reload()
    parser, path = _CONFIG.load()
    return parser, (str(path) if path is not None else None)
