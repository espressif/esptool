# SPDX-FileCopyrightText: 2014-2025 Espressif Systems (Shanghai) CO LTD,
# other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import configparser
import os

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


def _validate_config_file(file_path, verbose=False):
    if not os.path.exists(file_path):
        return False

    cfg = configparser.RawConfigParser()
    try:
        cfg.read(file_path, encoding="UTF-8")
        # Only consider it a valid config file if it contains [esptool] section
        if cfg.has_section("esptool"):
            if verbose:
                unknown_opts = list(set(cfg.options("esptool")) - set(CONFIG_OPTIONS))
                unknown_opts.sort()
                no_of_unknown_opts = len(unknown_opts)
                if no_of_unknown_opts > 0:
                    suffix = "s" if no_of_unknown_opts > 1 else ""
                    log.note(
                        "Ignoring unknown config file option{}: {}".format(
                            suffix, ", ".join(unknown_opts)
                        )
                    )
            return True
    except (UnicodeDecodeError, configparser.Error) as e:
        if verbose:
            log.note(f"Ignoring invalid config file {file_path}: {e}")
    return False


def _find_config_file(dir_path, verbose=False):
    for candidate in ("esptool.cfg", "setup.cfg", "tox.ini"):
        cfg_path = os.path.join(dir_path, candidate)
        if _validate_config_file(cfg_path, verbose):
            return cfg_path
    return None


def load_config_file(verbose=False):
    set_with_env_var = False
    env_var_path = os.environ.get("ESPTOOL_CFGFILE")
    if env_var_path is not None and _validate_config_file(env_var_path):
        cfg_file_path = env_var_path
        set_with_env_var = True
    else:
        home_dir = os.path.expanduser("~")
        os_config_dir = (
            f"{home_dir}/.config/esptool"
            if os.name == "posix"
            else f"{home_dir}/AppData/Local/esptool/"
        )
        # Search priority: 1) current dir, 2) OS specific config dir, 3) home dir
        for dir_path in (os.getcwd(), os_config_dir, home_dir):
            cfg_file_path = _find_config_file(dir_path, verbose)
            if cfg_file_path:
                break

    cfg = configparser.ConfigParser()
    cfg["esptool"] = {}  # Create an empty esptool config for when no file is found

    if cfg_file_path is not None:
        # If config file is found and validated, read and parse it
        cfg.read(cfg_file_path)
        if verbose:
            msg = " (set with ESPTOOL_CFGFILE)" if set_with_env_var else ""
            log.print(
                f"Loaded custom configuration from "
                f"{os.path.abspath(cfg_file_path)}{msg}"
            )
    return cfg, cfg_file_path
