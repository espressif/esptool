# SPDX-FileCopyrightText: 2023-2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from pkcs11.exceptions import (
    AnotherUserAlreadyLoggedIn,
    ArgumentsBad,
    DeviceRemoved,
    DomainParamsInvalid,
    FunctionFailed,
    MechanismInvalid,
    NoSuchKey,
    NoSuchToken,
    OperationNotInitialized,
    SessionClosed,
)
from rich.markup import escape

from esptool.logger import log

try:
    # AlreadyInitialized is not available since python-pkcs11 9.0, as multiple
    # initializations are now supported.
    from pkcs11.exceptions import AlreadyInitialized
except ImportError:
    AlreadyInitialized = None


def handle_exceptions(e, info=""):
    exception_type = e.__class__
    if exception_type == MechanismInvalid:
        log.err(
            f"The External HSM does not support the given mechanism: "
            f"{escape(str(info))}"
        )
    elif exception_type == FunctionFailed:
        log.err(
            "Please ensure proper configuration, privileges and environment variables."
        )
    elif exception_type == AlreadyInitialized:
        log.err("pkcs11 is already initialized with another library.")
    elif exception_type == AnotherUserAlreadyLoggedIn:
        log.err("Another User has been already logged in.")
    elif exception_type == ArgumentsBad:
        log.err("Please check the arguments supplied to the function.")
    elif exception_type == DomainParamsInvalid:
        log.err(
            "Invalid or unsupported domain parameters were supplied to the function."
        )
    elif exception_type == DeviceRemoved:
        log.err(
            "The token has been removed from its slot during "
            "the execution of the function."
        )
    elif exception_type == NoSuchToken:
        log.err("No such token found.")
    elif exception_type == NoSuchKey:
        log.err("No such key found.")
    elif exception_type == OperationNotInitialized:
        log.err("Operation not initialized.")
    elif exception_type == SessionClosed:
        log.err("Session already closed.")
    else:
        log.err(f"{e.__class__}: {escape(str(info))}")
