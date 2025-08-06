# SPDX-FileCopyrightText: 2023-2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from esptool.logger import log

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


try:
    # AlreadyInitialized is not available since python-pkcs11 9.0, as multiple
    # initializations are now supported.
    from pkcs11.exceptions import AlreadyInitialized
except ImportError:
    AlreadyInitialized = None


def handle_exceptions(e, info=""):
    exception_type = e.__class__
    if exception_type == MechanismInvalid:
        log.error(f"The External HSM does not support the given mechanism: {info}")
    elif exception_type == FunctionFailed:
        log.error(
            "Please ensure proper configuration, privileges and environment variables."
        )
    elif exception_type == AlreadyInitialized:
        log.error("pkcs11 is already initialized with another library.")
    elif exception_type == AnotherUserAlreadyLoggedIn:
        log.error("Another User has been already logged in.")
    elif exception_type == ArgumentsBad:
        log.error("Please check the arguments supplied to the function.")
    elif exception_type == DomainParamsInvalid:
        log.error(
            "Invalid or unsupported domain parameters were supplied to the function."
        )
    elif exception_type == DeviceRemoved:
        log.error(
            "The token has been removed from its slot during "
            "the execution of the function."
        )
    elif exception_type == NoSuchToken:
        log.error("No such token found.")
    elif exception_type == NoSuchKey:
        log.error("No such key found.")
    elif exception_type == OperationNotInitialized:
        log.error("Operation not initialized.")
    elif exception_type == SessionClosed:
        log.error("Session already closed.")
    else:
        log.error(f"{e.__class__}: {info}")
