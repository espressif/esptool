# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from pkcs11.exceptions import (
    AlreadyInitialized,
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


def handle_exceptions(e, info=""):
    exception_type = e.__class__
    if exception_type == MechanismInvalid:
        print("The External HSM does not support the given mechanism", info)
    elif exception_type == FunctionFailed:
        print(
            "Please ensure proper configuration, privileges and environment variables"
        )
    elif exception_type == AlreadyInitialized:
        print("pkcs11 is already initialized with another library")
    elif exception_type == AnotherUserAlreadyLoggedIn:
        print("Another User has been already logged in")
    elif exception_type == ArgumentsBad:
        print("Please check the arguments supplied to the function")
    elif exception_type == DomainParamsInvalid:
        print("Invalid or unsupported domain parameters were supplied to the function")
    elif exception_type == DeviceRemoved:
        print(
            "The token has been removed from its slot during "
            "the execution of the function"
        )
    elif exception_type == NoSuchToken:
        print("No such token found")
    elif exception_type == NoSuchKey:
        print("No such key found")
    elif exception_type == OperationNotInitialized:
        print("Operation not Initialized")
    elif exception_type == SessionClosed:
        print("Session already closed")
    else:
        print(e.__class__, info)
