.. _get-custom-mac-cmd:

Get Custom Mac
==============

The ``espefuse.py get-custom-mac`` command prints the Custom MAC Address (``CUSTOM_MAC``).

The chips also have a factory MAC address (eFuse name ``MAC``), which is written at the factory. It can not be changed with this tool.

.. only:: esp32

    .. code-block:: none

        > espefuse.py get-custom-mac

        === Run "get-custom-mac" command ===
        Custom MAC Address version 1: 48:63:92:15:72:16 (CRC 0x75 OK)

    If the custom MAC address is not burned, then you will see the message "Custom MAC Address is not set in the device". And in the summary, those eFuses associated with custom MAC addresses will not show up.

.. only:: not esp32

    .. code-block:: none

        > espefuse.py get-custom-mac

        === Run "get-custom-mac" command ===
        Custom MAC Address: 48:63:92:15:72:16 (OK)

    If the custom MAC address is not burned, then you will see the message "Custom MAC Address: 00:00:00:00:00:00 (OK)".
