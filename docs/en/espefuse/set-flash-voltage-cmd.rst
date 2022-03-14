.. _set-flash-voltage-cmd:

Set Flash Voltage
=================

{IDF_TARGET_VDD_SPI:default="VDD_SPI",esp32="VDD_SDIO"}
{IDF_TARGET_VDD_FORCE:default="VDD_SPI_FORCE",esp32="XPD_SDIO_FORCE"}
{IDF_TARGET_VDD_TIEH:default="VDD_SPI_TIEH",esp32="XPD_SDIO_TIEH"}
{IDF_TARGET_VDD_REG:default="VDD_SPI_XPD",esp32="XPD_SDIO_REG"}
{IDF_TARGET_VDD_GPIO:default="GPIO45",esp32="GPIO12"}

The ``espefuse.py set_flash_voltage`` command permanently sets the internal flash voltage regulator to either 1.8V, 3.3V or OFF. This means a GPIO can be high or low at reset without changing the flash voltage.

Positional arguments:

- ``voltage`` - Voltage selection ['1.8V', '3.3V', 'OFF'].  

.. only:: esp32c2 or esp32c3

    .. note::

        This command is not supported. The tool prints the error ``set_flash_voltage not supported!``.

Setting Flash Voltage ({IDF_TARGET_VDD_SPI})
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

After reset, the default {IDF_TARGET_NAME} behaviour is to enable and configure the flash voltage regulator ({IDF_TARGET_VDD_SPI}) based on the level of the MTDI pin ({IDF_TARGET_VDD_GPIO}).

The default behaviour on reset is:

+--------------------+--------------------+
| MTDI               | Internal Regulator |
+====================+====================+
| Low or unconnected | Enabled at 3.3V    |
+--------------------+--------------------+
| High               | Enabled at 1.8V    |
+--------------------+--------------------+

.. only:: esp32

    Consult ESP32 Technical Reference Manual chapter 4.8.1 "{IDF_TARGET_VDD_SPI} Power Domain" for details.

.. only:: not esp32

    Consult {IDF_TARGET_NAME} Technical Reference Manual for details.

A combination of 3 efuses (``{IDF_TARGET_VDD_FORCE}``, ``{IDF_TARGET_VDD_REG}``, ``{IDF_TARGET_VDD_TIEH}``) can be burned in order to override this behaviour and disable {IDF_TARGET_VDD_SPI} regulator, or set it to a fixed voltage. These efuses can be burned with individual ``burn_efuse`` commands, but the ``set_flash_voltage`` command makes it easier:

Disable {IDF_TARGET_VDD_SPI} Regulator
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: none

    espefuse.py set_flash_voltage OFF

Once set:

* {IDF_TARGET_VDD_SPI} regulator always disabled.
* MTDI pin ({IDF_TARGET_VDD_GPIO}) is ignored.
* Flash must be powered externally and voltage supplied to {IDF_TARGET_VDD_SPI} pin of {IDF_TARGET_NAME}.
* Efuse ``{IDF_TARGET_VDD_FORCE}`` is burned.

Fixed 1.8V {IDF_TARGET_VDD_SPI}
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: none

    espefuse.py set_flash_voltage 1.8V

Once set:

* {IDF_TARGET_VDD_SPI} regulator always enables at 1.8V.
* MTDI pin ({IDF_TARGET_VDD_GPIO}) is ignored.
* External voltage should not be supplied to {IDF_TARGET_VDD_SPI}.
* Efuses ``{IDF_TARGET_VDD_FORCE}`` and ``{IDF_TARGET_VDD_REG}`` are burned.

Fixed 3.3V {IDF_TARGET_VDD_SPI}
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: none

    espefuse.py set_flash_voltage 3.3V

Once set:

* {IDF_TARGET_VDD_SPI} regulator always enables at 3.3V.
* MTDI pin ({IDF_TARGET_VDD_GPIO}) is ignored.
* External voltage should not be supplied to {IDF_TARGET_VDD_SPI}.
* Efuses ``{IDF_TARGET_VDD_FORCE}``, ``{IDF_TARGET_VDD_REG}``, ``{IDF_TARGET_VDD_TIEH}`` are burned.

Subsequent Changes
^^^^^^^^^^^^^^^^^^

Once an efuse is burned it cannot be un-burned. However, changes can be made by burning additional efuses:

*  ``set_flash_voltage OFF`` can be changed to ``1.8V`` or ``3.3V``
*  ``set_flash_voltage 1.8V`` can be changed to ``3.3V``


.. only:: esp32s2 or esp32s3

    .. code-block:: none

        > espefuse.py set_flash_voltage 1.8V

        === Run "set_flash_voltage" command ===
        Set internal flash voltage regulator (VDD_SPI) to 1.8V.

        VDD_SPI setting complete.

        Check all blocks for burn...
        idx, BLOCK_NAME,          Conclusion
        [00] BLOCK0               is empty, will burn the new value
        . 
        This is an irreversible operation!
        Type 'BURN' (all capitals) to continue.
        BURN
        BURN BLOCK0  - OK (write block == read block)
        Reading updated efuses...
        Successful


    .. code-block:: none

        > espefuse.py set_flash_voltage 3.3V

        === Run "set_flash_voltage" command ===
        Enable internal flash voltage regulator (VDD_SPI) to 3.3V.

        VDD_SPI setting complete.

        Check all blocks for burn...
        idx, BLOCK_NAME,          Conclusion
        [00] BLOCK0               is empty, will burn the new value
        . 
        This is an irreversible operation!
        Type 'BURN' (all capitals) to continue.
        BURN
        BURN BLOCK0  - OK (write block == read block)
        Reading updated efuses...
        Successful


    .. code-block:: none

        > espefuse.py set_flash_voltage OFF

        === Run "set_flash_voltage" command ===
        Disable internal flash voltage regulator (VDD_SPI). SPI flash will 
        VDD_SPI setting complete.

        Check all blocks for burn...
        idx, BLOCK_NAME,          Conclusion
        [00] BLOCK0               is empty, will burn the new value
        . 
        This is an irreversible operation!
        Type 'BURN' (all capitals) to continue.
        BURN
        BURN BLOCK0  - OK (write block == read block)
        Reading updated efuses...
        Successful
