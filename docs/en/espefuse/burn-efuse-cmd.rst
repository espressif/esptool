.. _burn-efuse-cmd:

Burn Efuse
==========

The ``espefuse.py burn_efuse`` command burns eFuses. The arguments to ``burn_efuse`` are eFuse names (as shown in summary output) and new values.

Positional arguments:

- ``eFuse name``
- ``value``

It can be list of eFuse names and values (like EFUSE_NAME1 1 EFUSE_NAME2 7 EFUSE_NAME3 10 etc.).

New values can be a numeric value in decimal or hex (with "0x" prefix). eFuse bits can only be burned from 0 to 1, attempting to set any back to 0 will have no effect. Most eFuses have a limited bit width (many are only 1-bit flags). Longer eFuses (MAC addresses, keys) can be set with this command, but it's better to use a specific command (``burn_custom_mac``, ``burn_key``) for a specific field.

This command supports simultaneous burning of multiple eFuses, it doesn't matter if they are from different eFuse blocks or not. The format is the same as for burning just one eFuse, just list the eFuse name and value pairs, see the example below.

.. code-block:: none

    > espefuse.py --port /dev/ttyUSB0 burn_efuse   DIS_USB_JTAG 1   VDD_SPI_AS_GPIO 1

    === Run "burn_efuse" command ===
    The efuses to burn:
    from BLOCK0
        - DIS_USB_JTAG
        - VDD_SPI_AS_GPIO

    Burning efuses:

        - 'DIS_USB_JTAG' (Disables USB JTAG. JTAG access via pads is controlled separately) 0b0 -> 0b1
        - 'VDD_SPI_AS_GPIO' (Set this bit to vdd spi pin function as gpio) 0b0 -> 0b1

    Check all blocks for burn...
    idx, BLOCK_NAME,          Conclusion
    [00] BLOCK0               is empty, will burn the new value
    .
    This is an irreversible operation!
    Type 'BURN' (all capitals) to continue.

By default, ``espefuse.py`` will ask you to type ``BURN`` before it permanently sets eFuses. The ``--do-not-confirm`` option allows you to bypass this.

.. code-block:: none

    BURN
    BURN BLOCK0  - OK (write block == read block)
    Reading updated efuses...
    Checking efuses...
    Successful

.. _espefuse-spi-flash-pins:

SPI Flash Pins
--------------

The following efuses configure the SPI flash pins which are used to boot:

.. only:: esp32

    .. code-block:: none

        SPI_PAD_CONFIG_CLK     Override SD_CLK pad (GPIO6/SPICLK)                = 0 R/W (0x0)
        SPI_PAD_CONFIG_Q       Override SD_DATA_0 pad (GPIO7/SPIQ)               = 0 R/W (0x0)
        SPI_PAD_CONFIG_D       Override SD_DATA_1 pad (GPIO8/SPID)               = 0 R/W (0x0)
        SPI_PAD_CONFIG_HD      Override SD_DATA_2 pad (GPIO9/SPIHD)              = 0 R/W (0x0)
        SPI_PAD_CONFIG_CS0     Override SD_CMD pad (GPIO11/SPICS0)               = 0 R/W (0x0)

.. only:: not esp32

    .. code-block:: none

        Spi_Pad_Config fuses:
        SPI_PAD_CONFIG_CLK (BLOCK1)              SPI CLK pad                                        = 0 R/W (0b000000)
        SPI_PAD_CONFIG_Q (BLOCK1)                SPI Q (D1) pad                                     = 0 R/W (0b000000)
        SPI_PAD_CONFIG_D (BLOCK1)                SPI D (D0) pad                                     = 0 R/W (0b000000)
        SPI_PAD_CONFIG_CS (BLOCK1)               SPI CS pad                                         = 0 R/W (0b000000)
        SPI_PAD_CONFIG_HD (BLOCK1)               SPI HD (D3) pad                                    = 0 R/W (0b000000)
        SPI_PAD_CONFIG_WP (BLOCK1)               SPI WP (D2) pad                                    = 0 R/W (0b000000)
        SPI_PAD_CONFIG_DQS (BLOCK1)              SPI DQS pad                                        = 0 R/W (0b000000)
        SPI_PAD_CONFIG_D4 (BLOCK1)               SPI D4 pad                                         = 0 R/W (0b000000)
        SPI_PAD_CONFIG_D5 (BLOCK1)               SPI D5 pad                                         = 0 R/W (0b000000)
        SPI_PAD_CONFIG_D6 (BLOCK1)               SPI D6 pad                                         = 0 R/W (0b000000)
        SPI_PAD_CONFIG_D7 (BLOCK1)               SPI D7 pad                                         = 0 R/W (0b000000)

On {IDF_TARGET_NAME} chips without integrated SPI flash, these eFuses are left zero at the factory. This causes the default GPIO pins (shown in the summary output above) to be used for the SPI flash.

On {IDF_TARGET_NAME} chips with integrated internal SPI flash, these eFuses are burned in the factory to the GPIO numbers where the flash is connected. These values override the defaults on boot.

In order to change the SPI flash pin configuration, these eFuses can be burned to the GPIO numbers where the flash is connected. If at least one of these eFuses is burned, all of of them must be set to the correct values.

If these eFuses are burned, GPIO1 (U0TXD pin) is no longer consulted to set the boot mode from SPI to HSPI flash on reset.

These pins can be set to any GPIO number in the range 0-29, 32 or 33. Values 30 and 31 cannot be set. The "raw" hex value for pins 32, 33 is 30, 31 (this is visible in the summary output if these pins are configured for any SPI I/Os.)

For example:

.. code-block:: none

    SPI_PAD_CONFIG_CS0     Override SD_CMD pad (GPIO11/SPICS0)               = 32 R/W (0x1e)

If using the ``burn_efuse`` command to configure these pins, always specify the actual GPIO number you wish to set.
