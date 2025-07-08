.. _migration:

``v5`` Migration Guide
======================

This document describes the breaking changes made to esptool.py, espsecure.py and espefuse.py in the major release ``v5``. It provides guidance on adapting existing workflows and scripts to ensure compatibility when updating from ``v4.*``.


Command-Line Tool Invocation Changes
************************************

The preferred way to invoke esptool command-line tools has changed. Instead of running the scripts with `.py` suffix, you should now use the console scripts without the `.py` suffix.

**Affected Tools:**

- ``esptool.py`` → ``esptool``
- ``espefuse.py`` → ``espefuse``
- ``espsecure.py`` → ``espsecure``
- ``esp_rfc2217_server.py`` → ``esp_rfc2217_server``

**Migration Steps:**

1. Update your command-line invocations to use the new names without `.py`:

   **Before:**

   .. code-block:: bash

       esptool.py chip_id
       espefuse.py summary
       espsecure.py sign_data --keyfile key.pem data.bin

   **After:**

   .. code-block:: bash

       esptool chip_id
       espefuse summary
       espsecure sign-data --keyfile key.pem data.bin

2. Update scripts to use the new command names.

.. note::

   Scripts with ``.py`` suffix are still available for backward compatibility, but they will produce deprecation warning and will be removed in the next major release.


esptool ``v5`` Migration Guide
******************************

``image-info`` Output Format Change
###################################

The output format of the :ref:`image-info <image-info>` command has been **updated in v5**. The original format (``--version 1``) is **deprecated** and replaced by the updated format (``--version 2``). The ``--version`` argument has been **removed entirely**, and the new format is now the default and only option.

**Changes in the New Format:**

- Improved readability and structure.
- Additional metadata fields for better debugging and analysis.
- Consistent formatting for all ESP chip variants.

**Migration Steps:**

1. Update any scripts or tools that parse the ``image-info`` output to use the new format.
2. Remove any ``--version`` arguments from ``image-info`` commands.

Output Logging
##############

The esptool ``v5`` release introduces a centralized logging mechanism to improve output management and allow redirection.

**Key Changes:**

- All esptool output is now routed through an ``EsptoolLogger`` class.
- The output can include ANSI color codes for better readability.
- Custom loggers can be implemented to redirect output to files or other destinations.

**Migration Steps:**

1. If your scripts rely on direct ``print()`` statements, update them to use the centralized logger for consistent output. Calls to the logger should be made using ``log.print()`` (or the respective method, such as ``log.note()``, ``log.warning()``, or ``log.error()``).
2. Refer to the provided documentation to implement custom loggers as needed.
3. Update GUIs or tools to leverage the progress tracking API for better user feedback during lengthy operations.

See the :ref:`logging <logging>` section for more details on available logger methods and custom logger implementation.

``write-flash`` ``--verify`` Argument
#####################################

The ``--verify`` option for the :ref:`write-flash <write-flash>` command has been **deprecated in v5**. Flash verification is performed automatically after every successful write operation when technically feasible.

**Behavior:**

- Verification occurs by default after flashing completes.
- No action is needed to enable verification - it is mandatory when possible.
- Verification is **skipped** if Secure Download Mode (SDM) is active or during encrypted writes (using ``--encrypt``).

**Migration Steps:**

1. Remove all ``--verify`` arguments from existing ``write-flash`` commands.
2. Update scripts/CI pipelines to remove ``--verify`` flags.

Error Output Handling
#####################

In ``v5``, error handling and output behavior have been improved to provide better user experience and script compatibility.

**Key Changes:**

- All error messages, including fatal errors, are now printed to **STDERR** instead of STDOUT.
- User keyboard interrupts (e.g., Ctrl+C) are caught and raise an exit code of 2 to indicate an operation interruption.
- Error messages are displayed in **red text** for better visibility.
- This change ensures that errors are not lost when STDOUT is filtered or redirected.

**Migration Steps:**

1. Update scripts that rely on parsing STDOUT for error messages to check STDERR instead.
2. Ensure scripts handle non-zero exit codes correctly in the case of operations interrupted by the user.

Beta Target Support Removal
###########################

Support for the following beta targets has been **removed in v5**:

- ``ESP32-C5(beta3)``
- ``ESP32-C6(beta)``
- ``ESP32-H2(beta1)``
- ``ESP32-H2(beta2)``
- ``ESP32-S3(beta2)``

**Migration Steps:**

1. Update any scripts or workflows not to target these beta chips.
2. Remove any references to these beta targets from CI/CD pipelines or build scripts.

Use esptool ``v4`` for legacy workflows targeting these beta chips.

``verify-flash`` ``--diff`` Argument
####################################

The format of the ``--diff`` option of the :ref:`verify-flash <verify-flash>` command has **changed in v5**. Previously, ``--diff=yes/no`` had to be specified to enable or disable the diff output. In the new version, the ``--diff`` option is a simple boolean switch without the need of a ``yes`` or ``no`` value.

**Migration Steps:**

1. Rewrite the ``--diff=yes`` argument to a simple ``--diff`` in any existing ``verify-flash`` commands in scripts/CI pipelines. Delete ``--diff=no`` completely if detailed diff output is not required.

Using esptool as a Python Module
################################

All command functions (e.g., ``verify-flash``, ``write-flash``) have been refactored to remove their dependency on the ``args`` object from the argparse module. Instead, all arguments are now passed explicitly as individual parameters. This change, combined with enhancements to the public API, provides a cleaner, more modular interface for programmatic use of esptool in custom scripts and applications (see :ref:`scripting <scripting>`).

**Key Changes:**

- Refactored Function Signatures: Previously, command functions relied on an ``args`` object (e.g., ``args.addr_filename``, ``args.diff``). Now, they take individual parameters with explicit types and default values, improving clarity and enabling a robust API.
- Public API Expansion: The public API (exposed via ``esptool.cmds``) has been formalized with high-level functions like ``detect_chip()``, ``attach_flash()``, ``write-flash()``, and ``reset_chip()``, designed for ease of use in Python scripts.

**Migration Steps:**

1. Update Function Calls: If you are calling esptool functions programmatically, replace ``args`` object usage with individual parameter passing. Refer to the function signatures in ``esptool.cmds`` for the new parameter names, types, and defaults.
2. Leverage the Public API: Use the new high-level functions in ``esptool.cmds`` for common operations like chip detection, flash attachment, flashing, resetting, or image generation.
3. Test your updated scripts to ensure compatibility with the new API.

For detailed examples and API reference, see the :ref:`scripting <scripting>` section.


Flash Operations from Non-flash Related Commands
################################################

When esptool is used as a CLI tool, the following commands no longer automatically attach the flash by default, since flash access is not required for their core functionality:

- ``load-ram``
- ``read-mem``
- ``write-mem``
- ``dump-mem``
- ``chip-id``
- ``read-mac``

The ``--spi-connection`` CLI argument has been **removed** from non-flash related commands in v5. This argument had no effect on the command execution. Affected commands:

- ``elf2image``
- ``merge-bin``

**Migration Steps:**

1. Update any scripts that attempt to attach flash from non-flash related commands.
2. If you need to attach flash for above mentioned commands, use the ``attach_flash`` function from the public API instead. For more details see :ref:`scripting <scripting>`.
3. Remove the ``--spi-connection`` argument from ``elf2image`` and ``merge-bin`` commands.


Shell Completion
################

The esptool ``v5`` has switched to using `Click <https://click.palletsprojects.com/>`_ for command line argument parsing, which changes how shell completion works.

**Migration Steps:**

1. Remove the old shell completion code from your scripts and shell configuration files like ``.bashrc``, ``.zshrc``, ``.config/fish/config.fish``, etc.
2. Follow the new shell completion setup instructions in the :ref:`shell-completion` section of the :ref:`installation <installation>` guide.

``merge-bin`` ``--fill-flash-size`` Argument
############################################

The ``--fill-flash-size`` option of the :ref:`merge-bin <merge-bin>` command has been renamed to ``--pad-to-size``. This change provides a more intuitive and descriptive name for the argument and is consistent with the naming scheme in other esptool image manipulation commands.

**Migration Steps:**

1. Rename the ``--fill-flash-size`` to ``--pad-to-size`` in any existing ``merge-bin`` commands in scripts/CI pipelines.

``write-flash`` ``--ignore-flash-encryption-efuse-setting`` Argument
####################################################################

The ``--ignore-flash-encryption-efuse-setting`` option of the :ref:`write-flash <write-flash>` command has been renamed to ``--ignore-flash-enc-efuse``. This change shortens the argument name to improve readability and consistency with other esptool options.

**Migration Steps:**

1. Rename the ``--ignore-flash-encryption-efuse-setting`` to ``--ignore-flash-enc-efuse`` in any existing ``write-flash`` commands in scripts/CI pipelines.

``make_image`` Command Removal
##############################

The ``make_image`` command for the ESP8266 has been **removed in v5**. This command has been deprecated in favor of using **objcopy** (or other tools) to generate ELF images and then using ``elf2image`` to create the final ``.bin`` file.

**Migration Steps:**

1. Replace any ``make_image`` workflows with the recommended way of assembling firmware images using **objcopy** and ``elf2image``.

Using Binary from GitHub Releases on Linux
##########################################

The ``esptool`` binary from GitHub Releases on Linux is now using Ubuntu 22.04 as the base image. That means the image is using ``glibc`` 2.35, which is not fully compatible with the ``glibc`` 2.28 from Ubuntu 20.04 (the base image for ``v4.*``).

**Migration Steps:**

1. Update your operating system to a newer version which bundles ``glibc`` 2.35 or later

Command and Option Renaming
###########################

All the commands and options have been renamed to use ``-`` instead of ``_`` as a separator (e.g., ``write_flash`` -> ``write-flash``).

Old command and option names are **deprecated**, meaning they will work for now with a warning, but will be removed in the next major release.

This change affects most of the commands and the following options: ``--flash_size``, ``--flash_mode``, ``--flash_freq``, ``--use_segments``.

**Migration Steps:**

1. Replace all underscores in command and option names with ``-`` in your scripts and CI pipelines.

Log Format Changes
##################

A significant amount of changes have been made to the log styling and formatting in ``v5``. Some of the messages, warnings, and errors are now formatted differently or reworded to provide more context and improve readability. Exhaustive list of changed messages won't be provided.

**Migration Steps:**

1. Make sure to adjust any of your scripts, asserts, CI workflows, or others to accommodate the new/changed format of messages. If you are parsing the log output (not recommended), consider importing esptool as a module and using the public API (see :ref:`here <scripting>`) to get the information you need.


Reset Mode Renaming
###################

Choices for the ``--before`` and ``--after`` options have been renamed to use ``-`` instead of ``_`` as a separator (e.g., ``default_reset`` -> ``default-reset``).


**Migration Steps:**

1. Replace all underscores in the ``--before`` and ``--after`` options with ``-`` in your scripts.

.. only:: not esp8266

    espsecure ``v5`` Migration Guide
    ********************************

    Command and Option Renaming
    ###########################

    All the commands and options have been renamed to use ``-`` instead of ``_`` as a separator (e.g., ``sign_data`` -> ``sign-data``).

    Old command and option names are **deprecated**, meaning they will work for now with a warning, but will be removed in the next major release.

    This change affects most of the commands and the following options: ``--aes_xts``, ``--flash_crypt_conf``, ``--append_signatures``.

    **Migration Steps:**

    1. Replace all underscores in command and option names with ``-`` in your scripts and CI pipelines.

    Public API Changes
    ##################

    The public API of ``espsecure`` has been updated to provide a more consistent and user-friendly interface for programmatic use in custom scripts and applications.

    **Key Changes:**

    - All functions now accept individual parameters instead of relying on the ``args`` object from the argparse module. Affected functions are:
        - ``digest_secure_bootloader``
        - ``generate_signing_key``
        - ``digest_secure_bootloader``
        - ``generate_signing_key``
        - ``sign_data`` including ``sign_secure_boot_v1`` and ``sign_secure_boot_v2``
        - ``verify_signature`` including ``verify_signature_v1`` and ``verify_signature_v2``
        - ``extract_public_key``
        - ``signature_info_v2``
        - ``digest_sbv2_public_key`` and ``digest_rsa_public_key``
        - ``digest_private_key``
        - ``generate_flash_encryption_key``
        - ``decrypt_flash_data``
        - ``encrypt_flash_data``
    - The ``main`` function parameter ``custom_commandline`` has been renamed to ``argv`` to unify the naming convention with esptool.

    **Migration Steps:**

    1. Update function calls to pass individual parameters instead of the ``args`` object. For example:
    ``sign_data(args)`` -> ``sign_data(data=args.data, key=args.key, ...)``
    or if you were mocking the args object, now you don't have to do that and you can pass parameters directly to the function like:
    ``sign_data(data=data, key=key, ...)``.
    2. Replace the ``custom_commandline`` parameter with ``argv`` in the ``main`` function call.

    espefuse ``v5`` Migration Guide
    *******************************

    Reset Mode Renaming
    ###################

    Choices for the ``--before`` option have been renamed to use ``-`` instead of ``_`` as a separator (e.g., ``default_reset`` -> ``default-reset``).

    **Migration Steps:**

    1. Replace all underscores in the ``--before`` option with ``-`` in your scripts.

    Command and Option Renaming
    ###########################

    All the commands and options have been renamed to use ``-`` instead of ``_`` as a separator (e.g., ``burn_custom_mac`` -> ``burn-custom-mac``).

    From options only ``--file_name`` has been renamed to ``--file-name``.

    Old command and option names are **deprecated**, meaning they will work for now with a warning, but will be removed in the next major release.

    **Migration Steps:**

    1. Replace all underscores in the command names with ``-`` in your scripts.


    ``--port`` Option is Required
    #############################

    The ``--port`` option is now required for all commands (except when using ``--virt``). Previously it was optional and defaulted to ``/dev/ttyUSB0``.

    **Migration Steps:**

    1. Add the ``--port`` option to all your espefuse commands.


    ``execute-scripts`` Command Removal
    ###################################

    The ``execute-scripts`` command has been **removed in v5**. This command was used to execute custom eFuses scripts. It was deprecated in favor of using ``espefuse`` as a Python module (see :ref:`here <espefuse-scripting>`).

    **Migration Steps:**

    1. Refactor any workflows using the deprecated ``execute-scripts`` to use the public API.
    2. Make sure to use the ``batch_mode`` argument for ``init_commands`` to avoid burning eFuses one by one.
    3. Variables ``idx`` and ``configfiles`` are no longer supported. These can be replaced with simple for loops in Python.

    For example, the following commands and script (using ESP32):

    .. code-block:: bash

        > espefuse --port /dev/ttyUSB0 execute_scripts efuse_script.py --do-not-confirm

    .. code-block:: python

        espefuse(esp, efuses, args, "burn_efuse JTAG_DISABLE 1 DISABLE_SDIO_HOST 1 CONSOLE_DEBUG_DISABLE 1")
        espefuse(esp, efuses, args, "burn_key flash_encryption ../../images/efuse/256bit --no-protect-key")
        espefuse(esp, efuses, args, "burn_key_digest ../../secure_images/rsa_secure_boot_signing_key.pem")
        espefuse(esp, efuses, args, "burn_bit BLOCK3 64 66 69 72 78 82 83 90")
        espefuse(esp, efuses, args, "burn_custom_mac AA:BB:CC:DD:EE:88")

        efuses.burn_all()

        espefuse(esp, efuses, args, "summary")
        espefuse(esp, efuses, args, "adc_info")
        espefuse(esp, efuses, args, "get_custom_mac")

        if not efuses["BLOCK1"].is_readable() or not efuses["BLOCK1"].is_writeable():
            raise Exception("BLOCK1 should be readable and writeable")

    Can be replaced with public API:

    .. code-block:: python

        from espefuse import init_commands

        with init_commands(port="/dev/ttyUSB0", batch_mode=True, do_not_confirm=True) as espefuse:
            espefuse.burn_efuse({"JTAG_DISABLE": "1", "DISABLE_SDIO_HOST": "1", "CONSOLE_DEBUG_DISABLE": "1"})
            with open("../../images/efuse/256bit", "rb") as f:
                espefuse.burn_key(["flash_encryption"], [f], no_protect_key=True)
            with open("../../secure_images/rsa_secure_boot_signing_key.pem", "rb") as f:
                espefuse.burn_key_digest([f])
            espefuse.burn_bit("BLOCK3", [64, 66, 69, 72, 78, 82, 83, 90])
            espefuse.burn_custom_mac(b"\xaa\xbb\xcc\xdd\xee\x88")

            espefuse.burn_all()

            espefuse.summary()
            espefuse.adc_info()
            espefuse.get_custom_mac()

            if not espefuse.efuses["BLOCK1"].is_readable() or not espefuse.efuses["BLOCK1"].is_writeable():
                raise Exception("BLOCK1 should be readable and writeable")

    .. note::

        Please note that the ``batch_mode`` argument for ``init_commands`` is required to avoid burning eFuses one by one. This was previously
        the default behavior for ``execute-scripts`` command.

    For more details on the public API, see :ref:`espefuse-scripting`.
