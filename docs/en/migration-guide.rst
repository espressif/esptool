.. _migration:

esptool.py ``v5`` Migration Guide
=================================

This document describes the breaking changes made to esptool.py in the major release ``v5``. It provides guidance on adapting existing workflows and scripts to ensure compatibility when updating from ``v4.*``.


``image_info`` Output Format Change
***********************************

The output format of the :ref:`image_info <image-info>` command has been **updated in v5**. The original format (``--version 1``) is **deprecated** and replaced by the updated format (``--version 2``). The ``--version`` argument has been **removed entirely**, and the new format is now the default and only option.

**Changes in the New Format:**

- Improved readability and structure.
- Additional metadata fields for better debugging and analysis.
- Consistent formatting for all ESP chip variants.

**Migration Steps:**

1. Update any scripts or tools that parse the ``image_info`` output to use the new format.
2. Remove any ``--version`` arguments from ``image_info`` commands.

Output Logging
**************

The esptool ``v5`` release introduces a centralized logging mechanism to improve output management and allow redirection.

**Key Changes:**

- All esptool output is now routed through an ``EsptoolLogger`` class.
- The output can include ANSI color codes for better readability.
- Custom loggers can be implemented to redirect output to files or other destinations.

**Migration Steps:**

1. If your scripts rely on direct ``print()`` statements, update them to use the centralized logger for consistent output. Calls to the logger should be made using ``log.print()`` (or the respective method, such as ``log.info()``, ``log.warning()``, or ``log.error()``).
2. Refer to the provided documentation to implement custom loggers as needed.
3. Update GUIs or tools to leverage the progress tracking API for better user feedback during lengthy operations.

See the :ref:`logging <logging>` section for more details on available logger methods and custom logger implementation.

``write_flash`` ``--verify`` Argument
*************************************

The ``--verify`` option for the :ref:`write_flash <write-flash>` command has been **deprecated in v5**. Flash verification is performed automatically after every successful write operation when technically feasible.

**Behavior:**

- Verification occurs by default after flashing completes.
- No action is needed to enable verification - it is mandatory when possible.
- Verification is **skipped** if Secure Download Mode (SDM) is active or during encrypted writes (using ``--encrypt``).

**Migration Steps:**

1. Remove all ``--verify`` arguments from existing ``write_flash`` commands.
2. Update scripts/CI pipelines to remove ``--verify`` flags.

Error Output Handling
*********************

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
***************************

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

``verify_flash`` ``--diff`` Argument
*************************************

The format of the ``--diff`` option of the :ref:`verify_flash <verify-flash>` command has **changed in v5**. Previously, ``--diff=yes/no`` had to be specified to enable or disable the diff output. In the new version, the ``--diff`` option is a simple boolean switch without the need of a ``yes`` or ``no`` value.

**Migration Steps:**

1. Rewrite the ``--diff=yes`` argument to a simple ``--diff`` in any existing ``verify_flash`` commands in scripts/CI pipelines. Delete ``--diff=no`` completely if detailed diff output is not required.

Using esptool as a Python Module
********************************

All command functions (e.g., ``verify_flash``, ``write_flash``) have been refactored to remove their dependency on the ``args`` object from the argparse module. Instead, all arguments are now passed explicitly as individual parameters. This change, combined with enhancements to the public API, provides a cleaner, more modular interface for programmatic use of esptool in custom scripts and applications (see :ref:`scripting <scripting>`).

**Key Changes:**

- Refactored Function Signatures: Previously, command functions relied on an ``args`` object (e.g., ``args.addr_filename``, ``args.diff``). Now, they take individual parameters with explicit types and default values, improving clarity and enabling a robust API.
- Public API Expansion: The public API (exposed via ``esptool.cmds``) has been formalized with high-level functions like ``detect_chip()``, ``attach_flash()``, ``write_flash()``, and ``reset_chip()``, designed for ease of use in Python scripts.

**Migration Steps:**

1. Update Function Calls: If you are calling esptool functions programmatically, replace ``args`` object usage with individual parameter passing. Refer to the function signatures in ``esptool.cmds`` for the new parameter names, types, and defaults.
2. Leverage the Public API: Use the new high-level functions in ``esptool.cmds`` for common operations like chip detection, flash attachment, flashing, resetting, or image generation.
3. Test your updated scripts to ensure compatibility with the new API.

For detailed examples and API reference, see the :ref:`scripting <scripting>` section.


Flash Operations from Non-flash Related Commands
************************************************

When esptool is used as a CLI tool, the following commands no longer automatically attach the flash by default, since flash access is not required for their core functionality:

- ``load_ram``
- ``read_mem``
- ``write_mem``
- ``dump_mem``
- ``chip_id``
- ``read_mac``

The ``--spi-connection`` CLI argument has been **removed** from non-flash related commands in v5. This argument had no effect on the command execution. Affected commands:

- ``elf2image``
- ``merge_bin``

**Migration Steps:**

1. Update any scripts that attempt to attach flash from non-flash related commands.
2. If you need to attach flash for above mentioned commands, use the ``attach_flash`` function from the public API instead. For more details see :ref:`scripting <scripting>`.
3. Remove the ``--spi-connection`` argument from ``elf2image`` and ``merge_bin`` commands.


Shell Completion
****************

The esptool ``v5`` has switched to using `Click <https://click.palletsprojects.com/>`_ for command line argument parsing, which changes how shell completion works.

**Migration Steps:**

1. Remove the old shell completion code from your scripts and shell configuration files like ``.bashrc``, ``.zshrc``, ``.config/fish/config.fish``, etc.
2. Follow the new shell completion setup instructions in the :ref:`shell-completion` section of the :ref:`installation <installation>` guide.
