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

- ESP32-C5(beta3)
- ESP32-C6(beta)
- ESP32-H2(beta1)
- ESP32-H2(beta2)
- ESP32-S3(beta2)

**Migration Steps:**

1. Update any scripts or workflows not to target these beta chips.
2. Remove any references to these beta targets from CI/CD pipelines or build scripts.

Use esptool ``v4`` for legacy workflows targeting these beta chips.
