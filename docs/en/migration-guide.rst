.. _migration:

esptool.py ``v5`` Migration Guide
=================================

This document describes the breaking changes made to esptool.py in the major release ``v5``. It provides guidance on adapting existing workflows and scripts to ensure compatibility when updating from ``v4.*``.


``image_info`` Output Format Change
***********************************

The output format of the :ref:`image_info <image-info>` command has been **updated in v5**. The original format (``--version 1``) is **deprecated** and replaced by the updated format (``--version 2``). The ``--version`` argument has been **removed entirely**, and the new format is now the default and only option.

**Changes in the New Format:**

- Improved readability and structure
- Additional metadata fields for better debugging and analysis
- Consistent formatting for all ESP chip variants

**Migration Steps:**

1. Update any scripts or tools that parse the ``image_info`` output to use the new format
2. Remove any ``--version`` arguments from ``image_info`` commands
