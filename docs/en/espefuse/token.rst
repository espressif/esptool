.. _token:

Token Dump
----------

Overview
^^^^^^^^

The ``--token`` option allows you to inspect an eFuse state **without connecting to a device**. A *token* is a compact, single-line string that encodes either:

* the current programmed eFuse contents (read snapshot), and/or
* a set of staged eFuse writes (write snapshot).

The token dump includes a CRC32 checksum that protects the token from accidental modification.

This is particularly useful when direct access to the chip is not possible (for example, UART download is disabled, secure download mode is enabled, secure boot/flash encryption restricts tooling access, or the device is physically remote), but you still need to review the eFuse summary, archive a state, or exchange eFuse information with someone else.

Typical Use Cases
^^^^^^^^^^^^^^^^^

* **Field debugging / remote support:** a device in production prints a token; you decode it locally with ``espefuse --token ... summary``.
* **Post-provisioning verification:** confirm that provisioning (secure boot, flash encryption, key purposes, disable JTAG/UART download, etc.) was applied as intended.
* **Investigating coding errors:** capture and share the coding-error registers snapshot embedded in the token.
* **Auditing and traceability:** store a token as an artifact of manufacturing/provisioning to prove what was programmed at a given time.
* **Staged/batch workflows:** generate an ``EFSW`` token (staged writes) on the host and apply it later on the device.

Security Note
^^^^^^^^^^^^^

Tokens are **not encrypted**. Treat tokens as sensitive data:

* Tokens can include **unique identifiers** (for example MAC/UUID-like fields) and **security-relevant configuration bits** (secure boot, flash encryption, JTAG/UART disablement, key purposes).
* ``EFSW`` tokens represent **staged writes**. They may include **write-only key data** (for example flash-encryption keys or other keys that become read-protected after burning) and therefore can disclose provisioning intent and, in some workflows, key data before it is irreversibly locked down.
* Even when certain eFuses are read-protected on the target, the token may still carry **operationally sensitive values**.

Recommendations:

* Share tokens only with trusted parties and via trusted channels (avoid public issue trackers and unencrypted logs).
* Store tokens as you would store other manufacturing/provisioning artifacts (restricted access, limited retention).
* Prefer ``EFSR`` tokens for diagnostics and auditing; use ``EFSW`` tokens only when you explicitly need to transfer staged write state.

How To Obtain Token
^^^^^^^^^^^^^^^^^^^

A token can be obtained in one of the following ways:

1) From Chip Firmware (Recommended For Locked-Down Devices)
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

Firmware can print a token using the ESP-IDF API (for example ``esp_efuse_token_dump()``; see the `ESP-IDF eFuse API Token Dump documentation <https://docs.espressif.com/projects/esp-idf/en/latest/api-reference/system/efuse.html#token-dump>`__). It can produce any types of efuse tokens (``EFSR``, ``EFSW``, ``EFSRW``). The printed token can then be copied and decoded on the host using ``espefuse --token ...``.

2) From ``espefuse`` (To Share Or Archive A Connected Device State)
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

You can generate a read snapshot token directly from a connected chip:

.. code-block:: bash

   espefuse dump --format token

This prints an ``EFSR`` token representing the current programmed eFuses.

3) From ``espefuse`` Burn Commands (To Export Staged Writes)
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

All burn commands support ``--show-token`` to display the staged write token **before** confirmation:

.. code-block:: bash

   espefuse burn-efuse SOME_FIELD 1 --show-token

If your goal is only to obtain the token, abort at the confirmation prompt (no burning will occur).

Token Types
^^^^^^^^^^^

- ``EFSR`` — Read snapshot token. Represents the current programmed eFuse state (read-only snapshot).
- ``EFSW`` — Write/staging snapshot token. Represents staged eFuse writes that can be applied later (write snapshot).  This is the **only** token type intended for burning back onto a device.
- ``EFSRW`` — Combined snapshot token. Represents both the current state and staged writes. This is primarily useful for debugging firmware-side batch/staging logic.

.. note::

   ``EFSR`` and ``EFSRW`` tokens must not be used for burning, because they may include eFuses that are read-protected. The tool and ESP-IDF APIs do not allow to do that. Only ``EFSW`` is designed to represent staged writes.

Using Token
^^^^^^^^^^^

To decode a token and print a human-readable eFuse summary:

.. code-block:: bash

   espefuse --token <TOKEN> summary --active

Example: ``--active`` is used here to limit the output to **fields that are present/set** in the token, which is often preferable for quick review and for reducing noise when sharing logs:

.. code-block:: bash

   espefuse --token EFSR:esp32c3:004:AAGAAAEAAAAAAAAEAAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAA:AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA::::::::::epNVBg summary --active

The ``--token`` option replaces chip I/O with a virtual eFuse state constructed from the token, allowing you to use any espefuse commands without physical access to the target.

Relationship To ``--virt``
^^^^^^^^^^^^^^^^^^^^^^^^^^

``--token`` works similarly to ``--virt`` in the sense that both create a *virtual* eFuse state. If you want to reuse the decoded state across multiple invocations, you can save it to a file using ``--path-efuse-file`` (where supported by your workflow), then operate on that file later using ``--virt`` plus the same path.

Conceptually:

* ``--virt``: create empty virtual state, all eFuses zeroed.
* ``--token <TOKEN>``: create virtual state from a token string.
* ``--token <TOKEN> --path-efuse-file <file>``: create virtual state from a token string and save it to a file. Previously saved file will be overwritten.
* ``--virt --path-efuse-file <file>``: reuse a previously saved virtual state from a file.

Token Format
^^^^^^^^^^^^

Token format (colon-separated fields):

.. code-block:: none

   <token_name>:<chip>:<ver>:<b64_block0>:...:<b64_blockN>:<b64_cerr>:<b64_crc32>

Token fields:

* ``token_name`` — one of ``EFSR``, ``EFSW``, or ``EFSRW``.
* ``chip`` — chip name (lowercase, without dashes), for example ``esp32c3``.
* ``ver`` — chip revision as three decimal digits (leading zeros), for example ``004``. Constructed from major and minor wafer version fields using the formula ``ver = major * 100 + minor``, where the major version occupies the first digit and the minor version occupies the last two digits.
* ``b64_block0 ... b64_blockN`` — Base64URL-encoded per-block data. Each block is a concatenation of 32-bit words in little-endian byte order. Empty/all-zero blocks may be encoded as empty fields, resulting in consecutive colons (``::``).
* ``b64_cerr`` — optional Base64URL-encoded coding-error registers snapshot. It may be empty if there are no errors.
* ``b64_crc32`` — Base64URL-encoded CRC32 over whole token ``"<token_name>:<chip>:<ver>:<b64_block0>:...:<b64_blockN>:<b64_cerr>:"``. CRC32 is stored little-endian and encoded as unpadded Base64URL.

The number of blocks is not explicitly encoded in the format. It is derived from the chip type. The number of blocks can be determined by counting the colon separators (``:``) in the token. Empty blocks are represented as consecutive colons (``::``).

A token can be decoded and interpreted correctly only when it is processed using the **same target context** it was created for. ESP-IDF APIs and ``espefuse`` validate and rely on the following fields: chip name, chip revision, and block layout, as well as CRC32 integrity. If any of these do not match the target chip, decoding errors or missing fields may occur.

Base64URL uses the Base64 alphabet but replaces ``+`` with ``-`` and ``/`` with ``_``, and omits padding (``=``).

Editing
^^^^^^^

You cannot safely edit a token by hand:

* Any change to any field will invalidate ``b64_crc32``.
* ``espefuse`` verifies the CRC and rejects modified.

If you need a different eFuse state, generate a fresh token from the device, or regenerate a staged-write token using host-side burn commands with ``--show-token``.

Recommended Workflow Patterns
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Remote Decode (Device Prints Token, Host Decodes)
"""""""""""""""""""""""""""""""""""""""""""""""""

1. Device prints ``EFSR`` (or ``EFSRW``) token to logs.
2. Copy token from logs. Make sure to copy the entire token string.
3. Decode locally:

   .. code-block:: bash

      espefuse --token <TOKEN> summary --active

Provisioning Preview (Host Computes Staged Writes, Exports Token)
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

1. Prepare burn command(s) and use ``--show-token`` to capture ``EFSW``.
2. Store the ``EFSW`` token as an auditable artifact.
3. Apply staged writes later on-device using the corresponding device-side API.

ESP-IDF and ESP-IDF-Monitor Integration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For details on generating and applying tokens in firmware (``esp_efuse_token_dump()``, ``esp_efuse_token_burn()``, token types, and examples), see the *Token Dump* section in the ESP-IDF eFuse documentation:
`ESP-IDF eFuse API (Token Dump) <https://docs.espressif.com/projects/esp-idf/en/latest/api-reference/system/efuse.html#token-dump>`__.

For details on how ``idf.py monitor`` executes host-side commands emitted by the target (for example lines prefixed with ``IDF_MONITOR_EXECUTE_ESPEFUSE_SUMMARY``), see:
`ESP-IDF Monitor <https://github.com/espressif/esp-idf-monitor?tab=readme-ov-file#embedded-command-execution>`__.
