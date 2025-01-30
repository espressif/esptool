.. _execute-scripts-cmd:

Execute Scripts
===============

The ``espefuse.py execute_scripts`` command executes scripts to burn at one time.

Positional arguments:

- ``scripts`` - it is special format of python scripts (receives list of files, like script1.py script2.py etc.).

Optional arguments:

- ``--index`` - integer index. It allows to retrieve unique data per chip from configfiles and then burn them (ex. CUSTOM_MAC, UNIQUE_ID).
- ``--configfiles`` - List of configfiles with data (receives list of configfiles, like configfile1.py configfile2.py etc.).

.. code-block:: none

    > espefuse.py execute_scripts efuse_script1.py efuse_script2.py ...

This command allows burning all needed eFuses at one time based on your own python script and control issues during the burn process if so it will abort the burn process. This command has a few arguments:

*  ``scripts`` is a list of scripts. The special format of python scripts can be executed inside ``espefuse.py``.
*  ``--index`` integer index (it means the number of chip in the batch in the range 1 - the max number of chips in the batch). It allows to retrieve unique data per chip from configfiles and then burn them (ex. CUSTOM_MAC, UNIQUE_ID).
*  ``--configfiles`` List of configfiles with data.

Below you can see some examples of the script. This script file is run from ``espefuse.py`` as ``exec(open(file.name).read())`` it means that some functions and imported libs are available for using like ``os``. Please use only provided functions.
If you want to use other libs in the script you can add them manually.

Inside this script, you can call all commands which are available in CLI, see ``espefuse.py --help``. To run a eFuse command you need to call ``espefuse(esp, efuses, args, 'burn_efuse DISABLE_DL_DECRYPT 1')``. This command will not burn eFuses immediately, the burn occurs at the end of all scripts.
If necessary, you can call ``efuses.burn_all()`` which prompts ``Type 'BURN' (all capitals) to continue.``. To skip this check and go without confirmation just add the ``--do-not-confirm`` flag to the ``execute_scripts`` command.

This command supports nesting. This means that one script can be called from another script (see the test case ``test_execute_scripts_nesting`` in ``esptool/test/test_espefuse.py``).

.. code-block:: none

    > espefuse.py execute_scripts efuse_script1.py --do-not-confirm

Additionally, you can implement some checks based on the value of eFuses. To get value of an eFuse use ``efuses['FLASH_CRYPT_CNT'].get()``. Some eFuses have a dictionary to convert from a value to a human-readable as it looks in the table is printed by the ``summary`` command.
See how it is done (for ESP32) for ``CODING_SCHEME`` when ``get_meaning()`` is called:

* 0: ``NONE (BLK1-3 len=256 bits)``
* 1: ``3/4 (BLK1-3 len=192 bits)``
* 2: ``REPEAT (BLK1-3 len=128 bits) not supported``
* 3: ``NONE (BLK1-3 len=256 bits)``

.. code:: python

    print("connected chip: %s, coding scheme %s" % (esp.get_chip_description(), efuses["CODING_SCHEME"].get_meaning()))
    if os.path.exists("flash_encryption_key.bin"):
        espefuse(esp, efuses, args, "burn_key flash_encryption flash_encryption_key.bin")
    else:
        raise esptool.FatalError("The 'flash_encryption_key.bin' file is missing in the project directory")

    espefuse(esp, efuses, args, 'burn_efuse FLASH_CRYPT_CNT 0x7')

    current_flash_crypt_cnt = efuses['FLASH_CRYPT_CNT'].get()
    if current_flash_crypt_cnt in [0, 3]:
        espefuse(esp, efuses, args, 'burn_efuse FLASH_CRYPT_CNT')

    espefuse(esp, efuses, args, 'burn_efuse DISABLE_DL_ENCRYPT 1')

    espefuse(esp, efuses, args, 'burn_efuse DISABLE_DL_DECRYPT 1')

    espefuse(esp, efuses, args, 'burn_efuse DISABLE_DL_CACHE 1')

    espefuse(esp, efuses, args, 'burn_efuse JTAG_DISABLE 1')
    ...

After ``efuses.burn_all()``, all needed eFuses will be burnt to chip in order ``BLK_MAX`` to ``BLK_0``. This order prevents cases when protection is set before the value goes to a block. Please note this while developing your scripts.
Upon completion, the new eFuses will be read back, and will be done some checks of written eFuses by ``espefuse.py``. In production, you might need to check that all written eFuses are set properly, see the example below.

The script `execute_efuse_script.py <https://github.com/espressif/esptool/blob/master/test/efuse_scripts/esp32xx/execute_efuse_script.py>`__ burns some eFuses and checks them after reading back. To check read and write protection, ``is_readable()`` and ``is_writeable()`` are called.

Burn Unique Data Per Chip
^^^^^^^^^^^^^^^^^^^^^^^^^

In case you are running the ``execute_scripts`` command from your production script, you may need to pass ``index`` to get the unique data for each chip from the ``configfiles`` (* .txt, * .json, etc.). The espefuse command will be like this, where ``{index}`` means the number of chip in the batch, you increment it by your own script in the range 1 - the max number of chips in the batch:

.. code-block:: none

    espefuse.py execute_scripts efuse_script2.py --do-not-confirm --index {index} --configfiles mac_addresses.json  unique_id.json

The example of a script to burn custom_mac address and unique_id getting them from configfiles.

.. code:: python

    # efuse_script2.py

    mac_addresses = json.load(args.configfiles[0])
    unique_id = json.load(args.configfiles[1])

    mac_val = mac_addresses[str(args.index)]
    cmd = 'burn_custom_mac {}'.format(mac_val)
    print(cmd)
    espefuse(esp, efuses, args, cmd)

    unique_id_val = unique_id[str(args.index)]
    cmd = 'burn_efuse UNIQUE_ID {}'.format(unique_id_val)
    print(cmd)
    espefuse(esp, efuses, args, cmd)

The example of a script to burn custom_mac address that generated right in the script.

.. code:: python

    # efuse_script2.py

    step = 4
    base_mac = '0xAABBCCDD0000'
    mac = ''
    for index in range(100):
        mac = "{:012X}".format(int(base_mac, 16) + (args.index - 1) * step)
        mac = ':'.join(mac[k] + mac [k + 1] for k in range(0, len(mac), 2))
        break

    cmd = 'burn_custom_mac mac'
    print(cmd)
    espefuse(esp, efuses, args, cmd)
