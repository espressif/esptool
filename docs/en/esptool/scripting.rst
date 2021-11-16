.. _scripting:

Embedding into Custom Scripts
=============================

``esptool.py``, ``espefuse.py``, and ``espsecure.py`` can easily be integrated into Python applications or called from other Python scripts.

While it currently does have a poor Python API, something which `#208 <https://github.com/espressif/esptool/issues/208>`_ will address, it allows for passing CLI arguments to ``esptool.main()``. This workaround makes integration very straightforward as you can pass exactly the same arguments as you would on the CLI:

.. code-block:: python

    command = ['--baud', '460800', 'read_flash', '0', '0x200000', 'flash_contents.bin']
    print('Using command %s' % ' '.join(command))
    esptool.main(command)
