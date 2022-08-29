.. _installation:

Installation and Dependencies
=============================

You will need `Python 3.7 or newer <https://www.python.org/downloads/>`_ installed on your system to use the latest version of ``esptool.py``.
If your use case requires Python 2.7, 3.4, 3.5, or 3.6, please use ``esptool.py`` v3.3.* instead.

The latest stable esptool release can be installed from `PyPI <https://pypi.org/project/esptool/>`_ via pip:

::

   $ pip install esptool

With some Python installations this may not work and you’ll receive an error, try ``python -m pip install esptool`` or ``pip3 install esptool``, or consult your `Python installation manual <https://pip.pypa.io/en/stable/installation/>`_ for information about how to access pip.

`Setuptools <https://setuptools.pypa.io/en/latest/userguide/quickstart.html>`_ is also a requirement which is not available on all systems by default. You can install it by a package manager of your operating system, or by ``pip install setuptools``.

After installing, you will have ``esptool.py`` installed into the default Python executables directory and you should be able to run it with the command ``esptool.py`` or ``python -m esptool``. Please note that probably only ``python -m esptool`` will work for Pythons installed from Windows Store.

.. note::

   If you actually plan to do development work with esptool itself, see :ref:`development-setup` for more information.
