Installation / dependencies
===========================

Easy Installation
-----------------

You will need `either Python 2.7 or Python 3.4 or newer`_ installed on
your system.

The latest stable esptool.py release can be installed from `pypi`_ via
pip:

::

   $ pip install esptool

With some Python installations this may not work and you’ll receive an
error, try ``python -m pip install esptool`` or
``pip2 install esptool``, or consult your `Python installation manual`_
for information about how to access pip.

`Setuptools`_ is also a requirement which is not available on all
systems by default. You can install it by a package manager of your
operating system, or by ``pip install setuptools``.

After installing, you will have ``esptool.py`` installed into the
default Python executables directory and you should be able to run it
with the command ``esptool.py`` or ``python -m esptool``. Please note
that probably only ``python -m esptool`` will work for Pythons installed
from Windows Store.

Development Mode Installation
-----------------------------

Development mode allows you to run the latest development version from
this repository.

.. code:: sh

   $ git clone https://github.com/espressif/esptool.git
   $ cd esptool
   $ pip install --user -e .

This will install esptool’s dependencies and create some executable
script wrappers in the user’s ``bin`` directory. The wrappers will run
the scripts found in the git working directory directly, so any time the
working directory contents change it will pick up the new versions.

It’s also possible to run the scripts directly from the working
directory with this Development Mode installation.

(Note: if you actually plan to do development work with esptool itself,
see the CONTRIBUTING.md file.)

.. _either Python 2.7 or Python 3.4 or newer: https://www.python.org/downloads/
.. _pypi: http://pypi.python.org/pypi/esptool
.. _Python installation manual: https://pip.pypa.io/en/stable/installing/
.. _Setuptools: https://setuptools.readthedocs.io/en/latest/userguide/quickstart.html