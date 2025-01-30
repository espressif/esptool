Installation and Dependencies
=============================

.. _installation:

How to Install
--------------

Global Installation
^^^^^^^^^^^^^^^^^^^

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

Virtual Environment Installation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To ensure that ``esptool.py`` is used in isolation, and any changes made during its usage won't affect other Python environments or SDK installations, it is advised to install it in a virtual environment and use it directly if possible (more information in the :ref:`flashing` article).

Creating a virtual environment (venv) is a good practice. This is particularly helpful for users who may be concerned about interfering with existing installations (e.g. in an environment of a development-setup framework). Here's a quick guide:

- Create a virtual environment and choose its name, e.g. 'esptoolenv': ``python -m venv esptoolenv``
- Activate the virtual environment:

   - On Windows: ``esptoolenv\Scripts\activate``
   - On Linux or macOS: ``source esptoolenv/bin/activate``

- Install the latest ``esptool.py`` version within the active virtual environment: ``pip install esptool``
- You can now use it within this virtual environment without affecting your system-wide installations: ``esptool.py <command>``
- When you're done using ``esptool.py``, deactivate the virtual environment: ``deactivate``. The environment can be reused by activating it again.
- If you no longer need the virtual environment, you can remove it by deleting the ``esptoolenv`` directory.

How to Update
-------------

Standalone
^^^^^^^^^^

If you are using ``esptool.py`` as a standalone tool (as a global installation or in a virtual environment), updating to the latest version released on the `PyPI <https://pypi.org/project/esptool/>`_ index is simple:

::

   $ pip install --upgrade esptool

As a Part of SDK/Framework
^^^^^^^^^^^^^^^^^^^^^^^^^^

If ``esptool.py`` is installed as a part of a development SDK/framework (e.g. `ESP-IDF <https://docs.espressif.com/projects/esp-idf/>`_, `Arduino <https://docs.espressif.com/projects/arduino-esp32/>`_, or `PlatformIO <https://docs.platformio.org/en/latest/platforms/espressif32.html>`_), it is advised to follow the update guide of used framework for instructions and not to update the tool directly.

If updating directly is unavoidable, make sure you update to a compatible version by staying on the same MAJOR version number (explained in the :ref:`versions` article). For instance, if your currently installed ``esptool.py`` is ``v3.3.1``, only update to ``v3.*.*``. You risk introducing incompatible changes by updating to ``v4.*.*`` or higher.

::

   $ pip install "esptool<4"

Shell Completions
-----------------

To activate autocompletion, you can manually add commands provided below to your shell's config file
or run them in your current terminal session for one-time activation.
You will likely have to restart or re-login for the autocompletion to start working.

Bash
^^^^

::

   eval "$(register-python-argcomplete esptool.py espsecure.py espefuse.py)"

Zsh
^^^

To activate completions in zsh, first make sure `compinit` is marked for
autoload and run autoload:

.. code-block:: bash

   autoload -U compinit
   compinit

Afterwards you can enable completions for esptool.py, espsecure.py and espefuse.py:

::

   eval "$(register-python-argcomplete esptool.py espsecure.py espefuse.py)"

Fish
^^^^

Not required to be in the config file, only run once

::

   register-python-argcomplete --shell fish esptool.py espsecure.py espefuse.py >~/.config/fish/completions/esptool.py.fish

Other shells nor OS Windows are not supported.
