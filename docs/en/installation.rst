Installation and Dependencies
=============================

.. _installation:

How to Install
--------------

Global Installation
^^^^^^^^^^^^^^^^^^^

You will need `Python 3.10 or newer <https://www.python.org/downloads/>`_ installed on your system to use the latest version of ``esptool``.
If your use case requires Python 3.7, 3.8, or 3.9, please use ``esptool`` v4.x. For Python 2.7, 3.4, 3.5, or 3.6, please use ``esptool`` v3.3.* instead.

The latest stable esptool release can be installed from `PyPI <https://pypi.org/project/esptool/>`_ via pip:

::

   $ pip install esptool

With some Python installations this may not work and you'll receive an error, try ``python -m pip install esptool`` or ``pip3 install esptool``, or consult your `Python installation manual <https://pip.pypa.io/en/stable/installation/>`_ for information about how to access pip.

`Setuptools <https://setuptools.pypa.io/en/latest/userguide/quickstart.html>`_ is also a requirement which is not available on all systems by default. You can install it by a package manager of your operating system, or by ``pip install setuptools``.

After installing, you will have ``esptool`` installed into the default Python executables directory and you should be able to run it with the command ``esptool`` or ``python -m esptool``. Please note that probably only ``python -m esptool`` will work for Pythons installed from Windows Store.

.. note::

   If you actually plan to do development work with esptool itself, see :ref:`development-setup` for more information.

Virtual Environment Installation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To ensure that ``esptool`` is used in isolation, and any changes made during its usage won't affect other Python environments or SDK installations, it is advised to install it in a virtual environment and use it directly if possible (more information in the :ref:`flashing` article).

Creating a virtual environment (venv) is a good practice. This is particularly helpful for users who may be concerned about interfering with existing installations (e.g. in an environment of a development-setup framework). Here's a quick guide:

- Create a virtual environment and choose its name, e.g. 'esptoolenv': ``python -m venv esptoolenv``
- Activate the virtual environment:

   - On Windows: ``esptoolenv\Scripts\activate``
   - On Linux or macOS: ``source esptoolenv/bin/activate``

- Install the latest ``esptool`` version within the active virtual environment: ``pip install esptool``
- You can now use it within this virtual environment without affecting your system-wide installations: ``esptool <command>``
- When you're done using ``esptool``, deactivate the virtual environment: ``deactivate``. The environment can be reused by activating it again.
- If you no longer need the virtual environment, you can remove it by deleting the ``esptoolenv`` directory.

Binary Releases
^^^^^^^^^^^^^^^^

If you do not want to install Python and all the dependencies, you can use the pre-built binaries from the `GitHub Releases <https://github.com/espressif/esptool/releases>`_.

Please note that the binaries might have some limitations:

- The binaries might rely on some system libraries that are not available on all systems.
- The binaries are available only for selected operating systems - currently macOS (x86_64, arm64), Linux (x86_64, armv7,aarch64) and Windows (x86_64).
- The binaries might get reported as malware by your antivirus software.
- The application is larger in size compared to the Python package installation, as it includes all dependencies.
- The application has slower startup time compared to running the Python script directly.
- The application cannot be imported as a Python module in other Python applications.

.. note::

   For Linux, the binaries are built using Ubuntu 22.04 as the base image. That means any version older than Ubuntu 22.04 (or any other distribution that uses ``glibc<2.35``) might not work.
   For using on Ubuntu 20.04, please use the Python package installation or ``v4.*`` release.

How to Update
-------------

Standalone
^^^^^^^^^^

If you are using ``esptool`` as a standalone tool (as a global installation or in a virtual environment), updating to the latest version released on the `PyPI <https://pypi.org/project/esptool/>`_ index is simple:

::

   $ pip install --upgrade esptool

As a Part of SDK/Framework
^^^^^^^^^^^^^^^^^^^^^^^^^^

If ``esptool`` is installed as a part of a development SDK/framework (e.g. `ESP-IDF <https://docs.espressif.com/projects/esp-idf/>`_, `Arduino <https://docs.espressif.com/projects/arduino-esp32/>`_, or `PlatformIO <https://docs.platformio.org/en/latest/platforms/espressif32.html>`_), it is advised to follow the update guide of used framework for instructions and not to update the tool directly.

If updating directly is unavoidable, make sure you update to a compatible version by staying on the same MAJOR version number (explained in the :ref:`versions` article). For instance, if your currently installed ``esptool`` is ``v3.3.1``, only update to ``v3.*.*``. You risk introducing incompatible changes by updating to ``v4.*.*`` or higher.

::

   $ pip install "esptool<4"

.. _shell-completion:

Shell Completions
-----------------

To activate autocompletion, you can manually add commands provided below to your shell's config file
or run them in your current terminal session for one-time activation.
You will likely have to restart or re-login for the autocompletion to start working.

.. tabs::

   .. group-tab:: Bash

         .. code-block:: bash

               eval "$(_ESPTOOL_PY_COMPLETE=bash_source esptool)"
               eval "$(_ESPSECURE_PY_COMPLETE=bash_source espsecure)"
               eval "$(_ESPEFUSE_PY_COMPLETE=bash_source espefuse)"


   .. group-tab:: Zsh

      To activate completions in zsh, first make sure `compinit` is marked for
      autoload and run autoload:

      .. code-block:: bash

         autoload -U compinit
         compinit

      Afterwards you can enable completions for esptool, espsecure and espefuse:


      .. code-block:: bash

         eval "$(_ESPTOOL_PY_COMPLETE=zsh_source esptool)"
         eval "$(_ESPSECURE_PY_COMPLETE=zsh_source espsecure)"
         eval "$(_ESPEFUSE_PY_COMPLETE=zsh_source espefuse)"


   .. group-tab:: Fish

      .. code-block:: bash

         _ESPTOOL_PY_COMPLETE=fish_source esptool | source
         _ESPSECURE_PY_COMPLETE=fish_source espsecure | source
         _ESPEFUSE_PY_COMPLETE=fish_source espefuse | source



Other shells nor OS Windows are not supported.
