Contributions Guide
===================

.. _feature-requests:

Before You Start
----------------

* Search the `existing issues <https://github.com/espressif/esptool/issues>`_ and the `troubleshooting guide <https://docs.espressif.com/projects/esptool/en/latest/troubleshooting.html>`_.
* Before you report a bug, you must check that it still happens with the latest code on GitHub, as described in `Testing the Latest Code`_.
* Send flasher stub changes to the `esp-flasher-stub repository <https://github.com/espressif/esp-flasher-stub>`_.

.. important::

   For a new feature, a change of behaviour or a fix whose cause is not obvious, `open an issue <https://github.com/espressif/esptool/issues/new/choose>`_ and agree on the goal with the maintainers before you open a pull request. A typo, a documentation fix or a small fix with an obvious cause can go straight to a pull request.

Testing the Latest Code
-----------------------

Bugfixes reach the ``master`` branch on GitHub before they are released. Test the latest code of ``master`` before you report a bug. You need `Git <https://git-scm.com/downloads>`_. Create and activate a new `virtual environment <https://docs.espressif.com/projects/esptool/en/latest/installation.html#virtual-environment-installation>`_, so that your current esptool installation stays unchanged. Then run:

.. code-block:: sh

   git clone https://github.com/espressif/esptool.git
   cd esptool

If you must stay on an older major version, switch to its branch now. For esptool v4.x, run ``git checkout release/v4``. Then install the code:

.. code-block:: sh

   pip install -e .

The ``esptool`` command in this virtual environment now runs the code in the ``esptool`` directory. On ``release/v4`` and older branches, this command is ``esptool.py``. To print the version of that code for the issue report, run ``git describe`` in the ``esptool`` directory. To get the latest code later, run ``git pull`` and then ``pip install -e .`` in the ``esptool`` directory.

.. _development-setup:

Development Setup
-----------------

Fork https://github.com/espressif/esptool. In a Python 3.10 or newer virtual environment, run:

.. code-block:: sh

   git clone https://github.com/<your-user>/esptool.git
   cd esptool
   pip install -e ".[dev]"
   pre-commit install

.. _automated-integration-tests:

Code and Tests
--------------

* Use `esp-pylib <https://github.com/espressif/esp-pylib>`_ instead of reimplementing shared code. Print output with ``esptool.logger.log`` instead of ``print()`` or ``logging``. Raise ``FatalError`` from ``esptool.util``. Define CLI options with ``esp_pylib.cli_types`` and ``esp_pylib.cli_options``.
* If a new helper can serve other Espressif tools, say so in the pull request.
* Add or update tests and documentation for every change in behaviour.
* Run the host tests. They must pass:

  .. code-block:: sh

     pytest -m host_test

  On Windows, run ``pytest -m "host_test and not linux_host_test"`` instead.

* For espefuse changes, run ``pytest test/test_espefuse.py --chip <chip>`` without ``--reset-port``.
* For espsecure HSM changes, set up SoftHSM2 as the "SoftHSM2 setup" step in ``.github/workflows/test_esptool.yml`` does, run ``pip install -e ".[dev,hsm]"``, then run ``pytest test/test_espsecure_hsm.py``.
* For changes to chip communication, run ``pytest test/test_esptool.py --port <port> --chip <chip> --baud <baud>`` on a dedicated development board. Run ``test/test_esptool_sdm.py`` with the same options on a board in Secure Download Mode. If you did not run them, say so in the pull request.

.. warning::

   ``test/test_esptool.py`` and ``test/test_esptool_sdm.py`` erase flash and can burn eFuses irreversibly. Running ``pytest`` without ``-m host_test`` also runs them, against ``/dev/ttyUSB0`` by default. Never run them on a production device or on a board you cannot identify.

Pre-commit Checks
-----------------

.. important::

   All pre-commit checks must pass before you open a pull request and before every push to it:

   .. code-block:: sh

      pre-commit run --all-files

* If a hook changes files, add the changes to the commit they belong to.
* Do not bypass hooks with ``git commit --no-verify`` or the ``SKIP`` environment variable. Do not add ``# noqa`` or ``# type: ignore`` unless the pull request description explains why.

Commits
-------

* ``pre-commit install`` also installs a ``commit-msg`` hook that checks the format of each commit message when you commit. If the hook rejects a message, correct it as the hook's output describes. ``pre-commit run --all-files`` does not check commit messages.
* Squash fixup commits into the commits they fix.
* Do not edit ``CHANGELOG.md``.

Pull Requests
-------------

* Keep one logical change per pull request.
* Open the pull request against ``master`` and fill in the sections of ``.github/pull_request_template.md``.
