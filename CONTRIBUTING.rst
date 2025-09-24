Contributions Guide
===================

We welcome contributions to the ``esptool`` project!

How to Contribute
-----------------

Contributions to ``esptool`` - fixing bugs, adding features, adding documentation - are welcome. We accept contributions via `Github Pull Requests <https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-requests>`_.

.. _development-setup:

Development Setup
-----------------

Development mode allows you to run the latest development version from the `esptool repository on GitHub <https://github.com/espressif/esptool>`_.

.. code-block:: sh

   $ git clone https://github.com/espressif/esptool.git
   $ cd esptool
   $ pip install --user -e .

This will install ``esptool``'s dependencies and create some executable script wrappers in the user's ``bin`` directory. The wrappers will run the scripts found in the git working directory directly, so any time the working directory contents change it will pick up the new versions.

It's also possible to run the scripts directly from the working directory with this Development Mode installation.

To also install additional tools needed for actually developing and testing ``esptool``, run this command to install a development copy of ``esptool`` *plus* packages useful for development:

::

   $ pip install --user -e ".[dev]"

(This command uses the “extras” feature of setuptools.)

Reporting Issues
----------------

Please report bugs in ``esptool`` if you find them. However, before reporting a bug please check through the following:

*  `Troubleshooting Guide <https://docs.espressif.com/projects/esptool/en/latest/troubleshooting.html>`_ - common problems and known issues.

*  `Existing Open Issues <https://github.com/espressif/esptool/issues>`_ - someone might have already encountered this.

If you don’t find anything, please `open a new issue <https://github.com/espressif/esptool/issues/new/choose>`_.

.. _feature-requests:

Sending Feature Requests
------------------------

Feel free to post feature requests. It’s helpful if you can explain exactly why the feature would be useful.

There are usually some outstanding feature requests in the `existing issues list <https://github.com/espressif/esptool/issues?q=is%3Aopen+is%3Aissue+label%3Aenhancement>`_, feel free to add comments to them.

Before Contributing
-------------------

Before sending us a Pull Request, please consider this list of points:

* Have you tried running ``esptool`` test suite locally?

* Is the code adequately commented for people to understand how it is structured?

* Is there documentation or examples that go with code contributions?

* Are comments and documentation written in clear English, with no spelling or grammar errors?

* If the contribution contains multiple commits, are they grouped together into logical changes (one major change per pull request)? Are any commits with names like "fixed typo" `squashed into previous commits <https://eli.thegreenplace.net/2014/02/19/squashing-github-pull-requests-into-a-single-commit/>`_?

* If you're unsure about any of these points, please open the Pull Request anyhow and then ask us for feedback.

Code Style & Static Analysis
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Please follow these coding standards when writing code for ``esptool``:

Pre-Commit Checks
"""""""""""""""""

`pre-commit <https://pre-commit.com/>`_ is a framework for managing pre-commit hooks. These hooks help to identify simple issues before committing code for review.

To use the tool, first install ``pre-commit``. Then enable the ``pre-commit`` and ``commit-msg`` git hooks:

::

   $ python -m pip install pre-commit
   $ pre-commit install -t pre-commit -t commit-msg

On the first commit ``pre-commit`` will install the hooks, subsequent checks will be significantly faster. If an error is found an appropriate error message will be displayed. Review the changes and re-stage for commit if you are happy with them.

Conventional Commits
""""""""""""""""""""

``esptool`` complies with the `Conventional Commits standard <https://www.conventionalcommits.org/en/v1.0.0/#specification>`_. Every commit message is checked with `Conventional Precommit Linter <https://github.com/espressif/conventional-precommit-linter>`_, ensuring it adheres to the standard.


Ruff
""""

``esptool`` is `PEP8 <https://peps.python.org/pep-0008/>`_ compliant and enforces this style guide. For compliance checking, we use `ruff <https://docs.astral.sh/ruff/>`_.
``Ruff`` also auto-format files in the same style as previously used ``black``.


``Ruff`` and ``Conventional Precommit Linter`` tools will be automatically run by ``pre-commit`` if that is configured. To check your code manually before submitting, run ``python -m ruff`` (this tool is installed as part of the development requirements shown at the beginning of this document).

When you submit a Pull Request, the GitHub Actions automated build system will run automated checks using these tools.

Sphinx-Lint
"""""""""""

The documentation is checked for stylistic and formal issues by ``sphinx-lint``.


Codespell Check
"""""""""""""""

This repository utilizes an automatic `spell checker <https://github.com/codespell-project/codespell>`_ integrated into the pre-commit process. If any spelling issues are detected, the recommended corrections will be applied automatically to the file, ready for commit.
In the event of false positives, you can adjust the configuration in the `.codespell.rc`. To exclude files from the spell check, utilize the `skip` keyword followed by comma-separated paths to the files (wildcards are supported). Additionally, to exclude specific words from the spell check, employ the `ignore-words-list` keyword followed by comma-separated words to be skipped.


Automated Integration Tests
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The test directory contains a `pytest <https://docs.pytest.org/>`_ integration suite with some integration tests for ``esptool``, ``espefuse``, and ``espsecure``.

It is necessary to have ``esptool`` installed (see `Development Setup`_) in your environment in order to run these tests.

The following tests run automatically by GitHub Actions for each Pull Request. You can run them locally to check for regressions in the respective functionality:

*  ``test_imagegen.py`` tests the ``elf2image`` command
*  ``test_image_info.py`` tests the ``image-info`` command
*  ``test_mergebin.py`` tests the ``merge-bin`` command
*  ``test_port_sorting.py`` tests the port sorting algorithm of ``esptool``
*  ``test_modules.py`` tests the modules used by ``esptool`` for regressions
*  ``test_espsecure.py`` tests ``espsecure`` functionality
*  ``test_espsecure_hsm.py`` tests support of external HSM signing in ``espsecure``. These tests require additional prerequisites, see ``SoftHSM2 setup`` in the `tests workflow definition <https://github.com/espressif/esptool/blob/master/.github/workflows/test_esptool.yml>`_ for more information.

The following tests are not run automatically by GitHub Actions, because they need real connected hardware. Therefore, they need to be run locally in a command line:

*  ``test_esptool.py`` contains integration tests for ``esptool`` and needs to be run against real Espressif hardware with the following format:

   ``pytest test_esptool.py --port <serial port> --chip <name of chip> --baud <baud rate>``

   For example, to run all tests on an ESP32 board connected to /dev/ttyUSB0, at 230400bps:

   ``pytest test_esptool.py --port /dev/ttyUSB0 --chip esp32 --baud 230400``

   Or to run the ``TestFlashing`` suite only (using the pytest ``-k`` option to select tests based on their name) on an ESP8266 board connected to /dev/ttyUSB2, at 460800bps:

   ``pytest test_esptool.py --port /dev/ttyUSB2 --chip esp8266 --baud 460800 -k TestFlashing``

   .. note::

      Some tests might fail at higher baud rates on some hardware.

*  ``test_esptool_sdm.py`` contains integration tests for ``esptool`` with chips in secure download mode. It needs to be run against real Espressif hardware (with active SDM). The command line format is the same as for ``test_esptool.py``.

The following tests are not run automatically by GitHub Actions, but can be run locally in a command line:

*  ``test_espefuse.py`` tests ``espefuse`` functionality. To run it:

   ``pytest test_espefuse.py --chip <name of chip>``

   These test use the ``--virt`` virtual mode of ``espefuse`` to safely test the functionality without a connection to a chip and without the possibility of affecting the actual eFuses in a real hardware.

   .. warning::

      Do not attempt to run these tests on real hardware! You risk damaging or destroying the ESP chip!

The whole test suite (without the tests needing an actual hardware or installation of additional prerequisites) can be easily run with the following command in the esptool root folder: ``pytest -m host_test``


Pull Request Process
--------------------

If you would like to contribute to the flasher stub, please see the `Flasher stub repository <https://github.com/espressif/esptool-legacy-flasher-stub>`_.

After you open the Pull Request, there will probably be some discussion in the comments field of the request itself.

Once the Pull Request is ready to merge, it will first be merged into our internal git system for in-house automated testing.

If this process passes, it will be merged onto the public github repository, hooray!
