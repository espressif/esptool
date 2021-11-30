Contributions Guide
===================

We welcome contributions to the esptool project!

How to Contribute
-----------------

Contributions to esptool - fixing bugs, adding features, adding documentation - are welcome. We accept contributions via `Github Pull Requests <https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-requests>`_.

.. _development-setup:

Development Setup
-----------------

Development mode allows you to run the latest development version from the `esptool repository on GitHub <https://github.com/espressif/esptool>`_.

.. code-block:: sh

   $ git clone https://github.com/espressif/esptool.git
   $ cd esptool
   $ pip install --user -e .

This will install esptool’s dependencies and create some executable script wrappers in the user’s ``bin`` directory. The wrappers will run the scripts found in the git working directory directly, so any time the working directory contents change it will pick up the new versions.

It’s also possible to run the scripts directly from the working directory with this Development Mode installation.

To also install additional tools needed for actually developing and testing esptool, run this command to install a development copy of esptool *plus* packages useful for development:

::

   $ pip install --user -e .[dev]

(This command uses the “extras” feature of setuptools.)

Reporting Issues
----------------

Please report bugs in esptool if you find them. However, before reporting a bug please check through the following:

*  `Troubleshooting Guide <https://docs.espressif.com/projects/esptool/en/latest/troubleshooting.html>`_ - common problems and known issues.

*  `Existing Open Issues <https://github.com/espressif/esptool/issues>`_ - someone might have already encountered this.

If you don’t find anything, please `open a new issue <https://github.com/espressif/esptool/issues/new/choose>`_.

Sending Feature Requests
------------------------

Feel free to post feature requests. It’s helpful if you can explain exactly why the feature would be useful.

There are usually some outstanding feature requests in the `existing issues list <https://github.com/espressif/esptool/issues?q=is%3Aopen+is%3Aissue+label%3Aenhancement>`_, feel free to add comments to them.

Before Contributing
-------------------

Before sending us a Pull Request, please consider this list of points:

* Have you tried running esptool test suite locally?

* Is the code adequately commented for people to understand how it is structured?

* Is there documentation or examples that go with code contributions?

* Are comments and documentation written in clear English, with no spelling or grammar errors?

* If the contribution contains multiple commits, are they grouped together into logical changes (one major change per pull request)? Are any commits with names like "fixed typo" `squashed into previous commits <https://eli.thegreenplace.net/2014/02/19/squashing-github-pull-requests-into-a-single-commit/>`_?

* If you're unsure about any of these points, please open the Pull Request anyhow and then ask us for feedback.

Code Style & Static Analysis
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

esptool complies with Flake 8 and is valid Python 2 & Python 3 code (in the same source file.)

When you submit a Pull Request, the GitHub Actions automated build system will run automated checks for this, using the `flake8 tool <http://flake8.readthedocs.io/en/latest/>`_. To check your code locally before submitting, run ``python -m flake8`` (the flake8 tool is installed as part of the development requirements shown at the beginning of this document.)

Automated Integration Tests
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The test directory contains an integration suite with some integration tests for ``esptool.py``:

*  ``test_imagegen.py`` tests the elf2image command and is run automatically by GitHub Actions for each Pull Request. You can run this command locally to check for regressions in the elf2image functionality.

*  ``test_esptool.py`` is a `Python unittest <https://docs.python.org/3/library/unittest.html>`_ file that contains integration tests to be run against real Espressif hardware. These tests need real hardware so are not run automatically by GitHub Actions, they need to be run locally in a command line with the following format:

   ``./test_esptool.py <serial port> <name of chip> <baud rate> [optional test name(s)]``

   For example, to run all tests on an ESP32 board connected to /dev/ttyUSB0, at 230400bps:

   ``./test_esptool.py /dev/ttyUSB0 esp32 230400``

   Or to run the TestFlashing suite only on an ESP8266 board connected to /dev/ttyUSB2, at 460800bps:

   ``./test_esptool.py /dev/ttyUSB2 esp8266 460800 TestFlashing``

   .. note::

      Some tests might fail at higher baud rates on some hardware.

Pull Request Process
--------------------

After you open the Pull Request, there will probably be some discussion in the comments field of the request itself.

Once the Pull Request is ready to merge, it will first be merged into our internal git system for in-house automated testing.

If this process passes, it will be merged onto the public github repository, hooray!
