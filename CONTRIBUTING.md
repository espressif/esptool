# Contributing to esptool.py

## Reporting Issues

Please report bugs in esptool.py if you find them.

However, before reporting a bug please check through the following:

* [Troubleshooting Section](https://github.com/espressif/esptool/#troubleshooting) - common problems and known issues

* [Existing Open Issues](https://github.com/espressif/esptool/issues) - someone might have already encountered this.

If you don't find anything, please [open a new issue](https://github.com/espressif/esptool/issues/new).

## Sending Feature Requests

Feel free to post feature requests. It's helpful if you can explain exactly why the feature would be useful.

There are usually some outstanding feature requests in the [existing issues list](https://github.com/espressif/esptool/issues?q=is%3Aopen+is%3Aissue+label%3Aenhancement), feel free to add comments to them.

## Sending Pull Requests

Pull Requests with changes and fixes are also welcome!

### Code Style & Static Analysis

esptool.py complies with Flake 8 and is valid Python 2 & Python 3 code (in the same source file.)

When you submit a Pull Request, the Travis automated build system will run automated checks for this, using the [flake8 tool](http://flake8.readthedocs.io/en/latest/). If you want to check your code locally before submitting, you can install flake8 and run `python setup.py flake8` to test it.

### Automated Integration Tests

The test directory contains an integration suite with some integration tests for esptool.py:

* `test_imagegen.py` tests the elf2image command and is run automatically by Travis for each Pull Request. You can run this command locally to check for regressions in the elf2image functionality.

* `test_esptool.py` is a [Python unittest](https://docs.python.org/3/library/unittest.html) file that contains integration tests to be run against real ESP8266 or ESP32 hardware. These tests need real hardware so are not run automatically by Travis, they need to be run locally:

`test_esptool.py` takes a command line with the following format:

`./test_esptool.py <serial port> <name of chip> <baud rate> [optional test name(s)]`

For example, to run all tests on an ESP32 board connected to /dev/ttyUSB0, at 230400bps:

`./test_esptool.py /dev/ttyUSB0 esp32 230400`

Or to run the TestFlashing suite only on an ESP8266 board connected to /dev/ttyUSB2` at 460800bps:

`./test_esptool.py /dev/ttyUSB2 esp8266 460800 TestFlashing`

(Note that some tests will fail at higher baud rates on some hardware.)
