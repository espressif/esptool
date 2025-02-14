import pytest
import os


def pytest_addoption(parser):
    # test_esptool.py and test_espefuse.py
    parser.addoption(
        "--port", action="store", default="/dev/ttyUSB0", help="Serial port"
    )
    parser.addoption("--chip", action="store", default="esp32", help="Chip type")

    # test_esptool.py only
    parser.addoption("--baud", action="store", default=115200, help="Baud rate")
    parser.addoption("--with-trace", action="store_true", default=False, help="Trace")
    parser.addoption(
        "--preload-port",
        action="store",
        default=False,
        help="Port for dummy binary preloading for USB-JTAG/Serial tests",
    )

    # test_espefuse.py only
    parser.addoption(
        "--reset-port", action="store", default=None, help="FPGA reset port"
    )


def pytest_configure(config):
    # test_esptool.py and test_espefuse.py
    global arg_port, arg_chip
    arg_port = config.getoption("--port")
    arg_chip = config.getoption("--chip")

    # test_esptool.py only
    global arg_baud, arg_trace, arg_preload_port
    arg_baud = config.getoption("--baud")
    arg_trace = config.getoption("--with-trace")
    arg_preload_port = config.getoption("--preload-port")

    # test_espefuse.py only
    global arg_reset_port
    arg_reset_port = config.getoption("--reset-port")

    # register custom markers
    config.addinivalue_line(
        "markers",
        "host_test: mark esptool tests that run on the host machine only "
        "(don't require a real chip connected).",
    )

    config.addinivalue_line(
        "markers",
        "quick_test: mark esptool tests checking basic functionality.",
    )


def need_to_install_package_err():
    pytest.exit(
        "To run the tests, install esptool in development mode. "
        "Instructions: https://docs.espressif.com/projects/esptool/en/latest/"
        "contributing.html#development-setup"
    )


@pytest.fixture(scope="session", autouse=True)
def set_terminal_width():
    """Make sure terminal width is set to 120 columns for consistent test output."""
    os.environ["COLUMNS"] = "120"
