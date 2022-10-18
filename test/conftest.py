def pytest_addoption(parser):
    # test_esptool.py and test_espefuse.py
    parser.addoption(
        "--port", action="store", default="/dev/ttyUSB0", help="Serial port"
    )
    parser.addoption("--chip", action="store", default="esp32", help="Chip type")

    # test_esptool.py only
    parser.addoption("--baud", action="store", default=115200, help="Baud rate")
    parser.addoption("--with-trace", action="store_true", default=False, help="Trace")

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
    global arg_baud, arg_trace
    arg_baud = config.getoption("--baud")
    arg_trace = config.getoption("--with-trace")

    # test_espefuse.py only
    global arg_reset_port
    arg_reset_port = config.getoption("--reset-port")
