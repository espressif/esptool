def pytest_addoption(parser):
    parser.addoption(
        "--port", action="store", default="/dev/ttyUSB0", help="Serial port"
    )
    parser.addoption("--chip", action="store", default="esp32", help="Chip type")
    parser.addoption("--baud", action="store", default=115200, help="Baud rate")
    parser.addoption(
        "--with_trace",
        action="store_true",
        default=False,
        help="Trace interactions",
    )


def pytest_configure(config):
    global arg_port, arg_chip, arg_baud, arg_trace
    arg_port = config.getoption("--port")
    arg_chip = config.getoption("--chip")
    arg_baud = config.getoption("--baud")
    arg_trace = config.getoption("--with_trace")
