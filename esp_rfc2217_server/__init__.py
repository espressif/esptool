# SPDX-FileCopyrightText: 2009-2015 Chris Liechti
# SPDX-FileContributor: 2020-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: BSD-3-Clause
#
# Redirect data from a TCP/IP connection to a serial port and vice versa using RFC 2217.

###################################################################################
# redirect data from a TCP/IP connection to a serial port and vice versa
# using RFC 2217
#
# (C) 2009-2015 Chris Liechti <cliechti@gmx.net>
#
# SPDX-License-Identifier: BSD-3-Clause

import logging
import socket

import rich_click as click
import serial
from esp_pylib.cli_types import SerialPortType
from rich.markup import escape

from esp_rfc2217_server.redirector import Redirector
from esptool.logger import log
from esptool.util import check_deprecated_py_suffix


@click.command(
    no_args_is_help=True,
    context_settings=dict(help_option_names=["-h", "--help"], max_content_width=120),
    help="RFC 2217 Serial to Network (TCP/IP) redirector.",
    epilog="NOTE: no security measures are implemented. "
    "Anyone can remotely connect to this service over the network. "
    "Only one connection at once is supported. "
    "When the connection is terminated it waits for the next connect.",
)
@click.argument("serialport", metavar="SERIALPORT", type=SerialPortType())
@click.option(
    "--localport",
    "-p",
    type=int,
    metavar="TCPPORT",
    default=2217,
    show_default=True,
    help="Local TCP port.",
)
@click.option(
    "--verbose",
    "-v",
    "verbosity",
    count=True,
    help="Print more diagnostic messages (option can be given multiple times).",
)
@click.option(
    "--r0",
    is_flag=True,
    help="Use delays necessary for ESP32 revision 0 chips.",
)
def cli(serialport: str, localport: int, verbosity: int, r0: bool):
    if verbosity > 3:
        verbosity = 3
    # The ``-v`` count only tunes pyserial's RFC2217 ``PortManager``, which
    # logs through the stdlib ``logging`` module (it expects a
    # ``logging.Logger``). The server's own status/error output below goes
    # through the shared esptool/esp-pylib logger instead.
    level = (logging.WARNING, logging.INFO, logging.DEBUG, logging.NOTSET)[verbosity]
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)
    logging.getLogger("rfc2217").setLevel(level)

    # connect to serial port
    ser = serial.serial_for_url(serialport, do_not_open=True, exclusive=True)
    ser.timeout = 3  # required so that the reader thread can exit
    # reset control line as no _remote_ "terminal" has been connected yet
    ser.dtr = False
    ser.rts = False

    log.print("RFC 2217 TCP/IP to Serial redirector - type Ctrl-C / BREAK to quit")

    try:
        ser.open()
    except serial.SerialException as e:
        log.die(f"Could not open serial port {escape(str(ser.name))}: {escape(str(e))}")

    log.print(f"Serving serial port: {ser.name}")
    settings = ser.get_settings()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("", localport))
    srv.listen(1)
    log.print(f"TCP/IP port: {localport}")

    try:
        host_ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        # CI/minimal containers often have no DNS for gethostname(); the server
        # is still reachable on loopback.
        host_ip = "127.0.0.1"
    wait_msg = (
        "Waiting for connection ... use the 'rfc2217://"
        f"{host_ip}:{localport}?ign_set_control' as a PORT"
    )
    log.print(wait_msg)

    while True:
        srv.settimeout(5)
        client_socket = None
        try:
            while client_socket is None:
                try:
                    client_socket, addr = srv.accept()
                except TimeoutError:
                    print(".", end="", flush=True)
        except KeyboardInterrupt:
            print("")  # resetting inline print
            log.print("Exited with keyboard interrupt")
            break
        try:
            log.print(f"Connected by {addr[0]}:{addr[1]}")
            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            ser.rts = True
            ser.dtr = True
            # enter network <-> serial loop
            r = Redirector(ser, client_socket, verbosity > 0, r0)
            try:
                r.shortcircuit()
            finally:
                log.print("Disconnected")
                r.stop()
                client_socket.close()
                ser.dtr = False
                ser.rts = False
                # Restore port settings (may have been changed by RFC 2217
                # capable client)
                ser.apply_settings(settings)
        except KeyboardInterrupt:
            print(flush=True)
            break
        except OSError as msg:
            log.err(str(msg))

    log.print("--- exit ---")


def main(argv: list[str] | None = None):
    """Entry point for the ``esp_rfc2217_server`` console script.

    ``argv`` is an optional override for ``sys.argv`` (a list of argument
    strings) to ease programmatic invocation and testing.
    """
    check_deprecated_py_suffix("esp_rfc2217_server")
    cli.main(args=argv)


if __name__ == "__main__":
    main()
