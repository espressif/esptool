#!/usr/bin/env python
#
# Redirect data from a TCP/IP connection to a serial port and vice versa using RFC 2217.
#
# This is a modified version of rfc2217_server.py provided by the pyserial package
# (https://pythonhosted.org/pyserial/examples.html#single-port-tcp-ip-serial-bridge-rfc-2217).
# It uses a custom PortManager for properly apply the RTS & DTR signals for reseting ESP chips.
#
# Run the following command on the server side to make connection between /dev/ttyUSB1 and TCP port 4000:
#
#   esp_rfc2217_server.py -p 4000 /dev/ttyUSB1
#
# Esptool can connect to the ESP device through that server as it is demonstrated in the following example:
#
#   esptool.py --port rfc2217://localhost:4000?ign_set_control flash_id
#
# Copyright (C) 2020 Espressif Systems (Shanghai) PTE LTD
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
###################################################################################
# redirect data from a TCP/IP connection to a serial port and vice versa
# using RFC 2217
#
# (C) 2009-2015 Chris Liechti <cliechti@gmx.net>
#
# SPDX-License-Identifier:    BSD-3-Clause
from __future__ import division, print_function

import logging
import socket
import sys
import threading
import time

import serial
import serial.rfc2217
from serial.rfc2217 import (COM_PORT_OPTION, SET_CONTROL, SET_CONTROL_DTR_OFF, SET_CONTROL_DTR_ON, SET_CONTROL_RTS_OFF,
                            SET_CONTROL_RTS_ON)


class EspPortManager(serial.rfc2217.PortManager):
    """ The beginning of the reset sequence is detected and the proper reset sequence is applied in a thread. The rest
    of the reset sequence received is just ignored and not sent to the serial port.
    """

    def __init__(self, serial_port, connection, esp32r0_delay, logger=None):
        self.esp32r0_delay = esp32r0_delay
        super(EspPortManager, self).__init__(serial_port, connection, logger)

    def _telnet_process_subnegotiation(self, suboption):
        if suboption[0:1] == COM_PORT_OPTION and suboption[1:2] == SET_CONTROL:
            if suboption[2:3] == SET_CONTROL_DTR_OFF:
                self.serial.dtr = False
                return
            elif suboption[2:3] == SET_CONTROL_RTS_ON and not self.serial.dtr:
                reset_thread = threading.Thread(target=self._reset_thread)
                reset_thread.daemon = True
                reset_thread.name = 'reset_thread'
                reset_thread.start()
                return
            elif suboption[2:3] in [SET_CONTROL_DTR_ON, SET_CONTROL_RTS_ON, SET_CONTROL_RTS_OFF]:
                return
        # only in cases not handled above do the original implementation in PortManager
        super(EspPortManager, self)._telnet_process_subnegotiation(suboption)

    def _setDTR(self, state):
        self.serial.setDTR(state)

    def _setRTS(self, state):
        self.serial.setRTS(state)
        # Work-around for adapters on Windows using the usbser.sys driver:
        # generate a dummy change to DTR so that the set-control-line-state
        # request is sent with the updated RTS state and the same DTR state
        self.serial.setDTR(self.serial.dtr)

    def _reset_thread(self):
        """ The reset logic is used from esptool.py because the RTS and DTR signals cannot be retransmitted through
        RFC 2217 with proper timing.
        """
        if self.logger:
            self.logger.info("Activating reset in thread")
        self._setDTR(False)  # IO0=HIGH
        self._setRTS(True)   # EN=LOW, chip in reset
        time.sleep(0.1)
        if self.esp32r0_delay:
            time.sleep(1.2)
        self._setDTR(True)   # IO0=LOW
        self._setRTS(False)  # EN=HIGH, chip out of reset
        if self.esp32r0_delay:
            time.sleep(0.4)
        time.sleep(0.05)
        self._setDTR(False)  # IO0=HIGH, done


class Redirector(object):
    def __init__(self, serial_instance, socket, debug=False, esp32r0delay=False):
        self.serial = serial_instance
        self.socket = socket
        self._write_lock = threading.Lock()
        self.rfc2217 = EspPortManager(
            self.serial,
            self,
            esp32r0delay,
            logger=logging.getLogger('rfc2217.server') if debug else None)
        self.log = logging.getLogger('redirector')

    def statusline_poller(self):
        self.log.debug('status line poll thread started')
        while self.alive:
            time.sleep(1)
            self.rfc2217.check_modem_lines()
        self.log.debug('status line poll thread terminated')

    def shortcircuit(self):
        """connect the serial port to the TCP port by copying everything
           from one side to the other"""
        self.alive = True
        self.thread_read = threading.Thread(target=self.reader)
        self.thread_read.daemon = True
        self.thread_read.name = 'serial->socket'
        self.thread_read.start()
        self.thread_poll = threading.Thread(target=self.statusline_poller)
        self.thread_poll.daemon = True
        self.thread_poll.name = 'status line poll'
        self.thread_poll.start()
        self.writer()

    def reader(self):
        """loop forever and copy serial->socket"""
        self.log.debug('reader thread started')
        while self.alive:
            try:
                data = self.serial.read(self.serial.in_waiting or 1)
                if data:
                    # escape outgoing data when needed (Telnet IAC (0xff) character)
                    self.write(b''.join(self.rfc2217.escape(data)))
            except socket.error as msg:
                self.log.error('{}'.format(msg))
                # probably got disconnected
                break
        self.alive = False
        self.log.debug('reader thread terminated')

    def write(self, data):
        """thread safe socket write with no data escaping. used to send telnet stuff"""
        with self._write_lock:
            self.socket.sendall(data)

    def writer(self):
        """loop forever and copy socket->serial"""
        while self.alive:
            try:
                data = self.socket.recv(1024)
                if not data:
                    break
                self.serial.write(b''.join(self.rfc2217.filter(data)))
            except socket.error as msg:
                self.log.error('{}'.format(msg))
                # probably got disconnected
                break
        self.stop()

    def stop(self):
        """Stop copying"""
        self.log.debug('stopping')
        if self.alive:
            self.alive = False
            self.thread_read.join()
            self.thread_poll.join()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description="RFC 2217 Serial to Network (TCP/IP) redirector.",
        epilog="""\
NOTE: no security measures are implemented. Anyone can remotely connect
to this service over the network.

Only one connection at once is supported. When the connection is terminated
it waits for the next connect.
""")

    parser.add_argument('SERIALPORT')

    parser.add_argument(
        '-p', '--localport',
        type=int,
        help='local TCP port, default: %(default)s',
        metavar='TCPPORT',
        default=2217)

    parser.add_argument(
        '-v', '--verbose',
        dest='verbosity',
        action='count',
        help='print more diagnostic messages (option can be given multiple times)',
        default=0)

    parser.add_argument(
        '--r0',
        help="Use delays necessary for ESP32 revision 0 chips",
        action='store_true')

    args = parser.parse_args()

    if args.verbosity > 3:
        args.verbosity = 3
    level = (logging.WARNING,
             logging.INFO,
             logging.DEBUG,
             logging.NOTSET)[args.verbosity]
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger('root').setLevel(logging.INFO)
    logging.getLogger('rfc2217').setLevel(level)

    # connect to serial port
    ser = serial.serial_for_url(args.SERIALPORT, do_not_open=True)
    ser.timeout = 3     # required so that the reader thread can exit
    # reset control line as no _remote_ "terminal" has been connected yet
    ser.dtr = False
    ser.rts = False

    logging.info("RFC 2217 TCP/IP to Serial redirector - type Ctrl-C / BREAK to quit")

    try:
        ser.open()
    except serial.SerialException as e:
        logging.error("Could not open serial port {}: {}".format(ser.name, e))
        sys.exit(1)

    logging.info("Serving serial port: {}".format(ser.name))
    settings = ser.get_settings()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('', args.localport))
    srv.listen(1)
    logging.info("TCP/IP port: {}".format(args.localport))
    while True:
        try:
            client_socket, addr = srv.accept()
            logging.info('Connected by {}:{}'.format(addr[0], addr[1]))
            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            ser.rts = True
            ser.dtr = True
            # enter network <-> serial loop
            r = Redirector(
                ser,
                client_socket,
                args.verbosity > 0,
                args.r0)
            try:
                r.shortcircuit()
            finally:
                logging.info('Disconnected')
                r.stop()
                client_socket.close()
                ser.dtr = False
                ser.rts = False
                # Restore port settings (may have been changed by RFC 2217
                # capable client)
                ser.apply_settings(settings)
        except KeyboardInterrupt:
            sys.stdout.write('\n')
            break
        except socket.error as msg:
            logging.error(str(msg))

    logging.info('--- exit ---')
