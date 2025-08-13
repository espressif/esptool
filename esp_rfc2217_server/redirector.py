# SPDX-FileCopyrightText: 2014-2024 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: BSD-3-Clause
import threading
import time
import logging

from esp_rfc2217_server.esp_port_manager import EspPortManager


class Redirector:
    def __init__(self, serial_instance, socket, debug=False, esp32r0delay=False):
        self.serial = serial_instance
        self.socket = socket
        self._write_lock = threading.Lock()
        self.rfc2217 = EspPortManager(
            self.serial,
            self,
            esp32r0delay,
            logger=logging.getLogger("rfc2217.server") if debug else None,
        )
        self.log = logging.getLogger("redirector")
        self.force_exit = False

    def statusline_poller(self):
        self.log.debug("status line poll thread started")
        while self.alive:
            time.sleep(1)
            self.rfc2217.check_modem_lines()
        self.log.debug("status line poll thread terminated")

    def shortcircuit(self):
        """connect the serial port to the TCP port by copying everything
        from one side to the other"""
        self.alive = True
        self.thread_read = threading.Thread(target=self.reader)
        self.thread_read.daemon = True
        self.thread_read.name = "serial->socket"
        self.thread_read.start()
        self.thread_poll = threading.Thread(target=self.statusline_poller)
        self.thread_poll.daemon = True
        self.thread_poll.name = "status line poll"
        self.thread_poll.start()
        self.writer()

    def reader(self):
        """loop forever and copy serial->socket"""
        self.log.debug("reader thread started")
        while self.alive:
            try:
                data = self.serial.read(self.serial.in_waiting or 1)
                if data:
                    # escape outgoing data when needed (Telnet IAC (0xff) character)
                    self.write(b"".join(self.rfc2217.escape(data)))
            except OSError as msg:
                self.log.error("{}".format(msg))
                # probably got disconnected
                break
        self.alive = False
        self.log.debug("reader thread terminated")

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
                self.serial.write(b"".join(self.rfc2217.filter(data)))
            except OSError as msg:
                self.log.error("{}".format(msg))
                # probably got disconnected
                break
        self.stop()

    def stop(self):
        """Stop copying"""
        self.log.debug("stopping")
        if self.alive:
            self.alive = False
            self.thread_read.join()
            self.thread_poll.join()
