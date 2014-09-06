#!/usr/bin/env python
#
# ESP8266 ROM Bootloader Utility
# Copyright (C) 2014 Fredrik Ahlberg
#
# 
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

import struct
import serial

class ESPROM:

    ESP_FLASH_BEGIN = 0x02
    ESP_FLASH_DATA  = 0x03
    ESP_FLASH_END   = 0x04
    ESP_MEM_BEGIN   = 0x05
    ESP_MEM_END     = 0x06
    ESP_MEM_DATA    = 0x07
    ESP_SYNC        = 0x08
    ESP_WRITE_REG   = 0x09
    ESP_READ_REG    = 0x0a

    def __init__(self, port = 0):
        self._port = serial.Serial(port, 115200)

    def read(self, length = 1):
        b = ''
        while len(b) < length:
            c = self._port.read(1)
            if c == '\xdb':
                c = self._port.read(1)
                if c == '\xdc':
                    b = b + '\xc0'
                elif c == '\xdd':
                    b = b + '\xdb'
                else:
                    raise Exception('Invalid SLIP escape')
            else:
                b = b + c
        return b

    def command(self, op, data, chk = 0):
        # Construct and send request
        pkt = struct.pack('<BBBHI', 0xc0, 0x00, op, len(data), chk) + data + chr(0xc0)
        self._port.write(pkt)

        # Read header of response and parse
        if self._port.read(1) != '\xc0':
            raise Exception('Invalid head of packet')
        hdr = self.read(8)
        (resp, op_ret, len_ret, val) = struct.unpack('<BBHI', hdr)
        if resp != 0x01 or op_ret != op:
            raise Exception('Invalid response')

        # The variable-length body
        body = self.read(len_ret)

        # Terminating byte
        if self._port.read(1) != chr(0xc0):
            raise Exception('Invalid end of packet')

        return val, body

    def read_reg(self, addr):
        res = self.command(ESPROM.ESP_READ_REG, struct.pack('<I', addr))
        return res[0]

    def write_reg(self, addr, value, mask, delay_us = 0):
        res = self.command(ESPROM.ESP_WRITE_REG,
                struct.pack('<IIII', addr, value, mask, delay_us))

if __name__ == '__main__':
    f = file('irom.bin','w')
    esp = ESPROM('/dev/ttyUSB1')
    print '%x' % esp.read_reg(0x40000000)
    print '%x' % esp.read_reg(0x40000100)
    esp.write_reg(0x40000000, 0xcafebabe, 0xffffffff)
    print '%x' % esp.read_reg(0x40000000)
    print '%x' % esp.read_reg(0x40000100)

    #for i in xrange(262144/4):
    #    d = esp.read_reg(0x40240000+(i*4))
    #    f.write(struct.pack('<I', d))
    #    if i % 1024 == 0:
    #        print i
    #    #print '%08x: %08x' % (0x40000000+(i*4), esp.read_reg(0x40000000+(i*4)))
