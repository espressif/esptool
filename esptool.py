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
import math
import time

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

    ESP_BLOCK_MAX   = 0x1800

    def __init__(self, port = 0):
        self._port = serial.Serial(port, 115200, timeout=1)

    # Perform SLIP unescaping
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

    # Perform SLIP escaping
    def write(self, packet):
        buf = '\xc0'
        for b in packet:
            if b == '\xc0':
                buf += '\xdb\xdc'
            elif b == '\xdb':
                buf += '\xdb\xdd'
            else:
                buf += b
        buf += '\xc0'
        self._port.write(buf)

    def checksum(self, data):
        chk = 0xef
        for b in data:
            chk ^= ord(b)
        return chk

    def command(self, op = None, data = None, chk = 0):
        if op:
            # Construct and send request
            pkt = struct.pack('<BBHI', 0x00, op, len(data), chk) + data
            self.write(pkt)

        # Read header of response and parse
        if self._port.read(1) != '\xc0':
            raise Exception('Invalid head of packet')
        hdr = self.read(8)
        (resp, op_ret, len_ret, val) = struct.unpack('<BBHI', hdr)
        if resp != 0x01 or (op and op_ret != op):
            raise Exception('Invalid response')

        # The variable-length body
        body = self.read(len_ret)

        # Terminating byte
        if self._port.read(1) != chr(0xc0):
            raise Exception('Invalid end of packet')

        return val, body

    def sync(self):
        self.command(ESPROM.ESP_SYNC,
                '\x07\x07\x12\x20'+32*'\x55')
        for i in xrange(7):
            self.command()

    def read_reg(self, addr):
        res = self.command(ESPROM.ESP_READ_REG, struct.pack('<I', addr))
        return res[0]

    def write_reg(self, addr, value, mask, delay_us = 0):
        res = self.command(ESPROM.ESP_WRITE_REG,
                struct.pack('<IIII', addr, value, mask, delay_us))

    def mem_begin(self, size, blocks, blocksize, offset):
        if self.command(ESPROM.ESP_MEM_BEGIN,
                struct.pack('<IIII', size, blocks, blocksize, offset))[1] != "\0\0":
            raise Exception('Failed to enter RAM download mode')

    def mem_block(self, data, seq):
        if self.command(ESPROM.ESP_MEM_DATA,
                struct.pack('<IIII', len(data), seq,0,0)+data, self.checksum(data))[1] != "\0\0":
            raise Exception('Failed to write to target RAM')

    def mem_finish(self, entrypoint = 0):
        if self.command(ESPROM.ESP_MEM_END,
                struct.pack('<II', 1 if entrypoint == 0 else 0, entrypoint))[1] != "\0\0":
            raise Exception('Failed to start execution')

class ESPFirmwareImage:
    
    def __init__(self, filename):
        self.segments = []

        f = file(filename, 'rb')
        (magic, segments, _, _, self.entrypoint) = struct.unpack('<BBBBI', f.read(8))
        
        # some sanity check
        if magic != 0xe9 or segments > 16:
            raise Exception('Invalid firmware image')
    
        for i in xrange(segments):
            (offset, size) = struct.unpack('<II', f.read(8))
            if offset > 0x40200000 or offset < 0x3ffe0000 or size > 65536:
                raise Exception('Suspicious segment %x,%d' % (offset, size))
            self.segments.append((offset, size, f.read(size)))

if __name__ == '__main__':
    f = ESPFirmwareImage('wi07c.rom')

    esp = ESPROM('/dev/ttyUSB1')

    esp.sync()

    print 'RAM boot...'
    for (offset, size, data) in f.segments:
        print 'Downloading %d bytes at %08x...' % (size, offset)
        esp.mem_begin(size, math.ceil(size / float(esp.ESP_BLOCK_MAX)), esp.ESP_BLOCK_MAX, offset)

        seq = 0
        while len(data) > 0:
            esp.mem_block(data[0:esp.ESP_BLOCK_MAX], seq)
            data = data[esp.ESP_BLOCK_MAX:]
            print '%d' % seq
            seq += 1
        print 'done!'

    print 'Done, executing at %08x' % f.entrypoint
    esp.mem_finish(f.entrypoint)

    #f = file('iram1.bin','w')
    #print '%x' % esp.read_reg(0x40100000)
    #print '%x' % esp.read_reg(0x40100100)
    #esp.write_reg(0x40200000, 0xcafebabe, 0xffffffff)
    #print '%x' % esp.read_reg(0x40200000)
    #print '%x' % esp.read_reg(0x40200100)

    #for i in xrange(655364/4):
    #    d = esp.read_reg(0x40100000+(i*4))
    #    f.write(struct.pack('<I', d))
    #    if i % 1024 == 0:
    #        print i
    #    print '%08x: %08x' % (0x40240000+(i*4), esp.read_reg(0x40240000+(i*4)))
