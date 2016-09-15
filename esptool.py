#!/usr/bin/env python
# NB: Before sending a PR to change the above line to '#!/usr/bin/env python2', please read https://github.com/themadinventor/esptool/issues/21
#
# ESP8266 & ESP32 ROM Bootloader Utility
# https://github.com/themadinventor/esptool
#
# Copyright (C) 2014-2016 Fredrik Ahlberg, Angus Gratton, Espressif Systems (Shanghai) PTE LTD, other contributors as noted.
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

import argparse
import hashlib
import inspect
import os
import serial
import struct
import sys
import time
import base64
import zlib

__version__ = "2.0-dev"


MAX_UINT32 = 0xffffffff
MAX_UINT24 = 0xffffff


class ESPROM(object):
    """ Base class providing access to ESP ROM bootloader. Subclasses provide
    ESP8266 & ESP32 specific functionality.

    Don't instantiate this base class directly, either instantiate a subclass or
    call ESPROM.detect_chip() which will interrogate the chip and return the
    appropriate subclass instance.

    """
    CHIP_NAME = "Espressif device"

    DEFAULT_PORT = "/dev/ttyUSB0"

    # Commands supported by ESP8266 ROM bootloader
    ESP_FLASH_BEGIN = 0x02
    ESP_FLASH_DATA  = 0x03
    ESP_FLASH_END   = 0x04
    ESP_MEM_BEGIN   = 0x05
    ESP_MEM_END     = 0x06
    ESP_MEM_DATA    = 0x07
    ESP_SYNC        = 0x08
    ESP_WRITE_REG   = 0x09
    ESP_READ_REG    = 0x0a

    # Some comands supported by ESP32 ROM bootloader (or -8266 w/ stub)
    ESP_SPI_SET_PARAMS = 0x0B
    ESP_SPI_ATTACH     = 0x0D

    ESP_CHANGE_BAUDRATE = 0x0F
    ESP_FLASH_DEFL_BEGIN = 0x10
    ESP_FLASH_DEFL_DATA  = 0x11
    ESP_FLASH_DEFL_END   = 0x12
    ESP_SPI_FLASH_MD5    = 0x13

    # Some commands supported by stub only
    ESP_ERASE_FLASH = 0xD0
    ESP_ERASE_REGION = 0xD1
    ESP_READ_FLASH = 0xD2
    ESP_GET_FLASH_ID = 0xD3

    # Maximum block sized for RAM and Flash writes, respectively.
    ESP_RAM_BLOCK   = 0x1800
    ESP_FLASH_BLOCK = 0x400

    FLASH_WRITE_SIZE = ESP_FLASH_BLOCK

    # Default baudrate. The ROM auto-bauds, so we can use more or less whatever we want.
    ESP_ROM_BAUD    = 115200

    # First byte of the application image
    ESP_IMAGE_MAGIC = 0xe9

    # Initial state for the checksum routine
    ESP_CHECKSUM_MAGIC = 0xef

    # Flash sector size, minimum unit of erase.
    ESP_FLASH_SECTOR = 0x1000

    UART_DATA_REG_ADDR = 0x60000078

    # SPI peripheral "command" bitmasks
    SPI_CMD_READ_ID = 0x10000000

    # Memory addresses
    IROM_MAP_START = 0x40200000
    IROM_MAP_END = 0x40300000

    # The number of bytes in the response that signify command status
    STATUS_BYTES_LENGTH = 2

    def __init__(self, port=DEFAULT_PORT, baud=ESP_ROM_BAUD, do_connect=True):
        """Base constructor for ESPROM bootloader interaction

        Don't call this constructor, either instantiate ESP8266ROM
        or ESP32ROM, or use ESPROM.detect_chip().

        This base class has all of the instance methods for bootloader
        functionality supported across various chips & stub
        loaders. Subclasses replace the functions they don't support
        with ones which throw NotImplementedInROMError().

        """
        if isinstance(port, serial.Serial):
            self._port = port
        else:
            self._port = serial.Serial(port)
        self._slip_reader = slip_reader(self._port)
        # setting baud rate in a separate step is a workaround for
        # CH341 driver on some Linux versions (this opens at 9600 then
        # sets), shouldn't matter for other platforms/drivers. See
        # https://github.com/themadinventor/esptool/issues/44#issuecomment-107094446
        self._port.baudrate = baud
        if do_connect:
            self.connect()

    @staticmethod
    def detect_chip(port=DEFAULT_PORT, baud=ESP_ROM_BAUD):
        """Use serial access to detect the chip type.

        We use the UART's datecode register for this, it's mapped at
        the same address on ESP8266 & ESP32 so we can use one
        memory read and compare to the datecode register for each chip
        type.

        """
        detect_port = ESPROM(port, baud, True)
        sys.stdout.write('Detecting chip type... ')
        date_reg = detect_port.read_reg(ESPROM.UART_DATA_REG_ADDR)

        for cls in [ESP8266ROM, ESP32ROM]:
            if date_reg == cls.DATE_REG_VALUE:
                # don't connect a second time
                inst = cls(detect_port._port, baud, False)
                print '%s' % inst.CHIP_NAME
                return inst
        print ''
        raise FatalError("Unexpected UART datecode value 0x%08x. Failed to autodetect chip type." % date_reg)

    """ Read a SLIP packet from the serial port """
    def read(self):
        r = self._slip_reader.next()
        return r

    """ Write bytes to the serial port while performing SLIP escaping """
    def write(self, packet):
        buf = '\xc0' \
              + (packet.replace('\xdb','\xdb\xdd').replace('\xc0','\xdb\xdc')) \
              + '\xc0'
        self._port.write(buf)

    """ Calculate checksum of a blob, as it is defined by the ROM """
    @staticmethod
    def checksum(data, state=ESP_CHECKSUM_MAGIC):
        for b in data:
            state ^= ord(b)
        return state

    """ Send a request and read the response """
    def command(self, op=None, data="", chk=0):
        if op is not None:
            pkt = struct.pack('<BBHI', 0x00, op, len(data), chk) + data
            self.write(pkt)

        # tries to get a response until that response has the
        # same operation as the request or a retries limit has
        # exceeded. This is needed for some esp8266s that
        # reply with more sync responses than expected.
        for retry in xrange(100):
            p = self.read()
            if len(p) < 8:
                continue
            (resp, op_ret, len_ret, val) = struct.unpack('<BBHI', p[:8])
            if resp != 1:
                continue
            data = p[8:]
            if op is None or op_ret == op:
                return val, data

        raise FatalError("Response doesn't match request")

    def check_command(self, op_description, op=None, data="", chk=0):
        """
        Execute a command with 'command', check the result code and throw an appropriate
        FatalError if it fails.

        Returns the "result" of a successful command.
        """
        val, data = self.command(op, data, chk)

        # things are a bit weird here, bear with us

        # the status bytes are the last 2/4 bytes in the data (depending on chip)
        if len(data) < self.STATUS_BYTES_LENGTH:
            raise FatalError("Failed to %s. Only got %d byte status response." % (op_description, len(data)))
        status_bytes = data[-self.STATUS_BYTES_LENGTH:]
        # we only care if the first one is non-zero. If it is, the second byte is a reason.
        if status_bytes[0] != '\0':
            raise FatalError.WithResult('Failed to %s' % op_description, status_bytes)

        # if we had more data than just the status bytes, return it as the result
        # (this is used by the md5sum command, maybe other commands?)
        if len(data) > self.STATUS_BYTES_LENGTH:
            return data[:-self.STATUS_BYTES_LENGTH]
        else:  # otherwise, just return the 'val' field which comes from the reply header (this is used by read_reg)
            return val

    def flush_input(self):
        self._port.flushInput()
        self._slip_reader = slip_reader(self._port)

    def sync(self):
        """ Perform a connection test """
        self.command(ESPROM.ESP_SYNC, '\x07\x07\x12\x20' + 32 * '\x55')
        for i in xrange(7):
            self.command()

    def connect(self):
        """ Try connecting repeatedly until successful, or giving up """
        print 'Connecting...'

        for _ in xrange(4):
            # issue reset-to-bootloader:
            # RTS = either CH_PD or nRESET (both active low = chip in reset)
            # DTR = GPIO0 (active low = boot to flasher)
            self._port.setDTR(False)
            self._port.setRTS(True)
            time.sleep(0.05)
            self._port.setDTR(True)
            self._port.setRTS(False)
            time.sleep(0.05)
            self._port.setDTR(False)

            # worst-case latency timer should be 255ms (probably <20ms)
            self._port.timeout = 0.3
            last_exception = None
            for _ in xrange(4):
                try:
                    self.flush_input()
                    self._port.flushOutput()
                    self.sync()
                    self._port.timeout = 5
                    return
                except FatalError as e:
                    last_exception = e
                    time.sleep(0.05)
        raise FatalError('Failed to connect to %s: %s' % (self.CHIP_NAME, last_exception))

    """ Read memory address in target """
    def read_reg(self, addr):
        # we don't call check_command here because read_reg() function is called
        # when detecting chip type, and the way we check for success (STATUS_BYTES_LENGTH) is different
        # for different chip types (!)
        val, data = self.command(ESPROM.ESP_READ_REG, struct.pack('<I', addr))
        if data[0] != '\0':
            raise FatalError.WithResult("Failed to read register address %08x" % addr, data)
        return val

    """ Write to memory address in target """
    def write_reg(self, addr, value, mask=0xFFFFFFFF, delay_us=0):
        return self.check_command("write target memory", ESPROM.ESP_WRITE_REG,
                                  struct.pack('<IIII', addr, value, mask, delay_us))

    """ Start downloading an application image to RAM """
    def mem_begin(self, size, blocks, blocksize, offset):
        return self.check_command("enter RAM download mode", ESPROM.ESP_MEM_BEGIN,
                                  struct.pack('<IIII', size, blocks, blocksize, offset))

    """ Send a block of an image to RAM """
    def mem_block(self, data, seq):
        return self.check_command("write to target RAM", ESPROM.ESP_MEM_DATA,
                                  struct.pack('<IIII', len(data), seq, 0, 0) + data,
                                  ESPROM.checksum(data))

    """ Leave download mode and run the application """
    def mem_finish(self, entrypoint=0):
        return self.check_command("leave RAM download mode", ESPROM.ESP_MEM_END,
                                  struct.pack('<II', int(entrypoint == 0), entrypoint))

    """ Start downloading to Flash (performs an erase) """
    def flash_begin(self, size, offset):
        old_tmo = self._port.timeout
        num_blocks = (size + ESPROM.ESP_FLASH_BLOCK - 1) / ESPROM.ESP_FLASH_BLOCK
        erase_size = self.get_erase_size(offset, size)

        self._port.timeout = 20
        t = time.time()
        self.check_command("enter Flash download mode", ESPROM.ESP_FLASH_BEGIN,
                           struct.pack('<IIII', erase_size, num_blocks, ESPROM.ESP_FLASH_BLOCK, offset))
        if size != 0:
            print "Took %.2fs to erase flash block" % (time.time() - t)
        self._port.timeout = old_tmo

    """ Write block to flash """
    def flash_block(self, data, seq):
        self.check_command("write to target Flash after seq %d" % seq,
                           ESPROM.ESP_FLASH_DATA,
                           struct.pack('<IIII', len(data), seq, 0, 0) + data,
                           ESPROM.checksum(data))

    """ Leave flash mode and run/reboot """
    def flash_finish(self, reboot=False):
        pkt = struct.pack('<I', int(not reboot))
        self.check_command("leave Flash mode", ESPROM.ESP_FLASH_END, pkt)

    """ Run application code in flash """
    def run(self, reboot=False):
        # Fake flash begin immediately followed by flash end
        self.flash_begin(0, 0)
        self.flash_finish(reboot)

    """ Read SPI flash manufacturer and device id """
    def flash_id(self):
        resp = self.check_command("get flash id", ESPROM.ESP_GET_FLASH_ID)
        return struct.unpack('<I', resp)[0]

    def parse_flash_size_arg(self, arg):
        try:
            return self.FLASH_SIZES[arg]
        except KeyError:
            raise FatalError("Flash size '%s' is not supported by this chip type. Supported sizes: %s"
                             % (arg, ", ".join(self.FLASH_SIZES.keys())))

    """ Abuse the loader protocol to force flash to be left in write mode """
    def flash_unlock_dio(self):
        # Enable flash write mode
        self.flash_begin(0, 0)
        # Reset the chip rather than call flash_finish(), which would have
        # write protected the chip again (why oh why does it do that?!)
        self.mem_begin(0,0,0,0x40100000)
        self.mem_finish(0x40000080)

    def run_stub(self, stub=None):
        if stub is None:
            stub = self.STUB_CODE

        # Upload
        print "Uploading stub..."
        for field in ['text', 'data']:
            if field in stub:
                offs = stub[field + "_start"]
                length = len(stub[field])
                blocks = (length + self.ESP_RAM_BLOCK - 1) / self.ESP_RAM_BLOCK
                self.mem_begin(length, blocks, self.ESP_RAM_BLOCK, offs)
                for seq in range(blocks):
                    from_offs = seq * self.ESP_RAM_BLOCK
                    to_offs = from_offs + self.ESP_RAM_BLOCK
                    self.mem_block(stub[field][from_offs:to_offs], seq)
        print "Running stub..."
        self.mem_finish(stub['entry'])

        p = self.read()
        if p != 'OHAI':
            raise FatalError("Failed to start stub. Unexpected response: %s" % p)
        print "Stub running..."
        return self.STUB_CLASS(self)

    def flash_defl_begin(self, size, compsize, offset):
        """ Start downloading compressed data to Flash (performs an erase) """
        old_tmo = self._port.timeout
        num_blocks = (compsize + self.ESP_FLASH_BLOCK - 1) / self.ESP_FLASH_BLOCK
        erase_blocks = (size + self.ESP_FLASH_BLOCK - 1) / self.ESP_FLASH_BLOCK

        erase_size = size
        if erase_size > 0 and (offset + erase_size) >= (16 / 8) * 1024 * 1024:
            self.flash_spi_param_set()

        self._port.timeout = 20
        t = time.time()
        print "Unc size %d comp size %d comp blocks %d" % (size, compsize, num_blocks)
        self.check_command("enter compressed flash mode", self.ESP_FLASH_DEFL_BEGIN,
                           struct.pack('<IIII', erase_blocks * self.ESP_FLASH_BLOCK, num_blocks, self.ESP_FLASH_BLOCK, offset))
        if size != 0:
            print "Took %.2fs to erase flash block" % (time.time() - t)
        self._port.timeout = old_tmo

    """ Write block to flash, send compressed """
    def flash_defl_block(self, data, seq):
        self.check_command("write compressed data to flash after seq %d" % seq,
                           self.ESP_FLASH_DEFL_DATA, struct.pack('<IIII', len(data), seq, 0, 0) + data, ESPROM.checksum(data))

    """ Leave compressed flash mode and run/reboot """
    def flash_defl_finish(self, reboot=False):
        pkt = struct.pack('<I', int(not reboot))
        self.check_command("leave compressed flash mode", self.ESP_FLASH_DEFL_END, pkt)
        self.in_bootloader = False

    def flash_md5sum(self, addr, size):
        # the MD5 command returns additional bytes in the standard
        # command reply slot
        res = self.check_command('calculate md5sum', self.ESP_SPI_FLASH_MD5, struct.pack('<IIII', addr, size, 0, 0))

        if len(res) == 32:
            return res  # already hex formatted
        elif len(res) == 16:
            return hexify(res).lower()
        else:
            raise FatalError("MD5Sum command returned unexpected result: %r" % res)

    def change_baud(self, baud):
        print "Changing baud rate to %d" % baud
        self.command(self.ESP_CHANGE_BAUDRATE, struct.pack('<II', baud, 0))
        print "Changed."
        self._port.baudrate = baud
        time.sleep(0.05)  # get rid of crap sent during baud rate change
        self.flush_input()

    def erase_flash(self):
        oldtimeout = self._port.timeout
        # depending on flash chip model the erase may take this long (maybe longer!)
        self._port.timeout = 128
        try:
            self.check_command("erase flash", self.ESP_ERASE_FLASH)
        finally:
            self._port.timeout = oldtimeout

    def erase_region(self, offset, size):
        if offset % ESPROM.ESP_FLASH_SECTOR != 0:
            raise FatalError("Offset to erase from must be a multiple of 4096")
        if size % ESPROM.ESP_FLASH_SECTOR != 0:
            raise FatalError("Size of data to erase must be a multiple of 4096")
        self.check_command("erase region", self.ESP_ERASE_REGION, struct.pack('<II', offset, size))

    def read_flash(self, offset, length, progress_fn=None):
        # issue a standard bootloader command to trigger the read
        self.check_command("read flash", self.ESP_READ_FLASH,
                           struct.pack('<IIII',
                                       offset,
                                       length,
                                       self.ESP_FLASH_BLOCK,
                                       64))
        # now we expect (length / block_size) SLIP frames with the data
        data = ''
        while len(data) < length:
            p = self.read()
            data += p
            print "Read %d bytes total %d" % (len(p), len(data))
            self.write(struct.pack('<I', len(data)))
            if progress_fn and (len(data) % 1024 == 0 or len(data) == length):
                progress_fn(len(data), length)
        if progress_fn:
            progress_fn(len(data), length)
        if len(data) > length:
            raise FatalError('Read more than expected')
        digest_frame = self.read()
        if len(digest_frame) != 16:
            raise FatalError('Expected digest, got: %s' % hexify(digest_frame))
        expected_digest = hexify(digest_frame).upper()
        digest = hashlib.md5(data).hexdigest().upper()
        if digest != expected_digest:
            raise FatalError('Digest mismatch: expected %s, got %s' % (expected_digest, digest))
        return data

    def flash_spi_attach(self,is_hspi,is_legacy):
        """Send SPI attach command to enable the SPI flash pins

        ESP8266 ROM does this when you send flash_begin, ESP32 ROM
        has it as a SPI command.
        """
        # last 3 bytes in ESP_SPI_ATTACH argument are reserved values
        arg = struct.pack('<IBBBB', 1 if is_hspi else 0, 1 if is_legacy else 0, 0, 0, 0)
        self.check_command("configure SPI flash pins", ESP32ROM.ESP_SPI_ATTACH, arg)

    def flash_set_parameters(self, size):
        """Tell the ESP bootloader the parameters of the chip

        Corresponds to the "flashchip" data structure that the ROM
        has in RAM.

        'size' is in bytes.

        All other flash parameters are currently hardcoded (on ESP8266
        these are mostly ignored by ROM code, on ESP32 I'm not sure.)
        """
        fl_id = 0
        total_size = size
        block_size = 64 * 1024
        sector_size = 4 * 1024
        page_size = 256
        status_mask = 0xffff
        self.check_command("set SPI params", ESP32ROM.ESP_SPI_SET_PARAMS,
                           struct.pack('<IIIIII', fl_id, total_size, block_size, sector_size, page_size, status_mask))


class ESP8266ROM(ESPROM):
    """ Access class for ESP8266 ROM bootloader
    """
    CHIP_NAME = "ESP8266EX"

    DATE_REG_VALUE = 0x00062000

    # OTP ROM addresses
    ESP_OTP_MAC0    = 0x3ff00050
    ESP_OTP_MAC1    = 0x3ff00054
    ESP_OTP_MAC3    = 0x3ff0005c

    SPI_CMD_REG_ADDR = 0x60000200
    SPI_W0_REG_ADDR = 0x60000240

    FLASH_SIZES = {
        '512KB':0x00,
        '256KB':0x10,
        '1MB':0x20,
        '2MB':0x30,
        '4MB':0x40,
        '2MB-c1': 0x50,
        '4MB-c1':0x60,
        '4MB-c2':0x70}

    def change_baud(self, baud):
        if baud != self._port.baud:
            raise NotImplementedInROMError(self)

    def flash_defl_begin(self, size, compsize, offset):
        raise NotImplementedInROMError(self)

    def flash_defl_block(self, data, seq):
        raise NotImplementedInROMError(self)

    def flash_defl_finish(self, reboot=False):
        raise NotImplementedInROMError(self)

    def flash_md5sum(self, addr, size):
        raise NotImplementedInROMError(self)

    def flash_id(self):
        raise NotImplementedInROMError(self)

    def erase_flash(self):
        raise NotImplementedInROMError(self)

    def erase_region(self):
        raise NotImplementedInROMError(self)

    def read_flash(self, *args):
        raise NotImplementedInROMError(self)

    def flash_spi_attach(self, is_spi, is_legacy):
        pass  # not implemented in ROM, but OK to silently skip

    def flash_set_parameters(self, size):
        pass  # not implemented in ROM, but OK to silently skip

    def chip_id(self):
        """ Read Chip ID from OTP ROM - see http://esp8266-re.foogod.com/wiki/System_get_chip_id_%28IoT_RTOS_SDK_0.9.9%29 """
        id0 = self.read_reg(self.ESP_OTP_MAC0)
        id1 = self.read_reg(self.ESP_OTP_MAC1)
        return (id0 >> 24) | ((id1 & MAX_UINT24) << 8)

    def read_mac(self):
        """ Read MAC from OTP ROM """
        mac0 = self.read_reg(self.ESP_OTP_MAC0)
        mac1 = self.read_reg(self.ESP_OTP_MAC1)
        mac3 = self.read_reg(self.ESP_OTP_MAC3)
        if (mac3 != 0):
            oui = ((mac3 >> 16) & 0xff, (mac3 >> 8) & 0xff, mac3 & 0xff)
        elif ((mac1 >> 16) & 0xff) == 0:
            oui = (0x18, 0xfe, 0x34)
        elif ((mac1 >> 16) & 0xff) == 1:
            oui = (0xac, 0xd0, 0x74)
        else:
            raise FatalError("Unknown OUI")
        return oui + ((mac1 >> 8) & 0xff, mac1 & 0xff, (mac0 >> 24) & 0xff)

    def get_erase_size(self, offset, size):
        """ Calculate an erase size given a specific size in bytes.

        Provides a workaround for the bootloader erase bug."""

        sectors_per_block = 16
        sector_size = self.ESP_FLASH_SECTOR
        num_sectors = (size + sector_size - 1) / sector_size
        start_sector = offset / sector_size

        head_sectors = sectors_per_block - (start_sector % sectors_per_block)
        if num_sectors < head_sectors:
            head_sectors = num_sectors

        if num_sectors < 2 * head_sectors:
            return (num_sectors + 1) / 2 * sector_size
        else:
            return (num_sectors - head_sectors) * sector_size


class ESP8266StubLoader(ESP8266ROM):
    """ Access class for ESP8266 stub loader, runs on top of ROM.
    """
    FLASH_WRITE_SIZE = 8192  # matches MAX_WRITE_BLOCK in stub_loader.c

    def __init__(self, rom_loader):
        self._port = rom_loader._port
        self.flush_input()  # resets _slip_reader

    def change_baud(self, baud):
        return ESPROM.change_baud(self, baud)

    def flash_defl_begin(self, size, compsize, offset):
        return ESPROM.flash_defl_begin(self, size, compsize, offset)

    def flash_defl_block(self, data, seq):
        return ESPROM.flash_defl_block(self, data, seq)

    def flash_defl_finish(self, reboot=False):
        return ESPROM.flash_defl_finish(self, reboot)

    def flash_md5sum(self, addr, size):
        return ESPROM.flash_md5sum(self, addr, size)

    def flash_id(self):
        return ESPROM.flash_id(self)

    def erase_flash(self):
        return ESPROM.erase_flash(self)

    def erase_region(self, offset, size):
        return ESPROM.erase_region(self, offset, size)

    def read_flash(self, *args):
        return ESPROM.read_flash(self, *args)

ESP8266ROM.STUB_CLASS = ESP8266StubLoader


class ESP32ROM(ESPROM):
    """Access class for ESP32 ROM bootloader

    """
    CHIP_NAME = "ESP32"

    DATE_REG_VALUE = 0x15122500

    IROM_MAP_START = 0x400d0000
    IROM_MAP_END   = 0x40400000
    DROM_MAP_START = 0x3F400000
    DROM_MAP_END   = 0x3F700000

    # ESP32 uses a 4 byte status reply
    STATUS_BYTES_LENGTH = 4

    SPI_CMD_REG_ADDR = 0x60003000
    SPI_W0_REG_ADDR = 0x60003040

    EFUSE_BASE = 0x6001a000

    FLASH_SIZES = {
        '1MB':0x00,
        '2MB':0x10,
        '4MB':0x20,
        '8MB':0x30,
        '16MB':0x40
    }

    def read_efuse(self, n):
        """ Read the nth word of the ESP3x EFUSE region. """
        return self.read_reg(self.EFUSE_BASE + (4 * n))

    def chip_id(self):
        word16 = self.read_efuse(16)
        word17 = self.read_efuse(17)
        return ((word17 & MAX_UINT24) << 24) | (word16 >> 8) & MAX_UINT24

    def read_mac(self):
        """ Read MAC from EFUSE region """
        word16 = self.read_efuse(16)
        word17 = self.read_efuse(17)
        word18 = self.read_efuse(18)
        word19 = self.read_efuse(19)
        wifi_mac = (((word17 >> 16) & 0xff), ((word17 >> 8) & 0xff), ((word17 >> 0) & 0xff),
                    ((word16 >> 24) & 0xff), ((word16 >> 16) & 0xff), ((word16 >> 8) & 0xff))
        bt_mac = (((word19 >> 16) & 0xff), ((word19 >> 8) & 0xff), ((word19 >> 0) & 0xff),
                  ((word18 >> 24) & 0xff), ((word18 >> 16) & 0xff), ((word18 >> 8) & 0xff))
        return (wifi_mac,bt_mac)

    def get_erase_size(self, offset, size):
        return size

    def erase_flash(self):
        raise NotImplementedInROMError(self)

    def erase_region(self):
        raise NotImplementedInROMError(self)

    def flash_id(self):
        raise NotImplementedInROMError(self)


class ESP32StubLoader(ESP32ROM):
    """ Access class for ESP32 stub loader, runs on top of ROM.
    """
    FLASH_WRITE_SIZE = 8192  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM

    def __init__(self, rom_loader):
        self._port = rom_loader._port
        self.flush_input()  # resets _slip_reader

    def change_baud(self, baud):
        return ESPROM.change_baud(self, baud)

    def flash_md5sum(self, addr, size):
        return ESPROM.flash_md5sum(self, addr, size)

    def flash_id(self):
        return ESPROM.flash_id(self)

    def erase_flash(self):
        return ESPROM.erase_flash(self)

    def erase_region(self, offset, size):
        return ESPROM.erase_region(self, offset, size)

    def read_flash(self, *args):
        return ESPROM.read_flash(self, *args)

ESP32ROM.STUB_CLASS = ESP32StubLoader


class ESPBOOTLOADER(object):
    """ These are constants related to software ESP bootloader, working with 'v2' image files """

    # First byte of the "v2" application image
    IMAGE_V2_MAGIC = 0xea

    # First 'segment' value in a "v2" application image, appears to be a constant version value?
    IMAGE_V2_SEGMENT = 4


def LoadFirmwareImage(chip, filename):
    """ Load a firmware image. Can be for ESP8266 or ESP32. ESP8266 images will be examined to determine if they are
        original ROM firmware images (ESPFirmwareImage) or "v2" OTA bootloader images.

        Returns a BaseFirmwareImage subclass, either ESPFirmwareImage (v1) or OTAFirmwareImage (v2).
    """
    with open(filename, 'rb') as f:
        if chip == 'esp32':
            return ESP32FirmwareImage(f)
        else:  # Otherwise, ESP8266 so look at magic to determine the image type
            magic = ord(f.read(1))
            f.seek(0)
            if magic == ESPROM.ESP_IMAGE_MAGIC:
                return ESPFirmwareImage(f)
            elif magic == ESPBOOTLOADER.IMAGE_V2_MAGIC:
                return OTAFirmwareImage(f)
            else:
                raise FatalError("Invalid image magic number: %d" % magic)


class ImageSegment(object):
    """ Wrapper class for a segment in an ESP image
    (very similar to a section in an ELFImage also) """
    def __init__(self, addr, data, file_offs=None):
        self.addr = addr
        # pad all ImageSegments to at least 4 bytes length
        pad_mod = len(data) % 4
        if pad_mod != 0:
            data += "\x00" * (4 - pad_mod)
        self.data = data
        self.file_offs = file_offs

    def copy_with_new_addr(self, new_addr):
        """ Return a new ImageSegment with same data, but mapped at
        a new address. """
        return ImageSegment(new_addr, self.data, 0)

    def __repr__(self):
        r = "len 0x%05x load 0x%08x" % (len(self.data), self.addr)
        if self.file_offs is not None:
            r += " file_offs 0x%08x" % (self.file_offs)
        return r


class ELFSection(ImageSegment):
    """ Wrapper class for a section in an ELF image, has a section
    name as well as the common properties of an ImageSegment. """
    def __init__(self, name, addr, data):
        super(ELFSection, self).__init__(addr, data)
        self.name = name

    def __repr__(self):
        return "%s %s" % (self.name, super(ELFSection, self).__repr__())


class BaseFirmwareImage(object):
    SEG_HEADER_LEN = 8

    """ Base class with common firmware image functions """
    def __init__(self):
        self.segments = []
        self.entrypoint = 0

    def load_common_header(self, load_file, expected_magic):
            (magic, segments, self.flash_mode, self.flash_size_freq, self.entrypoint) = struct.unpack('<BBBBI', load_file.read(8))

            if magic != expected_magic or segments > 16:
                raise FatalError('Invalid firmware image magic=%d segments=%d' % (magic, segments))
            return segments

    def load_segment(self, f, is_irom_segment=False):
        """ Load the next segment from the image file """
        file_offs = f.tell()
        (offset, size) = struct.unpack('<II', f.read(8))
        if not is_irom_segment:
            if offset > 0x40200000 or offset < 0x3ffe0000 or size > 65536:
                print('WARNING: Suspicious segment 0x%x, length %d' % (offset, size))
        segment_data = f.read(size)
        if len(segment_data) < size:
            raise FatalError('End of file reading segment 0x%x, length %d (actual length %d)' % (offset, size, len(segment_data)))
        segment = ImageSegment(offset, segment_data, file_offs)
        self.segments.append(segment)
        return segment

    def save_segment(self, f, segment, checksum=None):
        """ Save the next segment to the image file, return next checksum value if provided """
        f.write(struct.pack('<II', segment.addr, len(segment.data)))
        f.write(segment.data)
        if checksum is not None:
            return ESPROM.checksum(segment.data, checksum)

    def read_checksum(self, f):
        """ Return ESPROM checksum from end of just-read image """
        # Skip the padding. The checksum is stored in the last byte so that the
        # file is a multiple of 16 bytes.
        align_file_position(f, 16)
        return ord(f.read(1))

    def append_checksum(self, f, checksum):
        """ Append ESPROM checksum to the just-written image """
        align_file_position(f, 16)
        f.write(struct.pack('B', checksum))

    def write_common_header(self, f, segments):
        f.write(struct.pack('<BBBBI', ESPROM.ESP_IMAGE_MAGIC, len(segments),
                            self.flash_mode, self.flash_size_freq, self.entrypoint))

    def is_irom_addr(self, addr):
        """ Returns True if an address starts in the irom region.
        Valid for ESP8266 only.
        """
        return ESPROM.IROM_MAP_START <= addr < ESPROM.IROM_MAP_END

    def get_irom_segment(self):
            irom_segments = [s for s in self.segments if self.is_irom_addr(s.addr)]
            if len(irom_segments) > 0:
                if len(irom_segments) != 1:
                    raise FatalError('Found %d segments that could be irom0. Bad ELF file?' % len(irom_segments))
                return irom_segments[0]
            return None

    def get_non_irom_segments(self):
        irom_segment = self.get_irom_segment()
        return [s for s in self.segments if s != irom_segment]


class ESPFirmwareImage(BaseFirmwareImage):
    """ 'Version 1' firmware image, segments loaded directly by the ROM bootloader. """
    def __init__(self, load_file=None):
        super(ESPFirmwareImage, self).__init__()
        self.flash_mode = 0
        self.flash_size_freq = 0
        self.version = 1

        if load_file is not None:
            segments = self.load_common_header(load_file, ESPROM.ESP_IMAGE_MAGIC)

            for _ in xrange(segments):
                self.load_segment(load_file)
            self.checksum = self.read_checksum(load_file)

    def default_output_name(self, input_file):
        """ Derive a default output name from the ELF name. """
        return input_file + '-'

    def save(self, basename):
        """ Save a set of V1 images for flashing. Parameter is a base filename. """
        # IROM data goes in its own plain binary file
        irom_segment = self.get_irom_segment()
        if irom_segment is not None:
            with open("%s0x%05x.bin" % (basename, irom_segment.addr), "wb") as f:
                f.write(irom_segment.data)

        # everything but IROM goes at 0x00000 in an image file
        normal_segments = self.get_non_irom_segments()
        with open("%s0x00000.bin" % basename, 'wb') as f:
            self.write_common_header(f, normal_segments)
            checksum = ESPROM.ESP_CHECKSUM_MAGIC
            for segment in self.segments:
                checksum = self.save_segment(f, segment, checksum)
            self.append_checksum(f, checksum)


class OTAFirmwareImage(BaseFirmwareImage):
    """ 'Version 2' firmware image, segments loaded by software bootloader stub
        (ie Espressif bootloader or rboot)
    """
    def __init__(self, load_file=None):
        super(OTAFirmwareImage, self).__init__()
        self.version = 2
        if load_file is not None:
            segments = self.load_common_header(load_file, ESPBOOTLOADER.IMAGE_V2_MAGIC)
            if segments != ESPBOOTLOADER.IMAGE_V2_SEGMENT:
                # segment count is not really segment count here, but we expect to see '4'
                print 'Warning: V2 header has unexpected "segment" count %d (usually 4)' % segments

            # irom segment comes before the second header
            #
            # the file is saved in the image with a zero load address
            # in the header, so we need to calculate a load address
            irom_offs = load_file.tell()
            irom_segment = self.load_segment(load_file, True)
            irom_segment.addr = irom_offs + ESPROM.IROM_MAP_START

            first_flash_mode = self.flash_mode
            first_flash_size_freq = self.flash_size_freq
            first_entrypoint = self.entrypoint
            # load the second header
            self.load_common_header(load_file, ESPROM.ESP_IMAGE_MAGIC)
            (magic, segments, self.flash_mode, self.flash_size_freq, self.entrypoint) = struct.unpack('<BBBBI', load_file.read(8))

            if first_flash_mode != self.flash_mode:
                print('WARNING: Flash mode value in first header (0x%02x) disagrees with second (0x%02x). Using second value.'
                      % (first_flash_mode, self.flash_mode))
            if first_flash_size_freq != self.flash_size_freq:
                print('WARNING: Flash size/freq value in first header (0x%02x) disagrees with second (0x%02x). Using second value.'
                      % (first_flash_size_freq, self.flash_size_freq))
            if first_entrypoint != self.entrypoint:
                print('WARNING: Entrypoint address in first header (0x%08x) disagrees with second header (0x%08x). Using second value.'
                      % (first_entrypoint, self.entrypoint))

            # load all the usual segments
            for _ in xrange(segments):
                self.load_segment(load_file)
            self.checksum = self.read_checksum(load_file)

    def default_output_name(self, input_file):
        """ Derive a default output name from the ELF name. """
        irom_segment = self.get_irom_segment()
        if irom_segment is not None:
            irom_offs = irom_segment.addr - ESPROM.IROM_MAP_START
        else:
            irom_offs = 0
        return "%s-0x%05x.bin" % (os.path.splitext(input_file)[0],
                                  irom_offs & ~(ESPROM.ESP_FLASH_SECTOR - 1))

    def save(self, filename):
        with open(filename, 'wb') as f:
            # Save first header for irom0 segment
            f.write(struct.pack('<BBBBI', ESPBOOTLOADER.IMAGE_V2_MAGIC, ESPBOOTLOADER.IMAGE_V2_SEGMENT,
                                self.flash_mode, self.flash_size_freq, self.entrypoint))

            irom_segment = self.get_irom_segment()
            if irom_segment is not None:
                # save irom0 segment, make sure it has load addr 0 in the file
                irom_segment = irom_segment.copy_with_new_addr(0)
                self.save_segment(f, irom_segment)

            # second header, matches V1 header and contains loadable segments
            normal_segments = self.get_non_irom_segments()
            self.write_common_header(f, normal_segments)
            checksum = ESPROM.ESP_CHECKSUM_MAGIC
            for segment in normal_segments:
                checksum = self.save_segment(f, segment, checksum)
            self.append_checksum(f, checksum)


class ESP32FirmwareImage(BaseFirmwareImage):
    """ ESP32 firmware image is very similar to V1 ESP8266 image,
    except with an additional 16 byte reserved header at top of image,
    and because of new flash mapping capabilities the flash-mapped regions
    can be placed in the normal image (just @ 64kB padded offsets).
    """
    def __init__(self, load_file=None):
        super(ESP32FirmwareImage, self).__init__()
        self.flash_mode = 0
        self.flash_size_freq = 0
        self.version = 1
        self.additional_header = '\x00' * 16

        if load_file is not None:
            segments = self.load_common_header(load_file, ESPROM.ESP_IMAGE_MAGIC)
            self.additional_header = load_file.read(16)

            for i in xrange(segments):
                self.load_segment(load_file)
            self.checksum = self.read_checksum(load_file)

    def is_flash_addr(self, addr):
        return (ESP32ROM.IROM_MAP_START <= addr < ESP32ROM.IROM_MAP_END) \
            or (ESP32ROM.DROM_MAP_START <= addr < ESP32ROM.DROM_MAP_END)

    def default_output_name(self, input_file):
        """ Derive a default output name from the ELF name. """
        return "%s.bin" % (os.path.splitext(input_file)[0])

    def save(self, filename):
        padding_segments = 0
        with open(filename, 'wb') as f:
            self.write_common_header(f, self.segments)
            f.write(self.additional_header)

            checksum = ESPROM.ESP_CHECKSUM_MAGIC
            last_addr = None
            for segment in sorted(self.segments, key=lambda s:s.addr):
                # IROM/DROM segment flash mappings need to align on
                # 64kB boundaries.
                #
                # TODO: intelligently order segments to reduce wastage
                # by squeezing smaller DRAM/IRAM segments into the
                # 64kB padding space.
                IROM_ALIGN = 65536

                # check for multiple ELF sections that live in the same flash mapping region.
                # this is usually a sign of a broken linker script, but if you have a legitimate
                # use case then let us know (we can merge segments here, but as a rule you probably
                # want to merge them in your linker script.)
                if last_addr is not None and self.is_flash_addr(last_addr) \
                   and self.is_flash_addr(segment.addr) and segment.addr // IROM_ALIGN == last_addr // IROM_ALIGN:
                    raise FatalError(("Segment loaded at 0x%08x lands in same 64KB flash mapping as segment loaded at 0x%08x. " +
                                     "Can't generate binary. Suggest changing linker script or ELF to merge sections.") %
                                     (segment.addr, last_addr))
                last_addr = segment.addr

                if self.is_flash_addr(segment.addr):
                    # Actual alignment required for the segment header: positioned so that
                    # after we write the next 8 byte header, file_offs % IROM_ALIGN == segment.addr % IROM_ALIGN
                    #
                    # (this is because the segment's vaddr may not be IROM_ALIGNed, more likely is aligned
                    # IROM_ALIGN+0x10 to account for longest possible header.
                    align_past = (segment.addr % IROM_ALIGN) - self.SEG_HEADER_LEN
                    assert (align_past + self.SEG_HEADER_LEN) == (segment.addr % IROM_ALIGN)

                    # subtract SEG_HEADER_LEN a second time, as the padding block has a header as well
                    pad_len = (IROM_ALIGN - (f.tell() % IROM_ALIGN)) + align_past - self.SEG_HEADER_LEN
                    if pad_len < 0:
                        pad_len += IROM_ALIGN
                    if pad_len > 0:
                        null = ImageSegment(0, '\x00' * pad_len, f.tell())
                        checksum = self.save_segment(f, null, checksum)
                        padding_segments += 1
                    # verify that after the 8 byte header is added, were are at the correct offset relative to the segment's vaddr
                    assert (f.tell() + 8) % IROM_ALIGN == segment.addr % IROM_ALIGN
                checksum = self.save_segment(f, segment, checksum)
            self.append_checksum(f, checksum)
            # kinda hacky: go back to the initial header and write the new segment count
            # that includes padding segments. Luckily(?) this header is not checksummed
            f.seek(1)
            f.write(chr(len(self.segments) + padding_segments))


class ELFFile(object):
    SEC_TYPE_PROGBITS = 0x01
    SEC_TYPE_STRTAB = 0x03

    def __init__(self, name):
        # Load sections from the ELF file
        self.name = name
        with open(self.name, 'rb') as f:
            self._read_elf_file(f)

    def get_section(self, section_name):
        for s in self.sections:
            if s.name == section_name:
                return s
        raise ValueError("No section %s in ELF file" % section_name)

    def _read_elf_file(self, f):
        # read the ELF file header
        LEN_FILE_HEADER = 0x34
        try:
            (ident,_type,machine,_version,
             self.entrypoint,_phoff,shoff,_flags,
             _ehsize, _phentsize,_phnum,_shentsize,
             _shnum,shstrndx) = struct.unpack("<16sHHLLLLLHHHHHH", f.read(LEN_FILE_HEADER))
        except struct.error as e:
            raise FatalError("Failed to read a valid ELF header from %s: %s" % (self.name, e))

        if ident[0] != '\x7f' or ident[1:4] != 'ELF':
            raise FatalError("%s has invalid ELF magic header" % self.name)
        if machine != 0x5e:
            raise FatalError("%s does not appear to be an Xtensa ELF file. e_machine=%04x" % (self.name, machine))
        self._read_sections(f, shoff, shstrndx)

    def _read_sections(self, f, section_header_offs, shstrndx):
        f.seek(section_header_offs)
        section_header = f.read()
        LEN_SEC_HEADER = 0x28
        if len(section_header) == 0:
            raise FatalError("No section header found at offset %04x in ELF file." % section_header_offs)
        if len(section_header) % LEN_SEC_HEADER != 0:
            print 'WARNING: Unexpected ELF section header length %04x is not mod-%02x' % (len(section_header),LEN_SEC_HEADER)

        # walk through the section header and extract all sections
        section_header_offsets = range(0, len(section_header), LEN_SEC_HEADER)

        def read_section_header(offs):
            name_offs,sec_type,_flags,lma,sec_offs,size = struct.unpack_from("<LLLLLL", section_header[offs:])
            return (name_offs, sec_type, lma, size, sec_offs)
        all_sections = [read_section_header(offs) for offs in section_header_offsets]
        prog_sections = [s for s in all_sections if s[1] == ELFFile.SEC_TYPE_PROGBITS]

        # search for the string table section
        if not shstrndx * LEN_SEC_HEADER in section_header_offsets:
            raise FatalError("ELF file has no STRTAB section at shstrndx %d" % shstrndx)
        _,sec_type,_,sec_size,sec_offs = read_section_header(shstrndx * LEN_SEC_HEADER)
        if sec_type != ELFFile.SEC_TYPE_STRTAB:
            print 'WARNING: ELF file has incorrect STRTAB section type 0x%02x' % sec_type
        f.seek(sec_offs)
        string_table = f.read(sec_size)

        # build the real list of ELFSections by reading the actual section names from the
        # string table section, and actual data for each section from the ELF file itself
        def lookup_string(offs):
            raw = string_table[offs:]
            return raw[:raw.index('\x00')]

        def read_data(offs,size):
            f.seek(offs)
            return f.read(size)

        prog_sections = [ELFSection(lookup_string(n_offs), lma, read_data(offs, size)) for (n_offs, _type, lma, size, offs) in prog_sections
                         if lma != 0]
        self.sections = prog_sections


def slip_reader(port):
    """Generator to read SLIP packets from a serial port.
    Yields one full SLIP packet at a time, raises exception on timeout or invalid data.

    Designed to avoid too many calls to serial.read(1), which can bog
    down on slow systems.
    """
    partial_packet = None
    in_escape = False
    while True:
        waiting = port.inWaiting()
        read_bytes = port.read(1 if waiting == 0 else waiting)
        if read_bytes == '':
            raise FatalError("Timed out waiting for packet %s" % ("header" if partial_packet is None else "content"))
        for b in read_bytes:
            if partial_packet is None:  # waiting for packet header
                if b == '\xc0':
                    partial_packet = ""
                else:
                    raise FatalError('Invalid head of packet (%r)' % b)
            elif in_escape:  # part-way through escape sequence
                in_escape = False
                if b == '\xdc':
                    partial_packet += '\xc0'
                elif b == '\xdd':
                    partial_packet += '\xdb'
                else:
                    raise FatalError('Invalid SLIP escape (%r%r)' % ('\xdb', b))
            elif b == '\xdb':  # start of escape sequence
                in_escape = True
            elif b == '\xc0':  # end of packet
                yield partial_packet
                partial_packet = None
            else:  # normal byte in packet
                partial_packet += b


def arg_auto_int(x):
    return int(x, 0)


def div_roundup(a, b):
    """ Return a/b rounded up to nearest integer,
    equivalent result to int(math.ceil(float(int(a)) / float(int(b))), only
    without possible floating point accuracy errors.
    """
    return (int(a) + int(b) - 1) / int(b)


def align_file_position(f, size):
    """ Align the position in the file to the next block of specified size """
    align = (size - 1) - (f.tell() % size)
    f.seek(align, 1)


def flash_size_bytes(size):
    """ Given a flash size of the type passed in args.flash_size
    (ie 512KB or 1MB) then return the size in bytes.
    """
    if "MB" in size:
        return int(size[:size.index("MB")]) * 1024 * 1024
    elif "KB" in size:
        return int(size[:size.index("KB")]) * 1024
    else:
        raise FatalError("Unknown size %s" % size)


def hexify(s):
    return ''.join('%02X' % ord(c) for c in s)


def unhexify(hs):
    s = ''
    for i in range(0, len(hs) - 1, 2):
        s += chr(int(hs[i] + hs[i + 1], 16))
    return s


class FatalError(RuntimeError):
    """
    Wrapper class for runtime errors that aren't caused by internal bugs, but by
    ESP8266 responses or input content.
    """
    def __init__(self, message):
        RuntimeError.__init__(self, message)

    @staticmethod
    def WithResult(message, result):
        """
        Return a fatal error object that appends the hex values of
        'result' as a string formatted argument.
        """
        message += " (result was %s)" % ", ".join(hex(ord(x)) for x in result)
        return FatalError(message)


class NotImplementedInROMError(FatalError):
    """
    Wrapper class for the error thrown when a particular ESP bootloader function
    is not implemented in the ROM bootloader.
    """
    def __init__(self, bootloader):
        FatalError.__init__(self, "%s ROM does not support this function." % bootloader.CHIP_NAME)

# "Operation" commands, executable at command line. One function each
#
# Each function takes either two args (<ESPROM instance>, <args>) or a single <args>
# argument.


def load_ram(esp, args):
    image = LoadFirmwareImage(esp, args.filename)

    print 'RAM boot...'
    for (offset, size, data) in image.segments:
        print 'Downloading %d bytes at %08x...' % (size, offset),
        sys.stdout.flush()
        esp.mem_begin(size, div_roundup(size, esp.ESP_RAM_BLOCK), esp.ESP_RAM_BLOCK, offset)

        seq = 0
        while len(data) > 0:
            esp.mem_block(data[0:esp.ESP_RAM_BLOCK], seq)
            data = data[esp.ESP_RAM_BLOCK:]
            seq += 1
        print 'done!'

    print 'All segments done, executing at %08x' % image.entrypoint
    esp.mem_finish(image.entrypoint)


def read_mem(esp, args):
    print '0x%08x = 0x%08x' % (args.address, esp.read_reg(args.address))


def write_mem(esp, args):
    esp.write_reg(args.address, args.value, args.mask, 0)
    print 'Wrote %08x, mask %08x to %08x' % (args.value, args.mask, args.address)


def dump_mem(esp, args):
    f = file(args.filename, 'wb')
    for i in xrange(args.size / 4):
        d = esp.read_reg(args.address + (i * 4))
        f.write(struct.pack('<I', d))
        if f.tell() % 1024 == 0:
            print '\r%d bytes read... (%d %%)' % (f.tell(),
                                                  f.tell() * 100 / args.size),
        sys.stdout.flush()
    print 'Done!'


def write_flash(esp, args):
    """Write data to flash
    """
    flash_mode = {'qio':0, 'qout':1, 'dio':2, 'dout': 3}[args.flash_mode]
    flash_size_freq = esp.parse_flash_size_arg(args.flash_size)
    flash_size_freq += {'40m':0, '26m':1, '20m':2, '80m': 0xf}[args.flash_freq]
    flash_info = struct.pack('BB', flash_mode, flash_size_freq)
    for address, argfile in args.addr_filename:
        print 'Erasing flash...'
        if args.compress:
            uncimage = argfile.read()
            calcmd5 = hashlib.md5(uncimage).hexdigest()
            uncsize = len(uncimage)
            image = zlib.compress(uncimage, 9)
            blocks = div_roundup(len(image), esp.FLASH_WRITE_SIZE)
            esp.flash_defl_begin(len(uncimage),len(image), address)
        else:
            image = argfile.read()
            calcmd5 = hashlib.md5(image).hexdigest()
            uncsize = len(image)
            blocks = div_roundup(len(image), esp.FLASH_WRITE_SIZE)
            esp.flash_begin(blocks * esp.FLASH_WRITE_SIZE, address)
        argfile.seek(0)  # in case we need it again
        seq = 0
        written = 0
        t = time.time()
        header_block = None
        while len(image) > 0:
            print '\rWriting at 0x%08x... (%d %%)' % (address + seq * esp.FLASH_WRITE_SIZE, 100 * (seq + 1) / blocks),
            sys.stdout.flush()
            block = image[0:esp.FLASH_WRITE_SIZE]
            if args.compress:
                esp.flash_defl_block(block, seq)
            else:
                # Pad the last block
                block = block + '\xff' * (esp.FLASH_WRITE_SIZE - len(block))
                # Fix sflash config data
                if address == 0 and seq == 0 and block[0] == '\xe9':
                    block = block[0:2] + flash_info + block[4:]
                    header_block = block
                esp.flash_block(block, seq)
            image = image[esp.FLASH_WRITE_SIZE:]
            seq += 1
            written += len(block)
        t = time.time() - t
        print '\rWrote %d bytes at 0x%08x in %.1f seconds (%.1f kbit/s)...' % (written, address, t, written / t * 8 / 1000)
        res = esp.flash_md5sum(address, uncsize)
        if res != calcmd5:
            print 'File  md5: %s' % calcmd5
            print 'Flash md5: %s' % res
            raise FatalError("MD5 of file does not match data in flash!")
        else:
            print 'Hash of data verified.'
    print '\nLeaving...'
    if args.flash_mode == 'dio':
        esp.flash_unlock_dio()
    else:
        esp.flash_begin(0, 0)
        if args.compress:
            esp.flash_defl_finish(False)
        else:
            esp.flash_finish(False)
    if args.verify:
        print 'Verifying just-written flash...'
        verify_flash(esp, args, header_block)


def image_info(args):
    image = LoadFirmwareImage(args.chip, args.filename)
    print('Image version: %d' % image.version)
    print('Entry point: %08x' % image.entrypoint) if image.entrypoint != 0 else 'Entry point not set'
    print '%d segments' % len(image.segments)
    print
    checksum = ESPROM.ESP_CHECKSUM_MAGIC
    idx = 0
    for seg in image.segments:
        idx += 1
        print 'Segment %d: %r' % (idx, seg)
        checksum = ESPROM.checksum(seg.data, checksum)
    print
    print 'Checksum: %02x (%s)' % (image.checksum, 'valid' if image.checksum == checksum else 'invalid!')


def make_image(args):
    image = ESPFirmwareImage()
    if len(args.segfile) == 0:
        raise FatalError('No segments specified')
    if len(args.segfile) != len(args.segaddr):
        raise FatalError('Number of specified files does not match number of specified addresses')
    for (seg, addr) in zip(args.segfile, args.segaddr):
        data = file(seg, 'rb').read()
        image.segments.append(ImageSegment(addr, data))
    image.entrypoint = args.entrypoint
    image.save(args.output)


def elf2image(args):
    e = ELFFile(args.input)
    if args.chip == 'auto':  # Default to ESP8266 for backwards compatibility
        print "Creating image for ESP8266..."
        args.chip == 'esp8266'

    if args.chip == 'esp32':
        image = ESP32FirmwareImage()
    elif args.version == '1':  # ESP8266
        image = ESPFirmwareImage()
    else:
        image = OTAFirmwareImage()
    image.entrypoint = e.entrypoint
    image.segments = e.sections  # ELFSection is a subclass of ImageSegment
    image.flash_mode = {'qio':0, 'qout':1, 'dio':2, 'dout': 3}[args.flash_mode]
    image.flash_size_freq = ESP8266ROM.FLASH_SIZES[args.flash_size]
    image.flash_size_freq += {'40m':0, '26m':1, '20m':2, '80m': 0xf}[args.flash_freq]

    if args.output is None:
        args.output = image.default_output_name(args.input)
    image.save(args.output)


def read_mac(esp, args):
    mac = esp.read_mac()
    print 'MAC: %s' % ':'.join(map(lambda x: '%02x' % x, mac))


def chip_id(esp, args):
    chipid = esp.chip_id()
    print 'Chip ID: 0x%08x' % chipid


def erase_flash(esp, args):
    print 'Erasing flash (this may take a while)...'
    t = time.time()
    esp.erase_flash()
    print 'Chip erase completed successfully in %.1fs' % (time.time() - t)


def erase_region(esp, args):
    print 'Erasing region (may be slow depending on size)...'
    esp.erase_region(args.address, args.size)
    print 'Erase completed successfully.'


def run(esp, args):
    esp.run()


def flash_id(esp, args):
    flash_id = esp.flash_id()
    print 'Manufacturer: %02x' % (flash_id & 0xff)
    print 'Device: %02x%02x' % ((flash_id >> 8) & 0xff, (flash_id >> 16) & 0xff)


def read_flash(esp, args):
    if args.no_progress:
        flash_progress = None
    else:
        def flash_progress(progress, length):
            msg = '%d (%d %%)' % (progress, progress * 100.0 / length)
            padding = '\b' * len(msg)
            if progress == length:
                padding = '\n'
            sys.stdout.write(msg + padding)
            sys.stdout.flush()
    t = time.time()
    data = esp.read_flash(args.address, args.size, flash_progress)
    t = time.time() - t
    print ('\rRead %d bytes at 0x%x in %.1f seconds (%.1f kbit/s)...'
           % (len(data), args.address, t, len(data) / t * 8 / 1000))
    file(args.filename, 'wb').write(data)


def verify_flash(esp, args, flash_params=None):
    differences = False
    for address, argfile in args.addr_filename:
        image = argfile.read()
        argfile.seek(0)  # rewind in case we need it again
        if address == 0 and image[0] == '\xe9' and flash_params is not None:
            image = image[0:2] + flash_params + image[4:]
        image_size = len(image)
        print 'Verifying 0x%x (%d) bytes @ 0x%08x in flash against %s...' % (image_size, image_size, address, argfile.name)
        # Try digest first, only read if there are differences.
        digest = esp.flash_md5sum(address, image_size)
        expected_digest = hashlib.md5(image).hexdigest()
        if digest == expected_digest:
            print '-- verify OK (digest matched)'
            continue
        else:
            differences = True
            if getattr(args, 'diff', 'no') != 'yes':
                print '-- verify FAILED (digest mismatch)'
                continue

        flash = esp.read_flash(address, image_size)
        assert flash != image
        diff = [i for i in xrange(image_size) if flash[i] != image[i]]
        print '-- verify FAILED: %d differences, first @ 0x%08x' % (len(diff), address + diff[0])
        for d in diff:
            print '   %08x %02x %02x' % (address + d, ord(flash[d]), ord(image[d]))
    if differences:
        raise FatalError("Verify failed.")


def version(args):
    print __version__

#
# End of operations functions
#


def main():
    parser = argparse.ArgumentParser(description='esptool.py v%s - ESP8266 ROM Bootloader Utility' % __version__, prog='esptool')

    parser.add_argument('--chip', '-c',
                        help='Target chip type',
                        choices=['auto', 'esp8266', 'esp31', 'esp32'],
                        default=os.environ.get('ESPTOOL_CHIP', 'auto'))

    parser.add_argument(
        '--port', '-p',
        help='Serial port device',
        default=os.environ.get('ESPTOOL_PORT', ESPROM.DEFAULT_PORT))

    parser.add_argument(
        '--baud', '-b',
        help='Serial port baud rate used when flashing/reading',
        type=arg_auto_int,
        default=os.environ.get('ESPTOOL_BAUD', ESPROM.ESP_ROM_BAUD))

    parser.add_argument(
        '--no-stub',
        help="Disable launching the flasher stub, only talk to ROM bootloader. Some features will not be available.",
        action='store_true')

    subparsers = parser.add_subparsers(
        dest='operation',
        help='Run esptool {command} -h for additional help')

    parser_load_ram = subparsers.add_parser(
        'load_ram',
        help='Download an image to RAM and execute')
    parser_load_ram.add_argument('filename', help='Firmware image')

    parser_dump_mem = subparsers.add_parser(
        'dump_mem',
        help='Dump arbitrary memory to disk')
    parser_dump_mem.add_argument('address', help='Base address', type=arg_auto_int)
    parser_dump_mem.add_argument('size', help='Size of region to dump', type=arg_auto_int)
    parser_dump_mem.add_argument('filename', help='Name of binary dump')

    parser_read_mem = subparsers.add_parser(
        'read_mem',
        help='Read arbitrary memory location')
    parser_read_mem.add_argument('address', help='Address to read', type=arg_auto_int)

    parser_write_mem = subparsers.add_parser(
        'write_mem',
        help='Read-modify-write to arbitrary memory location')
    parser_write_mem.add_argument('address', help='Address to write', type=arg_auto_int)
    parser_write_mem.add_argument('value', help='Value', type=arg_auto_int)
    parser_write_mem.add_argument('mask', help='Mask of bits to write', type=arg_auto_int)

    def add_spi_flash_subparsers(parent):
        """ Add common parser arguments for SPI flash properties """
        parent.add_argument('--flash_freq', '-ff', help='SPI Flash frequency',
                            choices=['40m', '26m', '20m', '80m'],
                            default=os.environ.get('ESPTOOL_FF', '40m'))
        parent.add_argument('--flash_mode', '-fm', help='SPI Flash mode',
                            choices=['qio', 'qout', 'dio', 'dout'],
                            default=os.environ.get('ESPTOOL_FM', 'qio'))
        parent.add_argument('--flash_size', '-fs', help='SPI Flash size in MegaBytes (1MB, 2MB, 4MB, 8MB, 16M)'
                            ' plus ESP8266-only (256KB, 512KB, 2MB-c1, 4MB-c1, 4MB-2)',
                            action=FlashSizeAction,
                            default=os.environ.get('ESPTOOL_FS', '1MB'))
        parent.add_argument('--ucIsHspi', '-ih', help='Config SPI PORT/PINS (Espressif internal feature)',action='store_true')
        parent.add_argument('--ucIsLegacy', '-il', help='Config SPI LEGACY (Espressif internal feature)',action='store_true')

    parser_write_flash = subparsers.add_parser(
        'write_flash',
        help='Write a binary blob to flash')
    parser_write_flash.add_argument('addr_filename', metavar='<address> <filename>', help='Address followed by binary filename, separated by space',
                                    action=AddrFilenamePairAction)
    add_spi_flash_subparsers(parser_write_flash)
    parser_write_flash.add_argument('--no-progress', '-p', help='Suppress progress output', action="store_true")
    parser_write_flash.add_argument('--verify', help='Verify just-written data (only necessary if very cautious, data is already CRCed', action='store_true')
    parser_write_flash.add_argument('--compress', '-z', help='Compress data in transfer',action="store_true")

    subparsers.add_parser(
        'run',
        help='Run application code in flash')

    parser_image_info = subparsers.add_parser(
        'image_info',
        help='Dump headers from an application image')
    parser_image_info.add_argument('filename', help='Image file to parse')

    parser_make_image = subparsers.add_parser(
        'make_image',
        help='Create an application image from binary files')
    parser_make_image.add_argument('output', help='Output image file')
    parser_make_image.add_argument('--segfile', '-f', action='append', help='Segment input file')
    parser_make_image.add_argument('--segaddr', '-a', action='append', help='Segment base address', type=arg_auto_int)
    parser_make_image.add_argument('--entrypoint', '-e', help='Address of entry point', type=arg_auto_int, default=0)

    parser_elf2image = subparsers.add_parser(
        'elf2image',
        help='Create an application image from ELF file')
    parser_elf2image.add_argument('input', help='Input ELF file')
    parser_elf2image.add_argument('--output', '-o', help='Output filename prefix (for version 1 image), or filename (for version 2 single image)', type=str)
    parser_elf2image.add_argument('--version', '-e', help='Output image version', choices=['1','2'], default='1')
    add_spi_flash_subparsers(parser_elf2image)

    subparsers.add_parser(
        'read_mac',
        help='Read MAC address from OTP ROM')

    subparsers.add_parser(
        'chip_id',
        help='Read Chip ID from OTP ROM')

    subparsers.add_parser(
        'flash_id',
        help='Read SPI flash manufacturer and device ID')

    parser_read_flash = subparsers.add_parser(
        'read_flash',
        help='Read SPI flash content')
    parser_read_flash.add_argument('address', help='Start address', type=arg_auto_int)
    parser_read_flash.add_argument('size', help='Size of region to dump', type=arg_auto_int)
    parser_read_flash.add_argument('filename', help='Name of binary dump')
    parser_read_flash.add_argument('--no-progress', '-p', help='Suppress progress output', action="store_true")

    parser_verify_flash = subparsers.add_parser(
        'verify_flash',
        help='Verify a binary blob against flash')
    parser_verify_flash.add_argument('addr_filename', help='Address and binary file to verify there, separated by space',
                                     action=AddrFilenamePairAction)
    parser_verify_flash.add_argument('--diff', '-d', help='Show differences',
                                     choices=['no', 'yes'], default='no')

    subparsers.add_parser(
        'erase_flash',
        help='Perform Chip Erase on SPI flash')

    parser_erase_region = subparsers.add_parser(
        'erase_region',
        help='Erase a region of the flash')
    parser_erase_region.add_argument('address', help='Start address (must be multiple of 4096)', type=arg_auto_int)
    parser_erase_region.add_argument('size', help='Size of region to erase (must be multiple of 4096)', type=arg_auto_int)

    subparsers.add_parser(
        'version', help='Print esptool version')

    # internal sanity check - every operation matches a module function of the same name
    for operation in subparsers.choices.keys():
        assert operation in globals(), "%s should be a module function" % operation

    args = parser.parse_args()

    print 'esptool.py v%s' % __version__

    # operation function can take 1 arg (args), 2 args (esp, arg)
    # or be a member function of the ESPROM class.

    operation_func = globals()[args.operation]
    operation_args,_,_,_ = inspect.getargspec(operation_func)
    if operation_args[0] == 'esp':  # operation function takes an ESPROM connection object
        initial_baud = min(ESPROM.ESP_ROM_BAUD, args.baud)  # don't sync faster than the default baud rate
        chip_constructor_fun = {
            'auto': ESPROM.detect_chip,
            'esp8266': ESP8266ROM,
            'esp32': ESP32ROM,
        }[args.chip]
        esp = chip_constructor_fun(args.port, initial_baud)

        if not args.no_stub:
            esp = esp.run_stub()

        if args.baud > initial_baud:
            esp.change_baud(args.baud)
            # TODO: handle a NotImplementedInROMError

        # override common SPI flash parameter stuff as required
        if hasattr(args, "ucIsHspi"):
            print "Attaching SPI flash..."
            esp.flash_spi_attach(args.ucIsHspi,args.ucIsLegacy)
        if hasattr(args, "flash_size"):
            print "Configuring flash size..."
            esp.flash_set_parameters(flash_size_bytes(args.flash_size))

        operation_func(esp, args)
    else:
        operation_func(args)


class FlashSizeAction(argparse.Action):
    """ Custom flash size parser class to support backwards compatibility with megabit size arguments.

    (At next major relase, remove deprecated sizes and this can become a 'normal' choices= argument again.)
    """
    def __init__(self, option_strings, dest, nargs=1, **kwargs):
        super(FlashSizeAction, self).__init__(option_strings, dest, nargs, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        try:
            value = {
                '2m': '256KB',
                '4m': '512KB',
                '8m': '1MB',
                '16m': '2MB',
                '32m': '4MB',
                '16m-c1': '2MB-c1',
                '32m-c1': '4MB-c1',
                '32m-c2': '4MB-c2'
            }[values[0]]
            print("WARNING: Flash size arguments in megabits like '%s' are deprecated." % (values[0]))
            print("Please use the equivalent size '%s'." % (value))
            print("Megabit arguments may be removed in a future release.")
        except KeyError:
            value = values[0]

        known_sizes = dict(ESP8266ROM.FLASH_SIZES)
        known_sizes.update(ESP32ROM.FLASH_SIZES)
        if value not in known_sizes:
            raise argparse.ArgumentError(self, '%s is not a known flash size. Known sizes: %s' % (value, ", ".join(known_sizes.keys())))
        setattr(namespace, self.dest, value)


class AddrFilenamePairAction(argparse.Action):
    """ Custom parser class for the address/filename pairs passed as arguments """
    def __init__(self, option_strings, dest, nargs='+', **kwargs):
        super(AddrFilenamePairAction, self).__init__(option_strings, dest, nargs, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        # validate pair arguments
        pairs = []
        for i in range(0,len(values),2):
            try:
                address = int(values[i],0)
            except ValueError as e:
                raise argparse.ArgumentError(self,'Address "%s" must be a number' % values[i])
            try:
                argfile = open(values[i + 1], 'rb')
            except IOError as e:
                raise argparse.ArgumentError(self, e)
            except IndexError:
                raise argparse.ArgumentError(self,'Must be pairs of an address and the binary filename to write there')
            pairs.append((address, argfile))
        setattr(namespace, self.dest, pairs)

# Binary stub code (see flasher_stub dir for source & details)
ESP8266ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
""")))
ESP32ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
""")))


if __name__ == '__main__':
    try:
        main()
    except FatalError as e:
        print '\nA fatal error occurred: %s' % e
        sys.exit(2)
