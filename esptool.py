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


def check_supported_function(func, check_func):
    """
    Decorator implementation that wraps a check around an ESPLoader
    bootloader function to check if it's supported.

    This is used to capture the multidimensional differences in
    functionality between the ESP8266 & ESP32 ROM loaders, and the
    software stub that runs on both. Not possible to do this cleanly
    via inheritance alone.
    """
    def inner(*args, **kwargs):
        obj = args[0]
        if check_func(obj):
            return func(*args, **kwargs)
        else:
            raise NotImplementedInROMError(obj)
    return inner


def stub_function_only(func):
    """ Attribute for a function only supported in the software stub loader """
    return check_supported_function(func, lambda o: o.IS_STUB)


def stub_and_esp32_function_only(func):
    """ Attribute for a function only supported by software stubs or ESP32 ROM """
    return check_supported_function(func, lambda o: o.IS_STUB or o.CHIP_NAME == "ESP32")


def esp8266_function_only(func):
    """ Attribute for a function only supported on ESP8266 """
    return check_supported_function(func, lambda o: o.CHIP_NAME == "ESP8266")


class ESPLoader(object):
    """ Base class providing access to ESP ROM & softtware stub bootloaders.
    Subclasses provide ESP8266 & ESP32 specific functionality.

    Don't instantiate this base class directly, either instantiate a subclass or
    call ESPLoader.detect_chip() which will interrogate the chip and return the
    appropriate subclass instance.

    """
    CHIP_NAME = "Espressif device"
    IS_STUB = False

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
        """Base constructor for ESPLoader bootloader interaction

        Don't call this constructor, either instantiate ESP8266ROM
        or ESP32ROM, or use ESPLoader.detect_chip().

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
        detect_port = ESPLoader(port, baud, True)
        sys.stdout.write('Detecting chip type... ')
        date_reg = detect_port.read_reg(ESPLoader.UART_DATA_REG_ADDR)

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
        self.command(self.ESP_SYNC, '\x07\x07\x12\x20' + 32 * '\x55')
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
        val, data = self.command(self.ESP_READ_REG, struct.pack('<I', addr))
        if data[0] != '\0':
            raise FatalError.WithResult("Failed to read register address %08x" % addr, data)
        return val

    """ Write to memory address in target """
    def write_reg(self, addr, value, mask=0xFFFFFFFF, delay_us=0):
        return self.check_command("write target memory", self.ESP_WRITE_REG,
                                  struct.pack('<IIII', addr, value, mask, delay_us))

    """ Start downloading an application image to RAM """
    def mem_begin(self, size, blocks, blocksize, offset):
        return self.check_command("enter RAM download mode", self.ESP_MEM_BEGIN,
                                  struct.pack('<IIII', size, blocks, blocksize, offset))

    """ Send a block of an image to RAM """
    def mem_block(self, data, seq):
        return self.check_command("write to target RAM", self.ESP_MEM_DATA,
                                  struct.pack('<IIII', len(data), seq, 0, 0) + data,
                                  self.checksum(data))

    """ Leave download mode and run the application """
    def mem_finish(self, entrypoint=0):
        return self.check_command("leave RAM download mode", self.ESP_MEM_END,
                                  struct.pack('<II', int(entrypoint == 0), entrypoint))

    """ Start downloading to Flash (performs an erase) """
    def flash_begin(self, size, offset):
        old_tmo = self._port.timeout
        num_blocks = (size + self.ESP_FLASH_BLOCK - 1) / self.ESP_FLASH_BLOCK
        erase_size = self.get_erase_size(offset, size)

        self._port.timeout = 20
        t = time.time()
        self.check_command("enter Flash download mode", self.ESP_FLASH_BEGIN,
                           struct.pack('<IIII', erase_size, num_blocks, self.ESP_FLASH_BLOCK, offset))
        if size != 0:
            print "Took %.2fs to erase flash block" % (time.time() - t)
        self._port.timeout = old_tmo

    """ Write block to flash """
    def flash_block(self, data, seq):
        self.check_command("write to target Flash after seq %d" % seq,
                           self.ESP_FLASH_DATA,
                           struct.pack('<IIII', len(data), seq, 0, 0) + data,
                           self.checksum(data))

    """ Leave flash mode and run/reboot """
    def flash_finish(self, reboot=False):
        pkt = struct.pack('<I', int(not reboot))
        self.check_command("leave Flash mode", self.ESP_FLASH_END, pkt)

    """ Run application code in flash """
    def run(self, reboot=False):
        # Fake flash begin immediately followed by flash end
        self.flash_begin(0, 0)
        self.flash_finish(reboot)

    """ Read SPI flash manufacturer and device id """
    @stub_function_only
    def flash_id(self):
        resp = self.check_command("get flash id", self.ESP_GET_FLASH_ID)
        return struct.unpack('<I', resp)[0]

    def parse_flash_size_arg(self, arg):
        try:
            return self.FLASH_SIZES[arg]
        except KeyError:
            raise FatalError("Flash size '%s' is not supported by this chip type. Supported sizes: %s"
                             % (arg, ", ".join(self.FLASH_SIZES.keys())))

    """ Abuse the loader protocol to force flash to be left in write mode """
    @esp8266_function_only
    def flash_unlock_dio(self):
        # Enable flash write mode
        self.flash_begin(0, 0)
        # Reset the chip rather than call flash_finish(), which would have
        # write protected the chip again (why oh why does it do that?!)
        self.mem_begin(0,0,0,0x40100000)
        self.mem_finish(0x40000080)

    def run_stub(self, stub=None):
        if stub is None:
            if self.IS_STUB:
                raise FatalError("Not possible for a stub to load another stub (memory likely to overlap.)")
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

    @stub_and_esp32_function_only
    def flash_defl_begin(self, size, compsize, offset):
        """ Start downloading compressed data to Flash (performs an erase) """
        old_tmo = self._port.timeout
        num_blocks = (compsize + self.ESP_FLASH_BLOCK - 1) / self.ESP_FLASH_BLOCK
        erase_blocks = (size + self.ESP_FLASH_BLOCK - 1) / self.ESP_FLASH_BLOCK

        self._port.timeout = 20
        t = time.time()
        print "Unc size %d comp size %d comp blocks %d" % (size, compsize, num_blocks)
        self.check_command("enter compressed flash mode", self.ESP_FLASH_DEFL_BEGIN,
                           struct.pack('<IIII', erase_blocks * self.ESP_FLASH_BLOCK, num_blocks, self.ESP_FLASH_BLOCK, offset))
        if size != 0 and not self.IS_STUB:
            # (stub erases as it writes, but ROM loaders erase on begin)
            print "Took %.2fs to erase flash block" % (time.time() - t)
        self._port.timeout = old_tmo

    """ Write block to flash, send compressed """
    @stub_and_esp32_function_only
    def flash_defl_block(self, data, seq):
        self.check_command("write compressed data to flash after seq %d" % seq,
                           self.ESP_FLASH_DEFL_DATA, struct.pack('<IIII', len(data), seq, 0, 0) + data, self.checksum(data))

    """ Leave compressed flash mode and run/reboot """
    @stub_and_esp32_function_only
    def flash_defl_finish(self, reboot=False):
        pkt = struct.pack('<I', int(not reboot))
        self.check_command("leave compressed flash mode", self.ESP_FLASH_DEFL_END, pkt)
        self.in_bootloader = False

    @stub_and_esp32_function_only
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

    @stub_and_esp32_function_only
    def change_baud(self, baud):
        print "Changing baud rate to %d" % baud
        self.command(self.ESP_CHANGE_BAUDRATE, struct.pack('<II', baud, 0))
        print "Changed."
        self._port.baudrate = baud
        time.sleep(0.05)  # get rid of crap sent during baud rate change
        self.flush_input()

    @stub_function_only
    def erase_flash(self):
        oldtimeout = self._port.timeout
        # depending on flash chip model the erase may take this long (maybe longer!)
        self._port.timeout = 128
        try:
            self.check_command("erase flash", self.ESP_ERASE_FLASH)
        finally:
            self._port.timeout = oldtimeout

    @stub_function_only
    def erase_region(self, offset, size):
        if offset % self.ESP_FLASH_SECTOR != 0:
            raise FatalError("Offset to erase from must be a multiple of 4096")
        if size % self.ESP_FLASH_SECTOR != 0:
            raise FatalError("Size of data to erase must be a multiple of 4096")
        self.check_command("erase region", self.ESP_ERASE_REGION, struct.pack('<II', offset, size))

    @stub_function_only
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


class ESP8266ROM(ESPLoader):
    """ Access class for ESP8266 ROM bootloader
    """
    CHIP_NAME = "ESP8266"
    IS_STUB = False

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
    IS_STUB = True

    def __init__(self, rom_loader):
        self._port = rom_loader._port
        self.flush_input()  # resets _slip_reader

ESP8266ROM.STUB_CLASS = ESP8266StubLoader


class ESP32ROM(ESPLoader):
    """Access class for ESP32 ROM bootloader

    """
    CHIP_NAME = "ESP32"
    IS_STUB = False

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


class ESP32StubLoader(ESP32ROM):
    """ Access class for ESP32 stub loader, runs on top of ROM.
    """
    FLASH_WRITE_SIZE = 8192  # matches MAX_WRITE_BLOCK in stub_loader.c
    STATUS_BYTES_LENGTH = 2  # same as ESP8266, different to ESP32 ROM
    IS_STUB = True

    def __init__(self, rom_loader):
        self._port = rom_loader._port
        self.flush_input()  # resets _slip_reader

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
            if magic == ESPLoader.ESP_IMAGE_MAGIC:
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
            return ESPLoader.checksum(segment.data, checksum)

    def read_checksum(self, f):
        """ Return ESPLoader checksum from end of just-read image """
        # Skip the padding. The checksum is stored in the last byte so that the
        # file is a multiple of 16 bytes.
        align_file_position(f, 16)
        return ord(f.read(1))

    def append_checksum(self, f, checksum):
        """ Append ESPLoader checksum to the just-written image """
        align_file_position(f, 16)
        f.write(struct.pack('B', checksum))

    def write_common_header(self, f, segments):
        f.write(struct.pack('<BBBBI', ESPLoader.ESP_IMAGE_MAGIC, len(segments),
                            self.flash_mode, self.flash_size_freq, self.entrypoint))

    def is_irom_addr(self, addr):
        """ Returns True if an address starts in the irom region.
        Valid for ESP8266 only.
        """
        return ESPLoader.IROM_MAP_START <= addr < ESPLoader.IROM_MAP_END

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
            segments = self.load_common_header(load_file, ESPLoader.ESP_IMAGE_MAGIC)

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
            checksum = ESPLoader.ESP_CHECKSUM_MAGIC
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
            irom_segment.addr = irom_offs + self.IROM_MAP_START

            first_flash_mode = self.flash_mode
            first_flash_size_freq = self.flash_size_freq
            first_entrypoint = self.entrypoint
            # load the second header
            self.load_common_header(load_file, ESPLoader.ESP_IMAGE_MAGIC)
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
            irom_offs = irom_segment.addr - self.IROM_MAP_START
        else:
            irom_offs = 0
        return "%s-0x%05x.bin" % (os.path.splitext(input_file)[0],
                                  irom_offs & ~(ESPLoader.ESP_FLASH_SECTOR - 1))

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
            checksum = ESPLoader.ESP_CHECKSUM_MAGIC
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
            segments = self.load_common_header(load_file, ESPLoader.ESP_IMAGE_MAGIC)
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

            checksum = ESPLoader.ESP_CHECKSUM_MAGIC
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
# Each function takes either two args (<ESPLoader instance>, <args>) or a single <args>
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

    # verify file sizes fit in flash
    flash_end = flash_size_bytes(args.flash_size)
    for address, argfile in args.addr_filename:
        argfile.seek(0,2)  # seek to end
        if address + argfile.tell() > flash_end:
            raise FatalError(("File %s (length %d) at offset %d will not fit in %d bytes of flash. " +
                             "Use --flash-size argument, or change flashing address.")
                             % (argfile.name, argfile.tell(), address, flash_end))
        argfile.seek(0)

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
    if args.flash_mode == 'dio' and esp.CHIP_NAME == "ESP8266":
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
    checksum = ESPLoader.ESP_CHECKSUM_MAGIC
    idx = 0
    for seg in image.segments:
        idx += 1
        print 'Segment %d: %r' % (idx, seg)
        checksum = ESPLoader.checksum(seg.data, checksum)
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
        default=os.environ.get('ESPTOOL_PORT', ESPLoader.DEFAULT_PORT))

    parser.add_argument(
        '--baud', '-b',
        help='Serial port baud rate used when flashing/reading',
        type=arg_auto_int,
        default=os.environ.get('ESPTOOL_BAUD', ESPLoader.ESP_ROM_BAUD))

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
    # or be a member function of the ESPLoader class.

    operation_func = globals()[args.operation]
    operation_args,_,_,_ = inspect.getargspec(operation_func)
    if operation_args[0] == 'esp':  # operation function takes an ESPLoader connection object
        initial_baud = min(ESPLoader.ESP_ROM_BAUD, args.baud)  # don't sync faster than the default baud rate
        chip_constructor_fun = {
            'auto': ESPLoader.detect_chip,
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
