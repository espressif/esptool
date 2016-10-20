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

    # Memory addresses
    IROM_MAP_START = 0x40200000
    IROM_MAP_END = 0x40300000

    # The number of bytes in the UART response that signify command status
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
    def flash_id(self):
        SPIFLASH_RDID = 0x9F
        return self.run_spiflash_command(SPIFLASH_RDID, b"", 24)

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
        print "Compressed %d bytes to %d..." % (size, compsize)
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

    def run_spiflash_command(self, spiflash_command, data=b"", read_bits=0):
        """Run an arbitrary SPI flash command.

        This function uses the "USR_COMMAND" functionality in the ESP
        SPI hardware, rather than the precanned commands supported by
        hardware. So the value of spiflash_command is an actual command
        byte, sent over the wire.

        After writing command byte, writes 'data' to MOSI and then
        reads back 'read_bits' of reply on MISO. Result is a number.
        """

        # SPI_USR register flags
        SPI_USR_COMMAND = (1 << 31)
        SPI_USR_MISO    = (1 << 28)
        SPI_USR_MOSI    = (1 << 27)

        # SPI registers, base address differs ESP32 vs 8266
        base = self.SPI_REG_BASE
        SPI_CMD_REG       = base + 0x00
        SPI_CTRL_REG      = base + 0x08
        SPI_USR_REG       = base + 0x1C
        SPI_USR1_REG      = base + 0x20
        SPI_USR2_REG      = base + 0x24
        SPI_W0_REG        = base + 0x80

        # following two registers are ESP32 only
        if self.SPI_HAS_MOSI_DLEN_REG:
            # ESP32 has a more sophisticated wayto set up "user" commands
            def set_data_lengths(mosi_bits, miso_bits):
                SPI_MOSI_DLEN_REG = base + 0x28
                SPI_MISO_DLEN_REG = base + 0x2C
                if mosi_bits > 0:
                    self.write_reg(SPI_MOSI_DLEN_REG, mosi_bits - 1)
                if miso_bits > 0:
                    self.write_reg(SPI_MISO_DLEN_REG, miso_bits - 1)
        else:

            def set_data_lengths(mosi_bits, miso_bits):
                SPI_DATA_LEN_REG = SPI_USR1_REG
                SPI_MOSI_BITLEN_S = 17
                SPI_MISO_BITLEN_S = 8
                mosi_mask = 0 if (mosi_bits == 0) else (mosi_bits - 1)
                miso_mask = 0 if (miso_bits == 0) else (miso_bits - 1)
                self.write_reg(SPI_DATA_LEN_REG,
                               (miso_mask << SPI_MISO_BITLEN_S) | (
                                   mosi_mask << SPI_MOSI_BITLEN_S))

        # SPI peripheral "command" bitmasks for SPI_CMD_REG
        SPI_CMD_USR  = (1 << 18)

        # shift values
        SPI_USR2_DLEN_SHIFT = 28

        if read_bits > 32:
            raise FatalError("Reading more than 32 bits back from a SPI flash operation is unsupported")
        if len(data) > 64:
            raise FatalError("Writing more than 64 bytes of data with one SPI command is unsupported")

        data_bits = len(data) * 8
        self.write_reg(SPI_CTRL_REG, 0)
        flags = SPI_USR_COMMAND
        if read_bits > 0:
            flags |= SPI_USR_MISO
        if data_bits > 0:
            flags |= SPI_USR_MOSI
        set_data_lengths(data_bits, read_bits)
        self.write_reg(SPI_USR_REG, flags)
        self.write_reg(SPI_USR2_REG,
                       (7 << SPI_USR2_DLEN_SHIFT) | spiflash_command)
        if data_bits == 0:
            self.write_reg(SPI_W0_REG, 0)  # clear data register before we read it
        else:
            if len(data) % 4 != 0:  # pad to 32-bit multiple
                data += b'\0' * (4 - (len(data) % 4))
            words = struct.unpack("I" * (len(data) / 4), data)
            next_reg = SPI_W0_REG
            for word in words:
                self.write_reg(next_reg, word)
                next_reg += 4
        self.write_reg(SPI_CMD_REG, SPI_CMD_USR)
        while self.read_reg(SPI_CMD_REG) != 0:
            print "Waiting... %08x" % self.read_reg(SPI_CMD_REG)
            pass
        status = self.read_reg(SPI_W0_REG)
        return status

    def read_status(self, num_bytes=2):
        """Read up to 24 bits (num_bytes) of SPI flash status register contents
        via RDSR, RDSR2, RDSR3 commands

        Not all SPI flash supports all three commands. The upper 1 or 2
        bytes may be 0xFF.
        """
        SPIFLASH_RDSR  = 0x05
        SPIFLASH_RDSR2 = 0x35
        SPIFLASH_RDSR3 = 0x15

        status = 0
        shift = 0
        for cmd in [SPIFLASH_RDSR, SPIFLASH_RDSR2, SPIFLASH_RDSR3][0:num_bytes]:
            status += self.run_spiflash_command(cmd, read_bits=8) << shift
            shift += 8
        return status

    def write_status(self, new_status, num_bytes=2, set_non_volatile=False):
        """Write up to 24 bits (num_bytes) of new status register

        num_bytes can be 1, 2 or 3.

        Not all flash supports the additional commands to write the
        second and third byte of the status register. When writing 2
        bytes, esptool also sends a 16-byte WRSR command (as some
        flash types use this instead of WRSR2.)

        If the set_non_volatile flag is set, non-volatile bits will
        be set as well as volatile ones (WREN used instead of WEVSR).

        """
        SPIFLASH_WRSR = 0x01
        SPIFLASH_WRSR2 = 0x31
        SPIFLASH_WRSR3 = 0x11
        SPIFLASH_WEVSR = 0x50
        SPIFLASH_WREN = 0x06
        SPIFLASH_WRDI = 0x04

        enable_cmd = SPIFLASH_WREN if set_non_volatile else SPIFLASH_WEVSR

        # try using a 16-bit WRSR (not supported by all chips)
        # this may be redundant, but shouldn't hurt
        if num_bytes == 2:
            self.run_spiflash_command(enable_cmd)
            self.run_spiflash_command(SPIFLASH_WRSR, struct.pack("<H", new_status))

        # also try using individual commands (also not supported by all chips for num_bytes 2 & 3)
        for cmd in [SPIFLASH_WRSR, SPIFLASH_WRSR2, SPIFLASH_WRSR3][0:num_bytes]:
            self.run_spiflash_command(enable_cmd)
            self.run_spiflash_command(cmd, struct.pack("B", new_status & 0xFF))
            new_status >>= 8

        self.run_spiflash_command(SPIFLASH_WRDI)


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

    SPI_REG_BASE    = 0x60000200
    SPI_HAS_MOSI_DLEN_REG = False

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
    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
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

    SPI_REG_BASE   = 0x60002000
    EFUSE_REG_BASE = 0x6001a000

    SPI_HAS_MOSI_DLEN_REG = True

    FLASH_SIZES = {
        '1MB':0x00,
        '2MB':0x10,
        '4MB':0x20,
        '8MB':0x30,
        '16MB':0x40
    }

    def read_efuse(self, n):
        """ Read the nth word of the ESP3x EFUSE region. """
        return self.read_reg(self.EFUSE_REG_BASE + (4 * n))

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
    FLASH_WRITE_SIZE = 0x4000  # matches MAX_WRITE_BLOCK in stub_loader.c
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
        self.include_in_checksum = True

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
        self.warn_if_unusual_segment(offset, size, is_irom_segment)
        segment_data = f.read(size)
        if len(segment_data) < size:
            raise FatalError('End of file reading segment 0x%x, length %d (actual length %d)' % (offset, size, len(segment_data)))
        segment = ImageSegment(offset, segment_data, file_offs)
        self.segments.append(segment)
        return segment

    def warn_if_unusual_segment(self, offset, size, is_irom_segment):
        if not is_irom_segment:
            if offset > 0x40200000 or offset < 0x3ffe0000 or size > 65536:
                print('WARNING: Suspicious segment 0x%x, length %d' % (offset, size))

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

    def calculate_checksum(self):
        """ Calculate checksum of loaded image, based on segments in
        segment array.
        """
        checksum = ESPLoader.ESP_CHECKSUM_MAGIC
        for seg in self.segments:
            if seg.include_in_checksum:
                checksum = ESPLoader.checksum(seg.data, checksum)
        return checksum

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
        return ESP8266ROM.IROM_MAP_START <= addr < ESP8266ROM.IROM_MAP_END

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

    ROM_LOADER = ESP8266ROM

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
            with open("%s0x%05x.bin" % (basename, irom_segment.addr - ESP8266ROM.IROM_MAP_START), "wb") as f:
                f.write(irom_segment.data)

        # everything but IROM goes at 0x00000 in an image file
        normal_segments = self.get_non_irom_segments()
        with open("%s0x00000.bin" % basename, 'wb') as f:
            self.write_common_header(f, normal_segments)
            checksum = ESPLoader.ESP_CHECKSUM_MAGIC
            for segment in normal_segments:
                checksum = self.save_segment(f, segment, checksum)
            self.append_checksum(f, checksum)


class OTAFirmwareImage(BaseFirmwareImage):
    """ 'Version 2' firmware image, segments loaded by software bootloader stub
        (ie Espressif bootloader or rboot)
    """

    ROM_LOADER = ESP8266ROM

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
            irom_segment = self.load_segment(load_file, True)
            # for actual mapped addr, add ESP8266ROM.IROM_MAP_START + flashing_Addr + 8
            irom_segment.addr = 0
            irom_segment.include_in_checksum = False

            first_flash_mode = self.flash_mode
            first_flash_size_freq = self.flash_size_freq
            first_entrypoint = self.entrypoint
            # load the second header

            segments = self.load_common_header(load_file, ESPLoader.ESP_IMAGE_MAGIC)

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
            irom_offs = irom_segment.addr - ESP8266ROM.IROM_MAP_START
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

    ROM_LOADER = ESP32ROM

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

    def warn_if_unusual_segment(self, offset, size, is_irom_segment):
        pass  # TODO: add warnings for ESP32 segment offset/size combinations that are wrong

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
        image = argfile.read()
        # Update header with flash parameters
        if address == 0 and image[0] == '\xe9':
            image = image[0:2] + flash_info + image[4:]
        calcmd5 = hashlib.md5(image).hexdigest()
        uncsize = len(image)
        if args.compress:
            uncimage = image
            image = zlib.compress(uncimage, 9)
            blocks = div_roundup(len(image), esp.FLASH_WRITE_SIZE)
            esp.flash_defl_begin(len(uncimage),len(image), address)
        else:
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
                esp.flash_block(block, seq)
            image = image[esp.FLASH_WRITE_SIZE:]
            seq += 1
            written += len(block)
        t = time.time() - t
        speed_msg = ""
        if args.compress:
            if t > 0.0:
                speed_msg = " (effective %.1f kbit/s)" % (uncsize / t * 8 / 1000)
            print '\rWrote %d bytes (%d compressed) at 0x%08x in %.1f seconds%s...' % (uncsize, written, address, t, speed_msg)
        else:
            if t > 0.0:
                speed_msg = " (%.1f kbit/s)" % (written / t * 8 / 1000)
            print '\rWrote %d bytes at 0x%08x in %.1f seconds%s...' % (written, address, t, speed_msg)
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
    idx = 0
    for seg in image.segments:
        idx += 1
        print 'Segment %d: %r' % (idx, seg)
    calc_checksum = image.calculate_checksum()
    print 'Checksum: %02x (%s)' % (image.checksum,
                                   'valid' if image.checksum == calc_checksum else 'invalid - calculated %02x' % calc_checksum)


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
    image.flash_size_freq = image.ROM_LOADER.FLASH_SIZES[args.flash_size]
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
    t = time.time()
    esp.erase_region(args.address, args.size)
    print 'Erase completed successfully in %.1f seconds.' % (time.time() - t)


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


def read_flash_status(esp, args):
    print ('Status value: 0x%04x' % esp.read_status(args.bytes))


def write_flash_status(esp, args):
    fmt = "0x%%0%dx" % (args.bytes * 2)
    args.value = args.value & ((1 << (args.bytes * 8)) - 1)
    print (('Initial flash status: ' + fmt) % esp.read_status(args.bytes))
    print (('Setting flash status: ' + fmt) % args.value)
    esp.write_status(args.value, args.bytes, args.non_volatile)
    print (('After flash status:   ' + fmt) % esp.read_status(args.bytes))


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

    parser_read_status = subparsers.add_parser(
        'read_flash_status',
        help='Read SPI flash status register')

    parser_read_status.add_argument('--bytes', help='Number of bytes to read (1-3)', type=int, choices=[1,2,3], default=2)

    parser_write_status = subparsers.add_parser(
        'write_flash_status',
        help='Write SPI flash status register')

    parser_write_status.add_argument('--non-volatile', help='Write non-volatile bits (use with caution)', action='store_true')
    parser_write_status.add_argument('--bytes', help='Number of status bytes to write (1-3)', type=int, choices=[1,2,3], default=2)
    parser_write_status.add_argument('value', help='New value', type=arg_auto_int)

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
        else:
            esp.flash_spi_attach(0, 0)
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
eNrFPGl71Eaaf0VqG7CNSaoktVQyJtNum8Yw8AxH7CGzTuLSBWEIaze9a8J49rev3ktVUrcx5JoPBlV1qY73vkr/urWoPyxu7QS3Tj405uSDito/dXryQSuvoZYa8md0+17Z/jUnH0oVQO9G+08cBOvHU+iG33N4\
2Gv/sb2BmzAwbLuyXvdDWotbh9A6XvRGwD7j9q9dV0e4jSRYUyfzdpAa7E+7Z6P6z039F3/whJaQP5rWBwjsSdMSZWR5k9qdSmFnPNqmF3V68sHCy+3/5VigAP1T6Lzv95x8yCN4boFRRwK1pHfmvAcVxNTxexix\
8Zgg0cQnt9bax0wA0wK8LnhrKUNMbWwHQXLc9sIyNQyRTZQw5cvtduUaDzQ5aju1gn8BijKON/AdTNh2V9ES7uIe7mLCnXkcYH/+2GzvjDa3mXRKEzrI6mUUGnk+5R2qJSJsG3kLKotHBYyWt/nJDJGe+O3JRJ4e\
/5Nf0L1JTTcp0OiYweRRQZUDhLrTth3EQAvoy0N4S/egA4Qz4gf8WwDyL/GFuukNHQEqEe4V9AfBgqioBCzCJiyMr9ttpnNGBSG7w3r7ymSfDsxzvgTChN8N/P4obulQxwIKIDddVKen9MivFC/g30f33b4O4N9I\
3gSCxTPCmdr3WimSx7ttb1UyGdMDrAojmh1Hw69h389kBL4KZAowSB0ferIi6VPfTJiz1530xUtHojsj4guPPKPnjO4WXmXZMoWFnaTELlXKDFkp5iHTQ7XwIxAw4B0IYRUhq7ssXBzltDuxMEWBiAckN5UcVghQ\
xpQ8wA4H8Iau5h2PUhdIMAinjESNGt93q6J0GDNeaWcyzPDy+qr9VTTAUe9n72+wR+CYjqWQg2DqaAfw52EaV1alcBMgjnZggEFZ3FWwfRKJ7YshIx0fok9jq7+tGrdlZS8jAeLJ4hxlPSuYqhweHsF2hzbqNube\
p9fMKpidA01Z2UMw3BriS9ST+nCIxLX3bkk4sQwCcCZqdy9f7/TwZtKxAv/pcbC9B8O/fY7cvXnAWB+vROo9HxZj1YpyE18vyQW03fNLv3HmN9pnQ/KXGKf8Kz4lXh8MynNu5Nqhfgl1dQ6GRztkcQ7k1cqbXInY\
JumKh6lo14Tp+OrzNz43pCcLlgYVQbJsCa9oGL3Q1wAR1AAx/QRAopjYl6ZFjd3t4x5PoZ4EzF/V8jsVnK4mAQVcUKrjx8DUIJNx55E7lrYjnmiJ6DqbgzVszKOBbmlZIeS0x/wlAb6q6V2ANUDVUXBlnsF6AH4n\
CYJlwnjt437hNz74jcs+iRjVb+fDthFGmVQigq3rY6oph1QDzM4n+gzy0bYBLZP6qr4PdVQTHdK3SQJpG5MFZnmzSIbJcxZrTfQWxlwlWUOiMeisgd4imtSkYAgqRha8Wqx8tbMSUMFtPYOlDkRzprsy1IrGxlO+\
Ji2BVk9KM4KQLWqP1sEQKJDwQKk38m68IUR19AvomT4zFNFwj5Yomxf+QAubsuBzJdO3ZDGDkUBGSHuYaiyEqvE8sFJyDxYBo4lMFIRMf3W7xA3t1i0b3m4XRy9JQVa2ht911/8T9APJDDYcOhumpYENRNAtQkgB\
r5e4xNnXQkUxejQ9ZDrOgpnI+n7G4p0Wn9ZOBZWrwFhU3a4MuxwGEfZMyIDlP2HnkA5ZpCD+o446L0EQBkfq6Y8A04xNBfARim4vzaN0tM+iuzig7RPhtm/XMVsTRX7zAKxiUBdNc48XF8lk0hXUatQKyQQorTKP\
nxCVKySkCOj5NrwpJ9IXLKTdGfccVsl3QiKarsNvDzJP3ykVrLGcyQoPVYjPmZPTIFzyXyUZHz8a2IvOCNFMVbUnlliDkfOuy/Bbpt382RZavdhE2cWKDQVRucdWn+5rZ5D5BYJ8Yxv88hE554BxWwyd1Q1CS62+\
CXxVtUq9mbIzGJLNkxN+swXI1p1NeN7YZXiALqsiFjD5LgPIAW2FEmFX/m+Hew/J6us8QZ2wPECLYaX3qJ1V1Tn9uN++56jVZNmUkZdaarjl//I/bVdOwO5tR0kD4g6290vPUQ02vTVarJoK33npRS0Akt3boJBs\
LQ2wnGiRS68btWXh5rVooKmVrnYgVo1ST4HTvYaOvCl8p9saH+5Nd4IWgzb3Qi1uQ4mwLO9OebtTvR8TdsygAcSpxwNzrOmfpIMxNmR14+v+ouwaL3HgZPtxZ1kKAxbJQ34qy686W5SsJWxUhizQ113fISk+si8U\
KZ628fgm9xmeEvQDx1OAlyzbC860GNk1DCjtY6xpCkxhQWdHFlz1yEJIglSBJ/xJP5KQIGBgKO2vowzlA3OgKbfAESr374sWCCmCAnIF5kTuRmWOv25t+/ELdntlKVU+Zwtgpa2RsRlq2c/1Y3oqCfrBrU6YrxAg\
uB5L+ipb8fvKfn3MQS4ipmfsAtXnTl3QxAVvUWZa0qagYFDHh6AOay+KIdYNhGH6oR4vSulF7ja92GUMMTqTCDz16Nk+9oxHdgSkAfOaLm4RubkMmOBaq1HQTE8WG9u93UTt2wNXE+3NeoX/DsyloWHE90c5MHYA\
amTZeOSvz6KvFcUQagrZnG5IX4AVozNS1Db1XN+a7cU8v2I/suE8Gw4gsq4qpiixcTHyGVHcieGc7sD4LMrp19z7dfaWfgIh0vB4laLl0uyLOv8HNtfk17ssn9O3fXIsBquenOBvYObRWrUbW/l7+J77U5ZbuuzN\
ZNKvu00qkji6N0CliQxoZ+uA88gPy2h4Ae26Urr8Laz7Y5WMpcm/c9vWFXmWGoNEMZt+6d8EEG23aWTX3c+P+2yZV8uoBOsRDJecjS2THnbaB0IRaA8usfPxcxKPwJ5ICLj7r2iIKZ8EGIM8fkHrofkegQx+6YW5\
El9XBAE5+bBctiTAjlnfNWSDwYpolqivxQH6hk6Cjni0cgE6zMWKk8xXnuOYGQ/glUae7KtpOPHITQf3MjVCn0Dv40ZsW9gOs7LpZlLez+g/SeQv3er9OiP+hZ/aYT3rZjiDlRluSDBhTJFF2nbkQnfd/lNyXB09\
4+JmGzTqc0Ja2bAhSeHaTjrwNHnMkT8tWg28DQxQRD6V7U8dRsD8qevJCGbNvoJlnvMmx8635AfwODHzoUXUZKdHKGAPoPPpQQADMEw0iQPYXinys9RydLCKwQaEQDXZLCFtGqDjgOFByJalibzfDMcW42gqCYbn\
TGapZ5yCsUrcLchDyTh2pNMxc3rybol5Zzx27MbRezPOJqkeUbnR5ZIH0fzN+UQI9/Eq8h34HoPf0X1Rku8w7KHXbc99aQ6UhV5SFsckdqpsNNAU4IrqKDy5Bbirb0Y/NFN3LjRuIEeUvly2KlEO0+u1hMkjbI5n\
3/rDQ3aDKAx4ayk0vB2K+6D29rZAEuv14SAMsd6hKMVoVeg9pkgenr5eYQ6BPHVbwpRkhAZWPMX05EvQVgDfHK2a2b4MX63tY1T1cRBRAgpTGMR+910IR6X3GDmfsFdGbK4q5nPiYXubaQ9oLh/7YjTkSFWtHVwL\
yaJBoA391apg6yXGxFk0D28X9gb9yIL7ViYmK8WXTYQDIguUPD6VmcPxOXMdJNei8PbZX1nc2wPyUsBmquw/C7uJk2xPOJINoISsnMGQ+gwYLbkgK5oo7B1tAFy0usSYBMhtQIseb7yF1ezNuV3HWbd2XwC7Q/gE\
BySvMVrprAsWvQlY1ejwkJCkWBPBAqVK+JMvjl3AByJKYOnD/wZspQr+wSBJ9pe76GqsA9u9C/D5JitBkGotVEDYl2tgt2sVntIKoMxzMW2Th8X3nFmrSIeiTCjYueM4eZ1E4oiF/6BZQEyXDW7KF3XcQZPNfAKJ\
XEKk9y4c4Gc6M+2fgpSw+O7GzDMrcco5HenG0wyP9MQdScXfyVFU+hULatl/6vb/cLD/3KWthBNUOPMGlTgoPOAuFE/g5EevCTNG3QCmeTOaWvXcJoX9GvADrE9Eiw6VXjauCMPTUD0PkyLEl8KYSJsYriZXK2g4\
5VH+79MgEcY0ASi/+Om34IgURxIQO2cLn41aPUZXGf2mV5mXkhpPJhxbJ0U6AYaJVQNkU854tnQJ/OEGQGF7PydQzyikRiUL8sdIaNJ7E0Tipu/pDomNSXQUbDBzlnQ+VULFCei4psoLIVaaqbS0ZIfdSNA5khN2\
hCD6y8tGElL5uZqIqAYXqQa2MQXTYOqi+kqdEzsCCbQ6bn0TvOYg3NukZBLwXB3vcVAMd338fA0V5DoKA8httLBY+wQs8g4Wmxy6LF+wbdtYj5W6Y5s/5Nhl79gsv+EYXF004dMCsvQloDCgF7VyVplOn5BVAWl6\
A9niTx5+LidHFwfnKaX4Jfnzjm5SCYuGHMovNYiL+s0IcrE1mHegkjokG4aF2ZNjD0Jc2e7e51O/ZOlKzoojG8w3S5qhYPvByeSQnady7y5sshNxb0aPRgIf2jKvi6IdLcU9VNVv4kcx5AO06WAckrJu54xkzlLm\
lOMLODUmrtKZs8wkIJNrKFuoi5NFPjpZgBJXFIVoWsNicTc6Wez4xoamOUE3qq6+JKX9UjVRD3Db72cSyWMTDYlsF+F943OJbDc+Jj1ac5Kq7xL6yuMPEy8Sg1fMUAbyqqbT4hRq74itV16xuz/joH+0LEc2KTKD\
WT41DyGsWTTz+7LBIy9Qh0roCVdcqH0wDU7X0EC4xZVYGSOi7qsu9JfqcsUGDG7AdBtgQJk+eDtxtw3m0kJc1V9cMm0FDqWIIaWg5ZLSkS0g7iCgU83DzadwFCrk+gj/XHD+Tv8bFoVWKq30jqQ+S4BJRvp8juZW\
X6XPhwp9HkaiyEmFgzqH9cqPR2cNBw1gJZAaKGQRdi2Xz2dD/2xwGsxI8LFzRMNNjnmgDxc6Ghu9ApZC10GkQzWFvi6HNr76SLizphocShx3s3WhWThU/hHbE7fnBrhlUwlNTrskY3xBxmYDYbAyOqM0iURW82Q6\
lZEjzj5iNouivBJyB8opF0NHdnrYvUpcZ4xMMY4ohVGbHc4ogO+dyXzN1uH8wL3MxjpGmNKfBx4vQLfAYMAbiNYyA6JKv07grDBvMCAZH7OI+A9JnboWqRNyuLwSQeCdcY/T7pXUWuGkYHbpyYwRDWCr0etUgYu8\
rbATDpEiIU9YPoqDm/A6BPOxvAuz7SmIcB1yNlb8ICh9bM/wHHNYA2It7JBYBWMtOfaNaVTNmeiKe/mvMcXAvjsmwVFG/yGTBEOt1R4FepvSJ8gWzmp9a32PZLZErsgSdZq7M1NboIfU1WDKV8dZSuF+XcaIGeDQ\
FLxUfX7pY+RsDmSNnD45+wAqC4o3spfgl+gD8X9aHaZ9lM0tRic15c6GMubk1h6I04ogsHVyyyu5wRBzMXwnfMeOH8SIZGtbm1NKdxrllSoMSKRlSd0SyAaE7VBYY/UxL2gi4FM9snfwCF85PemTk+nqMP0jbGGg\
P/ZlEnKLmq4JoR9MS3psN/EVoRNd+0TWAWrTm1T64qlnNg4wujNHOLctSzo+N6A7oQUZ+BzqLhoyrFD8bnKRnj1oSMpB2Nd0JRbAD+usRzqg6286hC+kBlHHAQly+DNc1aex6AS8r1RKrK9Q27GUGhfgzMEok8uy\
iMHcGg4lCAQhuIdWIxgOlmrUJcg7tSgdD7CMfW7NWRZwDFrryGZRmE7DjDLU8zCN7MYkDqahOTtH0j+Y23RqzQMK8UCdFCpYsHOyTJ8d0lFydeAiyZOJntoN54ZS8ePE1atbPZO9T9sDTd7DBFNwl42Np3+H1pzz\
e5h5y6j826RBp87a16C+Mk8mF/gy4xfMBoNLjnCaYNoF52oF5SUEEpYzKFKi9vBncPizAyD+OVehN5MHSKnQi/O3vvuiPdaU8sqa6xNt0u579C0KdW+tFpAAvIsWeO2j0nstoEEAlJ1ay9jqtPMwA8IwZ4gBKvVW\
RjF35riJCdLRWUwSIY9eOLmY5z6H6NxlMYpSkvHhnZubLoZtM0musH0hIjvi+rfIz36hJbhFO7fpSH7aZI2IxYZYMAMbS84p/t4UW2tnIwZcl25g6kDBlnJYTU8eamGaB1TdJXFtP8+MA7IJZfsy7ou6DI0XiOPD\
2O4wmxS5QS+9vOQLQU7pYmAHuKakyxPJI4CyjQnYkYv+AenXMevHYnq7NYXA9EVjLmHxmYrXubs+rEX6tAtPpWDsxed/ohfvEB95nmnm+RWZH5PEGacu/2CKO701YldzwDbQOq66FtDCt2lXom41Zo+KPgl979NP\
5NMPiiwVCP2gMle5hrmR6b1EECEd4/pcEG4TRr4uxIpMHAWAzdlRwAh1A21gxAshBeDdiidcep+6S14tcMENbfnwZpe9pyXinmXnZVzRwNZx+ABOqwnPYKWADkGTQUvQoJRsvecM3hw6pVMuvlHopoFENfFpJNyS\
cfkf1qf9LLoEtnylVadLsWv+iw0qLHooZfkc6zEo7dFZViPLAby/CBN8bgxLl2vHRBfisvq2fscE2WommK3ggN49iihcX+YFR4fKdHyR3YOlQvaNSkFqTjOUZBsby7kaneN0FzDdMjhgaxeA+ws45NYF1tlAmSJk\
OVoav/mIpln0iISEPNEJz6nlYkMMhonBixBoupZvDnYOIr6bd50XTr5l6Zt4rVFHrvjHxjfbZkMv4ZxDMMUUEabRD9TRFqEbU9Szn4FOXjG7SI4jWklaL9gTbxr937AlzLaUy/kAPIXS/zfcdrvn8CWa47SdKW8n\
/hiHR9SPvI9ww0qFsm/YDj3ykKtcwbDCiHoR5/Rk5BKa3eDkdVpQrMakL5yA73RkjTchM/GCWAvFXOWZjjsW3nyai1btynKkCCX1LmD29e4Gh9exNA3L2cHUTHrKtvhDlO3sek3LAhar/xLKU/5aTdt8tqa98SVC\
5j1nMtlEQhOzWqVt0z9R25rfX9uyPImWFe4e27eOdiai5xztoEsUnDLt0B2ZYFPDPUpDGFh4BBBfkiY0Ht51sdbTgCjZTl+hcYuqdwciPraZgIEKcM1TQf6sKxYYKtmlSEngyUkqs3gl9uvsoeMlkcZYVMLqBf1I\
dU0wtvCjwOIgd/Yy5Jcz8OVyV+zoaEIKDNaCq+hiCTfsVBaqw80e+X6N3Rn10KQ8NCndooa4pqs+KgkTuli/5NufA3sHS0M6Ppw7xOUobe1HZMplztwXC0iQg3dUfvbSmldgiMCq4oHd3uMIbacrAYmiLFgPrmaw\
TtlHPjynS/A8h1vR9tHoSucEurFc2LZe10MGa+MVCNusC6To4sGlZ+plePAzUeFYP3WGnuVHWE3/CEt3kP7YWZfOxBxh4KdCDYKGHDgCdGV+1K4Y3feryXtgngzAHIn0PPrZ4Yrz9jKTvn00eyWsRazdMLFAzK6w\
AmWMgG6BTYRpNSg5owzVmxGX5q5L3Ld4U0BXWoC1pFMwU1NgyeqA9yG5BoVsbq6S2WtosnKK27Imz+NZ4LHgSrswGohrFwWPhuK6M3LucAJtaCSyeCXhrXoGou1ZhHHPGBSp7MV7fZNuhcUncSPfXCCkJWJd7Axs\
hZLqC883RJSj79SpUqjRU42EJkuud9P6dMIy3eI1ktOfxB5IXrE9EE29cKJnGOjsFMsbHzgmNohfLn7smQTdObaIGwzSje98k1Y4Rdo9hLMBAarkzQGG37qgS56I4DlgN6Yob8eAAko8pX1zQKklMvP16rWUZpjS\
LKbr2C/tiCz/HYhsSF5qlYWA4HM12HwR8EoLofAthCdXWggJ9swwJxEHarUKOmdg5lfR1NSnqb6Naei7Cw91912Kzk7IyeNh8kg7T1zAkzpyIAuRyeFKC3FfkJ2sMBKukI17xyK9UDPvHGCiZWrX976lH0AC7CR4\
xQGdY53yFVG0CKrp5xPXUj1Zn74Ktm7Ryvh9Say4Xoi9AglWzpfEV9Z7gYIMnhCT7KDTdQLhM0/7IOByKeEsCnSeFRVAlq3jtr3H9QvFKfo/Zzg3ugKR3VL7wd9F/j29H5BFtnXwAEoysTI7kls4+PGZ7RcUIcfb\
b7svQq7bxEsS63kx+3E1YryMf53Pwy3Pyd/GgD2mwDUpKCAMsrvU1prn2uviYoQKeW63UNMKhxeFFCK1nkV3IW0qJlLBYYJqet/v19jU0ozuxtgR3T0ChknF/xGBx+RuuY4Gr7vQ/LSpBpA3lk6NnfrNERvp2slt\
TGnWXmEqBgnyDbajMy4eQYPiLVGrq9P6Bj0wTCp9drBzm/ZEbtjsDQdZrgr4jP+4sq3aSYxfUbLFp0ukoObel+a3tzk9RHDAqMWf6IgO6mkoKQr16SvKtWZOu19zxEEqeJtMAedxT3/PU+r/IlbXRXPIC7FCwuXR\
t09nLt1Tye3w/q4xYJRvr+WFuwForqZmUF1J+BTewVohshrbg2/B5d45sAuYXckv8PQTuQcGuzDsAw/jS2K5hr+FU7KPgp9CUnyPJBH1P+HvilTwxQU0su1T/owBSoTyKWxmTPW0vTLahGxDF/f6N9ttkp8uf6GC\
Wg76bQyKK7wEI95tsl6f/scPJDuAjbpeyM/aoxU/xFf9kFz1w/iqH9KrfsgGP2DDoA1q4ws0oM/W9gDUI4J3gXeGT3uVYpEv4Ec73UxbO2IfX8BZ4IYq3ki2+C2UFvgYqqRMfqvIviZEPLd8W9vqIS5asEtE1sqF\
9zucKpcLZnYQ86SEPGHrjLRxScHEr8858W9bjH7PaAa5au4R8RZwR7OUi0rx8CoIXgsKqZQcbT979B3JgpqlHBAq2HSQh7LRJakFFBBCtVwaAEfCl8zg8hJS3LBIeixm7yXUc1LsoQhvb2A5cCOX00ZyW4Fv0ugf\
YNzmmjmZY7qIv1ZRxme7Lseqx4VcwcD6mQolxOkNNlSLH57+EOD3H8aYO5k/HYGALOe8swyrtO4zXGsagxi4zSXqMZenlYcUJqDvUHSpbbj/j9/F6xR1LX5TRWZF2cV55fJPtol3WFLHeVj6VMNcpRe4BGuqsSN3\
pap/TQyGs2LhREY3Nm9XmHFliaWP53lj0VGzWHuEn2qxQyqEzma5U4oU6K0l2g0oYA1wN3wnCamersfBdxLUnQDSeJCa6zaj+SNT+IqR/XZn3IYX1fhHuVnol9bjZYAErwjF8HELQxeF8I7XSzZ4SjTOpFyju9WG\
5fgFfbzhsTk5CUgGmAgBNZbb17ghIz5yXmGFwG0wKNfddynItQ6o8D+Xj7u1s7d7P3z88uTk9dsPl91W4CNUQ8DKlzDkCx51d1mQcR6zX6XNClTRvFxGKeg2u8PvL3a31fgyieFMX2Ofy6U0rCj5OweqCrefHEoN\
u3ocFZNgwC9Z3OTqj/HNdS7k6cIEU/kkG5SVRFtoMmzK5+96pa8yssSRJwtZGUeTvOx9e0nGV6vGu2/Ude9QAA+bt7aDW5Vd2B/fL+wcvh6qVRZnkYoixb/QF0V7n7zoLhkm3gdFY89NZ+3XGVAWctT46Y0WlfR4\
g36mztg1FmTptI87fAz83ELpNaTmvD8cIwZzfHxJGMVOnUmRUG+w/x6mbJaHdCZc23jFd7Axjty4xsoZnxAN9DsfE2vjDCBEufEd7bB9us2l8/jpioSqWq7e9MrHmJKsw3Ng1MEKkDjygw24ocyA/5dbEWQ3AfIR\
/48BWXk0qT+dWrnm7/n4vlvZ5t0jOtuy3+HHb/yrwx09qv5XSXrt8aDdKxx3H1HBv8HXVvRgbSxG8j+dofxPT7jGnt+wg4/3DOYs9Ypv4erBeD34PRq040E7GbTTQdsM2mW/rQf70b3xgd/ojfQ/v6NPl7/F84f9\
6Wva0RfS0HU0dR2NDdvpNe3smrb5ZHvxida7T7T6X/NZ1S4/2Z5/ineu/ftSvk2/CEaLLzj3cOfNNVJgsHM92IkeQFH35lvzG7f9Rm/aXoXUvt944Td6CHk/kDSDfdpBuxy063gFl+g/kYv/aCnwW6XEb5Uiv1XK\
/FYpdF37C/+0cl/o7TgwQ86jusWxu0rOibc5Q40/MNRx2iodd+VJwayFz+H7Zm2S5SpRYNbW7xbzX7rOSI2jf/8/INHiGw==\
""")))
ESP32ROM.STUB_CODE = eval(zlib.decompress(base64.b64decode(b"""
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\
ql1jAA==\
""")))

if __name__ == '__main__':
    try:
        main()
    except FatalError as e:
        print '\nA fatal error occurred: %s' % e
        sys.exit(2)
