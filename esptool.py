#!/usr/bin/env python
# NB: Before sending a PR to change the above line to '#!/usr/bin/env python2', please read https://github.com/themadinventor/esptool/issues/21
#
# ESP8266 ROM Bootloader Utility
# https://github.com/themadinventor/esptool
#
# Copyright (C) 2014-2016 Fredrik Ahlberg, Angus Gratton, Cesanta
# Software Limited & other contributors as noted. ESP31 support
# Copyright (C) 2016 Angus Gratton, based in part on esptool.py work
# that was Copyright (C) 2015-2016 Espressif Systems.
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
import json
import os
import serial
import struct
import subprocess
import sys
import tempfile
import time


__version__ = "1.3-dev"

MAX_UINT32 = 0xffffffff
MAX_UINT24 = 0xffffff


class ESPROM(object):
    """ Base class providing access to ESP ROM bootloader. Subclasses provide
    ESP8266, ESP31 & ESP32 specific functionality.

    Don't instantiate this base class directly, either instantiate a subclass or call ESPROM.detect_chip() which will interrogate the chip and return the appropriate subclass instance.

    """
    CHIP_NAME = "Espressif device"

    DEFAULT_PORT = "/dev/ttyUSB0"

    # These are the currently known commands supported by the ROM
    ESP_FLASH_BEGIN = 0x02
    ESP_FLASH_DATA  = 0x03
    ESP_FLASH_END   = 0x04
    ESP_MEM_BEGIN   = 0x05
    ESP_MEM_END     = 0x06
    ESP_MEM_DATA    = 0x07
    ESP_SYNC        = 0x08
    ESP_WRITE_REG   = 0x09
    ESP_READ_REG    = 0x0a

    # Maximum block sized for RAM and Flash writes, respectively.
    ESP_RAM_BLOCK   = 0x1800
    ESP_FLASH_BLOCK = 0x400

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

    def __init__(self, port=DEFAULT_PORT, baud=ESP_ROM_BAUD, do_connect=True):
        """Base constructor for ESPROM objects

        Don't call this constructor, either instantiate ESP8266ROM,
        ESP31ROM, or ESP32ROM, or use ESPROM.detect_chip().

        """
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
        the same address on ESP8266 & ESP31/32 so we can use one
        memory read and compare to the datecode register for each chip
        type.

        """
        detect_port = ESPROM(port, baud, True)
        sys.stdout.write('Detecting chip type... ')
        date_reg = detect_port.read_reg(ESPROM.UART_DATA_REG_ADDR)
        for cls in [ESP8266ROM, ESP31ROM, ESP32ROM]:
            if date_reg == cls.DATE_REG_VALUE:
                inst = cls(port, baud, False)  # don't connect a second time
                print '%s' % inst.CHIP_NAME
                return inst
        print ''
        raise FatalError("Unexpected UART datecode value 0x%08x. Failed to autodetect chip type." % date_reg)

    """ Read a SLIP packet from the serial port """
    def read(self):
        return self._slip_reader.next()

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
    def command(self, op=None, data=None, chk=0):
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
            body = p[8:]
            if op is None or op_ret == op:
                return val, body  # valid response received

        raise FatalError("Response doesn't match request")

    """ Perform a connection test """
    def sync(self):
        self.command(ESPROM.ESP_SYNC, '\x07\x07\x12\x20' + 32 * '\x55')
        for i in xrange(7):
            self.command()

    """ Try connecting repeatedly until successful, or giving up """
    def connect(self):
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
            for _ in xrange(4):
                try:
                    self._port.flushInput()
                    self._slip_reader = slip_reader(self._port)
                    self._port.flushOutput()
                    self.sync()
                    self._port.timeout = 5
                    return
                except:
                    time.sleep(0.05)
        raise FatalError('Failed to connect to %s' % self.CHIP_NAME)

    """ Read memory address in target """
    def read_reg(self, addr):
        res = self.command(ESPROM.ESP_READ_REG, struct.pack('<I', addr))
        if res[1] != "\0\0":
            raise FatalError('Failed to read target memory')
        return res[0]

    """ Write to memory address in target """
    def write_reg(self, addr, value, mask, delay_us=0):
        if self.command(ESPROM.ESP_WRITE_REG,
                        struct.pack('<IIII', addr, value, mask, delay_us))[1] != "\0\0":
            raise FatalError('Failed to write target memory')

    """ Start downloading an application image to RAM """
    def mem_begin(self, size, blocks, blocksize, offset):
        if self.command(ESPROM.ESP_MEM_BEGIN,
                        struct.pack('<IIII', size, blocks, blocksize, offset))[1] != "\0\0":
            raise FatalError('Failed to enter RAM download mode')

    """ Send a block of an image to RAM """
    def mem_block(self, data, seq):
        if self.command(ESPROM.ESP_MEM_DATA,
                        struct.pack('<IIII', len(data), seq, 0, 0) + data,
                        ESPROM.checksum(data))[1] != "\0\0":
            raise FatalError('Failed to write to target RAM')

    """ Leave download mode and run the application """
    def mem_finish(self, entrypoint=0):
        if self.command(ESPROM.ESP_MEM_END,
                        struct.pack('<II', int(entrypoint == 0), entrypoint))[1] != "\0\0":
            raise FatalError('Failed to leave RAM download mode')

    """ Start downloading to Flash (performs an erase) """
    def flash_begin(self, size, offset):
        old_tmo = self._port.timeout
        num_blocks = (size + ESPROM.ESP_FLASH_BLOCK - 1) / ESPROM.ESP_FLASH_BLOCK

        sectors_per_block = 16
        sector_size = self.ESP_FLASH_SECTOR
        num_sectors = (size + sector_size - 1) / sector_size
        start_sector = offset / sector_size

        head_sectors = sectors_per_block - (start_sector % sectors_per_block)
        if num_sectors < head_sectors:
            head_sectors = num_sectors

        if num_sectors < 2 * head_sectors:
            erase_size = (num_sectors + 1) / 2 * sector_size
        else:
            erase_size = (num_sectors - head_sectors) * sector_size

        self._port.timeout = 20
        t = time.time()
        result = self.command(ESPROM.ESP_FLASH_BEGIN,
                              struct.pack('<IIII', erase_size, num_blocks, ESPROM.ESP_FLASH_BLOCK, offset))[1]
        if size != 0:
            print "Took %.2fs to erase flash block" % (time.time() - t)
        if result != "\0\0":
            raise FatalError.WithResult('Failed to enter Flash download mode (result "%s")', result)
        self._port.timeout = old_tmo

    """ Write block to flash """
    def flash_block(self, data, seq):
        result = self.command(ESPROM.ESP_FLASH_DATA,
                              struct.pack('<IIII', len(data), seq, 0, 0) + data,
                              ESPROM.checksum(data))[1]
        if result != "\0\0":
            raise FatalError.WithResult('Failed to write to target Flash after seq %d (got result %%s)' % seq, result)

    """ Leave flash mode and run/reboot """
    def flash_finish(self, reboot=False):
        pkt = struct.pack('<I', int(not reboot))
        if self.command(ESPROM.ESP_FLASH_END, pkt)[1] != "\0\0":
            raise FatalError('Failed to leave Flash mode')

    """ Run application code in flash """
    def run(self, reboot=False):
        # Fake flash begin immediately followed by flash end
        self.flash_begin(0, 0)
        self.flash_finish(reboot)

    """ Read SPI flash manufacturer and device id """
    def flash_id(self):
        self.flash_begin(0, 0)
        self.write_reg(self.SPI_W0_REG_ADDR, 0x0, MAX_UINT32)
        self.write_reg(self.SPI_CMD_REG_ADDR, self.SPI_CMD_READ_ID, MAX_UINT32)
        flash_id = self.read_reg(self.SPI_W0_REG_ADDR)
        self.flash_finish(False)
        return flash_id

    """ Abuse the loader protocol to force flash to be left in write mode """
    def flash_unlock_dio(self):
        # Enable flash write mode
        self.flash_begin(0, 0)
        # Reset the chip rather than call flash_finish(), which would have
        # write protected the chip again (why oh why does it do that?!)
        self.mem_begin(0,0,0,0x40100000)
        self.mem_finish(0x40000080)

    def run_stub(self, stub, params, read_output=False):
        stub = dict(stub)
        stub = stub[self.STUB_FLASHER_KEY]
        stub['code'] = unhexify(stub['code'])
        if 'data' in stub:
            stub['data'] = unhexify(stub['data'])

        if stub['num_params'] != len(params):
            raise FatalError('Stub requires %d params, %d provided'
                             % (stub['num_params'], len(params)))

        params = struct.pack('<' + ('I' * stub['num_params']), *params)
        pc = params + stub['code']

        # Upload
        self.flash_begin(0, 0)
        self.mem_begin(len(pc), 1, len(pc), stub['params_start'])
        self.mem_block(pc, 0)
        if 'data' in stub:
            self.mem_begin(len(stub['data']), 1, len(stub['data']), stub['data_start'])
            self.mem_block(stub['data'], 0)
        self.mem_finish(stub['entry'])

        if read_output:
            print 'Stub executed, reading response:'
            while True:
                p = self.read()
                print hexify(p)
                if p == '':
                    return


class ESP8266ROM(ESPROM):
    """ Access class for ESP8266 ROM bootloader
    """
    CHIP_NAME = "ESP8266EX"
    STUB_FLASHER_KEY = "stub_flasher_8266"

    DATE_REG_VALUE = 0x00062000

    # OTP ROM addresses
    ESP_OTP_MAC0    = 0x3ff00050
    ESP_OTP_MAC1    = 0x3ff00054
    ESP_OTP_MAC3    = 0x3ff0005c

    SPI_CMD_REG_ADDR = 0x60000200
    SPI_W0_REG_ADDR = 0x60000240

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


class ESP31ROM(ESPROM):
    """ Access class for ESP31 ROM bootloader
    """
    CHIP_NAME = "ESP31"
    STUB_FLASHER_KEY = "stub_flasher_31"

    DATE_REG_VALUE = 0x15052100

    SPI_CMD_REG_ADDR = 0x60003000
    SPI_W0_REG_ADDR = 0x60003040

    def read_efuse(self, n):
        """ Read the nth word of the ESP3x EFUSE region. """
        return 0x6001a000 + (4 * n)

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


class ESP32ROM(ESP31ROM):
    """Access class for ESP32 ROM bootloader

    ESP32 is currently not available, so this class is based on a UART
    date register value given by Espressif and the assumption that
    ESP31 code will otherwise work.

    """
    CHIP_NAME = "ESP32"

    DATE_REG_VALUE = 0x15122500


class ESPBOOTLOADER(object):
    """ These are constants related to software ESP bootloader, working with 'v2' image files """

    # First byte of the "v2" application image
    IMAGE_V2_MAGIC = 0xea

    # First 'segment' value in a "v2" application image, appears to be a constant version value?
    IMAGE_V2_SEGMENT = 4


def LoadFirmwareImage(filename):
    """ Load a firmware image, without knowing what kind of file (v1 or v2) it is.

        Returns a BaseFirmwareImage subclass, either ESPFirmwareImage (v1) or OTAFirmwareImage (v2).
    """
    with open(filename, 'rb') as f:
        magic = ord(f.read(1))
        f.seek(0)
        if magic == ESPROM.ESP_IMAGE_MAGIC:
            return ESPFirmwareImage(f)
        elif magic == ESPBOOTLOADER.IMAGE_V2_MAGIC:
            return OTAFirmwareImage(f)
        else:
            raise FatalError("Invalid image magic number: %d" % magic)


class BaseFirmwareImage(object):
    """ Base class with common firmware image functions """
    def __init__(self):
        self.segments = []
        self.entrypoint = 0

    def add_segment(self, addr, data, pad_to=4):
        """ Add a segment to the image, with specified address & data
        (padded to a boundary of pad_to size) """
        # Data should be aligned on word boundary
        l = len(data)
        if l % pad_to:
            data += b"\x00" * (pad_to - l % pad_to)
        if l > 0:
            self.segments.append((addr, len(data), data))

    def load_segment(self, f, is_irom_segment=False):
        """ Load the next segment from the image file """
        (offset, size) = struct.unpack('<II', f.read(8))
        if not is_irom_segment:
            if offset > 0x40200000 or offset < 0x3ffe0000 or size > 65536:
                raise FatalError('Suspicious segment 0x%x, length %d' % (offset, size))
        segment_data = f.read(size)
        if len(segment_data) < size:
            raise FatalError('End of file reading segment 0x%x, length %d (actual length %d)' % (offset, size, len(segment_data)))
        segment = (offset, size, segment_data)
        self.segments.append(segment)
        return segment

    def save_segment(self, f, segment, checksum=None):
        """ Save the next segment to the image file, return next checksum value if provided """
        (offset, size, data) = segment
        f.write(struct.pack('<II', offset, size))
        f.write(data)
        if checksum is not None:
            return ESPROM.checksum(data, checksum)

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

    def write_v1_header(self, f, segments):
        f.write(struct.pack('<BBBBI', ESPROM.ESP_IMAGE_MAGIC, len(segments),
                            self.flash_mode, self.flash_size_freq, self.entrypoint))


class ESPFirmwareImage(BaseFirmwareImage):
    """ 'Version 1' firmware image, segments loaded directly by the ROM bootloader. """
    def __init__(self, load_file=None):
        super(ESPFirmwareImage, self).__init__()
        self.flash_mode = 0
        self.flash_size_freq = 0
        self.version = 1

        if load_file is not None:
            (magic, segments, self.flash_mode, self.flash_size_freq, self.entrypoint) = struct.unpack('<BBBBI', load_file.read(8))

            # some sanity check
            if magic != ESPROM.ESP_IMAGE_MAGIC or segments > 16:
                raise FatalError('Invalid firmware image magic=%d segments=%d' % (magic, segments))

            for i in xrange(segments):
                self.load_segment(load_file)
            self.checksum = self.read_checksum(load_file)

    def save(self, filename):
        with open(filename, 'wb') as f:
            self.write_v1_header(f, self.segments)
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
            (magic, segments, first_flash_mode, first_flash_size_freq, first_entrypoint) = struct.unpack('<BBBBI', load_file.read(8))

            # some sanity check
            if magic != ESPBOOTLOADER.IMAGE_V2_MAGIC:
                raise FatalError('Invalid V2 image magic=%d' % (magic))
            if segments != 4:
                # segment count is not really segment count here, but we expect to see '4'
                print 'Warning: V2 header has unexpected "segment" count %d (usually 4)' % segments

            # irom segment comes before the second header
            self.load_segment(load_file, True)

            (magic, segments, self.flash_mode, self.flash_size_freq, self.entrypoint) = struct.unpack('<BBBBI', load_file.read(8))

            if first_flash_mode != self.flash_mode:
                print('WARNING: Flash mode value in first header (0x%02x) disagrees with second (0x%02x). Using second value.'
                      % (first_flash_mode, self.flash_mode))
            if first_flash_size_freq != self.flash_size_freq:
                print('WARNING: Flash size/freq value in first header (0x%02x) disagrees with second (0x%02x). Using second value.'
                      % (first_flash_size_freq, self.flash_size_freq))
            if first_entrypoint != self.entrypoint:
                print('WARNING: Enterypoint address in first header (0x%08x) disagrees with second header (0x%08x). Using second value.'
                      % (first_entrypoint, self.entrypoint))

            if magic != ESPROM.ESP_IMAGE_MAGIC or segments > 16:
                raise FatalError('Invalid V2 second header magic=%d segments=%d' % (magic, segments))

            # load all the usual segments
            for _ in xrange(segments):
                self.load_segment(load_file)
            self.checksum = self.read_checksum(load_file)

    def save(self, filename):
        with open(filename, 'wb') as f:
            # Save first header for irom0 segment
            f.write(struct.pack('<BBBBI', ESPBOOTLOADER.IMAGE_V2_MAGIC, ESPBOOTLOADER.IMAGE_V2_SEGMENT,
                                self.flash_mode, self.flash_size_freq, self.entrypoint))

            # irom0 segment identified by load address zero
            irom_segments = [segment for segment in self.segments if segment[0] == 0]
            if len(irom_segments) != 1:
                raise FatalError('Found %d segments that could be irom0. Bad ELF file?' % len(irom_segments))
            # save irom0 segment
            irom_segment = irom_segments[0]
            self.save_segment(f, irom_segment)

            # second header, matches V1 header and contains loadable segments
            normal_segments = [s for s in self.segments if s != irom_segment]
            self.write_v1_header(f, normal_segments)
            checksum = ESPROM.ESP_CHECKSUM_MAGIC
            for segment in normal_segments:
                checksum = self.save_segment(f, segment, checksum)
            self.append_checksum(f, checksum)


class ELFFile(object):
    def __init__(self, name):
        self.name = binutils_safe_path(name)
        self.symbols = None

    def _fetch_symbols(self):
        if self.symbols is not None:
            return
        self.symbols = {}
        try:
            tool_nm = "xtensa-lx106-elf-nm"
            if os.getenv('XTENSA_CORE') == 'lx106':
                tool_nm = "xt-nm"
            proc = subprocess.Popen([tool_nm, self.name], stdout=subprocess.PIPE)
        except OSError:
            print "Error calling %s, do you have Xtensa toolchain in PATH?" % tool_nm
            sys.exit(1)
        for l in proc.stdout:
            fields = l.strip().split()
            try:
                if fields[0] == "U":
                    print "Warning: ELF binary has undefined symbol %s" % fields[1]
                    continue
                if fields[0] == "w":
                    continue  # can skip weak symbols
                self.symbols[fields[2]] = int(fields[0], 16)
            except ValueError:
                raise FatalError("Failed to strip symbol output from nm: %s" % fields)

    def get_symbol_addr(self, sym):
        self._fetch_symbols()
        return self.symbols[sym]

    def get_entry_point(self):
        tool_readelf = "xtensa-lx106-elf-readelf"
        if os.getenv('XTENSA_CORE') == 'lx106':
            tool_readelf = "xt-readelf"
        try:
            proc = subprocess.Popen([tool_readelf, "-h", self.name], stdout=subprocess.PIPE)
        except OSError:
            print "Error calling %s, do you have Xtensa toolchain in PATH?" % tool_readelf
            sys.exit(1)
        for l in proc.stdout:
            fields = l.strip().split()
            if fields[0] == "Entry":
                return int(fields[3], 0)

    def load_section(self, section):
        tool_objcopy = "xtensa-lx106-elf-objcopy"
        if os.getenv('XTENSA_CORE') == 'lx106':
            tool_objcopy = "xt-objcopy"
        tmpsection = binutils_safe_path(tempfile.mktemp(suffix=".section"))
        try:
            subprocess.check_call([tool_objcopy, "--only-section", section, "-Obinary", self.name, tmpsection])
            with open(tmpsection, "rb") as f:
                data = f.read()
        finally:
            os.remove(tmpsection)
        return data


class Flasher(object):

    # From stub_flasher.h
    CMD_FLASH_WRITE = 1
    CMD_FLASH_READ = 2
    CMD_FLASH_DIGEST = 3
    CMD_FLASH_ERASE_CHIP = 5
    CMD_BOOT_FW = 6

    def __init__(self, esp, baud_rate=0):
        print 'Running flasher stub...'
        if baud_rate <= ESPROM.ESP_ROM_BAUD:  # don't change baud rates if we already synced at that rate
            baud_rate = 0
        self._esp = esp
        esp.run_stub(json.loads(_CESANTA_FLASHER_STUB), [baud_rate])
        if baud_rate > 0:
            esp._port.baudrate = baud_rate
        # Read the greeting.
        p = esp.read()
        if p != 'OHAI':
            raise FatalError('Failed to connect to the flasher (got %s)' % hexify(p))

        # flasher sends a response header with some of its params
        # some of these could be dynamic
        startup_params = esp.read()
        if len(startup_params) != 8:
            raise FatalError('Failed to read block sizes back from the flasher (got %r)' % startup_params)
        (self._write_block_len, self._max_writeahead) = struct.unpack('<II', startup_params)

    def flash_write(self, addr, data, show_progress=False):
        assert addr % self._esp.ESP_FLASH_SECTOR == 0, 'Address must be sector-aligned'
        assert len(data) % self._esp.ESP_FLASH_SECTOR == 0, 'Length must be sector-aligned'
        sys.stdout.write('Writing %d @ 0x%x... ' % (len(data), addr))
        sys.stdout.flush()
        self._esp.write(struct.pack('<B', self.CMD_FLASH_WRITE))
        self._esp.write(struct.pack('<III', addr, len(data), 1))
        num_sent, num_written = 0, 0
        while num_written < len(data):
            p = self._esp.read()
            if len(p) == 4:
                num_written = struct.unpack('<I', p)[0]
            elif len(p) == 1:
                status_code = struct.unpack('<B', p)[0]
                raise FatalError('Write failure, status: %x' % status_code)
            else:
                raise FatalError('Unexpected packet while writing: %s' % hexify(p))
            if show_progress:
                progress = '%d (%d %%)' % (num_written, num_written * 100.0 / len(data))
                sys.stdout.write(progress + '\b' * len(progress))
                sys.stdout.flush()
            while num_sent - num_written < self._max_writeahead:
                self._esp._port.write(data[num_sent:num_sent + self._write_block_len])
                num_sent += self._write_block_len
        p = self._esp.read()
        if len(p) != 16:
            raise FatalError('Expected digest, got: %s' % hexify(p))
        digest = hexify(p).upper()
        expected_digest = hashlib.md5(data).hexdigest().upper()
        print
        if digest != expected_digest:
            raise FatalError('Digest mismatch: expected %s, got %s' % (expected_digest, digest))
        p = self._esp.read()
        if len(p) != 1:
            raise FatalError('Expected status, got: %s' % hexify(p))
        status_code = struct.unpack('<B', p)[0]
        if status_code != 0:
            raise FatalError('Write failure, status: %x' % status_code)

    def flash_read(self, addr, length, show_progress=False):
        sys.stdout.write('Reading %d @ 0x%x... ' % (length, addr))
        sys.stdout.flush()
        self._esp.write(struct.pack('<B', self.CMD_FLASH_READ))
        # USB may not be able to keep up with the read rate, especially at
        # higher speeds. Since we don't have flow control, this will result in
        # data loss. Hence, we use small packet size and only allow small
        # number of bytes in flight, which we can reasonably expect to fit in
        # the on-chip FIFO. max_in_flight = 64 works for CH340G, other chips may
        # have longer FIFOs and could benefit from increasing max_in_flight.
        self._esp.write(struct.pack('<IIII', addr, length, 32, 64))
        data = ''
        while True:
            p = self._esp.read()
            data += p
            self._esp.write(struct.pack('<I', len(data)))
            if show_progress and (len(data) % 1024 == 0 or len(data) == length):
                progress = '%d (%d %%)' % (len(data), len(data) * 100.0 / length)
                sys.stdout.write(progress + '\b' * len(progress))
                sys.stdout.flush()
            if len(data) == length:
                break
            if len(data) > length:
                raise FatalError('Read more than expected')
        p = self._esp.read()
        if len(p) != 16:
            raise FatalError('Expected digest, got: %s' % hexify(p))
        expected_digest = hexify(p).upper()
        digest = hashlib.md5(data).hexdigest().upper()
        print
        if digest != expected_digest:
            raise FatalError('Digest mismatch: expected %s, got %s' % (expected_digest, digest))
        p = self._esp.read()
        if len(p) != 1:
            raise FatalError('Expected status, got: %s' % hexify(p))
        status_code = struct.unpack('<B', p)[0]
        if status_code != 0:
            raise FatalError('Write failure, status: %x' % status_code)
        return data

    def flash_digest(self, addr, length, digest_block_size=0):
        self._esp.write(struct.pack('<B', self.CMD_FLASH_DIGEST))
        self._esp.write(struct.pack('<III', addr, length, digest_block_size))
        digests = []
        while True:
            p = self._esp.read()
            if len(p) == 16:
                digests.append(p)
            elif len(p) == 1:
                status_code = struct.unpack('<B', p)[0]
                if status_code != 0:
                    raise FatalError('Write failure, status: %x' % status_code)
                break
            else:
                raise FatalError('Unexpected packet: %s' % hexify(p))
        return digests[-1], digests[:-1]

    def boot_fw(self):
        self._esp.write(struct.pack('<B', self.CMD_BOOT_FW))
        p = self._esp.read()
        if len(p) != 1:
            raise FatalError('Expected status, got: %s' % hexify(p))
        status_code = struct.unpack('<B', p)[0]
        if status_code != 0:
            raise FatalError('Boot failure, status: %x' % status_code)

    def flash_erase(self):
        self._esp.write(struct.pack('<B', self.CMD_FLASH_ERASE_CHIP))
        p = self._esp.read()
        if len(p) != 1:
            raise FatalError('Expected status, got: %s' % hexify(p))
        status_code = struct.unpack('<B', p)[0]
        if status_code != 0:
            raise FatalError('Chip erase failure, status: %x' % status_code)


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


def binutils_safe_path(p):
    """Returns a 'safe' version of path 'p' to pass to binutils

    Only does anything under Cygwin Python, where cygwin paths need to
    be translated to Windows paths if the binutils wasn't compiled
    using Cygwin (should also work with binutils compiled using
    Cygwin, see #73.)
    """
    if sys.platform == "cygwin":
        try:
            return subprocess.check_output(["cygpath", "-w", p]).rstrip('\n')
        except subprocess.CalledProcessError:
            print "WARNING: Failed to call cygpath to sanitise Cygwin path."
    return p


def align_file_position(f, size):
    """ Align the position in the file to the next block of specified size """
    align = (size - 1) - (f.tell() % size)
    f.seek(align, 1)


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
        Return a fatal error object that includes the hex values of
        'result' as a string formatted argument.
        """
        return FatalError(message % ", ".join(hex(ord(x)) for x in result))


# "Operation" commands, executable at command line. One function each
#
# Each function takes either two args (<ESPROM instance>, <args>) or a single <args>
# argument.

def load_ram(esp, args):
    image = LoadFirmwareImage(args.filename)

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
    flash_mode = {'qio':0, 'qout':1, 'dio':2, 'dout': 3}[args.flash_mode]
    flash_size_freq = {'4m':0x00, '2m':0x10, '8m':0x20, '16m':0x30, '32m':0x40, '16m-c1': 0x50, '32m-c1':0x60, '32m-c2':0x70}[args.flash_size]
    flash_size_freq += {'40m':0, '26m':1, '20m':2, '80m': 0xf}[args.flash_freq]
    flash_params = struct.pack('BB', flash_mode, flash_size_freq)

    flasher = Flasher(esp, args.baud)

    for address, argfile in args.addr_filename:
        image = argfile.read()
        argfile.seek(0)  # rewind in case we need it again
        # Fix sflash config data.
        if address == 0 and image[0] == '\xe9':
            print 'Flash params set to 0x%02x%02x' % (flash_mode, flash_size_freq)
            image = image[0:2] + flash_params + image[4:]
        # Pad to sector size, which is the minimum unit of writing (erasing really).
        if len(image) % esp.ESP_FLASH_SECTOR != 0:
            image += '\xff' * (esp.ESP_FLASH_SECTOR - (len(image) % esp.ESP_FLASH_SECTOR))
        t = time.time()
        flasher.flash_write(address, image, not args.no_progress)
        t = time.time() - t
        print ('\rWrote %d bytes at 0x%x in %.1f seconds (%.1f kbit/s)...'
               % (len(image), address, t, len(image) / t * 8 / 1000))
    print 'Leaving...'
    if args.verify:
        print 'Verifying just-written flash...'
        _verify_flash(flasher, args, flash_params)
    flasher.boot_fw()


def image_info(args):
    image = LoadFirmwareImage(args.filename)
    print('Image version: %d' % image.version)
    print('Entry point: %08x' % image.entrypoint) if image.entrypoint != 0 else 'Entry point not set'
    print '%d segments' % len(image.segments)
    print
    checksum = ESPROM.ESP_CHECKSUM_MAGIC
    for (idx, (offset, size, data)) in enumerate(image.segments):
        if image.version == 2 and idx == 0:
            print 'Segment 1: %d bytes IROM0 (no load address)' % size
        else:
            print 'Segment %d: %5d bytes at %08x' % (idx + 1, size, offset)
            checksum = ESPROM.checksum(data, checksum)
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
        image.add_segment(addr, data)
    image.entrypoint = args.entrypoint
    image.save(args.output)


def elf2image(args):
    e = ELFFile(args.input)
    if args.version == '1':
        image = ESPFirmwareImage()
    else:
        image = OTAFirmwareImage()
        irom_data = e.load_section('.irom0.text')
        if len(irom_data) == 0:
            raise FatalError(".irom0.text section not found in ELF file - can't create V2 image.")
        image.add_segment(0, irom_data, 16)
    image.entrypoint = e.get_entry_point()
    for section, start in ((".text", "_text_start"), (".data", "_data_start"), (".rodata", "_rodata_start")):
        data = e.load_section(section)
        image.add_segment(e.get_symbol_addr(start), data)

    image.flash_mode = {'qio':0, 'qout':1, 'dio':2, 'dout': 3}[args.flash_mode]
    image.flash_size_freq = {'4m':0x00, '2m':0x10, '8m':0x20, '16m':0x30, '32m':0x40, '16m-c1': 0x50, '32m-c1':0x60, '32m-c2':0x70}[args.flash_size]
    image.flash_size_freq += {'40m':0, '26m':1, '20m':2, '80m': 0xf}[args.flash_freq]

    irom_offs = e.get_symbol_addr("_irom0_text_start") - 0x40200000

    if args.version == '1':
        if args.output is None:
            args.output = args.input + '-'
        image.save(args.output + "0x00000.bin")
        data = e.load_section(".irom0.text")
        if irom_offs < 0:
            raise FatalError('Address of symbol _irom0_text_start in ELF is located before flash mapping address. Bad linker script?')
        if (irom_offs & 0xFFF) != 0:  # irom0 isn't flash sector aligned
            print "WARNING: irom0 section offset is 0x%08x. ELF is probably linked for 'elf2image --version=2'" % irom_offs
        with open(args.output + "0x%05x.bin" % irom_offs, "wb") as f:
            f.write(data)
            f.close()
    else:  # V2 OTA image
        if args.output is None:
            args.output = "%s-0x%05x.bin" % (os.path.splitext(args.input)[0], irom_offs & ~(ESPROM.ESP_FLASH_SECTOR - 1))
        image.save(args.output)


def read_mac(esp, args):
    mac = esp.read_mac()
    print 'MAC: %s' % ':'.join(map(lambda x: '%02x' % x, mac))


def chip_id(esp, args):
    chipid = esp.chip_id()
    print 'Chip ID: 0x%08x' % chipid


def erase_flash(esp, args):
    print 'Erasing flash (this may take a while)...'
    flasher = Flasher(esp, args.baud)
    flasher.flash_erase()
    print 'Erase completed successfully.'


def run(esp, args):
    esp.run()


def flash_id(esp, args):
    flash_id = esp.flash_id()
    print 'Manufacturer: %02x' % (flash_id & 0xff)
    print 'Device: %02x%02x' % ((flash_id >> 8) & 0xff, (flash_id >> 16) & 0xff)


def read_flash(esp, args):
    flasher = Flasher(esp, args.baud)
    t = time.time()
    data = flasher.flash_read(args.address, args.size, not args.no_progress)
    t = time.time() - t
    print ('\rRead %d bytes at 0x%x in %.1f seconds (%.1f kbit/s)...'
           % (len(data), args.address, t, len(data) / t * 8 / 1000))
    file(args.filename, 'wb').write(data)


def _verify_flash(flasher, args, flash_params=None):
    differences = False
    for address, argfile in args.addr_filename:
        image = argfile.read()
        argfile.seek(0)  # rewind in case we need it again
        if address == 0 and image[0] == '\xe9' and flash_params is not None:
            image = image[0:2] + flash_params + image[4:]
        image_size = len(image)
        print 'Verifying 0x%x (%d) bytes @ 0x%08x in flash against %s...' % (image_size, image_size, address, argfile.name)
        # Try digest first, only read if there are differences.
        digest, _ = flasher.flash_digest(address, image_size)
        digest = hexify(digest).upper()
        expected_digest = hashlib.md5(image).hexdigest().upper()
        if digest == expected_digest:
            print '-- verify OK (digest matched)'
            continue
        else:
            differences = True
            if getattr(args, 'diff', 'no') != 'yes':
                print '-- verify FAILED (digest mismatch)'
                continue

        flash = flasher.flash_read(address, image_size)
        assert flash != image
        diff = [i for i in xrange(image_size) if flash[i] != image[i]]
        print '-- verify FAILED: %d differences, first @ 0x%08x' % (len(diff), address + diff[0])
        for d in diff:
            print '   %08x %02x %02x' % (address + d, ord(flash[d]), ord(image[d]))
    if differences:
        raise FatalError("Verify failed.")


def verify_flash(esp, args, flash_params=None):
    flasher = Flasher(esp)
    _verify_flash(flasher, args, flash_params)


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
        parent.add_argument('--flash_size', '-fs', help='SPI Flash size in Mbit', type=str.lower,
                            choices=['4m', '2m', '8m', '16m', '32m', '16m-c1', '32m-c1', '32m-c2'],
                            default=os.environ.get('ESPTOOL_FS', '4m'))

    parser_write_flash = subparsers.add_parser(
        'write_flash',
        help='Write a binary blob to flash')
    parser_write_flash.add_argument('addr_filename', metavar='<address> <filename>', help='Address followed by binary filename, separated by space',
                                    action=AddrFilenamePairAction)
    add_spi_flash_subparsers(parser_write_flash)
    parser_write_flash.add_argument('--no-progress', '-p', help='Suppress progress output', action="store_true")
    parser_write_flash.add_argument('--verify', help='Verify just-written data (only necessary if very cautious, data is already CRCed', action='store_true')

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
            'esp31': ESP31ROM,
            'esp32': ESP32ROM,
        }[args.chip]
        esp = chip_constructor_fun(args.port, initial_baud)
        operation_func(esp, args)
    else:
        operation_func(args)


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

# This is "wrapped" stub_flasher.c for ESP8266 & ESP31/32, to be loaded using run_stub.
_CESANTA_FLASHER_STUB = """
{"stub_flasher_8266": {"code": "0000006051FFFF32D218C0200078258D05C020004875404074DCC48608006823C0200098081BA6\
A92392460068031B666903682337360129230B446604DFC6F3FFC0200079450DF00000010078480040004A0040B449004012C1F0C921D9\
11E901DD0209312020B4ED033C2C56C2073020B43C3C56420701F5FFC000003C4C569206CD0EEADD860300202C4101F1FFC0000056A204\
C2DCF0C02DC0CC6CCAE2D1EAFF0606002030F456D3FD86FBFF00002020F501E8FFC00000EC82D0CCC0C02EC0C73DEB2ADC460300202C41\
01E1FFC00000DC42C2DCF0C02DC056BCFEC602003C5C8601003C6C4600003C7C08312D0CD811C821E80112C1100DF0000C180000080010\
40741800006418000080180000841800009018000018980040880F0040A80F00404C4A004034980040980F00400099004012C1E091F7FF\
C961CD0221F3FFE941F9310971D9519011C01A223902E2D1180C02226E1D21E9FF31EDFF2AF11A332D0F42630001ECFFC00000C030B43C\
2256231321E5FF1A2228022030B43C3256331201B2FFC00000DD023C42566D1131DBFF4D010C52D90E192E126E0101DFFFC000002196FF\
32A101C0200039322C0201DBFFC000000627000031D5FF1A333803BCC322D20427BD3731D0FF1A333803D023C0319CFF27B318C020F4DC\
22C020F5019CFFC0000056D20A2197FF2ADD860300C02C410196FFC0000056F209D2DD1032A3FFC02000280E27B3F7381EC02C2042A400\
01C3FFC00000566208206300380E32D3FC390E20E613102000381E2D0F42A40001BCFFC00000222E1DC2DC0422D204226E1D281E22D204\
E7B204291E860000126E0121ABFF32A0042A21854D0031AAFF222E1D1A33380337B20206D2FF2C0201ADFFC0000021A3FF319FFF1A223A\
3101AAFFC00000219FFF1C031A22854A000C024603003C52060200003C62860000003C72919BFF9A110871C861D851E841F83112C1200D\
F00010000068100000581000007010000074100000781000007C100000801000001C4B004091FEFF12C1E061F8FFC961E941F9310971D9\
519011C01A66290621F4FFC2D1101A22390231F3FF0C0F1A33590331EBFFF26C1AED045C2247B3028635002D0C017EFFC0000021E6FF41\
EBFF2A611A4469044621000021E5FF1A222802F0D2C0D7BE01DD0E31E1FF4D0D1A3328033D0101E3FFC0000056D2082D01D03D20C53D00\
4D0D2D0C3D010170FFC0000041D7FFDAFF1A444804D0648041D4FF1A4462640061D3FF106680622600673F1331D2FF10338028030C4345\
40002642174613000041CCFF222C1A1A444804202FC047328406F6FF00222C1A273F3761C4FF222C1A1066806226006732B621BEFFC03C\
201A220157FFC0000021BBFF1C031A22C535000C024603005C3206020000005C424600005C5291B9FF9A110871C861D851E841F83112C1\
200DF0B0100000C0100000D010000012C1E091FEFFC961D951E9410971F931CD039011C0ED02DD0431A3FF9C1422A06247B302062C0021\
F4FF1A22490286010021F1FF1A223902219EFF2AF12D0F0131FFC00000861B0022D110012EFFC0000021E9FFFD0C1A222802C7B20621E6\
FF1A22F8022D0E3D014D0F0197FFC000008C5222A063C6170000218DFF3D011A22F04F200124FFC00000AC4D22D1103D014D0F0120FFC0\
000021D7FF32D110102280011EFFC0000021D3FF1C031A22852700F0EE80F0CCC056DCF821CEFF317CFF1022803031800115FFC0000021\
CAFF1C031A224525002D0C91C9FF9A110871C861D851E841F83112C1200DF00002006000000010FFFFFF0012C1E021FCFF31FCFF0971C2\
6106C02000326200C02000C80230CC10564CFFC0200032221021F5FF20231029010C432D01C51F0008712D0CC86112C1200DF0000080FE\
3F8449004012C1D0C9A109B17CFC22C1110C13852300261202462F00220111C24110B68202462A0031F5FF3022A02802A002002D011C03\
45210066820B280132210145ACFF060600003C128604002D011C03851F0066A20E28013811482145B8FF224110861A004C1206FDFF2D01\
1C03C51D0066B20E280138114821583105D1FF06F7FF005C1286F5FF0010212032A010851B0066A20D2221003811482145E2FF06EFFF00\
22A06146EDFF05F1FFC6EBFF000001D3FFC0000006E9FF000C022241100C1322C110451200220111060600000022C1100C134511002201\
1132C2FA303074B6230206C9FF08B1C8A112C1300DF00000004F4841491027000000001040007519032080FE3F00110040A8100040BC0F\
0040583F0040CC2E004088DC00408000004021F4FF12C1E029210C020971C2610601F7FFC0000001F6FFC0000021EEFF01F5FFC0000021\
EDFFC020003802AC03C02000380221EAFF304F0530448040412120248001EDFFC000003151FEC0200029538B210C4305070021E2FF3802\
2812390129110C832D0105060045E7FF20C22021D9FF01E0FFC00000666C202D0131D9FF4600004B22C0200048023794F531D6FFC02000\
39023DF0C60100000001D8FFC000000871C86112C1200DF0003138FE52A07FC0200048734040754045C0A614F1C0200029030DF00012C1\
F0C921D911CD02DD0322A0C0E9010931D0DC80C5FCFFE2A0C0460A000000220C00E7120932A0DB371210C604000022A0DB05FBFF22A0DC\
8601000045FAFF22A0DD05FAFF1BCCD79CD422A0C045F9FF0831C821D811E80112C1100DF0000012C1F04118FE9D02C931D2610222A0C0\
C0200058745050741645FFC0200068046060742796E9510FFE0C02A2A0C0B2A0DB7D05C2A0DCD2A0DD860F00C0200048754040741644FF\
C020004805404074A7144DB7941EC0200088778080741648FFC020008807808074C71806D71805C60300004D062A894248001B223792BD\
4600000C0231F8FD42A0C0C0200058735050741645FFC020005223005050744795E8C831D82112C1100DF0000000", "data_start": 1\
073643520, "code_start": 1074790404, "num_params": 1, "entry": 1074792056, "params_start": 1074790400, "data":\
 "86051040A1051040BF051040DE051040FE0510400606104010061040100610400014000000040000"}, "stub_flasher_31": {"cod\
e": "084700403641002080B43C245688043080B43C343A229C08060F000040AC4181F8FFE00800EC7A32D3F03042C0CC430C04C608000\
04080F45608FE40AC4181F0FFE00800CCEA42D4104792EEC6F7FF003C54860000003C742D041DF00C180000B418000000000060A418000\
0C01800003847004036E13151FDFF61F8FF1055804265006A610C0542D11852642DAD062050B4A5F6003C2756D50E3050B43C3756550EA\
1EFFF0C4BAAA159041924191472A3FF6542004628000000A8241B9A92640281E8FFC0200098789090741619FFC020009808924A0098041\
B99990498244739011924980497B7D081E0FF1A8888089C6892242D92D90497B50E20AC4181C0FFE00800568A0752D510B814C2A400AD0\
281D7FFE0080056BA06906300A804A2DAFCA90490E613102000B814C2A400AD0625EF0092242D22D20492D90492642D981492D90447B90\
49914860000126401A1C4FF0C4BAAA125380092242D37B90206E0FFB1BEFFA1C0FFBAB11AAAE5F300A1BEFF1C0B1AAA2536000C0706020\
0003C67860000003C772D071DF000100000A810000098100000B01000009848004036C12161FDFF72D11010668052660091F7FF62A0006\
2672A5C2847B902C62200AD07A5E3004615006083C0805463CD05BD01AD0281F2FFE00800562A06BD05AD01652F00CD05BD01AD07A5E30\
05A225A6637360F51E7FF0C4B5AA1653400264A1606100051E5FF82272A1A5558058086C05738B306F7FF0082272A87362B82272A3738C\
CA1DCFF70B72010AA80E5E700A1D9FF1C0B1AAA252A000C08060300005C388601005C484600005C582D081DF03011000036C12261CDFF8\
CA452A06247B60286200040642051CBFF5A51AD05E5D800461500000000A2D11025D80060736370C72010B12020A22081C4FFE008008C6\
A52A063C613000000CD07BD01AD0525D8009CE4CD07BD01A2D11065D700A1E8FFB2D11010AA8025DF00A1E5FF1C0B1AAA6521007022807\
033C05693FAB1B1FFA1DFFFB0B1801AAA25DD00A1DDFF1C0B1AAA651F005D032D051DF00030006000000010FFFFFF0036610021FDFF81F\
BFF9D02C02000226800C020002228009022105632FFC0200092281081F6FFB2A00480891010A1208901E51A001DF000000080FD3F36810\
0B2A001A2C111252000261A02862E0022AFFF820111224110B6880206280021F6FF2088A0222800A002001C0BAD01A51D003C12668A62B\
811A80125C9FF06060000B2A01010A120251C0022A04166AA48C821B811A80165CEFFA24110C61700B2A01010A120251A0022A05166BA2\
AD831C821B811A80125DFFF06F7FFB2A01010A12065180022A06166AA0DC22102B811A801A5E8FF06F0FF00224110C6070025F2FFC6ECF\
F0C1286FBFF22A000B2A001A2C110224110A50E002201119000000C1BA2C110101120A50D0022011182C2FA808074B6280286C9FF1DF00\
0004F484149102700000000044000B4C4042080FD3F00110040A8100040B42D004036610021F7FFA1F7FF292181FCFFE0080081F5FFC02\
00028089CD2C02000A80891F3FFA08F05AA888081219088802100FFA088D2C02000826205B2A004A2C10825060081EBFF0C8B28189808A\
D0199012911250500A5EAFFA02A20A1E2FF81E7FFE0080066621C8D0191E2FF860000004B88C02000A808979AF591DFFFC0200099083DF\
01DF0000036410091E9FE82A07FC0200028792020752028C0A612F11DF000000036410025FEFF41E1FE52A0C0C0200059043A324610000\
00052020072A0DB6715077715188609000000A5FBFFC02000790425FBFF52A0DC86050000000065FAFFC020005904E5F9FF52A0DD86000\
065F9FFC0200059041B2262A0C03792B965F8FFC0200069041DF036410081C8FE52A0C0C0200048784040741644FFC02000B808B0B0745\
79BE90C09E2A0C0F2A0DBDD0842A0DC52A0DD0610000000C02000A878A0A074164AFFC02000A808A0A074E71A4DF79A1EC02000C87DC0C\
074164CFFC02000C80DC0C074471C06571C05C6030000AD0B9AC2A24C001B993799BD4600000C0921AAFE32A0C0C020008872808074164\
8FFC020008222008080743798E82D091DF078A46AD756B7C7E8DB702024EECEBDC1AF0F7CF52AC68747134630A8019546FDD8988069AFF\
7448BB15BFFFFBED75C892211906B937198FD8E4379A62108B44962251EF640B340C0515A5E26AAC7B6E95D102FD65314440281E6A1D8C\
8FBD3E7E6CDE121D60737C3870DD5F4ED145A4505E9E3A9F8A3EFFCD9026F678A4C2A8D4239FAFF81F6718722619D6D0C38E5FD44EABEA\
4A9CFDE4B604BBBF670BCBFBEC67E9B28FA27A1EA8530EFD4051D880439D0D4D9E599DBE6F87CA21F6556ACC4442229F497FF2A43A7239\
4AB39A093FCC3595B6592CC0C8F7DF4EFFFD15D84854F7EA86FE0E62CFE144301A3A111084E827E53F735F23ABDBBD2D72A91D386EB36E\
10039E149F1382248426852583288E139D14901626101320801A20800803311A04320320802A2080300331140332080AA0130AA20A2621\
6B811A921A801C8D1F1AFFFB09A304821FA3C5099104A33B099304208053A9932080480441130642042080632080700441160442010494\
09099818033019A95403320A0D530393161A1FF90DD10A0DD30A8313262176A3BAA333ADD32080962080880331160432032080A62080B0\
033114033208066013066206941B801C194FF104440D0DD81DAD9626218F841906530CA3BD06610FA3342080D5066303A6632080C80441\
130A42042080E32080F004411A044208033014033203951004F40606681A184FF6A6DD04930B851326219604410AA35904430BA333A344\
20811A20810804411A07420420812B20813004411704420C179FF80BB0140BB20CA4B004A403033813A369A94604D30B2621A304410720\
815D044309A9442081480771140A720720816420817007711A0772080440170442042621B720819A168FFB961B208188077114971AA44B\
0A72072081A1049409099810077119A93DAD4A07720304630A2081B904410C15DFF60443080AA0170AA20DA44CABA1044404044814A496\
A6B90B33040BB10A2621C30BB306ABB62081DA981A2081C806611A0762062081EA2081F006611706620F14EFF80AA0160AA20FA6A004F4\
0B0BB81BAB43A36406930B06610906630A2621DA9913A36A20820620821C144FF806611A07620620822004A40303381006611706620720\
8233A3B807701606720CAA69A9AB0A43062621E30AA1069A140AA306208259AAA920824806611907620620826104940A0AA81006611706\
620720827AAA380770160672069B162621FF8B1612CFF6A6F4A46306B30A06610B066304A46620829F20828806611F07620F2082A10444\
040448100FF11706F20F2082B7121FF80FF0160FF207A7F4A4ABAB7A07330F2622040771062082D307730BA77B2082C806611B09620620\
82E004F4070778100661190662092082F7A748099016099206111FF9262216A693A36406A3070661099C1A066309208313A66320830809\
91130B920320832F26112003311B09320320833004A406066818033019033203262229102FF6A679A93AAA9709430609910409930AAA99\
20835D20834809911D0B920D20836104940A0AA8100DD11B09D20D20837AAA680DD0190DD2091F5FED262239A9D4A49609730A09910B20\
8397099304A9942083880BB1140CB2042083A104440909981004411C0B42042083B9A9A804401B04420B1E7FE426224BAB47A7BA0B6309\
0BB1060BB307A7BB2083DE2083C80BB11E0CB20E2083E004F4070778100EE11C0BE20E2083F7A7980EE01B0EE20B1D9FEC831BABE6A6B9\
0BA3070BB10A0BB306A6BB1D5FE004A406066816A67BABCAAAB60B73090BB1070BB30F881AAABB1CFFE104B40A0AA81AAA6BABF9A9BA0B\
63070BB1060BB30C8C19A9BB1C9FE1047409099819A9ABABC7A7B90BA3060BB10A0BB30F8217ABB71C3FE104240B0BB81BAB97A7F6A67B\
07930A07710907730C8716A6771BDFE004C406066816A6B7A7CAAA7607B30907710B07730F22112AAA771B7FE104B40A0AA81AAA67A7F9\
A97A07630B077106077309A9771B1FE1047409099819A9A7A7EBAB7907A30607710A07730E26225BAB771ABFEC861104240B0BB81BAB97\
A7C6A67B07930A07710907730F8B16A7761A5FE004C407077817A7B6A6FAAA6706B30906610B06630AAA6619FFE104B40A0AA81AAA76A6\
49A96A06730B06610706630C8519A966199FE1047409099819A9A6A6CBAB6906A30706610A06630F8A1BA66B193FE1042406066816A69B\
ABF7A7B60B930A0BB1090BB307A7BB18EFE004C407077817A76BABDAAAB70B63090BB1060BB30C841AAABB188FE104B40A0AA81AAA7BAB\
C9A9BA0B73060BB1070BB30F8919A9BB182FE1047409099819A9ABABF6A6B90BA3070BB10A0BB306A6BB17CFE1042406066816A69BAB37\
A7B60B930A0BB1090BB307ABBC8717176FE004C40B0BB81BAB6B0F6307A7CAAA7F07930C8A1AAA77171FE104C40A0AA81AAAB7A7C9A77A\
0CF307A7C98C1C16CFE1045407077817A7A70FA30CA996A69F0CB306A6CC168FE1040406066816A67CAC4609F30BABCBAC9004940C0CC8\
1B162FE9831CAC6C0F630BA99AAA9F09730AA99104C409099819A9C926111A861915BFE82C8409A9A7A79922111A89190BF307ABBF157F\
E104540B0BB81BAB9B07930FAFA6A6F70AC30F221126A6AA152FE1040406066816A6BAAAF607730CACACAA7004940A0AA81714CFEAAA6A\
0F6307A7D9A97F07B30C8219A977148FE104C409099819A9A7A7CBA7790CF307A7CB851C144FE1045407077817A7970F930CABB6A6BF0C\
A306A6CB881C13FFE1040406066816A67CABBAAAB60BF30AACB004940C0CC81B139FEA8B1CAC6C0F630BAAA9A9AF0A7309A9AA135FE104\
C409099819A9CAAA390BF307A7A7A7B104540707781B130FE7A7970F930BABE6A6BF0BC306A6BA841B12CFE1040406066816A67BAAACAC\
A60AF30CACAF821A128FE004940C0CC81AAAF9AAA7CF9CAC670B930C0BB2060BB30F122FEAABBA891104A40B0BB81FAAABABC7A7A60A93\
0B0AA20C0AA307A7AA11CFE104640707781AA447A7B6A64C04930704420B04430A8716A644116FE1041406066814A4A6A67CAC4B049306\
04420704430CAC44110FE004B40C0CC814A33CAC6BAB3703930C03320603330F851BAB3310AFE104A40B0BB813A3FBABC7A73603930B03\
320C033304221127A733104FE1046407077817A7B3AF4C03930703320B033306A6FA8316A6331FEFD1041406066813A3A6A67CAC3B0393\
0603320703330F8A1CAC331F8FD004B40C0CC813A3FCAC6BAB3703930C03320603330BAB331F2FD104A40B0BB81BABC3AEE603930B0332\
0C033307A7E48817A7331ECFD1046407077813A347A7B6A63C03930703320B033306A6331E7FD1041406066816A673ADDB039306033207\
03330CACDCAC3A86131E1FD004B40C0CC813A3ACAC6BAB3703930C03320603330BAB3F8C131DBFD104A40B0BB813A3FBABC7A73603930B\
03320C033307A73484131D5FD1046407077813A347A7B6A63C03930703320B033306A63A8B131CFFD1041406066813A3A6A67CA33B0C93\
060CC2070CC303A3C004B403033813A36C8D1F8013A55381148F16AFF7A33BACC68E13911C9D1F9014038C067130246C5FD9811C922593\
2F94299522D081DF00123456789ABCDEFFEDCBA987654321036410081FBFF892281FBFF893281FAFF894281FAFF89520C08890289121DF\
000FFFFFF1F74690040364100A80251FCFF4A6A5056105902A7B50558121B5559125812408D258A858912A0A054BC2A4C06A056C0A2CA1\
0AAA257B40ACD04BD038BAA460F000000BD03CD058BAA81EEFFE00800CD06B2C218AD025033805044C02566FF3CF547B512C2AFC0C0C41\
0BD0320A220E564FF3D0A504410CD0430B320A2C21881E0FFE008001DF00000E46B0040364100880352AF808080548A435244181BA84C0\
5A0C5C042C318F68C1A8AA30C0BA2CA1981F6FFE00800CD05BD0430A320E55FFFCD050C0AAAA3C2CCF80C0BA2CA1881EEFFE008008803B\
D04D0881180584189038243505243518050F580887582435388135243528058418243545243558050F58088755243568243574C0CAD03E\
55AFF4823C2A09842420048230C0B404841424201421305AD0342420242030B42420348334242044833404841424205421307424206420\
30F4242074843424208484340484142420942130942420A42031342420B485342420C485340484142420D42130B42420E42031742420F8\
1C3FFE008001DF000", "data_start": 1073577984, "code_start": 1074003972, "num_params": 1, "entry": 1074005048, \
"params_start": 1074003968, "data": "650304407C0304409A030440B7030440DA030440E0030440E5030440E5030440000400000\
0040000"}}\
"""

if __name__ == '__main__':
    try:
        main()
    except FatalError as e:
        print '\nA fatal error occurred: %s' % e
        sys.exit(2)
