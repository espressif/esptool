#!/usr/bin/env python
#
# ESP8266 ROM Bootloader Utility
# https://github.com/themadinventor/esptool
#
# Copyright (C) 2014 Fredrik Ahlberg
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

import sys
import struct
import serial
import time
import argparse
import os
import subprocess
import tempfile
import inspect


class ESPROM:
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

    # OTP ROM addresses
    ESP_OTP_MAC0    = 0x3ff00050
    ESP_OTP_MAC1    = 0x3ff00054
    ESP_OTP_MAC3    = 0x3ff0005c

    # Sflash stub: an assembly routine to read from spi flash and send to host
    SFLASH_STUB     = "\x80\x3c\x00\x40\x1c\x4b\x00\x40\x21\x11\x00\x40\x00\x80" \
                      "\xfe\x3f\xc1\xfb\xff\xd1\xf8\xff\x2d\x0d\x31\xfd\xff\x41\xf7\xff\x4a" \
                      "\xdd\x51\xf9\xff\xc0\x05\x00\x21\xf9\xff\x31\xf3\xff\x41\xf5\xff\xc0" \
                      "\x04\x00\x0b\xcc\x56\xec\xfd\x06\xff\xff\x00\x00"

    def __init__(self, port=0, baud=ESP_ROM_BAUD):
        self._port = serial.Serial(port)
        # setting baud rate in a separate step is a workaround for
        # CH341 driver on some Linux versions (this opens at 9600 then
        # sets), shouldn't matter for other platforms/drivers. See
        # https://github.com/themadinventor/esptool/issues/44#issuecomment-107094446
        self._port.baudrate = baud
        self.in_bootloader = False  # actually unknown, but assume not

    """ Read bytes from the serial port while performing SLIP unescaping """
    def read(self, length=1):
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
                    raise FatalError('Invalid SLIP escape')
            else:
                b = b + c
        return b

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
        if op:
            pkt = struct.pack('<BBHI', 0x00, op, len(data), chk) + data
            self.write(pkt)

        # tries to get a response until that response has the
        # same operation as the request or a retries limit has
        # exceeded. This is needed for some esp8266s that
        # reply with more sync responses than expected.
        retries = 100
        while retries > 0:
            (op_ret, val, body) = self.receive_response()
            if op is None or op_ret == op:
                return val, body  # valid response received
            retries = retries - 1

        raise FatalError("Response doesn't match request")

    """ Receive a response to a command """
    def receive_response(self):
        # Read header of response and parse
        if self._port.read(1) != '\xc0':
            raise FatalError('Invalid head of packet')
        hdr = self.read(8)
        (resp, op_ret, len_ret, val) = struct.unpack('<BBHI', hdr)
        if resp != 0x01:
            raise FatalError('Invalid response 0x%02x" to command' % resp)

        # The variable-length body
        body = self.read(len_ret)

        # Terminating byte
        if self._port.read(1) != chr(0xc0):
            raise FatalError('Invalid end of packet')

        return op_ret, val, body

    """ Perform a connection test """
    def sync(self):
        self.command(ESPROM.ESP_SYNC, '\x07\x07\x12\x20' + 32 * '\x55')
        for i in xrange(7):
            self.command()
        self.in_bootloader = True

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
                    self._port.flushOutput()
                    self.sync()
                    self._port.timeout = 5
                    return
                except:
                    time.sleep(0.05)
        raise FatalError('Failed to connect to ESP8266')

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
        self.in_bootloader = False

    """ Start downloading to Flash (performs an erase) """
    def flash_begin(self, size, offset):
        old_tmo = self._port.timeout
        num_blocks = (size + ESPROM.ESP_FLASH_BLOCK - 1) / ESPROM.ESP_FLASH_BLOCK

        sectors_per_block = 16
        sector_size = 4096
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
        result = self.command(ESPROM.ESP_FLASH_DATA, struct.pack('<IIII', len(data), seq, 0, 0) + data, ESPROM.checksum(data))[1]
        if result != "\0\0":
            raise FatalError.WithResult('Failed to write to target Flash after seq %d (got result %%s)' % seq, result)

    """ Leave flash mode and run/reboot """
    def flash_finish(self, reboot=False):
        pkt = struct.pack('<I', int(not reboot))
        if self.command(ESPROM.ESP_FLASH_END, pkt)[1] != "\0\0":
            raise FatalError('Failed to leave Flash mode')
        self.in_bootloader = False

    """ Run application code in flash """
    def run(self, reboot=False):
        # Fake flash begin immediately followed by flash end
        self.flash_begin(0, 0)
        self.flash_finish(reboot)

    """ Read MAC from OTP ROM """
    def read_mac(self):
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

    """ Read Chip ID from OTP ROM - see http://esp8266-re.foogod.com/wiki/System_get_chip_id_%28IoT_RTOS_SDK_0.9.9%29 """
    def chip_id(self):
        id0 = self.read_reg(self.ESP_OTP_MAC0)
        id1 = self.read_reg(self.ESP_OTP_MAC1)
        return (id0 >> 24) | ((id1 & 0xffffff) << 8)

    """ Read SPI flash manufacturer and device id """
    def flash_id(self):
        self.flash_begin(0, 0)
        self.write_reg(0x60000240, 0x0, 0xffffffff)
        self.write_reg(0x60000200, 0x10000000, 0xffffffff)
        flash_id = self.read_reg(0x60000240)
        self.flash_finish(False)
        return flash_id

    """ Read SPI flash """
    def flash_read(self, offset, size, count=1, progress=False):
        # Create a custom stub
        stub = struct.pack('<III', offset, size, count) + self.SFLASH_STUB

        # Trick ROM to initialize SFlash
        self.flash_begin(0, 0)

        # Download stub
        self.mem_begin(len(stub), 1, len(stub), 0x40100000)
        self.mem_block(stub, 0)
        self.mem_finish(0x4010001c)

        # Fetch the data
        data = ''
        for _ in xrange(count):
            if self._port.read(1) != '\xc0':
                raise FatalError('Invalid head of packet (sflash read)')

            data += self.read(size)
            if progress:
                if len(data) % 4096 == 0:
                    sys.stdout.write(".")
                    if len(data) % 204800 == 0:
                        sys.stdout.write(" %4d KiB\n" % (len(data) / 1024))
                    sys.stdout.flush()

            if self._port.read(1) != chr(0xc0):
                raise FatalError('Invalid end of packet (sflash read)')
        if progress and len(data) % 204800 != 0:
            sys.stdout.write(" %4d kiB\n" % (len(data) / 1024))
            sys.stdout.flush()

        return data

    """ Abuse the loader protocol to force flash to be left in write mode """
    def flash_unlock_dio(self):
        # Enable flash write mode
        self.flash_begin(0, 0)
        # Reset the chip rather than call flash_finish(), which would have
        # write protected the chip again (why oh why does it do that?!)
        self.mem_begin(0,0,0,0x40100000)
        self.mem_finish(0x40000080)

    """ Perform a chip erase of SPI flash """
    def flash_erase(self):
        # Trick ROM to initialize SFlash
        self.flash_begin(0, 0)

        # This is hacky: we don't have a custom stub, instead we trick
        # the bootloader to jump to the SPIEraseChip() routine and then halt/crash
        # when it tries to boot an unconfigured system.
        self.mem_begin(0,0,0,0x40100000)
        self.mem_finish(0x40004984)

        # Yup - there's no good way to detect if we succeeded.
        # It it on the other hand unlikely to fail.


class ESPFirmwareImage:

    def __init__(self, filename=None):
        self.segments = []
        self.entrypoint = 0
        self.flash_mode = 0
        self.flash_size_freq = 0

        if filename is not None:
            f = file(filename, 'rb')
            (magic, segments, self.flash_mode, self.flash_size_freq, self.entrypoint) = struct.unpack('<BBBBI', f.read(8))

            # some sanity check
            if magic != ESPROM.ESP_IMAGE_MAGIC or segments > 16:
                raise FatalError('Invalid firmware image')

            for i in xrange(segments):
                (offset, size) = struct.unpack('<II', f.read(8))
                if offset > 0x40200000 or offset < 0x3ffe0000 or size > 65536:
                    raise FatalError('Suspicious segment 0x%x, length %d' % (offset, size))
                segment_data = f.read(size)
                if len(segment_data) < size:
                    raise FatalError('End of file reading segment 0x%x, length %d (actual length %d)' % (offset, size, len(segment_data)))
                self.segments.append((offset, size, segment_data))

            # Skip the padding. The checksum is stored in the last byte so that the
            # file is a multiple of 16 bytes.
            align = 15 - (f.tell() % 16)
            f.seek(align, 1)

            self.checksum = ord(f.read(1))

    def add_segment(self, addr, data):
        # Data should be aligned on word boundary
        l = len(data)
        if l % 4:
            data += b"\x00" * (4 - l % 4)
        if l > 0:
            self.segments.append((addr, len(data), data))

    def save(self, filename):
        f = file(filename, 'wb')
        f.write(struct.pack('<BBBBI', ESPROM.ESP_IMAGE_MAGIC, len(self.segments),
                            self.flash_mode, self.flash_size_freq, self.entrypoint))

        checksum = ESPROM.ESP_CHECKSUM_MAGIC
        for (offset, size, data) in self.segments:
            f.write(struct.pack('<II', offset, size))
            f.write(data)
            checksum = ESPROM.checksum(data, checksum)

        align = 15 - (f.tell() % 16)
        f.seek(align, 1)
        f.write(struct.pack('B', checksum))


class ELFFile:

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
    image = ESPFirmwareImage(args.filename)

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
    flash_info = struct.pack('BB', flash_mode, flash_size_freq)

    for address, argfile in args.addr_filename:
        image = argfile.read()
        argfile.seek(0)  # in case we need it again
        print 'Erasing flash...'
        blocks = div_roundup(len(image), esp.ESP_FLASH_BLOCK)
        esp.flash_begin(blocks * esp.ESP_FLASH_BLOCK, address)
        seq = 0
        written = 0
        t = time.time()
        while len(image) > 0:
            print '\rWriting at 0x%08x... (%d %%)' % (address + seq * esp.ESP_FLASH_BLOCK, 100 * (seq + 1) / blocks),
            sys.stdout.flush()
            block = image[0:esp.ESP_FLASH_BLOCK]
            # Fix sflash config data
            if address == 0 and seq == 0 and block[0] == '\xe9':
                block = block[0:2] + flash_info + block[4:]
            # Pad the last block
            block = block + '\xff' * (esp.ESP_FLASH_BLOCK - len(block))
            esp.flash_block(block, seq)
            image = image[esp.ESP_FLASH_BLOCK:]
            seq += 1
            written += len(block)
        t = time.time() - t
        print '\rWrote %d bytes at 0x%08x in %.1f seconds (%.1f kbit/s)...' % (written, address, t, written / t * 8 / 1000)
    print '\nLeaving...'
    if args.flash_mode == 'dio':
        esp.flash_unlock_dio()
    else:
        esp.flash_begin(0, 0)
        esp.flash_finish(False)
    if args.verify:
        print 'Verifying just-written flash...'
        verify_flash(esp, args)


def image_info(args):
    image = ESPFirmwareImage(args.filename)
    print ('Entry point: %08x' % image.entrypoint) if image.entrypoint != 0 else 'Entry point not set'
    print '%d segments' % len(image.segments)
    print
    checksum = ESPROM.ESP_CHECKSUM_MAGIC
    for (idx, (offset, size, data)) in enumerate(image.segments):
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
    if args.output is None:
        args.output = args.input + '-'
    e = ELFFile(args.input)
    image = ESPFirmwareImage()
    image.entrypoint = e.get_entry_point()
    for section, start in ((".text", "_text_start"), (".data", "_data_start"), (".rodata", "_rodata_start")):
        data = e.load_section(section)
        image.add_segment(e.get_symbol_addr(start), data)

    image.flash_mode = {'qio':0, 'qout':1, 'dio':2, 'dout': 3}[args.flash_mode]
    image.flash_size_freq = {'4m':0x00, '2m':0x10, '8m':0x20, '16m':0x30, '32m':0x40, '16m-c1': 0x50, '32m-c1':0x60, '32m-c2':0x70}[args.flash_size]
    image.flash_size_freq += {'40m':0, '26m':1, '20m':2, '80m': 0xf}[args.flash_freq]

    image.save(args.output + "0x00000.bin")
    data = e.load_section(".irom0.text")
    off = e.get_symbol_addr("_irom0_text_start") - 0x40200000
    if off < 0:
        raise FatalError('Address of symbol _irom0_text_start in ELF is located before flash mapping address. Bad linker script?')
    f = open(args.output + "0x%05x.bin" % off, "wb")
    f.write(data)
    f.close()


def read_mac(esp, args):
    mac = esp.read_mac()
    print 'MAC: %s' % ':'.join(map(lambda x: '%02x' % x, mac))


def chip_id(esp, args):
    chipid = esp.chip_id()
    print 'Chip ID: 0x%08x' % chipid


def erase_flash(esp, args):
    print 'Erasing flash (this may take a while)...'
    esp.flash_erase()


def run(esp, args):
    esp.run()


def flash_id(esp, args):
    flash_id = esp.flash_id()
    print 'Manufacturer: %02x' % (flash_id & 0xff)
    print 'Device: %02x%02x' % ((flash_id >> 8) & 0xff, (flash_id >> 16) & 0xff)


def read_flash(esp, args):
    print 'Please wait...'
    file(args.filename, 'wb').write(esp.flash_read(args.address, 1024, div_roundup(args.size, 1024), args.progress)[:args.size])


def verify_flash(esp, args):
    differences = False
    for address, argfile in args.addr_filename:
        if not esp.in_bootloader:
            esp.connect()
        image = argfile.read()
        argfile.seek(0)  # rewind in case we need it again
        image_size = len(image)
        print 'Verifying 0x%x (%d) bytes @ 0x%08x in flash against %s...' % (image_size, image_size, address, argfile.name)
        flash = esp.flash_read(address, 1024, div_roundup(image_size, 1024))[:image_size]
        if flash == image:
            print '-- verify OK'
        else:
            differences = True
            diff = [i for i in xrange(image_size) if flash[i] != image[i]]
            print '-- verify FAILED: %d differences, first @ 0x%08x' % (len(diff), address + diff[0])
            try:
                if args.diff == 'yes':
                    for d in diff:
                        print '   %08x %02x %02x' % (address + d, ord(flash[d]), ord(image[d]))
            except AttributeError:
                pass  # if performing write_flash --verify, there is no .diff attribute
    if differences:
        raise FatalError("Verify failed.")

#
# End of operations functions
#


def main():
    parser = argparse.ArgumentParser(description='ESP8266 ROM Bootloader Utility', prog='esptool')

    parser.add_argument(
        '--port', '-p',
        help='Serial port device',
        default=os.environ.get('ESPTOOL_PORT', '/dev/ttyUSB0'))

    parser.add_argument(
        '--baud', '-b',
        help='Serial port baud rate',
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

    parser_write_flash = subparsers.add_parser(
        'write_flash',
        help='Write a binary blob to flash')
    parser_write_flash.add_argument('addr_filename', metavar='<address> <filename>', help='Address followed by binary filename, separated by space',
                                    action=AddrFilenamePairAction)
    parser_write_flash.add_argument('--flash_freq', '-ff', help='SPI Flash frequency',
                                    choices=['40m', '26m', '20m', '80m'],
                                    default=os.environ.get('ESPTOOL_FF', '40m'))
    parser_write_flash.add_argument('--flash_mode', '-fm', help='SPI Flash mode',
                                    choices=['qio', 'qout', 'dio', 'dout'],
                                    default=os.environ.get('ESPTOOL_FM', 'qio'))
    parser_write_flash.add_argument('--flash_size', '-fs', help='SPI Flash size in Mbit', type=str.lower,
                                    choices=['4m', '2m', '8m', '16m', '32m', '16m-c1', '32m-c1', '32m-c2'],
                                    default=os.environ.get('ESPTOOL_FS', '4m'))
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
    parser_elf2image.add_argument('--output', '-o', help='Output filename prefix', type=str)
    parser_elf2image.add_argument('--flash_freq', '-ff', help='SPI Flash frequency',
                                  choices=['40m', '26m', '20m', '80m'], default='40m')
    parser_elf2image.add_argument('--flash_mode', '-fm', help='SPI Flash mode',
                                  choices=['qio', 'qout', 'dio', 'dout'], default='qio')
    parser_elf2image.add_argument('--flash_size', '-fs', help='SPI Flash size in Mbit',
                                  choices=['4m', '2m', '8m', '16m', '32m', '16m-c1', '32m-c1', '32m-c2'], default='4m')

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
    parser_read_flash.add_argument('--progress', '-p', help='Show progression', action="store_true")

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

    # internal sanity check - every operation matches a module function of the same name
    for operation in subparsers.choices.keys():
        assert operation in globals(), "%s should be a module function" % operation

    args = parser.parse_args()

    # operation function can take 1 arg (args), 2 args (esp, arg)
    # or be a member function of the ESPROM class.

    operation_func = globals()[args.operation]
    operation_args,_,_,_ = inspect.getargspec(operation_func)
    if len(operation_args) == 2:  # operation function takes an ESPROM connection object
        esp = ESPROM(args.port, args.baud)
        esp.connect()
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

if __name__ == '__main__':
    try:
        main()
    except FatalError as e:
        print '\nA fatal error occurred: %s' % e
        sys.exit(2)
