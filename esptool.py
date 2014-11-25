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
import math
import time
import argparse
import operator

def chunks(iterable, n=1):
   l = len(iterable)
   for ndx in range(0, l, n):
	   yield iterable[ndx:min(ndx+n, l)]

class ESPROM:

	# These are the currently known commands supported by the ROM bootloader
	ESP_FLASH_BEGIN = 0x02
	ESP_FLASH_DATA	= 0x03
	ESP_FLASH_END	= 0x04
	ESP_MEM_BEGIN	= 0x05
	ESP_MEM_END		= 0x06
	ESP_MEM_DATA	= 0x07
	ESP_SYNC		= 0x08
	ESP_WRITE_REG	= 0x09
	ESP_READ_REG	= 0x0a

	# Maximum block sizes for RAM and Flash writes, respectively.
	ESP_RAM_BLOCK	= 0x1800
	ESP_FLASH_BLOCK = 0x400

	# Default baudrate used by the ROM. Don't know if this can be changed.
	ESP_ROM_BAUD	= 115200

	# First byte of the application image
	ESP_IMAGE_MAGIC = 0xe9

	# Initial state for the checksum routine
	ESP_CHECKSUM_MAGIC = 0xef

	def __init__(self, port=0):
		self._port = serial.Serial(port, self.ESP_ROM_BAUD)

	def read(self, length=1):
		""" Read bytes from the serial port while performing SLIP unescaping """
		def slip_read():
			c = self._port.read(1)[0]
			if c == '\xdb':
				try:
					return {'\xdc': 0xc0,
							'\xdd': 0xdb
						}[self._port.read(1)]
				except KeyError:
					raise ValueError('Invalid SLIP escape sequence received from device')
			return c[0]
		return bytes([slip_read() for _ in range(length)])

	def write(self, packet):
		""" Write bytes to the serial port while performing SLIP escaping """
		self._port.write(b'\xc0'+packet.replace(b'\xdb', b'\xdb\xdd').replace(b'\xc0', b'\xdb\xdc')+b'\xc0')

	@staticmethod
	def checksum(data, state=ESP_CHECKSUM_MAGIC):
		""" Calculate the XOR checksum of a blob, as it is defined by the ROM """
		return state ^ map(data, operator.xor)

	def command(self, op=None, data=None, chk=0):
		""" Send a request and read the response """
		if op is not None:
			# Construct and send request
			pkt = struct.pack('<BBHI', 0x00, op, len(data), chk) + data
			self.write(pkt)

		# Read header of response and parse
		if self._port.read(1) != '\xc0':
			raise ValueError('Invalid head of packet')
		hdr = self.read(8)
		(resp, op_ret, len_ret, val) = struct.unpack('<BBHI', hdr)
		if resp != 0x01 or (op and op_ret != op):
			raise ValueError('Invalid response')

		# The variable-length body
		body = self.read(len_ret)

		# Terminating byte
		if self._port.read(1) != '\xc0':
			raise ValueError('Invalid end of packet')

		return val, body

	def simple_command(self, op=None, data=None, chk=0):
		rv, body = self.command(op, data, chk)
		if body != b'\0\0':
			raise ValueError('Invalid command response from device')
		return rv

	def sync(self):
		""" Perform a connection test """
		self.command(ESPROM.ESP_SYNC, '\x07\x07\x12\x20'+32*'\x55')
		for i in range(7):
			self.command()

	def connect(self):
		""" Try connecting repeatedly until successful, or giving up """
		self._port.timeout = 0.5
		for i in range(10):
			try:
				self._port.flushInput()
				self._port.flushOutput()
				self.sync()
				self._port.timeout = 5
				return
			except:
				time.sleep(0.1)
		raise Exception('Failed to connect')

	def read_reg(self, addr):
		""" Read memory address in target """
		return self.simple_command(ESPROM.ESP_READ_REG, struct.pack('<I', addr))

	def write_reg(self, addr, value, mask, delay_us = 0):
		""" Write to memory address in target """
		return self.simple_command(ESPROM.ESP_WRITE_REG, struct.pack('<IIII', addr, value, mask, delay_us))

	def mem_begin(self, size, blocks, blocksize, offset):
		""" Start downloading an application image to RAM """
		return self.simple_command(ESPROM.ESP_MEM_BEGIN, struct.pack('<IIII', size, blocks, blocksize, offset))

	def mem_block(self, data, seq):
		""" Send a block of an image to RAM """
		return self.simple_command(ESPROM.ESP_MEM_DATA, struct.pack('<IIII', len(data), seq, 0, 0)+data, ESPROM.checksum(data))

	def mem_finish(self, entrypoint = 0):
		""" Leave download mode and run the application """
		return self.simple_command(ESPROM.ESP_MEM_END, struct.pack('<II', int(entrypoint == 0), entrypoint))

	def flash_begin(self, size, offset):
		""" Start downloading to Flash (performs an erase) """
		old_tmo, self._port.timeout = self._port.timeout, 10
		try:
			return self.simple_command(ESPROM.ESP_FLASH_BEGIN, struct.pack('<IIII', size, 0x200, 0x400, offset))
		finally:
			self._port.timeout = old_tmo

	def flash_block(self, data, seq):
		""" Write a block to flash """
		return self.simple_command(ESPROM.ESP_FLASH_DATA, struct.pack('<IIII', len(data), seq, 0, 0)+data, ESPROM.checksum(data))

	def flash_finish(self, reboot=False):
		""" Leave flash mode and run/reboot """
		pkt = struct.pack('<I', int(not reboot))
		rv, body = self.command(ESPROM.ESP_FLASH_END, pkt)
		if body not in ("\0\0", "\x01\x06"):
			raise Exception('Failed to leave Flash mode')

	def flash_image(self, offx, img, info=lambda *args:None):
		info('Erasing flash...')
		self.flash_begin(len(img), offx)
		for seq, chunk in enumerate(chunks(img, esp.ESP_FLASH_BLOCK)):
			info('\rWriting flash at {:#08x} ({.0f}%)...'.format(offx, seq*self.ESP_FLASH_BLOCK/len(img)*100))
			self.flash_block(chunk, seq)
		info('Finishing flashing...')
		self.flash_finish(False)

	def write_memory_image(self, sections, entrypoint, info=lambda *args:None):
		for i, (addr, data) in enumerate(sections):
			info('Uploading segment {}: {} bytes @{:#08x}'.format(i, len(data), addr))
			self.mem_begin(size, math.ceil(size/float(self.ESP_RAM_BLOCK)), self.ESP_RAM_BLOCK, addr)
			for seq, chunk in enumerate(chunks(data, self.ESP_RAM_BLOCK)):
				self.mem_block(chunk, seq)
			info('done!')
		info('All segments done, executing at {:#08x}'.format(entrypoint))
		self.mem_finish(entrypoint)

	def run(self, reboot = False):
		""" Run application code in flash """
		# Fake flash begin immediately followed by flash end
		self.flash_begin(0, 0)
		self.flash_finish(reboot)


class Image:
	def __init__(self):
		self.segments = []
		self.entrypoint = 0

	def add_segment(self, data, offx=None):
		loffx, lsize, _ = segments[-1] if segments else (0, 0, None)
		if offx is None:
			offx = loffx+lsize
		if offx > 0x40200000 or offx < 0x3ffe0000 or len(data) > 65536: #FIXME document these magic values
			raise ValueError('Suspicious segment of {} bytes at {:x}'.format(size, offx))
		if offx < loffx:
			raise UserWarning('Segments should be ordered by base address')
		self.segments.append((offx, len(data), data))

	@property
	def bytes(self):
		b = struct.pack('<BBBBI', ESPROM.ESP_IMAGE_MAGIC, len(self.segments), 0, 0, self.entrypoint)

		sechdr = lambda offx, size: struct.pack('<II', offx, size)
		for offx, size, data in self.segments:
			b += sechdr(offx, size) + data

		checksum = ESPROM.checksum(b''.join(data for _1,_2,data in self.segments))
		pad = 15-(len(b)%16)
		b += '\0'*pad + chr(checksum)

if __name__ == '__main__':
	_arg_auto_int = lambda x: int(x, 0)

	parser = argparse.ArgumentParser(description='ESP8266 ROM Bootloader Utility', prog='esptool')
	parser.add_argument('--port', '-p', help='Serial port device', default='/dev/ttyUSB0')
	subparsers = parser.add_subparsers(dest='operation', help='Run esptool {command} -h for additional help')

	# load_ram
	parser_load_ram = subparsers.add_parser('load_ram', help='Download an image to RAM and execute')
	parser_load_ram.add_argument('filename', help='Firmware image')

	# dump_mem
	parser_dump_mem = subparsers.add_parser('dump_mem', help='Dump arbitrary memory to disk')
	parser_dump_mem.add_argument('address', help='Base address', type=_arg_auto_int)
	parser_dump_mem.add_argument('size', help='Size of region to dump', type=_arg_auto_int)
	parser_dump_mem.add_argument('filename', help='Name of binary dump')

	# read_mem
	parser_read_mem = subparsers.add_parser('read_mem', help='Read arbitrary memory location')
	parser_read_mem.add_argument('address', help='Address to read', type=_arg_auto_int)

	# write_mem
	parser_write_mem=subparsers.add_parser('write_mem', help='Read-modify-write to arbitrary memory location')
	parser_write_mem.add_argument('address', help='Address to write', type=_arg_auto_int)
	parser_write_mem.add_argument('value', help='Value', type=_arg_auto_int)
	parser_write_mem.add_argument('mask', help='Mask of bits to write', type=_arg_auto_int)

	# write_flash
	parser_write_flash=subparsers.add_parser('write_flash', help='Write a binary blob to flash')
	parser_write_flash.add_argument('firmware', help='Address and binary file to write there, separated by space')

	# run
	parser_run=subparsers.add_parser('run', help='Run application code in flash')

	# image_info
	parser_image_info=subparsers.add_parser('image_info', help='Dump headers from an application image')
	parser_image_info.add_argument('filename', help='Image file to parse')

	# make_image
	parser_make_image=subparsers.add_parser('make_image', help='Create an application image from binary files')
	parser_make_image.add_argument('output', help='Output image file')
	parser_make_image.add_argument('--segfile', '-f', action='append', help='Segment input file') 
	parser_make_image.add_argument('--segaddr', '-a', action='append', help='Segment base address', type=_arg_auto_int) 
	parser_make_image.add_argument('--entrypoint', '-e', help='Address of entry point', type=_arg_auto_int, default=0)

	args = parser.parse_args()

	# Create the ESPROM connection object, if needed
	esp = None
	if args.operation not in ('image_info','make_image'):
		esp = ESPROM(args.port)
		print('Connecting...')
		esp.connect()

	# Do the actual work. Should probably be split into separate functions.
	if args.operation == 'load_ram':
		elf = ELFFile(args.firmware)

		SECTIONS = [b'.text', b'.data', b'.rodata', b'.irom0.text']
		secs = [ (sec[b'sh_addr'], sec.data()) for sec in (elf.get_section_by_name(section) for section in SECTIONS) ]

		esp.write_memory_image(secs, elf.header['e_entry'], info=print)

	elif args.operation == 'read_ram':
		print('@{:#08x}: {:#08x}'.format(args.address, esp.read_reg(args.address)))

	elif args.operation == 'write_ram':
		esp.write_reg(args.address, args.value, args.mask, 0)
		print('Wrote {:#08x} with mask {:#08x} to address {:#08x}'.format(args.value, args.mask, args.address))

	elif args.operation == 'dump_ram':
		with open(args.filename, 'wb') as f:
			for addr in range(args.address, args.address+args.size, 4):
				data = esp.read_reg(addr)
				f.write(struct.pack('<I', d))
				if f.tell() % 1024 == 0:
					print('{} bytes read ({:.0f}%)'.format(f.tell(), f.tell()/args.size*100))

	elif args.operation == 'write_flash':

		elf = ELFFile(args.firmware)

		# @0x00000
		text   = elf.get_section_by_name(b'.text').data()
		data   = elf.get_section_by_name(b'.data').data()
		rodata = elf.get_section_by_name(b'.rodata').data()

		img1 = Image()
		img1.add_segment(text)
		img1.add_segment(data)
		img1.add_segment(rodata)

		esp.flash_image(0x00000, img1.bytes, info=print)

		# @0x40000
		ir0text = elf.get_section_by_name(b'.irom0.text').data()

		img2 = Image()
		img2.add_segment(ir0text)

		esp.flash_image(0x40000, img2.bytes, info=print)

	elif args.operation == 'run':
		esp.run()

