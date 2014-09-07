#!/usr/bin/env python
#
# ESP8266 Flash image parse
# Copyright (c) 2014 Fredrik Ahlberg
#
# Released under GPLv2

import struct

f = file('wi07c.rom')

(magic, segments, _, _, entrypoint) = struct.unpack('<BBBBI', f.read(8))

print 'magic = %02x, segments = %d, entrypoint=%08x' % (magic, segments, entrypoint)

for i in xrange(segments):
    (offset, size) = struct.unpack('<II', f.read(8))
    print 'seg %d: %08x, %d' % (i, offset, size)

    # skip the data
    f.read(size)

print 'footer: ' + ' '.join(map(hex, map(ord, f.read(16))))
