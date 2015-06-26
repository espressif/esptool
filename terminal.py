#!/usr/bin/env python
#
# Copyright (c) 2015 Jeff Kent <jeff@jkent.net>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#

import sys

if sys.platform == 'win32':
    import msvcrt
    from time import sleep
else:
    from select import select
    import termios
    import tty


def stdin_gen(timeout=0.05):
    """Generator returns keystrokes from stdin"""
    if sys.platform == 'win32':
        do_timeout = True
        while msvcrt.kbhit():
            do_timeout = False
            c = msvcrt.getch()
            yield c
        if do_timeout:
            sleep(timeout)
    else:
        while select([sys.stdin.fileno()], [], [], timeout)[0]:
            c = sys.stdin.read(1)
            yield c


class raw_tty:
    """Decorator for wrapping functions needing raw tty"""
    def __init__(self, f):
        self.f = f

    def __call__(self, *args):
        ret = None
        if sys.platform != 'win32':
            try:
                self.saved = termios.tcgetattr(sys.stdin)
                tty.setraw(sys.stdin.fileno())
                ret = self.f(*args)
            finally:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN,
                                  self.saved)
        else:
            ret = self.f(*args)
        return ret


@raw_tty
def terminal(sp, auto_newline=True):
    """Interactive serial terminal.

    ^C twice in a row will stop the session.
    """

    break_count = 0
    while break_count < 2:
        serial_input = sp.read(sp.inWaiting())
        if serial_input:
            sys.stdout.write(serial_input)
            sys.stdout.flush()

        user_input = ''
        for c in stdin_gen():
            if c == '\x03':
                break_count += 1
                if break_count >= 2:
                    break
            else:
                break_count = 0
            if auto_newline and c == '\r':
                c += '\n'
            user_input += c
        if user_input:
            sp.write(user_input)
            sp.flush()

    sys.stdout.write('\n\r')


if __name__ == '__main__':
    from serial import Serial

    def usage():
        print "%s PORT [BAUD]" % sys.argv[0]
        sys.exit(1)

    if len(sys.argv) < 2 or len(sys.argv) > 3:
        usage()

    port = sys.argv[1]
    baud = 115200
    try:
        if len(sys.argv) == 3:
            baud = int(sys.argv[2])
    except:
        usage()

    sp = Serial(port, baud, timeout=0.25)
    print "Press ^C two times to exit"
    terminal(sp)

