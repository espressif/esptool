Remote Serial Ports
===================

If you would like to connect to an Espressif SoC that is not directly connected to your system, you can use a remote serial port. This is useful when the chip is on a different machine, or for example when using WSL on Windows.

It is possible to connect to any networked remote serial port that supports `RFC2217 <http://www.ietf.org/rfc/rfc2217.txt>`__ (Telnet) protocol. To do this, specify the serial port to esptool as ``rfc2217://<host>:<port>``. For example, to read information about your chip's SPI flash, run:

::

    esptool --port rfc2217://192.168.1.77:4000 flash-id

Custom baud rates and DTR/RTS automatic resetting are supported over the RFC2217 protocol, the same as for a local serial port.

.. _rfc2217_server:

Pyserial Example Servers
------------------------

PySerial (which is a dependency of esptool) includes two RFC2217 example programs - `a single-port example <http://pyserial.readthedocs.io/en/latest/examples.html#single-port-tcp-ip-serial-bridge-rfc-2217>`__ and a `multi-port example <http://pyserial.readthedocs.io/en/latest/examples.html#multi-port-tcp-ip-serial-bridge-rfc-2217>`__.
These example servers can run on any OS that supports pyserial, and are the simplest way to connect to an Espressif SoC over the network.

There is an issue with `automatic resetting due to network latency <https://github.com/espressif/esptool/issues/383>`__. In order to work around this issue, a modified version of the single-port server example called ``esp_rfc2217_server`` is provided with esptool.

On server:

::

    esp_rfc2217_server -p 4000 /dev/ttyUSB1

On client:

::

    esptool --port rfc2217://ADDRESS_OF_SERVER:4000?ign_set_control flash-id


Raw Sockets
-----------

For servers or hardware network/serial adapters which don't support the full RFC2217, it is also possible to specify ``--port socket://<host>:<port>`` syntax for a simple "raw TCP socket" protocol.

These raw sockets don't support setting the baud rate or automatic resetting into the bootloader. If using this mode, don't pass the ``--baud`` option to esptool. You need to set the baud rate manually on the server, and manually reset the chip into the bootloader mode (or use some other signalling/control method to tell the server to do so).

Here's a very basic example using the common Linux/macOS command line "netcat" and "stty" commands:

On server:

::

    stty -F /dev/ttyUSB1 230400  # set baud rate
    nc -p 4000 -lk < /dev/ttyUSB1 > /dev/ttyUSB1

On client:

::

    esptool -p socket://localhost:4000 flash-id

.. note::

    Using RFC2217 is strongly recommended where possible.

More Details
------------

All of the remote serial port support comes via pyserial. Read more `here <http://pyserial.readthedocs.io/en/latest/url_handlers.html>`__. (Please keep in mind that the link points to documentation for the most recent pyserial version. You may have an older version.)
