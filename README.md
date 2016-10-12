# esptool.py

A cute Python utility to communicate with the ROM bootloader in Espressif ESP8266.
It is intended to be a simple, platform independent, open source replacement for XTCOM.

[![Build Status](https://travis-ci.org/themadinventor/esptool.svg?branch=master)](https://travis-ci.org/themadinventor/esptool)

## Installation / dependencies

### Easy Installation

You will need [Python 2.7 or newer](https://www.python.org/downloads/) installed on your system.

The latest stable esptool.py release can be installed from [pypi](http://pypi.python.org/pypi/esptool) via pip:

```
$ pip install esptool
```

With some Python installations this may not work and you'll receive an error, try `python -m pip install esptool` or `pip2 install esptool`.

After installing, you will have `esptool.py` installed into the default Python executables directory and you should be able to run it with the command `esptool.py`.

### Manual Installation

Manual installation allows you to run the latest development version from this repository.

esptool.py depends on [pySerial](https://github.com/pyserial/pyserial#readme) version 2.5 or newer for serial communication with the target device.

If you choose to install esptool.py system-wide by running `python setup.py install`, then this will be taken care of automatically.

If not using `setup.py`, then you'll have to install pySerial manually by running something like `pip install pyserial`, `easy_install pyserial` or `apt-get install python-serial`, depending on your platform. (The official pySerial installation instructions are [here](https://pyserial.readthedocs.org/en/latest/pyserial.html#installation)).

## Usage

Use `esptool.py -h` to see a summary of all available commands and command line options.

To see all options for a particular command, append `-h` to the command name. ie `esptool.py write_flash -h`.

## Common Options

### Serial Port

The serial port is selected using the `-p` option, like `-p /dev/ttyUSB0` (on unixen like Linux and OSX) or `-p COM1`
(on Windows).

If using Cygwin on Windows, you have to convert the Windows-style name into an Unix-style path (`COM1` -> `/dev/ttyS0`, and so on).

### Baud rate

The default esptool.py baud rate is 115200bps. Different rates may be set using `-b 921600` (or another baudrate of your choice). Baudrate can also be specified using `ESPTOOL_BAUD` environment variable. This can speed up `write_flash` and `read_flash` operations.

The baud rate is limited to 115200 when esptool.py establishes the initial connection, higher speeds are only used for data transfers.

Most hardware configurations will work with `-b 230400`, some with `-b 460800`, `-b 921600` and/or `-b 1500000` or higher.

If you have connectivity problems then you can also set baud rates below 115200. You can also choose 74880, which is the usual baud rate used by the ESP8266 to output [boot log](#boot-log) information.

## Commands

### Convert ELF to Binary

The `elf2image` command converts an ELF file (from compiler/linker output) into the binary blobs to be flashed:
```
esptool.py elf2image my_app.elf
```

This command does not require a serial connection.

The default command output is two binary files: `my_app.elf-0x00000.bin` and `my_app.elf-0x40000.bin`. You can alter the firmware file name prefix using the `--output/-o` option.

`elf2image` can also produce a "version 2" image file suitable for use with a software bootloader stub such as [rboot](https://github.com/raburton/rboot) or the Espressif bootloader program. You can't flash a "version 2" image without also flashing a suitable bootloader.

```
esptool.py elf2image --version=2 -o my_app-ota.bin my_app.elf
```

### Writing binaries to flash

The binaries from elf2image or make_image can be sent to the ESP8266 via the serial `write_flash` command:

```
esptool.py --port COM4 write_flash 0x00000 my_app.elf-0x00000.bin 0x40000 my_app.elf-0x40000.bin
```

Or, for a "version 2" image, a single argument:

```
esptool.py --port COM4 write_flash 0x1000 my_app-0x01000.bin
```

The --port argument specifies the serial port. This may take the form of something like COMx (Windows), /dev/ttyUSBx (Linux) or /dev/tty.usbserial (OS X) or similar names.

The next arguments to write_flash are one or more pairs of offset (address) and file name. When generating "version 1" images, the file names created by elf2image include the flash offsets as part of the file name. For "version 2" images, the bootloader and linker script you are using determines the flash offset.

You may need to specify arguments for [flash mode and flash size](#flash-modes) as well (flash size is autodetected in the recent versions and usually can be omitted). For example:

```
esptool.py --port /dev/ttyUSB0 write_flash --flash_mode qio --flash_size 32m 0x0 bootloader.bin 0x1000 my_app.bin
```

The [Flash Modes](#flash-modes) section below explains the meaning of these additional arguments.

See the [Troubleshooting](#troubleshooting) section if the write_flash command is failing, or the flashed module fails to boot.

### Verifying flash

You can verify an image in the flash by passing the `--verify` option to the `write_flash` command, or by using the standalone `verify_flash` command:

```
./esptool.py verify_flash 0x40000 my_app.elf-0x40000.bin
```

Verification is not always necessary, the bootloader serial protocol includes a checksum and this is usually enough to guarantee accurate flashing.

NOTE: esptool.py may update the first 16 bytes (offset 0) of the ESP8266 flash when writing (see [Flash modes](#flash-modes)), to set the provided flash mode and flash size parameters. If this happens then the standalone `verify_flash` command may fail on these bytes (`write_flash --verify` accounts for this).

### Manually assembling a firmware image

You can also manually assemble a firmware image from binary segments (such as those extracted from objcopy), like this:

```
esptool.py make_image -f app.text.bin -a 0x40100000 -f app.data.bin -a 0x3ffe8000 -f app.rodata.bin -a 0x3ffe8c00 app.flash.bin
```

This command does not require a serial connection.

### Dumping Memory

The `dump_mem` command will dump a region from the ESP8266 memory space. For example, to dump the ROM (64 KiB) from the chip:

```
esptool.py dump_mem 0x40000000 65536 iram0.bin
```

### Read built-in MAC address

```
esptool.py read_mac
```

#### Read SPI flash id

```
esptool.py flash_id
```

Refer to [flashrom source code](http://code.coreboot.org/p/flashrom/source/tree/HEAD/trunk/flashchips.h) for flash chip manufacturer name and part number.

#### Read internal chip id:

```
esptool.py chip_id
```

This is the same as the output of the [system_get_chip_id()](http://esp8266-re.foogod.com/wiki/System_get_chip_id_%28IoT_RTOS_SDK_0.9.9%29) SDK function. The chip ID is four bytes long, the lower three bytes are the final bytes of the MAC address. The upper byte is zero on most (all?) ESP8266s.

## Serial Connections

The ESP8266 ROM serial bootloader uses a 3.3V UART serial connection. Many ESP8266 development boards make the serial connections for you onboard.

However, if you are wiring the ESP8266 yourself to a USB/Serial adapter or similar then the following connections must be made:

ESP8266 Pin     | Serial Port Pin
--------------- | ----------------------------
TX (aka GPIO1)  | RX (receive)
RX (aka GPIO3)  | TX (transmit)
Ground          | Ground

Note that TX (transmit) on the ESP8266 is connected to RX (receive) on the serial port connection, and vice versa.

Do not connect the ESP8266 to 5V TTL serial adapters, and especially not to high voltage RS-232 adapters! 3.3v serial only!

## Entering the Bootloader

The ESP8266 has to be reset in a certain way in order to launch the serial bootloader.

On some development boards (including NodeMCU, WeMOS, HUZZAH Feather), esptool.py can automatically trigger a reset into the serial bootloader - in which case you don't need to read this section.

For everyone else, three things must happen to enter the serial bootloader - a reset, required pins set correctly, and GPIO0 pulled low:

### Reset

The ESP8266 chooses the boot mode each time it resets. A reset event can happen in one of several ways:

* Power applied to ESP8266.
* The nRESET pin was low and is pulled high.
* The CH_PD pin ("enable") was low and is pulled high.

The nRESET and ENABLE pins must both be pulled high.

### Required Pins

The following ESP8266 pins must be pulled high/low for either normal or serial bootloader operation. Most development boards or modules make these connections already, internally:

GPIO | Must Be Pulled
---- | -----------------------------------------------
15   | Low/GND (directly, or with a resistor)
2    | High/VCC (always use a resistor)

If these pins are set differently to shown, nothing on the ESP8266 will work as expected. See [this wiki page](https://github.com/esp8266/esp8266-wiki/wiki/Boot-Process#esp-boot-modes) to see what boot modes are enabled for different pin combinations.

GPIO2 should always use a pullup resistor to VCC, not a direct connection. This is because it is configured as an output by the boot ROM. If GPIO15 is unused then it can be connected directly to ground, but it's safest to use a pulldown resistor here as well.

### Selecting bootloader mode

The ESP8266 will enter the serial bootloader when GPIO0 is held low on reset. Otherwise it will run the program in flash.

GPIO0 Input     | Mode
--------------- | ----------------------------------------------
Low/GND         | ROM serial bootloader for esptool.py
High/VCC        | Normal execution mode

Many configurations use a "Flash" button that pulls GPIO0 low when pressed.

### Automatic bootloader

esptool.py can automatically enter the bootloader on many boards by using only the RTS and DTR modem status lines.

Make the following connections for esptool.py to automatically enter the bootloader:

ESP8266 Pin                   | Serial Pin
----------------------------- | -------------------------
CH_PD ("enable") *or* nRESET  | RTS
GPIO0                         | DTR

Note that some serial terminal programs (not esptool.py) will assert both RTS and DTR when opening the serial port, pulling them low together and holding the ESP8266 in reset. If you've wired RTS to the ESP8266 then you should disable RTS/CTS "hardware flow control" in the program. Development boards like NodeMCU use additional circuitry to avoid this problem - if both RTS and DTR are asserted together, this doesn't reset the chip.

## Flash Modes

`write_flash` and some other comands accept command line arguments to set flash mode, flash size and flash clock frequency. The ESP8266 needs correct mode, frequency and size settings in order to run correctly - although there is some flexibility.

These arguments must appear after `write_flash` on the command line, for example:

```
esptool.py --port /dev/ttyUSB1 write_flash --flash_mode dio --flash_size 32m 0x0 bootloader.bin
```

When flashing at offset 0x0, the first sector of the ESP8266 flash is updated automatically using the arguments passed in.

### Flash Mode (--flash_mode, -fm)

These set Quad Flash I/O or Dual Flash I/O modes. Valid values are `qio`, `qout`, `dio`, `dout`. The default is `qio`. This parameter can also be specified using the environment variable `ESPTOOL_FM`.

Most boards use the default `qio`. Some ESP8266 modules, including the ESP-12E modules on some (not all) NodeMCU boards, are dual I/O and the firmware will only boot when flashed with `--flash_mode dio`.

In `qio` mode, GPIOs 9 and 10 are used for SPI flash communications. If flash mode is set to `dio` then these pins are available for other purposes.

### Flash Size (--flash_size, -fs)

Size of the SPI flash. Valid values are `4m`, `2m`, `8m`, `16m`, `32m`, `16m-c1`, `32m-c1`, `32m-c2` (megabits). For `write_flash` command, the default is `detect`, which tries to autodetect size based on SPI flash ID. If detection fails, older default of `4m` (4 megabits, 512 kilobytes) is used. This parameter can also be specified using the environment variable `ESPTOOL_FS`.

The ESP8266 SDK stores WiFi configuration at the "end" of flash, and it finds the end using this size. However there is no downside to specifying a smaller flash size than you really have, as long as you don't need to write an image larger than the configured size.

ESP-12, ESP-12E and ESP-12F modules (and boards that use them such as NodeMCU, HUZZAH, etc.) usually have at least 32 megabit (`32m` i.e. 4MB) flash. You can find the flash size by using the `flash_id` command and then looking up the ID from the output (see [Read SPI flash id](#read-spi-flash-id)). If `--flash_size=detect` (recent default) is used, this process is performed automatically by `esptool.py` itself.

### Flash Frequency (--flash_freq, -ff)

Clock frequency for SPI flash interactions. Valid values are 40m, 26m, 20m, 80m (MHz). The default is 40m (40MHz). This parameter can also be specified using the environment variable `ESPTOOL_FF`.

The flash chip on most ESP8266 modules works with 40MHz clock speeds, but you can try lower values if the device won't boot.

## Troubleshooting

ESP8266 problems can be fiddly to troubleshoot. Try the suggestions here if you're having problems:

### Bootloader won't respond

If you see errors like "Failed to connect to ESP8266" then your ESP8266 is probably not entering the bootloader properly:

* Check you are passing the correct serial port on the command line.
* Check you have permissions to access the serial port, and other software (such as modem-manager on Linux) is not trying to interact with it.
* Check the ESP8266 is receiving 3.3V from a stable power source (see [Insufficient Power](#insufficient-power) for more details.)
* Check that all pins are connected as described in [Entering the bootloader](#entering-the-bootloader). Check the voltages at each pin with a multimeter, "high" pins should be close to 3.3V and "low" pins should be close to 0V.
* If you have connected other devices to GPIO0, GPIO2 or GPIO15 then try removing them and see if esptool.py starts working.
* Try using a slower baud rate (`-b 9600` is a very slow value that you can use to verify it's not a baud rate problem.)


### write_flash operation fails part way through

If flashing fails with random errors part way through, retry with a lower baud rate.

Power stability problems may also cause this (see [Insufficient Power](#insufficient-power).)

### write_flash succeeds but ESP8266 doesn't run

If esptool.py can flash your module with `write_flash` but your program doesn't run, try the following:

#### Wrong Flash Mode

Some ESP8266 modules only support the `dio` flash mode. Writing to flash with `qio` mode will succeed but the ESP8266 can't read it back to run - so nothing happens on boot. Try passing the `-fm dio` option to write_flash.

#### Insufficient Power

The 3.3V power supply for the ESP8266 has to supply large amounts of current (up to 70mA continuous, 200-300mA peak). You also need sufficient capacitance on the power circuit to meet large spikes of power demand.

If you're using a premade development board or module then the built-in power regulator is usually good enough, provided the input power supply is adequate.

It is possible to have a power supply that supplies enough current for the serial bootloader stage with esptool.py, but not enough for normal firmware operation. You may see the 3.3V VCC voltage droop down if you measure it with a multimeter, but you can have problems even if this isn't happening.

Try swapping in a 3.3V supply with a higher current rating, add capacitors to the power line, and/or shorten any 3.3V power wires.

The 3.3V output from FTDI FT232R chips/adapters or Arduino boards *do not* supply sufficient current to power an ESP8266 (it may seem to work sometimes, but it won't work reliably).

#### Missing bootloader

Recent Espressif SDKs use a small firmware bootloader program. The hardware bootloader in ROM loads this firmware bootloader from flash, and then it runs the program. This firmware bootloader image (with a filename like `boot_v1.x.bin`) has to be flashed at offset 0. If the firmware bootloader is missing then the ESP8266 will not boot.

Refer to your SDK documentation for details regarding which binaries need to be flashed at which offsets.

#### SPI Pins which must be disconnected

Compared to the ROM bootloader that esptool.py talks to, a running firmware uses more of the ESP8266's pins to access the SPI flash.

If you set "Quad I/O" mode (`-fm qio`, the esptool.py default) then GPIOs 7, 8, 9 & 10 are used for reading the SPI flash and must be otherwise disconnected.

If you set "Dual I/O" mode (`-fm dio`) then GPIOs 7 & 8 are used for reading the SPI flash and must be otherwise disconnected.

Try disconnecting anything from those pins (and/or swap to Dual I/O mode if you were previously using Quad I/O mode but want to attach things to GPIOs 9 & 10).

In addition to these pins, GPIOs 6 & 11 are also used to access the SPI flash (in all modes). However flashing will usually fail completely if these pins are connected incorrectly.

### Early stage crash

Use a [serial terminal program](#serial-terminal-programs) to view the boot log at 74880bps, see if the program is crashing during early startup or outputting an error message. See [Boot log](#boot-log) for an example.

## Serial Terminal Programs

There are many serial terminal programs suitable for normal ESP8266 debugging & serial interaction. The pyserial module (which is required for esptool.py) includes one such command line terminal program - miniterm.py. For more details [see this page](http://pyserial.readthedocs.org/en/latest/tools.html#module-serial.tools.miniterm) or run `miniterm -h`.

Note that not every serial program supports the unusual ESP8266 74880bps "boot log" baud rate. Support is especially sparse on Linux. `miniterm.py` supports this baud rate on all platforms.

## Internal Technical Documentation

The [repository wiki](https://github.com/themadinventor/esptool/wiki) contains some technical documentation regarding the serial protocol and file format used by the ROM bootloader. This may be useful if you're developing esptool.py or hacking system internals:

* [Firmware Image Format](https://github.com/themadinventor/esptool/wiki/Firmware-Image-Format)
* [Serial Protocol](https://github.com/themadinventor/esptool/wiki/Serial-Protocol)


## Boot log
The boot rom writes a log to the UART when booting. The timing is a little bit unusual: 74880 baud

```
ets Jan  8 2014,rst cause 1, boot mode:(3,7)

load 0x40100000, len 24236, room 16
tail 12
chksum 0xb7
ho 0 tail 12 room 4
load 0x3ffe8000, len 3008, room 12
tail 4
chksum 0x2c
load 0x3ffe8bc0, len 4816, room 4
tail 12
chksum 0x46
csum 0x46
```

## About

esptool.py was initially created by Fredrik Ahlberg (themadinventor, kongo), and is currently maintained by Fredrik and Angus Gratton (@projectgus). It has also received improvements from many members of the ESP8266 community - including pfalcon, tommie, 0ff and george-hopkins.

This document and the attached source code is released under GPLv2.
