# esptool.py

A Python-based, open source, platform independent, utility to communicate with the ROM bootloader in Espressif ESP8266 & ESP32 series chips.

esptool.py was started by Fredrik Ahlberg (@[themadinventor](https://github.com/themadinventor/)) as an unofficial community project. It is now also supported by Espressif. Current primary maintainer is Angus Gratton (@[projectgus](https://github.com/projectgus/)).

esptool.py is Free Software under a GPLv2 license.

[![Test esptool](https://github.com/espressif/esptool/workflows/Test%20esptool/badge.svg?branch=master)](https://github.com/espressif/esptool)

## Installation / dependencies

### Easy Installation

You will need [either Python 2.7 or Python 3.4 or newer](https://www.python.org/downloads/) installed on your system.

The latest stable esptool.py release can be installed from [pypi](http://pypi.python.org/pypi/esptool) via pip:

```
$ pip install esptool
```

With some Python installations this may not work and you'll receive an error, try `python -m pip install esptool` or `pip2 install esptool`, or consult your [Python installation manual](https://pip.pypa.io/en/stable/installing/) for information about how to access pip.

[Setuptools](https://setuptools.readthedocs.io/en/latest/userguide/quickstart.html) is also a requirement which is not available on all systems by default. You can install it by a package manager of your operating system, or by `pip install setuptools`.

After installing, you will have `esptool.py` installed into the default Python executables directory and you should be able to run it with the command `esptool.py` or `python -m esptool`. Please note that probably only `python -m esptool` will work for Pythons installed from Windows Store.

### Development Mode Installation

Development mode allows you to run the latest development version from this repository.

```
$ git clone https://github.com/espressif/esptool.git
$ cd esptool
$ pip install --user -e .
```

This will install esptool's dependencies and create some executable script wrappers in the user's `bin` directory. The wrappers will run the scripts found in the git working directory directly, so any time the working directory contents change it will pick up the new versions.

It's also possible to run the scripts directly from the working directory with this Development Mode installation.

(Note: if you actually plan to do development work with esptool itself, see the CONTRIBUTING.md file.)

## Usage

Use `esptool.py -h` to see a summary of all available commands and command line options.

To see all options for a particular command, append `-h` to the command name. ie `esptool.py write_flash -h`.

## Common Options

### Serial Port

* The serial port is selected using the `-p` option, like `-p /dev/ttyUSB0` (Linux and macOS) or `-p COM1` (Windows).
* A default serial port can be specified by setting the `ESPTOOL_PORT` environment variable.
* If no `-p` option or `ESPTOOL_PORT` value is specified, `esptool.py` will enumerate all connected serial ports and try each one until it finds an Espressif device connected (new behaviour in v2.4.0).

Note: Windows and macOS may require drivers to be installed for a particular USB/serial adapter, before a serial port is available. Consult the documentation for your particular device. On macOS, you can also consult [System Information](https://support.apple.com/en-us/HT203001)'s list of USB devices to identify the manufacturer or device ID when the adapter is plugged in. On Windows, you can use [Windows Update or Device Manager](https://support.microsoft.com/en-us/help/15048/windows-7-update-driver-hardware-not-working-properly) to find a driver.

If using Cygwin or WSL on Windows, you have to convert the Windows-style name into a Unix-style path (`COM1` -> `/dev/ttyS0`, and so on). (This is not necessary if using ESP-IDF for ESP32 with the supplied Windows MSYS2 environment, this environment uses a native Windows Python which accepts COM ports as-is.)

In Linux, the current user may not have access to serial ports and a "Permission Denied" error will appear. On most Linux distributions, the solution is to add the user to the `dialout` group with a command like `sudo usermod -a -G dialout <USERNAME>`. Check your Linux distribution's documentation for more information.

### Baud rate

The default esptool.py baud rate is 115200bps. Different rates may be set using `-b 921600` (or another baud rate of your choice). A default baud rate can also be specified using the `ESPTOOL_BAUD` environment variable. This can speed up `write_flash` and `read_flash` operations.

The baud rate is limited to 115200 when esptool.py establishes the initial connection, higher speeds are only used for data transfers.

Most hardware configurations will work with `-b 230400`, some with `-b 460800`, `-b 921600` and/or `-b 1500000` or higher.

If you have connectivity problems then you can also set baud rates below 115200. You can also choose 74880, which is the usual baud rate used by the ESP8266 to output [boot log](#boot-log) information.

## Commands

### Write binary data to flash: write_flash

Binary data can be written to the ESP's flash chip via the serial `write_flash` command:

```
esptool.py --port COM4 write_flash 0x1000 my_app-0x01000.bin
```

Multiple flash addresses and file names can be given on the same command line:

```
esptool.py --port COM4 write_flash 0x00000 my_app.elf-0x00000.bin 0x40000 my_app.elf-0x40000.bin
```

The `--chip` argument is optional when writing to flash, esptool will detect the type of chip when it connects to the serial port.

The `--port` argument is documented under [Serial Port](#serial-port).

The next arguments to write_flash are one or more pairs of offset (address) and file name. When generating ESP8266 "version 1" images, the file names created by `elf2image` include the flash offsets as part of the file name. For other types of images, consult your SDK documentation to determine the files to flash at which offsets.

Numeric values passed to write_flash (and other commands) can be specified either in hex (ie 0x1000), or in decimal (ie 4096).

See the [Troubleshooting](#troubleshooting) section if the write_flash command is failing, or the flashed module fails to boot.

#### Setting flash mode and size

You may also need to specify arguments for [flash mode and flash size](#flash-modes), if you wish to override the defaults. For example:

```
esptool.py --port /dev/ttyUSB0 write_flash --flash_mode qio --flash_size 32m 0x0 bootloader.bin 0x1000 my_app.bin
```

Since esptool v2.0, these options are not often needed as the default is to keep the flash mode and size from the `.bin` image file. See the [Flash Modes](#flash-modes) section for more details.

#### Compression

By default, the serial transfer data is compressed for better performance. The `-u/--no-compress` option disables this behaviour.

### Read Flash Contents: read_flash

The read_flash command allows reading back the contents of flash. The arguments to the command are an address, a size, and a filename to dump the output to. For example, to read a full 2MB of attached flash:

```
esptool.py -p PORT -b 460800 read_flash 0 0x200000 flash_contents.bin
```

(Note that if `write_flash` updated the boot image's [flash mode and flash size](#flash-modes) during flashing then these bytes may be different when read back.)

### Erase Flash: erase_flash & erase region

To erase the entire flash chip (all data replaced with 0xFF bytes):

```
esptool.py erase_flash
```

To erase a region of the flash, starting at address 0x20000 with length 0x4000 bytes (16KB):

```
esptool.py erase_region 0x20000 0x4000
```

The address and length must both be multiples of the SPI flash erase sector size. This is 0x1000 (4096) bytes for supported flash chips.

### Read built-in MAC address: read_mac

```
esptool.py read_mac
```

### Read SPI flash id: flash_id

```
esptool.py flash_id
```

Example output:

```
Manufacturer: e0
Device: 4016
Detected flash size: 4MB
```

Refer to [flashrom source code](https://review.coreboot.org/cgit/flashrom.git/tree/flashchips.h) for flash chip manufacturer name and part number.

### Convert ELF to Binary: elf2image

The `elf2image` command converts an ELF file (from compiler/linker output) into the binary executable images which can be flashed and then booted into:
```
esptool.py --chip esp8266 elf2image my_app.elf
```

This command does not require a serial connection.

`elf2image` also accepts the [Flash Modes](#flash-modes) arguments `--flash_freq` and `--flash_mode`, which can be used to set the default values in the image header. This is important when generating any image which will be booted directly by the chip. These values can also be overwritten via the `write_flash` command, see the [write_flash command](#write-binary-data-to-flash-write_flash) for details.

By default, `elf2image` uses the sections in the ELF file to generate each segment in the binary executable. To use segments (PHDRs) instead, pass the `--use_segments` option.

#### elf2image for ESP8266

The default command output is two binary files: `my_app.elf-0x00000.bin` and `my_app.elf-0x40000.bin`. You can alter the firmware file name prefix using the `--output/-o` option.

`elf2image` can also produce a "version 2" image file suitable for use with a software bootloader stub such as [rboot](https://github.com/raburton/rboot) or the Espressif bootloader program. You can't flash a "version 2" image without also flashing a suitable bootloader.

```
esptool.py --chip esp8266 elf2image --version=2 -o my_app-ota.bin my_app.elf
```

#### elf2image for ESP32

For ESP32, elf2image produces a single output binary "image file". By default this has the same name as the .elf file, with a .bin extension. ie:

```
esptool.py --chip esp32 elf2image my_esp32_app.elf
```

In the above example, the output image file would be called `my_esp32_app.bin`.

### Output .bin image details: image_info

The `image_info` command outputs some information (load addresses, sizes, etc) about a `.bin` file created by `elf2image`.

```
esptool.py --chip esp32 image_info my_esp32_app.bin
```

Note that `--chip esp32` is required when reading ESP32 images. Otherwise the default is `--chip esp8266` and the image will be interpreted as an invalid ESP8266 image.

### Advanced Commands

The following commands are less commonly used, or only of interest to advanced users. They are documented on the wiki:

* [verify_flash](https://github.com/espressif/esptool/wiki/Advanced-Commands#verify_flash)
* [dump_mem](https://github.com/espressif/esptool/wiki/Advanced-Commands#dump_mem)
* [load_ram](https://github.com/espressif/esptool/wiki/Advanced-Commands#load_ram)
* [read_mem & write_mem](https://github.com/espressif/esptool/wiki/Advanced-Commands#read_mem--write_mem)
* [read_flash_status](https://github.com/espressif/esptool/wiki/Advanced-Commands#read_flash_status)
* [write_flash_status](https://github.com/espressif/esptool/wiki/Advanced-Commands#write_flash_status)
* [chip_id](https://github.com/espressif/esptool/wiki/Advanced-Commands#chip_id)
* [make_image](https://github.com/espressif/esptool/wiki/Advanced-Commands#make_image)
* [run](https://github.com/espressif/esptool/wiki/Advanced-Commands#run)

## Additional ESP32 Tools

The following tools for ESP32, bundled with esptool.py, are documented on the wiki:

* [espefuse.py - for reading/writing ESP32 efuse region](https://github.com/espressif/esptool/wiki/espefuse)
* [espsecure.py - for working with ESP32 security features](https://github.com/espressif/esptool/wiki/espsecure)

## Serial Connections

The ESP8266 & ESP32 ROM serial bootloader uses a 3.3V UART serial connection. Many development boards make the serial connections for you onboard.

However, if you are wiring the chip yourself to a USB/Serial adapter or similar then the following connections must be made:

ESP32/ESP8266 Pin     | Serial Port Pin
--------------------- | ----------------------------
TX (aka GPIO1)        | RX (receive)
RX (aka GPIO3)        | TX (transmit)
Ground                | Ground

Note that TX (transmit) on the ESP8266 is connected to RX (receive) on the serial port connection, and vice versa.

Do not connect the chip to 5V TTL serial adapters, and especially not to "standard" RS-232 adapters! 3.3V serial only!

## Entering the Bootloader

Both ESP8266 and ESP32 have to be reset in a certain way in order to launch the serial bootloader.

On some development boards (including NodeMCU, WeMOS, HUZZAH Feather, Core Board, ESP32-WROVER-KIT), esptool.py can automatically trigger a reset into the serial bootloader - in which case you don't need to read this section.

For everyone else, three things must happen to enter the serial bootloader - a reset, required pins set correctly, and GPIO0 pulled low:

### Boot Mode

Both ESP8266 and ESP32 choose the boot mode each time they reset. A reset event can happen in one of several ways:

* Power applied to chip.
* The nRESET pin was low and is pulled high (on ESP8266 only).
* The CH_PD/EN pin ("enable") pin was low and is pulled high.

On ESP8266, both the nRESET and CH_PD pins must be pulled high for the chip to start operating.

For more details on selecting the boot mode, see the following Wiki pages:

* [ESP8266 Boot Mode Selection](https://github.com/espressif/esptool/wiki/ESP8266-Boot-Mode-Selection)
* [ESP32 Boot Mode Selection](https://github.com/espressif/esptool/wiki/ESP32-Boot-Mode-Selection)

## Flash Modes

`write_flash` and some other commands accept command line arguments to set bootloader flash mode, flash size and flash clock frequency. The chip needs correct mode, frequency and size settings in order to run correctly - although there is some flexibility. A header at the beginning of a bootable image contains these values.

To override these values, the options `--flash_mode`, `--flash_size` and/or `--flash_freq` must appear after `write_flash` on the command line, for example:

```
esptool.py --port /dev/ttyUSB1 write_flash --flash_mode dio --flash_size 4MB 0x0 bootloader.bin
```

These options are only consulted when flashing a bootable image to an ESP8266 at offset 0x0, or an ESP32 at offset 0x1000. These are addresses used by the ROM bootloader to load from flash. When flashing at all other offsets, these arguments are not used.

### Flash Mode (--flash_mode, -fm)

These set Quad Flash I/O or Dual Flash I/O modes. Valid values are `keep`, `qio`, `qout`, `dio`, `dout`. The default is `keep`, which keeps whatever value is already in the image file. This parameter can also be specified using the environment variable `ESPTOOL_FM`.

Most boards use `qio` mode. Some ESP8266 modules, including the ESP-12E modules on some (not all) NodeMCU boards, are dual I/O and the firmware will only boot when flashed with `--flash_mode dio`. Most ESP32 modules are also dual I/O.

In `qio` mode, two additional GPIOs (9 and 10) are used for SPI flash communications. If flash mode is set to `dio` then these pins are available for other purposes.

For a full explanation of these modes, see the [SPI Flash Modes wiki page](https://github.com/espressif/esptool/wiki/SPI-Flash-Modes).

### Flash Frequency (--flash_freq, -ff)

Clock frequency for SPI flash interactions. Valid values are `keep`, `40m`, `26m`, `20m`, `80m` (MHz). The default is `keep`, which keeps whatever value is already in the image file. This parameter can also be specified using the environment variable `ESPTOOL_FF`.

The flash chip connected to most chips works with 40MHz clock speeds, but you can try lower values if the device won't boot. The highest 80MHz flash clock speed will give the best performance, but may cause crashing if the flash or board design is not capable of this speed.

### Flash Size (--flash_size, -fs)

Size of the SPI flash, given in megabytes. Valid values vary by chip type:

Chip     | flash_size values
---------|---------------------------------------------------------------
ESP32    | `keep`, `detect`, `1MB`, `2MB`, `4MB`, `8MB`, `16MB`
ESP8266  | `keep`, `detect`, `256KB`, `512KB`, `1MB`, `2MB`, `4MB`, `2MB-c1`, `4MB-c1`, `8MB`, `16MB`

For ESP8266, some [additional sizes & layouts for OTA "firmware slots" are available](#esp8266-and-flash-size).

The default `--flash_size` parameter is `keep`. This means that if no `--flash_size` argument is passed when flashing a bootloader, the value in the bootloader .bin file header is kept instead of detecting the actual flash size and updating the header.

To enable automatic flash size detection based on SPI flash ID, add the argument `esptool.py [...] write_flash [...] -fs detect`. If detection fails, a warning is printed and a default value of of `4MB` (4 megabytes) is used.

If flash size is not successfully detected, you can find the flash size by using the `flash_id` command and then looking up the ID from the output (see [Read SPI flash id](#read-spi-flash-id-flash_id)). Alternatively, read off the silkscreen labelling of the flash chip and search for its datasheet.

The default `flash_size` parameter can also be overridden using the environment variable `ESPTOOL_FS`.

#### ESP8266 and Flash Size

The ESP8266 SDK stores WiFi configuration at the "end" of flash, and it finds the end using this size. However there is no downside to specifying a smaller flash size than you really have, as long as you don't need to write an image larger than this size.

ESP-12, ESP-12E and ESP-12F modules (and boards that use them such as NodeMCU, HUZZAH, etc.) usually have at least 4 megabyte / `4MB` (sometimes labelled 32 megabit) flash.

If using OTA, some additional sizes & layouts for OTA "firmware slots" are available. If not using OTA updates then you can ignore these extra sizes:

|flash_size arg | Number of OTA slots | OTA Slot Size | Non-OTA Space |
|---------------|---------------------|---------------|---------------|
|256KB          | 1 (no OTA)          | 256KB         | N/A           |
|512KB          | 1 (no OTA)          | 512KB         | N/A           |
|1MB            | 2                   | 512KB         | 0KB           |
|2MB            | 2                   | 512KB         | 1024KB        |
|4MB            | 2                   | 512KB         | 3072KB        |
|2MB-c1         | 2                   | 1024KB        | 0KB           |
|4MB-c1         | 2                   | 1024KB        | 2048KB        |
|8MB [^]        | 2                   | 1024KB        | 6144KB        |
|16MB [^]       | 2                   | 1024KB        | 14336KB       |

* [^] Support for 8MB & 16MB flash size is not present in all ESP8266 SDKs. If your SDK doesn't support these flash sizes, use `--flash_size 4MB`.

#### ESP32 and Flash Size

The ESP-IDF flashes a partition table to the flash at offset 0x8000. All of the partitions in this table must fit inside the configured flash size, otherwise the ESP32 will not work correctly.

## Merging binaries

The `merge_bin` command will merge multiple binary files (of any kind) into a single file that can be flashed to a device later. Any gaps between the input files are padded with 0xFF bytes (same as unwritten flash contents).

For example:

```
esptool.py --chip esp32 merge_bin -o merged-flash.bin --flash_mode dio --flash_size 4MB 0x1000 bootloader.bin 0x8000 partition-table.bin 0x10000 app.bin
```

Will create a file `merged-flash.bin` with the contents of the other 3 files. This file can be later be written to flash with `esptool.py write_flash 0x0 merged-flash.bin`.

Note: Because gaps between the input files are padded with 0xFF bytes, when the merged binary is written then any flash sectors between the individual files will be erased. To avoid this, write the files individually.

### Options

* The `merge_bin` command supports the same `--flash_mode`, `--flash_size` and `--flash_speed` options as the `write_flash` command to override the bootloader flash header (see above for details). These options are applied to the output file contents in the same way as when writing to flash. Make sure to pass the `--chip` parameter if using these options, as the supported values and the bootloader offset both depend on the chip.
* The `--target-offset 0xNNN` option will create a merged binary that should be flashed at the specified offset, instead of at offset 0x0.
* The `--fill-flash-size SIZE` option will pad the merged binary with 0xFF bytes to the full flash specified size, for example `--fill-flash-size 4MB` will create a 4MB binary file.

```
## Advanced Options

See the [Advanced Options wiki page](https://github.com/espressif/esptool/wiki/Advanced-Options) for some of the more unusual esptool.py command line options.

## Remote Serial Ports

It is possible to connect to any networked remote serial port that supports [RFC2217](http://www.ietf.org/rfc/rfc2217.txt) (Telnet) protocol, or a plain TCP socket. See the [Remote Serial Ports wiki page](https://github.com/espressif/esptool/wiki/Remote-Serial-Ports) for details.

## Troubleshooting

Flashing problems can be fiddly to troubleshoot. Try the suggestions here if you're having problems:

### Bootloader won't respond

If you see errors like "Failed to connect" then your chip is probably not entering the bootloader properly:

* Check you are passing the correct serial port on the command line.
* Check you have permissions to access the serial port, and other software (such as modem-manager on Linux) is not trying to interact with it. A common pitfall is leaving a serial terminal accessing this port open in another window and forgetting about it.
* Check the chip is receiving 3.3V from a stable power source (see [Insufficient Power](#insufficient-power) for more details.)
* Check that all pins are connected as described in [Entering the bootloader](#entering-the-bootloader). Check the voltages at each pin with a multimeter, "high" pins should be close to 3.3V and "low" pins should be close to 0V.
* If you have connected other devices to GPIO pins mentioned above section, try removing them and see if esptool.py starts working.
* Try using a slower baud rate (`-b 9600` is a very slow value that you can use to verify it's not a baud rate problem.)


### write_flash operation fails part way through

If flashing fails with random errors part way through, retry with a lower baud rate.

Power stability problems may also cause this (see [Insufficient Power](#insufficient-power).)

### write_flash succeeds but program doesn't run

If esptool.py can flash your module with `write_flash` but your program doesn't run, try the following:

#### Wrong Flash Mode

Some devices only support the `dio` flash mode. Writing to flash with `qio` mode will succeed but the chip can't read the flash back to run - so nothing happens on boot. Try passing the `-fm dio` option to write_flash.

See the [SPI Flash Modes](https://github.com/espressif/esptool/wiki/SPI-Flash-Modes) wiki page for a full description of the flash modes and how to determine which ones are supported on your device.

#### Insufficient Power

The 3.3V power supply for the ESP8266 and ESP32 has to supply large amounts of current (up to 70mA continuous, 200-300mA peak, slightly higher for ESP32). You also need sufficient capacitance on the power circuit to meet large spikes of power demand.

##### Insufficient Capacitance

If you're using a pre-made development board or module then the built-in power regulator & capacitors are usually good enough, provided the input power supply is adequate.

*This is not true for some very simple pin breakout modules - [similar to this](https://user-images.githubusercontent.com/205573/30140831-9da417a6-93ba-11e7-95c3-f422744967de.jpg). These breakouts do not integrate enough capacitance to work reliably without additional components.*. Surface mount OEM modules like ESP-WROOM02 and ESP-WROOM32 require an external bulk capacitor on the PCB to be reliable, consult the module datasheet.

##### Power Supply Rating

It is possible to have a power supply that supplies enough current for the serial bootloader stage with esptool.py, but not enough for normal firmware operation. You may see the 3.3V VCC voltage droop down if you measure it with a multimeter, but you can have problems even if this isn't happening.

Try swapping in a 3.3V supply with a higher current rating, add capacitors to the power line, and/or shorten any 3.3V power wires.

The 3.3V output from FTDI FT232R chips/adapters or Arduino boards *do not* supply sufficient current to power an ESP8266 or ESP32 (it may seem to work sometimes, but it won't work reliably). Other USB TTL/serial adapters may also be marginal.

#### Missing bootloader

Recent ESP8266 SDKs and the ESP32 ESP-IDF both use a small firmware bootloader program. The hardware bootloader in ROM loads this firmware bootloader from flash, and then it runs the program. On ESP8266. firmware bootloader image (with a filename like `boot_v1.x.bin`) has to be flashed at offset 0. If the firmware bootloader is missing then the ESP8266 will not boot. On ESP32, the bootloader image should be flashed by ESP-IDF at offset 0x1000.

Refer to SDK or ESP-IDF documentation for details regarding which binaries need to be flashed at which offsets.

#### SPI Pins which must be disconnected

Compared to the ROM bootloader that esptool.py talks to, a running firmware uses more of the chip's pins to access the SPI flash.

If you set "Quad I/O" mode (`-fm qio`, the esptool.py default) then GPIOs 7, 8, 9 & 10 are used for reading the SPI flash and must be otherwise disconnected.

If you set "Dual I/O" mode (`-fm dio`) then GPIOs 7 & 8 are used for reading the SPI flash and must be otherwise disconnected.

Try disconnecting anything from those pins (and/or swap to Dual I/O mode if you were previously using Quad I/O mode but want to attach things to GPIOs 9 & 10). Note that if GPIOs 9 & 10 are also connected to input pins on the SPI flash chip, they may still be unsuitable for use as general purpose I/O.

In addition to these pins, GPIOs 6 & 11 are also used to access the SPI flash (in all modes). However flashing will usually fail completely if these pins are connected incorrectly.

### Early stage crash

Use a [serial terminal program](#serial-terminal-programs) to view the boot log. (ESP8266 baud rate is 74880bps, ESP32 is 115200bps). See if the program is crashing during early startup or outputting an error message.

## Serial Terminal Programs

There are many serial terminal programs suitable for debugging & serial interaction. The pyserial module (which is required for esptool.py) includes one such command line terminal program - miniterm.py. For more details [see this page](http://pyserial.readthedocs.org/en/latest/tools.html#module-serial.tools.miniterm) or run `miniterm -h`.

Note that not every serial program supports the unusual ESP8266 74880bps "boot log" baud rate. Support is especially sparse on Linux. `miniterm.py` supports this baud rate on all platforms. ESP32 uses the more common 115200bps.

## Tracing esptool.py interactions

Running `esptool.py --trace` will dump all serial interactions to the standard output (this is *a lot* of output). This can be helpful when debugging issues with the serial connection, or when providing information for bug reports.

## Using esptool from Python

esptool.py, espefuse.py, and espsecure.py can easily be integrated into Python applications or called from other Python scripts.

While it currently does have a poor Python API, something which [#208](https://github.com/espressif/esptool/issues/208) will address, it allows for passing CLI 
arguments to `esptool.main()`. This workaround makes integration very straightforward as you can pass exactly the 
same arguments as you would on the CLI.

```python
command = ['--baud', '460800', 'read_flash', '0', '0x200000', 'flash_contents.bin']
print('Using command %s' % ' '.join(command))
esptool.main(command)
```

## Internal Technical Documentation

The [repository wiki](https://github.com/espressif/esptool/wiki) contains some technical documentation regarding the serial protocol and file format used by the ROM bootloader. This may be useful if you're developing esptool.py or hacking system internals:

* [Firmware Image Format](https://github.com/espressif/esptool/wiki/Firmware-Image-Format)
* [Serial Protocol](https://github.com/espressif/esptool/wiki/Serial-Protocol)
* [ESP8266 Boot ROM Log](https://github.com/espressif/esptool/wiki/ESP8266-Boot-ROM-Log)


## About

esptool.py was initially created by Fredrik Ahlberg (@themadinventor, @kongo), and is currently maintained by Angus Gratton (@projectgus). It has also received improvements from many members of the ESP8266 community - including @rojer, @jimparis, @jms19, @pfalcon, @tommie, @0ff, @george-hopkins and others.

This document and the attached source code are released under GNU General Public License Version 2. See the accompanying file LICENSE for a copy.
