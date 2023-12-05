## v4.6.2 (2023-06-12)

### Bug Fixes

- **CH9102F**: Suggest to install new serial drivers if writing to RAM fails
- **compressed upload**: Accept short data blocks with only Adler-32 bytes

## v4.6.1 (2023-06-01)

### Bug Fixes

- **ESP32-S3**: Correct RTC WDT registers to fix resets during flashing

## v4.6 (2023-05-29)

### New Features

- **esptool**: add option to dump whole flash based on detected size

### Bug Fixes

- inconsistent usage of dirs separator
- USB-JTAG-Serial PID detection error
- Set flash parameters even with --flash_size keep
- **ESP32-C6**: Fix get_pkg_version and get_{major,minor}_chip_version

## v4.5.1 (2023-02-28)

### Bug Fixes

- **ESP32-S3**: Temporarily disable increasing CPU freq
- Unknown chip (ID or magic number) error
- **ESP32-S3**: Lower CPU freq to improve flasher stub stability
- **rfc2217_server**: Use new reset sequences

## v4.5 (2023-02-10)

### New Features

- **stub**: Add ESP32-S3 octal flash support
- **esp32h2**: Enable USB-JTAG/Serial mode in the stub flasher
- **bootloader reset**: Allow custom reset strategy setting with a config file
- Allow configuration with a config file
- **bootloader reset**: Tighter transitions on Unix systems
- **ci**: Publish development releases with custom pipeline
- **esp32c6 stub**: Increase CPU frequency and write/read speeds over USB-JTAG/Serial
- **esp32c6 stub**: Enable USB-JTAG/Serial
- **flash_id**: Print the flash type if available for the chip

### Bug Fixes

- **cmds**: Make clear that flash type is from eFuse and not detection
- **load config file**: Sort unknown config options
- **esp32c6**: Workaround for bad MSPI frequency in HS mode
- **flasher_stub**: Correct boundaries for SPIWrite4B and SPIRead4B
- **secure download mode**: Reconnect if ROM refuses to respond
- **secure download mode**: Fix SDM detection on S2/S3
- **ci**: Merge two "ci" directories and build_tools into one
- **ci**: The development release job should not run by default
- **setup**: Use latest reedsolo package which can be installed with Python3.10 and Cython
- **write_flash**: Fix `--erase-all` option
- **espefuse**: Close serial port even when espefuse fails
- **espefuse**: Fix compatibility with Bitstring>=4

### Code Refactoring

- Comply with black 23.1 style
- Optimize unnecessary chip interrogations
- **connection attempt**: Decouple reset sequence settings

## v4.4 (2022-11-21)

### New Features

- **flasher_stub**: Increase CPU frequency and write/read speeds over native USB (USB-OTG)
- **flasher_stub**: Increase CPU frequency and write/read speeds over USB-JTAG/Serial
- Readable error message for serial-related issues
- Detect Guru Meditation errors

### Bug Fixes

- Add workaround for breaking changes of bitstring==4
- close unused ports while get_default_connected_device

## v4.3 (2022-09-14)

### New Features

- **image_info**: Print application information if possible
- Add Macronix flash memory density definitions
- **write_flash**: Prevent flashing incompatible images
- Recover from serial errors when flashing
- Add stub flasher error messages definitions
- **image_info**: Image type autodetection

### Code Refactoring

- **elf2image**: Simplify bootloader image selection
