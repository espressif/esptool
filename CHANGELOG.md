## v4.11.0 (2026-01-27)

### New Features

- **esp32p4**: Add ECO6 stub flasher support
- **esp32p4**: Power on SPI flash chip during the attaching process
- Add missing chip features for ESP32-C5

### Bug Fixes

- **esp32-p4**: Fix flash power on sequence with stub flasher
- **espefuse**: Fix decoding error in esp32c5 summary
- **usb_mode_detection**: Fix USB mode detection on ESP32-C5 and ESP32-C61
- **change_baud**: Disable changing baud rate on ESP32-C2 and ESP32-C5 in SDM
- **esp32c6**: Fix ESP32-C6FH8 package detection
- **esp32c3**: fix usb-serial detection for rev1.1
- **espefuse**: Fix calibration efuses for ESP32-P4 ECO5
- **espefuse**: Fix ECDSA key purposes for ESP32-P4
- **image_info**: Sanitize app and bootloader info of null bytes
- **espsecure**: Allow verifying multiple appended ECDSA signatures

## v4.10.0 (2025-09-16)

### New Features

- **espefuse**: Support ESP32-P4 ECO5 (v3.0)
- **esp32p4**: Add support for ESP32-P4.ECO5
- **esp32c5**: Add support for >16 MB flash sizes
- **espefuse**: Add custom key purposes for ESP32C6/C5/P4
- **espefuse**: Support burning ECDSA_384 keys
- **espefuse**: Clean up limitation for BLOCK9 usage
- **espefuse**: Adds support for burning 512-bit keys for C5

### Bug Fixes

- **espefuse**: Fixes re-connection issue in check-error via UJS port
- **write_flash**: Make write flash mem independent
- Use correct error codes for ROM errors
- **elf2image**: Handle ELF files with zero program header counts
- **espefuse**: Disable programming and usage of XTS-AES-256 efuse key for ESP32-C5
- **esp32c5**: Erase during flashing above 16MB
- **espsecure**: Add support for python-pkcs11 9.0+

## v4.9.1 (2025-07-30)

### Bug Fixes

- **esp32-c3**: Disable flasher stub when Secure Boot is active
- **esp32-s3**: Allow stub flasher execution with active Secure Boot
- Fix buffering issues with CP2102 converter causing connection failures
- **elf2image**: Add support for ESP32-H4 MMU page size configuration
- **elf2image**: validate ELF section types and addresses before processing
- **elf2image**: handle PREINIT_ARRAY section type in ESP32-P4 elf file properly
- enable auto-detection of ESP32-S2 in secure download mode
- enable ESP32-P4 ECO5 chip detection

## v4.9.0 (2025-06-19)

### New Features

- **espefuse**: Add eFuses for ESP32-C61 ECO3
- **espefuse**: Support efuse for ESP32-C5 ECO2 (v1.0)
- **stub_flasher**: Support for >16MB flash on P4 and >16MB encrypted writes on S3
- **espefuse**: Updates esp32h4 efuse table and fixes tests
- **esp32h4**: add ESP32H4 esptool support
- **esp32h21**: Add Microsoft UF2 family ID
- print usb mode when output chip info
- **watchdog_reset**: Add a new watchdog_reset option working even in USB modes
- **espsecure**: Improves an error message for encrypt_flash_data and decrypt_flash_data
- **espefuse**: Clean up efuse code for ESP32H2
- **espefuse**: Support different efuse table versions for ESP32H2
- **espefuse**: Adds efuses for esp32h2 eco5
- **esp32h21**: add ESP32H21 esptool support
- Add new app description segments
- **esp32-p4**: add support for flasher stub in USB OTG mode
- **esp32-c5**: Add ECO1 magic number
- **esp_rfc2217**: Improved the logger message format
- **espefuse**: Adds 3 bit for PSRAM_CAP efuse field
- **espefuse**: Adds API for getting block and wafer versions
- **espefuse**: Adds ADC calibration data for ESP32-C61
- **espefuse**: Adds ADC calibration data for ESP32-C5
- **espefuse**: Adds ADC calibration data for ESP32-P4
- add filtering based on serial number
- **erase_region**: Enable erasing in ROM bootloader and SDM
- **hard_reset**: Support custom hard reset sequence configuration
- Add support for Python 3.13

### Bug Fixes

- Do not use padding for merged IntelHex files
- **stub_flasher**: Fix USB-Serial/JTAG mode on C5 ECO2 and C61 ECO3
- **write_flash**: Detect more cases of unresponsive flash, fix failing flash_size check
- **stub_flasher**: Fix ESP32-C5 ECO2 flashing
- **espefuse**: Fix output messages for set_flash_voltage
- **espefuse**: JTAG_SEL_ENABLE has GPIO34 strapping pin for ESP32P4
- **esp32c5**: fix bootloader address
- **elf2image**: fix elf2image for ram app when sha256 offset not specified
- **esp32h4**: Correct ESP32-H4 chip features
- **esp32h21**: Fix eFuse base address
- **elf2image**: support --flash-mmu-page-config for all chips
- **elf2image**: Try to correct MMU page size if not specified
- **elf2image**: Print correct MMU page size in error message
- **test**: Expect the correct module name for Python's 3.14 argparse
- close port when connect fails
- **write_flash**: Skip flash_size checks if we can't read flash size
- Hide missing app info based on IDF version
- add delay after WDT reset for better stability
- **save_segment**: Adds segment len check the same as bootloader does
- **chip_type_verification**: Enable in SDM, do not rely on magic numbers
- Not reading app description for some SoCs
- **esp32-c6**: Disable RTC WDT reset to prevent port disappearing
- **esp_rfc2217**: Fixed keyboard interrupt on Windows and added info for command
- Fix missing newline in output
- **detect_chip**: Select correct loader before further operations to avoid silent failures
- **usb_resets**: Fix resetting in USB-OTG and USB-Serial/JTAG modes

## v4.8.1 (2024-09-25)

### Bug Fixes

- **esp32c2**: Add esp32c2 eco4 rom magic value
- **packaging**: Correctly exclude the unwanted sub/modules

## v4.8.0 (2024-09-18)

### New Features

- **espefuse**: Supports wafer efuse versions for esp32c61
- **esptool**: add new command SFDP read
- **esptool**: Add option to retry connection in a loop
- **efuse**: Updates efuse table for esp32c5
- **efuse**: Updates efuse table for esp32p4
- **esp32c61**: Added stub flasher support
- **cli**: add autocompletions
- **esptool**: allow picking UART by VID/PID/Name
- **esp32c5**: Add USB-serial/JTAG stub support
- **esp32c5**: Add UART stub support
- **esptool**: Print key_purpose name for get_security_info cmd
- **espefuse**: Adds support extend efuse table by user CSV file
- **espefuse**: Adds efuse dump formats: separated(default) and united(new)
- **espefuse**: Adds incompatible eFuse settings check for S3
- **reset**: Apply reconnections to the whole reset sequence, not line transitions
- **reset**: Automatically reconnect if port disconnects during reset
- **esp32-p4**: Add ECO1 magic number
- **espsecure**: Add support for secure boot v2 using ECDSA-P384 signatures
- **write_flash**: retry flashing if chip disconnects
- **espefuse**: Allow filtering efuses based on command line arguments
- **esploader**: Enable context manager for esp instances
- **espefuse**: Added check for correctness of written data
- **espefuse**: Improves help for burn_efuse cmd
- **esp32s3**: clear boot control register on hard reset
- **esp32-p4**: add spi-connection restriction to ROM class
- add UF2 IDs for ESP32-C5 and ESP32-C61
- **espefuse**: Updates efuses for C5 and C61
- **esp32c61**: add c61 basic flash support (no_stub)
- **esp32c5**: skipped the stub check for esp32c5 mp
- **esp32c5**: base support of esp32c5 mp (no stub)
- Added warning when secure boot enabled
- **cmds/write_flash**: Recalculated SHA digest for image binary
- print flash voltage in flash_id command
- **esptool**: Adds wafer and pkg versions
- **espefuse**: Update adc_info commands for all chips
- **espefuse**: Adds new efuses for esp32p4
- **espefuse**: Allow the espefuse.py to work when coding scheme == 3
- **err_defs**: Add ROM bootloader flash error definitions
- Use ruff instead of flake8 and black both in pre-commit and CI
- **esp32p4**: Enable USB-serial/JTAG in flasher stub
- **espefuse**: Postpone some efuses to burn them at the very end
- add advisory port locking
- **espefuse**: check_error --recover chip even if there are num_errors
- **espefuse**: Adds new efuses for esp32c6 and esp32h2
- **esp32c5**: add target esp32c5 beta3

### Bug Fixes

- **esptool**: Fix esp32c61 flash frequency config
- **esptool**: Fix incorrect chip version for esp32c5
- **write_flash**: Verify if files will fit against the real flash size when possible
- **remote_ports**: Disable reset sequence when a socket is used
- **bitstring**: Restricted bitstring dependency to fix 32-bit compatibility
- **esp32_d0wdr2_v3**: Print correct chip name
- pass error message to exception in OTG mode
- **bin_image**: add check for ELF file segment when saving RAM segments
- **docs**: Add a note about entering manual bootloader mode
- **esp32c5**: Fix MAC reading for esptool
- Erase non-aligned bytes with --no-stub
- **esp32-c5**: Use a longer reset delay with usb-serial/jtag to stabilize boot-up
- **espefuse**: Use stub class if stub flasher is running
- Do not append SHA256 when `--ram-only-header`
- **elf2image**: add ELF flags to merge condition
- ram_only_header: pad flash segment to next boundary
- sort segments if ram_only_header is used
- **espefuse**: Fix efuse base addr for esp32c5 MP
- fix type annotation to comply with mypy
- **espefuse**: Fix burn_key for ECDSA_KEY, it can read pem file
- **secure_download_mode**: Disable secure boot detection and print more info
- **esptool**: clear boot control register on ESP32-S3
- **intelhex**: catch unicode decode errors when converting hex to binary
- ROM doesn't attach in-package flash chips
- close file gracefully in espsecure
- Fixed glitches on RTS line when no_reset option on Windows
- **merge_bin**: treat files starting with colon as raw files
- Index image segments from 0 instead of 1
- **read_flash**: add flash size arg to enable reading past 2MB without stub
- **read_flash**: flush transmit buffer less often to inrease throughput
- **esptool**: Proper alignment for SoCs with offset load
- ignore resetting on unsupported ports
- **esptool**: Remove the shebang from uf2_writer.py

### Code Refactoring

- Migrated esp_rfc2217_server into standalone subpackage
- **test/esptool**: Updated tests according to SHA recomputation for binary
- **style**: Comply with black>=24.0.0

## v4.7.0 (2023-12-13)

### New Features

- **test_esptool**: Added test for embedded and detected flash size match
- **spi_connection**: Support --spi-connection on all chips
- **espefuse**: Support XTS_AES_256_KEY key_purpose for ESP32P4
- **xip_psram**: support xip psram feature on esp32p4
- add support for intel hex format
- **esp32p4**: Stub flasher support
- **elf2image**: add ram-only-header argument
- **rfc2217_server**: Add hard reset sequence
- **espefuse**: Adds efuse ADC calibration data for ESP32H2
- **espefuse**: Update the way to complete the operation
- add support for get_security_info on esp32c3 ECO7
- **loader**: Added hints for some serial port issues when rising port error
- Add support for Python 3.12
- **esp32c3**: Support ECO6 and ECO7 magic numbers
- **merge_bin**: add support for uf2 format
- **esp32-s3**: Support >16MB quad flash chips
- **efuse**: Update key purpose table and tests
- **efuse**: ESP32P4 adds ecdsa_key support
- **espefuse**: Add support for esp32p4 chip
- **esptool**: added target to esp32p4
- **espsecure**: Allow prompting for HSM PIN in read_hsm_config
- **esptool**: Add new packages for ESP32C3 and flash efuses
- **esptool**: Add tests for get_chip_features
- **esptool**: Add PICO package for ESP32S3 and flash/psram efuses
- **get_security_info**: Improved the output format and added more details

### Bug Fixes

- **esp32c2**: Added get_flash_cap and get_flash_vendor
- **testloadram**: Windows assertion error
- fixed exit() to be used from right module
- **esp32c2**: Recommend using higher baud rate if connection fails
- **test_esptool**: Fixed connection issue on Windows
- **esptool**: Rephrase the --ram-only-header command message
- **load_ram**: check for overlaps in bss section
- **tests/intelhex**: make sure file is closed on Windows
- **spi_connection**: Unattach previously attached SPI flash
- **espefuse**: Fix ECDSA_FORCE_USE_HARDWARE_K for ECDSA key (esp32h2)
- **loader**: Could not open serial port message adjusted
- **flasher_stub**: fix usb-serial-jtag enabled non-related intr source
- **bin_image**: Check only ELF sections when searching for .flash.appdesc
- **danger-github**: Fir Danger GitHub token permission
- Fix redirection of STDOUT
- **autodetection**: Remove the ESP32-S2 ROM class from get_security_info autodetection
- assert in esp32 exclusive workaround
- **elf2image**: fix text/rodata mapping overlap issue on uni-idrom bus chips
- **dangerGH**: Update token permissions - allow Danger to add comments to PR
- **expand file args**: Correctly print the expanded command
- **esp32-c2**: Enable flashing in secure download mode

### Code Refactoring

- **stub_flasher**: Cleanup, make adding new targets easier

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
