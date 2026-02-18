## v5.2.0 (2026-02-18)

### ✨ New Features

- **stub_flasher**: Adopt new flasher stub *(Radim Karniš - cf9cdb7)*
- **espefuse**: Add ESP32-E22 support *(Radim Karniš - a47e86f)*
- **esptool**: Add ESP32-E22 support *(Radim Karniš - ce838cd)*
- **python**: Support Python v3.14 *(Radim Karniš - 8d201c7)*
- **espefuse**: Enable ecdsa keys burning support for ESP32-H4 *(nilesh.kale - a02d858)*
- **write_flash**: Add fast reflashing option to update changed flash sectors only *(Radim Karniš - 5aad298)*
- **esp32-s31**: Add dedicated UF2 family ID *(Radim Karniš - f9f6428)*
- **spi_flash**: add flash reset when detecting chip *(C.S.M - 1b57c61)*
- **efuse**: Adds eFuse for ESP32-H2 revision 1.2 *(Konstantin Kondrashov - 08f4cbb)*
- **espsecure**: Added --skip-padding flag to sign-data and verify-signature API *(hrushikesh.bhosale - ce5a4ac)*
- **esp32p4**: Add ECO6 stub flasher support *(Radim Karniš - 9393921)*
- **esp32p4**: Power on SPI flash chip during the attaching process *(Radim Karniš - 21c802f)*
- **write-flash**: apply compression only if it reduces the file size *(Jaroslav Safka - 188028d)*
- **esptool**: Update chip description for ESP32-C2/ESP8684H *(Konstantin Kondrashov - c6f1839)*
- **espfuse**: Add eFuse flash fields for ESP32-C2/ESP8684H *(Konstantin Kondrashov - b3d4e15)*
- **espefuse**: Set postpone flag by default *(Konstantin Kondrashov - 23e5ec1)*
- **esp_hsm_sign**: Use primitive HSM signing mechanisms *(harshal.patil - a1a4e95)*
- **esp32c5**: Add ECO3 stub flasher support *(Radim Karniš - fc0c984)*
- **write_flash**: Allow encrypted writes using key from the Key Manager *(harshal.patil - aa1b04a)*
- Added autocomplete for port and baud rate *(Peter Dragun - 8363cae)*
- enable compress and encryption together *(Jaroslav Safka - 5d747d8)*
- Add new target esp32s31 *(C.S.M - 3077627)*
- Improve ports sorting when autodetection is used *(Jaroslav Burian - ec84fba)*

### 🐛 Bug Fixes

- **esp32-h4**: Fix memory map and disable unsupported watchdog reset *(Radim Karniš - 7728772)*
- **logger**: Require custom logger to implement the correct interface *(Radim Karniš - deca775)*
- **log**: Fix warning log for ESP32-S31 *(Roland Dobai - 5920030)*
- **log**: Remove warning keyword from error outputs *(Roland Dobai - 30808a4)*
- **write-flash**: Print correct number of bytes and flash offsets when --no-stub *(Radim Karniš - e78ab87)*
- **esp32-p4**: Fix flash power on sequence with stub flasher *(Radim Karniš - ea62bd0)*
- **image_cmds**: Print the name of chip in full expanded form *(Radim Karniš - 6b6e0f4)*
- **erase_region**: Allow erasing past 4MB in ROM and SDM mode *(Radim Karniš - 06794d7)*
- **write_flash**: Fixed esp32 FE key validation *(Konstantin Kondrashov - 4f1d212)*
- **espefuse**: Ensure port is closed when creating commands fails *(Peter Dragun - 9646a80)*
- **espefuse**: Fix decoding error in esp32c5 summary *(Peter Dragun - e49c69a)*
- **logger**: Always flush output in stage mode *(Peter Dragun - a5c9090)*
- **usb_mode_detection**: Fix USB mode detection on ESP32-C5 and ESP32-C61 *(Radim Karniš - 81bdb76)*
- **change_baud**: Disable changing baud rate on ESP32-C2 and ESP32-C5 in SDM *(Radim Karniš - 9286189)*
- **esp32c6**: Fix ESP32-C6FH8 package detection *(Roland Dobai - d7f1adf)*
- **esp32c3**: fix usb-serial detection for rev1.1 *(Jaroslav Safka - 8bc2c50)*
- **write_flash**: Allow --force and --erase-all to be used together *(Radim Karniš - c26e58e)*
- **write_flash**: Fixed esp32c2 FE key validation *(Konstantin Kondrashov - c02d53f)*
- **windows**: Limit rich_click version to <1.9.0 *(Peter Dragun - fa97591)*
- **espefuse**: Fix calibration efuses for ESP32-P4 ECO5 *(Konstantin Kondrashov - a1ca6c9)*
- **espefuse**: Fix ECDSA key purposes for ESP32-P4 *(Konstantin Kondrashov - ae23ab2)*
- **espsecure**: Fixed the keyfile arg of the sign-data command by making it optional *(harshal.patil - ee35dda)*
- **espsecure**: Allow verifying multiple appended ECDSA signatures *(harshal.patil - 9a207b1)*
- allow bootloader reflash in secure-boot-v2 scheme *(Mahavir Jain - 9d0bdd5)*

### 📖 Documentation

- **write-flash**: Describe fast reflashing and skipping unchanged content *(Radim Karniš - f806d98)*
- **troubleshooting**: Add known limitations section, describe more errors *(Radim Karniš - 48b71b5)*
- **image-format**: Improve clarity about flash frequency on esp32-c6 *(Peter Dragun - 97e25ef)*
- **secure_download_mode**: Explain available commands and serial protocol restrictions in SDM *(Radim Karniš - 73d1c25)*
- **esp32h4**: Add ESP32-H4 documentation *(Jaroslav Safka - 1b37d3d)*
- **esp32h21**: Add documentation for ESP32-H21 *(Jaroslav Safka - cacc180)*
- Add note about setuptools version into troubleshooting guide *(Peter Dragun - bf1371d)*
- Remove note about GLIBC version from installation instructions *(Peter Dragun - 0bc3879)*
- Fix autocomplete instructions *(Peter Dragun - af7fd96)*

### 🔧 Code Refactoring

- **esp32-s31**: Remove unused variables *(Radim Karniš - 806e01b)*
- **espefuse**: Use dataclasses for eFuse definitions *(Peter Dragun - 62e8f46)*
- **espefuse**: Add type hints to classes in emulate eFuse controller *(Peter Dragun - cf12461)*
- **espefuse**: Remove custom FatalError and import esptool.FatalError *(Peter Dragun - 87c0415)*


## v5.1.0 (2025-09-15)

### ✨ New Features

- **espefuse**: Support ESP32-P4 ECO5 (v3.0) *(Konstantin Kondrashov - 40f103c)*
- **esp32p4**: Add support for ESP32-P4.ECO5 *(Jaroslav Safka - 6c10050)*
- **esp32c5**: Add support for >16 MB flash sizes *(Roland Dobai - 8e2b94e)*
- **espefuse**: Add custom key purposes for ESP32C6/C5/P4 *(Konstantin Kondrashov - c6ce0bc)*
- **espefuse**: Support burning ECDSA_384 keys *(Konstantin Kondrashov - 4a9a3d8)*
- **espefuse**: Clean up limitation for BLOCK9 usage *(Konstantin Kondrashov - d63e3db)*
- **espefuse**: Adds support for burning 512-bit keys for C5 *(Konstantin Kondrashov - 468de5c)*

### 🐛 Bug Fixes

- **espefuse**: Update CLI to support rich-click 1.9.0 *(Peter Dragun - 2ae5535)*
- **espsecure**: Fix printing key digest in signature info *(Radim Karniš - 7e53596)*
- **espefuse**: Fixes re-connection issue in check-error via UJS port *(Konstantin Kondrashov - a160468)*
- **write_flash**: Make write flash mem independent *(Jaroslav Safka - d19413c)*
- **elf2image**: Handle ELF files with zero program header counts *(Tormod Volden - d27ce37)*
- **espsecure**: Extract public key version 1 in RAW format *(Peter Dragun - 6cfced8)*
- **espsecure**: Allow signing multiple files in one go *(Peter Dragun - 0177d61)*
- **elf2image**: Fix --pad-to-size argument parsing *(Peter Dragun - 66a1377)*
- **espefuse**: Disable programming and usage of XTS-AES-256 efuse key for ESP32-C5 *(harshal.patil - c85a93d)*
- **esp32c5**: Erase during flashing above 16MB *(Jaroslav Burian - d65a24e)*
- **espsecure**: Add support for python-pkcs11 9.0+ *(Peter Dragun - 3ea646f)*
- Use correct error codes for ROM errors *(Jaroslav Burian - da4346b)*
- Handle deprecated options with "=" before value *(Peter Dragun - f05fb62)*
- stop exit 0 when being called programmatically *(Fu Hanxi - d8ae230)*

### 📖 Documentation

- **set_flash_voltage**: Disable for non-related chips *(Radim Karniš - cd2c98e)*
- bump up esp_docs to 2.1 *(Jaroslav Safka - bb8cd9b)*
- Add chip type detection explanation *(Jaroslav Safka - 528f605)*

### 🔧 Code Refactoring

- set up and apply pyupgrade ruff rules *(copilot-swe-agent[bot] - 206970a)*


## v5.0.2 (2025-07-30)

### 🐛 Bug Fixes

- **esp32-c3**: Disable flasher stub when Secure Boot is active *(Radim Karniš - 1f1ea9a)*
- **esp32-s3**: Allow stub flasher execution with active Secure Boot *(Radim Karniš - 7ba285b)*
- **espefuse**: Handle error in burn-efuse command when no arguments are provided *(Peter Dragun - 0f32306)*
- Fix buffering issues with CP2102 converter causing connection failures *(Jaroslav Burian - 5338ea0)*
- Fix compatibility with Click 8.2.0+ *(Peter Dragun - 524825e)*
- Fix --port-filter argument parsing *(Peter Dragun - b53a16c)*

### 🔧 Code Refactoring

- **elf2image**: Use common MMU page size configuration function for ESP32-H4 *(Jaroslav Burian - 977ff44)*


## v5.0.1 (2025-07-15)

### 🐛 Bug Fixes

- **elf2image**: validate ELF section types and addresses before processing *(Jaroslav Burian - 97a1546)*
- **elf2image**: handle PREINIT_ARRAY section type in ESP32-P4 elf file properly *(Jaroslav Burian - ec84a75)*
- **elf2image**: Fix incorrect logger call *(Marek Matej - 637f0e6)*


## v5.0.0 (2025-07-02)

### 🚨 Breaking changes

- - The .py suffix is deprecated for the following scripts:
  - esptool
  - espefuse
  - espsecure
  - esp_rfc2217_server *(Peter Dragun - 635cde1)*
- - execute-scripts command is removed *(Peter Dragun - ff72b26)*

### ✨ New Features

- **espefuse**: Use the esptool logger, more concise messages *(Radim Karniš - 983338f)*
- **espefuse**: Replace execute-scripts with public API *(Peter Dragun - ff72b26)*
- **espefuse**: Add public API for espefuse *(Peter Dragun - d7da0f8)*
- **espefuse**: Rename all commands to use dashes and add tests for deprecated commands *(Peter Dragun - ade3088)*
- **espefuse**: Add support for chaining commands with click parser *(Peter Dragun - 0a2ea69)*
- **espefuse**: Refactor CLI and use click for parsing arguments *(Peter Dragun - aa80001)*
- **espefuse**: Adds efuse calculation fields for ESP32-C5 *(Konstantin Kondrashov - 9104038)*
- **espefuse**: Adds 3-bit field for wafer major version in ESP32-P4 *(Konstantin Kondrashov - c102510)*
- **verbosity**: Allow setting silent or verbose output levels *(Radim Karniš - 90e3770)*
- **efuse**: Adds efuses for ESP32-C61 ECO3 *(Konstantin Kondrashov - 6146410)*
- **espefuse**: Support efuse for ESP32-C5 ECO2 (v1.0) *(Konstantin Kondrashov - 3726726)*
- **espsecure**: Use esptool logger, unify output format of messages *(Radim Karniš - 905249c)*
- **stub_flasher**: Support for >16MB flash on P4 and >16MB encrypted writes on S3 *(Radim Karniš - 4e6803e)*
- **espsecure**: Drop ecdsa module, use cryptography instead *(Radim Karniš - e132f6f)*
- **espsecure**: Unify all commands and options to use dash instead of underscore *(Peter Dragun - 36325fd)*
- **espsecure**: Use rich click for CLI parsing *(Peter Dragun - 9c7ddc1)*
- **targets**: Update chip features lists with more info *(Radim Karniš - 3c776aa)*
- **logging**: Add collapsible output stages and ASCII progress bars *(Radim Karniš - f3cf107)*
- **trace**: Update --trace with more info and more readable formatting *(Radim Karniš - 0beee77)*
- **cli**: Commands and options use dashes instead of underscores for uniformity *(Peter Dragun - 3cecd6d)*
- **cmds**: Expand input of all functions to file paths, bytes, or file-like objects *(Radim Karniš - 46a9e31)*
- **cmds**: Allow all functions to both return bytes and write to files *(Radim Karniš - 03b84a1)*
- **cmds**: Polish the public API, unify arg names, pack some args *(Radim Karniš - 37a13a9)*
- **cmds**: Encapsulate logic for running the stub flasher in run_stub *(Radim Karniš - 063d9d5)*
- **cli**: Add click-based CLI interface *(Peter Dragun - d40fefa)*
- **cmds**: Allow commands to output bytes, as well as write to a file *(Radim Karniš - 0153b79)*
- **cmds**: Rework the public API to work as a Python module *(Radim Karniš - ba36933)*
- **flash_attach**: Encapsulate logic for flash attaching and configuration *(Radim Karniš - 6e959ef)*
- **esp32h4**: update the ESP32H4StubLoader *(Chen Jichang - f7c78f8)*
- **espefuse**: Updates esp32h4 efuse table and fixes tests *(Konstantin Kondrashov - 3da8c57)*
- **esp32h4**: add ESP32H4 esptool support *(Chen Jichang - bcf5c6e)*
- **esp32h21**: Add Microsoft UF2 family ID *(Radim Karniš - cb0d334)*
- **errors**: Print errors to STDERR, catch KeyboardInterrupt *(Radim Karniš - 0864e17)*
- **write_flash**: Remove the superfluous --verify option *(Radim Karniš - dbf3d1c)*
- **logger**: Add a custom logger, allow output redirection *(Radim Karniš - 1ce02db)*
- **image_info**: Deprecate the --version 1 output format *(Radim Karniš - 3f625c3)*
- Remove .py suffix from scripts *(Peter Dragun - 635cde1)*
- detect flash size of Adesto flash chips *(Jaroslav Burian - 0b56f85)*
- Add support for k, M suffix for flash size *(Peter Dragun - 6f0d779)*
- Rename reset modes to use dash instead of underscore *(Peter Dragun - 851919f)*

### 🐛 Bug Fixes

- **logger**: Turn on smart features in more cases *(Jason2866 - 5d5eafb)*
- **elf2image**: Multiple fixes from 3rd party frameworks *(Sylvio Alves - cbd4e9b)*
- **stub_flasher**: Fix USB-Serial/JTAG mode on C5 ECO2 and C61 ECO3 *(Radim Karniš - 1decf86)*
- **write_flash**: Detect more cases of unresponsive flash, fix failing flash_size check *(Radim Karniš - e6bfc3b)*
- **stub_flasher**: Fix ESP32-C5 ECO2 flashing *(Radim Karniš - 3a4c15c)*
- **espefuse**: Fix output messages for set_flash_voltage *(Peter Dragun - daaedf8)*
- **espefuse**: JTAG_SEL_ENABLE has GPIO34 strapping pin for ESP32P4 *(Jan Beran - 78535e4)*
- **esp32c5**: fix bootloader address *(Jaroslav Burian - ec12073)*
- **autodetection**: Remove the Unsupported detection protocol stage *(Radim Karniš - 05553a4)*
- **logging**: Unify output messages, notes, and warning formatting *(Radim Karniš - 07879eb)*
- **elf2image**: fix elf2image for ram app when sha256 offset not specified *(Jaroslav Burian - 6f8ff39)*
- **esp32h4**: fix h4 chip feature *(Chen Jichang - 955943a)*
- **image_info**: Sanitize app and bootloader info of null bytes *(Radim Karniš - 8016455)*
- **lint**: Correct type annotations issues reported by mypy *(Radim Karniš - 0bca550)*
- **esptool**: Fix efuse base address for esp32h21 *(Konstantin Kondrashov - c3d28ee)*
- **elf2image**: support --flash-mmu-page-config for all chips *(Jaroslav Burian - 8be617c)*
- **elf2image**: Try to correct MMU page size if not specified *(Jaroslav Burian - f4fabc5)*
- **elf2image**: Print correct MMU page size in error message *(Jaroslav Burian - 9da4948)*
- **logging**: Avoid crashes when flushing if sys.stdout is not available *(Radim Karniš - 5176b67)*
- enable auto-detection of ESP32-S2 in secure download mode *(Jaroslav Burian - c2f5d21)*
- enable ESP32-P4 ECO5 chip detection *(Jaroslav Burian - 0b3460f)*
- Do not use padding for merged IntelHex files *(Peter Dragun - 08c170b)*
- lock upper version of click to <8.2.0 *(Peter Dragun - 5241cba)*
- Add timeout to read_flash to avoid infinite loops *(Peter Dragun - f26a7bb)*
- Close the data file after reading the data *(Stevan Stevic - 807d02b)*

### 📖 Documentation

- **elf2image**: Link an article with Simple Boot explanation *(Radim Karniš - 202dfad)*
- **logger**: Fix custom logger example code *(Radim Karniš - 26e86e9)*
- **logger**: Fix custom logger example code *(Radim Karniš - eaaa6b3)*
- Clarify versions in documentation *(Peter Dragun - 4586e4b)*
- Remove .py suffix from tool names *(Peter Dragun - e9f03ae)*
- Remove espefuse and espsecure migration guide for esp8266 *(Peter Dragun - b6e08a3)*
- Update migration guide for espefuse with click parser *(Peter Dragun - faf3e22)*
- Add missing esp32-p4 target to supported targets *(Peter Dragun - 8b5a5d9)*
- fix targets dropdown in production *(Peter Dragun - 2643101)*
- Update autocomplete docs for click-based CLI *(Peter Dragun - 89cfa52)*
- fix minor issues and improve vague statements *(Peter Dragun - 6d04155)*

### 🔧 Code Refactoring

- **cli_mode**: Improve CLI mode workflow code *(Radim Karniš - 0671d35)*
- **stub_class**: Make into a mixin to avoid code repetition *(Radim Karniš - 83613c8)*

### 🗑️ Removals

- **make_image**: Remove the make_image command in favor of other workflows *(Radim Karniš - 955a7c8)*
- **beta_targets**: Removed support for beta chip targets *(Radim Karniš - 8f1c206)*
- Deprecate Python versions 3.7, 3.8 and 3.9 *(Peter Dragun - 19f1bee)*


## v4.9.0 (2025-06-19)

### ✨ New Features

- **espefuse**: Add eFuses for ESP32-C61 ECO3 *(Radim Karniš - 98688ab)*
- **espefuse**: Support efuse for ESP32-C5 ECO2 (v1.0) *(Konstantin Kondrashov - ce16054)*
- **stub_flasher**: Support for >16MB flash on P4 and >16MB encrypted writes on S3 *(Radim Karniš - 0110514)*
- **espefuse**: Updates esp32h4 efuse table and fixes tests *(Konstantin Kondrashov - 777c505)*
- **esp32h4**: add ESP32H4 esptool support *(Chen Jichang - edb99bd)*
- **esp32h21**: Add Microsoft UF2 family ID *(Radim Karniš - 74d27ae)*
- **watchdog_reset**: Add a new watchdog_reset option working even in USB modes *(Radim Karniš - d37c38a)*
- **espsecure**: Improves an error message for encrypt_flash_data and decrypt_flash_data *(Konstantin Kondrashov - ef407ed)*
- **espefuse**: Clean up efuse code for ESP32H2 *(Konstantin Kondrashov - 4e922fe)*
- **espefuse**: Support different efuse table versions for ESP32H2 *(Konstantin Kondrashov - d51ecbe)*
- **espefuse**: Adds efuses for esp32h2 eco5 *(Konstantin Kondrashov - 9b74df6)*
- **esp32h21**: add ESP32H21 esptool support *(gaoxu - 92ceff2)*
- **esp32-p4**: add support for flasher stub in USB OTG mode *(Peter Dragun - 804f2db)*
- **esp32-c5**: Add ECO1 magic number *(Radim Karniš - 6cc002c)*
- **esp_rfc2217**: Improved the logger message format *(Jakub Kocka - 39a12a4)*
- **espefuse**: Adds 3 bit for PSRAM_CAP efuse field *(Konstantin Kondrashov - ab2e0bf)*
- **espefuse**: Adds API for getting block and wafer versions *(Konstantin Kondrashov - 111c6c0)*
- **espefuse**: Adds ADC calibration data for ESP32-C61 *(Konstantin Kondrashov - 36d9735)*
- **espefuse**: Adds ADC calibration data for ESP32-C5 *(Konstantin Kondrashov - a903812)*
- **espefuse**: Adds ADC calibration data for ESP32-P4 *(Konstantin Kondrashov - 215e4b8)*
- **erase_region**: Enable erasing in ROM bootloader and SDM *(Radim Karniš - e0deeac)*
- **hard_reset**: Support custom hard reset sequence configuration *(Radim Karniš - 1b15738)*
- print usb mode when output chip info *(Jan Beran - 749d1ad)*
- Add new app description segments *(Jaroslav Burian - b23e60f)*
- add filtering based on serial number *(Jaroslav Burian - 88319db)*
- Add support for Python 3.13 *(Radim Karniš - 6abd05d)*

### 🐛 Bug Fixes

- **stub_flasher**: Fix USB-Serial/JTAG mode on C5 ECO2 and C61 ECO3 *(Radim Karniš - 4382f14)*
- **write_flash**: Detect more cases of unresponsive flash, fix failing flash_size check *(Radim Karniš - f83d598)*
- **stub_flasher**: Fix ESP32-C5 ECO2 flashing *(Radim Karniš - bb237bc)*
- **espefuse**: Fix output messages for set_flash_voltage *(Peter Dragun - 759bcc6)*
- **espefuse**: JTAG_SEL_ENABLE has GPIO34 strapping pin for ESP32P4 *(Jan Beran - f6d1833)*
- **esp32c5**: fix bootloader address *(Jaroslav Burian - 83e0973)*
- **elf2image**: fix elf2image for ram app when sha256 offset not specified *(Radim Karniš - 9fd7b7a)*
- **esp32h4**: Correct ESP32-H4 chip features *(Radim Karniš - 5520963)*
- **esp32h21**: Fix eFuse base address *(Radim Karniš - dc05792)*
- **elf2image**: support --flash-mmu-page-config for all chips *(Jaroslav Burian - 54fdc75)*
- **elf2image**: Try to correct MMU page size if not specified *(Jaroslav Burian - d9afa9c)*
- **elf2image**: Print correct MMU page size in error message *(Jaroslav Burian - 447de60)*
- **test**: Expect the correct module name for Python's 3.14 argparse *(Karolina Surma - 98001b7)*
- **write_flash**: Skip flash_size checks if we can't read flash size *(Radim Karniš - 12095b2)*
- **save_segment**: Adds segment len check the same as bootloader does *(Konstantin Kondrashov - a6bceb7)*
- **chip_type_verification**: Enable in SDM, do not rely on magic numbers *(Radim Karniš - 598e07b)*
- **esp32-c6**: Disable RTC WDT reset to prevent port disappearing *(Radim Karniš - d47004e)*
- **esp_rfc2217**: Fixed keyboard interrupt on Windows and added info for command *(Jakub Kocka - 5569aa5)*
- **detect_chip**: Select correct loader before further operations to avoid silent failures *(Jan Beran - 8897ff8)*
- **usb_resets**: Fix resetting in USB-OTG and USB-Serial/JTAG modes *(Radim Karniš - 8298cdc)*
- Do not use padding for merged IntelHex files *(Peter Dragun - 739669f)*
- close port when connect fails *(Jaroslav Burian - d99c972)*
- Hide missing app info based on IDF version *(Jaroslav Burian - d2bca1e)*
- add delay after WDT reset for better stability *(Peter Dragun - 188c162)*
- Not reading app description for some SoCs *(Jaroslav Burian - 3555fe1)*
- Fix missing newline in output *(Jan Beran - 26b676b)*

### 📖 Documentation

- **esptool**: Fix reset sequences in documentation *(Jan Beran - 92160eb)*
- **flash_modes**: Correct QIO GPIO pins for all chips *(Radim Karniš - 23f11f0)*
- **espefuse**: Fixed JTAG strapping pin for ESP32-S3 in the help and documentation *(Roland Dobai - de1d1ce)*
- **scripting**: Add example of usage as a Python module *(Radim Karniš - d54e59f)*
- **esp8266**: change boot select pin to IO0 *(ChromaLock - c06ce1e)*
- **read_flash_sfdp**: Fix command formatting *(Radim Karniš - ec309bb)*
- **spi_connection**: Explain which flash chips are supported *(Radim Karniš - 6d37e30)*
- fix targets dropdown in production *(Peter Dragun - 9201ccd)*
- Point directly to the datasheet for given target *(Jan Beran - a32988e)*
- Add ESP32-C5 and ESP32-C61 docs *(Radim Karniš - f52c723)*

---

## v4.8.1 (2024-09-25)

### ✨ New Features

- **espefuse**: Supports wafer efuse versions for esp32c61 *(Konstantin Kondrashov - 0472846)*
- **esptool**: add new command SFDP read *(Xiao Xufeng - 92143ed)*
- **esptool**: Add option to retry connection in a loop *(Alfonso Acosta - 04045d6)*
- **efuse**: Updates efuse table for esp32c5 *(Konstantin Kondrashov - b3022fa)*
- **efuse**: Updates efuse table for esp32p4 *(Konstantin Kondrashov - 669a69f)*
- **esp32c61**: Added stub flasher support *(Jakub Kocka - e8b3911)*
- **cli**: add autocompletions *(Dmitriy Astapov - 7cc35e4)*
- **esptool**: allow picking UART by VID/PID/Name *(Richard Allen - 5dd3dcc)*
- **esp32c5**: Add USB-serial/JTAG stub support *(Jaroslav Burian - e170bcc)*
- **esp32c5**: Add UART stub support *(Konstantin Kondrashov - b199534)*
- **esptool**: Print key_purpose name for get_security_info cmd *(Konstantin Kondrashov - ccd8c72)*
- **espefuse**: Adds support extend efuse table by user CSV file *(Konstantin Kondrashov - 6bb2b92)*
- **espefuse**: Adds efuse dump formats: separated(default) and united(new) *(Konstantin Kondrashov - fc2856a)*
- **espefuse**: Adds incompatible eFuse settings check for S3 *(Konstantin Kondrashov - c244843)*
- **reset**: Apply reconnections to the whole reset sequence, not line transitions *(Radim Karniš - d49837e)*
- **reset**: Automatically reconnect if port disconnects during reset *(Andrew Leech - 9dc5dfb)*
- **esp32-p4**: Add ECO1 magic number *(Radim Karniš - d4d2153)*
- **espsecure**: Add support for secure boot v2 using ECDSA-P384 signatures *(harshal.patil - f014cad)*
- **write_flash**: retry flashing if chip disconnects *(Peter Dragun - a15089a)*
- **espefuse**: Allow filtering efuses based on command line arguments *(Jan Beran - bb52d36)*
- **esploader**: Enable context manager for esp instances *(Radim Karniš - d4c8cb3)*
- **espefuse**: Added check for correctness of written data *(Konstantin Kondrashov - d2bfaad)*
- **espefuse**: Improves help for burn_efuse cmd *(Konstantin Kondrashov - ef8ee8a)*
- **esp32s3**: clear boot control register on hard reset *(Peter Dragun - 1c355f9)*
- **esp32-p4**: add spi-connection restriction to ROM class *(Peter Dragun - dad0edc)*
- **espefuse**: Updates efuses for C5 and C61 *(Konstantin Kondrashov - e34df69)*
- **esp32c61**: add c61 basic flash support (no_stub) *(wanlei - ef4d8a7)*
- **esp32c5**: skipped the stub check for esp32c5 mp *(laokaiyao - a773e6b)*
- **esp32c5**: base support of esp32c5 mp (no stub) *(laokaiyao - e414cef)*
- **cmds/write_flash**: Recalculated SHA digest for image binary *(Jakub Kocka - 3b0939c)*
- **esptool**: Adds wafer and pkg versions *(Konstantin Kondrashov - 6c5cfd6)*
- **espefuse**: Update adc_info commands for all chips *(Konstantin Kondrashov - 31eb15b)*
- **espefuse**: Adds new efuses for esp32p4 *(Konstantin Kondrashov - 31477fb)*
- **espefuse**: Allow the espefuse.py to work when coding scheme == 3 *(Francisco Blas (klondike) Izquierdo Riera - 1e79f25)*
- **err_defs**: Add ROM bootloader flash error definitions *(radim.karnis - 2d8a3ad)*
- **esp32p4**: Enable USB-serial/JTAG in flasher stub *(Peter Dragun - 96a5c21)*
- **espefuse**: Postpone some efuses to burn them at the very end *(KonstantinKondrashov - bdeec68)*
- **espefuse**: check_error --recover chip even if there are num_errors *(KonstantinKondrashov - f72b5ad)*
- **espefuse**: Adds new efuses for esp32c6 and esp32h2 *(KonstantinKondrashov - 16e4fae)*
- **esp32c5**: add target esp32c5 beta3 *(laokaiyao - d9a6660)*
- add UF2 IDs for ESP32-C5 and ESP32-C61 *(Peter Dragun - cf6d94e)*
- Added warning when secure boot enabled *(Jakub Kocka - 8d26375)*
- print flash voltage in flash_id command *(Peter Dragun - 6393d6b)*
- Use ruff instead of flake8 and black both in pre-commit and CI *(Jan Beran - 1d5fcb3)*
- add advisory port locking *(Peter Dragun - 8ad6d57)*

### 🐛 Bug Fixes

- **esp32c2**: Add esp32c2 eco4 rom magic value *(Jiang Guang Ming - 3434433)*
- **packaging**: Correctly exclude the unwanted sub/modules *(Karolina Surma - 908d0b5)*
- **esptool**: Fix esp32c61 flash frequency config *(C.S.M - 6edafea)*
- **esptool**: Fix incorrect chip version for esp32c5 *(Konstantin Kondrashov - 138660b)*
- **write_flash**: Verify if files will fit against the real flash size when possible *(Radim Karniš - 1693449)*
- **remote_ports**: Disable reset sequence when a socket is used *(Radim Karniš - 28556fb)*
- **bitstring**: Restricted bitstring dependency to fix 32-bit compatibility *(Jakub Kocka - 4f7e223)*
- **esp32_d0wdr2_v3**: Print correct chip name *(Radim Karniš - dfd61e2)*
- **bin_image**: add check for ELF file segment when saving RAM segments *(Peter Dragun - 6e8632d)*
- **docs**: Add a note about entering manual bootloader mode *(Roland Dobai - 4d0c7d9)*
- **esp32c5**: Fix MAC reading for esptool *(Konstantin Kondrashov - 2b0ec7a)*
- **esp32-c5**: Use a longer reset delay with usb-serial/jtag to stabilize boot-up *(C.S.M - 1059ec7)*
- **espefuse**: Use stub class if stub flasher is running *(Radim Karniš - 67d66a0)*
- **elf2image**: add ELF flags to merge condition *(Marek Matej - e87cc3e)*
- **espefuse**: Fix efuse base addr for esp32c5 MP *(Konstantin Kondrashov - 248dc9a)*
- **espefuse**: Fix burn_key for ECDSA_KEY, it can read pem file *(Konstantin Kondrashov - 450db24)*
- **secure_download_mode**: Disable secure boot detection and print more info *(Radim Karniš - 1dc3c8b)*
- **esptool**: clear boot control register on ESP32-S3 *(Peter Dragun - 0215786)*
- **intelhex**: catch unicode decode errors when converting hex to binary *(Peter Dragun - a2bdaa2)*
- **merge_bin**: treat files starting with colon as raw files *(Peter Dragun - 2c0a5da)*
- **read_flash**: add flash size arg to enable reading past 2MB without stub *(Peter Dragun - f1eb65f)*
- **read_flash**: flush transmit buffer less often to inrease throughput *(Peter Dragun - 8ce5ed3)*
- **esptool**: Proper alignment for SoCs with offset load *(Marek Matej - 17866a5)*
- **esptool**: Remove the shebang from uf2_writer.py *(Karolina Surma - 45fbcdd)*
- pass error message to exception in OTG mode *(Peter Dragun - c266fdd)*
- Erase non-aligned bytes with --no-stub *(Jaroslav Burian - c984aa9)*
- Do not append SHA256 when `--ram-only-header` *(Tiago Medicci Serrano - 5d9d5be)*
- ram_only_header: pad flash segment to next boundary *(Sylvio Alves - 4394a65)*
- sort segments if ram_only_header is used *(Sylvio Alves - 4c5874a)*
- fix type annotation to comply with mypy *(Peter Dragun - 55b338a)*
- ROM doesn't attach in-package flash chips *(Jakub Kocka - bc9f2a6)*
- close file gracefully in espsecure *(gnought - 2381711)*
- Fixed glitches on RTS line when no_reset option on Windows *(Jakub Kocka - 956557b)*
- Index image segments from 0 instead of 1 *(Jan Beran - b5939da)*
- ignore resetting on unsupported ports *(Peter Dragun - e948993)*

### 📖 Documentation

- **troubleshooting**: Add info about debugging in USB-Serial/JTAG and USB-OTG modes *(Radim Karniš - 3a74f62)*
- **troubleshooting**: Mention needed permissions to the serial port on Linux *(Radim Karniš - 8e39ef6)*
- **troubleshooting**: Mention the ESP Hardware Design Guidelines docs *(Radim Karniš - 74ce286)*
- **flashing**: Fixed a typo in /docs/en/esptool/flashing-firmware.rst *(Green - 9f46568)*
- **sphinx-lint**: Add previous commit to .git-blame-ignore-revs *(Jan Beran - c750549)*
- **sphinx-lint**: Fix issues reported by sphinx-lint before adding it to pre-commit *(Jan Beran - 6282f98)*
- **sphinx-lint**: Add sphinx-lint to pre-commit, GH and GL pipelines *(Jan Beran - 1de1a26)*
- **esptool**: Reflect change from flake8 and black to ruff *(Jan Beran - 9f1bde4)*
- add note about Intel Hex merging limitations *(Peter Dragun - d83dd3b)*
- Updated documentation to reflect changes of SHA256 digest recomputation *(Jakub Kocka - 6c28df3)*
- add esp32p4 target to docs *(Peter Dragun - 4a6ad55)*
- Correct bootloader offsets *(radim.karnis - 79978c0)*
- Add instructions on how to update *(radim.karnis - d448851)*

### 🔧 Code Refactoring

- **test/esptool**: Updated tests according to SHA recomputation for binary *(Jakub Kocka - 598b703)*
- **style**: Comply with black>=24.0.0 *(radim.karnis - 5ad3c48)*
- Migrated esp_rfc2217_server into standalone subpackage *(Jakub Kocka - 9b24215)*

---

## v4.7.0 (2023-12-13)

### ✨ New Features

- **test_esptool**: Added test for embedded and detected flash size match *(Jakub Kocka - c0ea74a)*
- **spi_connection**: Support --spi-connection on all chips *(radim.karnis - 1a38293)*
- **espefuse**: Support XTS_AES_256_KEY key_purpose for ESP32P4 *(KonstantinKondrashov - a91eee1)*
- **xip_psram**: support xip psram feature on esp32p4 *(Armando - 1b350ce)*
- **esp32p4**: Stub flasher support *(radim.karnis - d266645)*
- **elf2image**: add ram-only-header argument *(Almir Okato - da28460)*
- **rfc2217_server**: Add hard reset sequence *(20162026 - d66de5c)*
- **espefuse**: Adds efuse ADC calibration data for ESP32H2 *(KonstantinKondrashov - 2a57d6c)*
- **espefuse**: Update the way to complete the operation *(KonstantinKondrashov - c8d688d)*
- **loader**: Added hints for some serial port issues when rising port error *(Jakub Kocka - d61da77)*
- **esp32c3**: Support ECO6 and ECO7 magic numbers *(radim.karnis - 6943c5d)*
- **merge_bin**: add support for uf2 format *(Peter Dragun - 3d899b2)*
- **esp32-s3**: Support >16MB quad flash chips *(radim.karnis - 67a91cb)*
- **efuse**: Update key purpose table and tests *(KonstantinKondrashov - cb5e850)*
- **efuse**: ESP32P4 adds ecdsa_key support *(KonstantinKondrashov - 3654267)*
- **espefuse**: Add support for esp32p4 chip *(KonstantinKondrashov - 8273916)*
- **esptool**: added target to esp32p4 *(Armando - 654e626)*
- **espsecure**: Allow prompting for HSM PIN in read_hsm_config *(Richard Retanubun - ab25fc1)*
- **esptool**: Add new packages for ESP32C3 and flash efuses *(KonstantinKondrashov - 8f37762)*
- **esptool**: Add tests for get_chip_features *(KonstantinKondrashov - d5bb1ee)*
- **esptool**: Add PICO package for ESP32S3 and flash/psram efuses *(KonstantinKondrashov - b70ead2)*
- **get_security_info**: Improved the output format and added more details *(Aditya Patwardhan - 9b95de8)*
- add support for intel hex format *(Peter Dragun - 7074bed)*
- add support for get_security_info on esp32c3 ECO7 *(Peter Dragun - 20565a0)*
- Add support for Python 3.12 *(radim.karnis - ef02d52)*

### 🐛 Bug Fixes

- **esp32c2**: Added get_flash_cap and get_flash_vendor *(Jakub Kocka - b8dd74d)*
- **testloadram**: Windows assertion error *(Jakub Kocka - cd51bbc)*
- **esp32c2**: Recommend using higher baud rate if connection fails *(Jakub Kocka - ef0c91f)*
- **test_esptool**: Fixed connection issue on Windows *(Jakub Kocka - 4622bb2)*
- **esptool**: Rephrase the --ram-only-header command message *(Marek Matej - da4a486)*
- **load_ram**: check for overlaps in bss section *(Peter Dragun - 3a82d7a)*
- **tests/intelhex**: make sure file is closed on Windows *(Peter Dragun - 900d385)*
- **spi_connection**: Unattach previously attached SPI flash *(radim.karnis - afaa7d2)*
- **espefuse**: Fix ECDSA_FORCE_USE_HARDWARE_K for ECDSA key (esp32h2) *(KonstantinKondrashov - f607f19)*
- **loader**: Could not open serial port message adjusted *(Jakub Kocka - 0d3a077)*
- **flasher_stub**: fix usb-serial-jtag enabled non-related intr source *(wuzhenghui - 3f2dc6f)*
- **bin_image**: Check only ELF sections when searching for .flash.appdesc *(radim.karnis - ffaf6db)*
- **danger-github**: Fir Danger GitHub token permission *(Tomas Sebestik - c0df9b7)*
- **autodetection**: Remove the ESP32-S2 ROM class from get_security_info autodetection *(radim.karnis - 3d8c304)*
- **elf2image**: fix text/rodata mapping overlap issue on uni-idrom bus chips *(wuzhenghui - c48523e)*
- **dangerGH**: Update token permissions - allow Danger to add comments to PR *(Tomas Sebestik - 6b4786a)*
- **expand file args**: Correctly print the expanded command *(radim.karnis - 2bea6f4)*
- **esp32-c2**: Enable flashing in secure download mode *(radim.karnis - e862e10)*
- fixed exit() to be used from right module *(Jakub Kocka - d1610a9)*
- Fix redirection of STDOUT *(radim.karnis - 9585c0e)*
- assert in esp32 exclusive workaround *(wuzhenghui - 5b69e07)*

### 📖 Documentation

- **advanced-topics**: Fixed strapping pin for Automatic Bootloader section *(Jakub Kocka - 590c2c6)*
- **serial-protocol**: add images and flowchart *(Peter Dragun - e99c114)*
- **boot_mode_selection**: Correct secondary strapping pin boot mode levels *(radim.karnis - 3b38e79)*
- **troubleshooting**: Explain issues when flashing with USB-Serial/JTAG or USB-OTG *(radim.karnis - 2a399a0)*
- **basic-commands**: added note for PowerShell users for merge_bin command *(Jakub Kocka - dc8a337)*
- Add other resources page *(radim.karnis - cc6c4ce)*

### 🔧 Code Refactoring

- **stub_flasher**: Cleanup, make adding new targets easier *(radim.karnis - fb7f4db)*

---

## v4.6.2 (2023-06-12)

### 🐛 Bug Fixes

- **CH9102F**: Suggest to install new serial drivers if writing to RAM fails *(radim.karnis - f4b5914)*
- **compressed upload**: Accept short data blocks with only Adler-32 bytes *(radim.karnis - d984647)*

### 📖 Documentation

- **boot-log**: fix list formatting *(Peter Dragun - b137d3d)*
- add c2, c6 and h2 as build targets *(Peter Dragun - 590fb55)*
- add explanation for flash_id example to avoid confusion *(Peter Dragun - fbe8066)*

---

## v4.6.1 (2023-06-01)

### ✨ New Features

- **esptool**: add option to dump whole flash based on detected size *(Peter Dragun - 049baaa)*

### 🐛 Bug Fixes

- **ESP32-S3**: Correct RTC WDT registers to fix resets during flashing *(radim.karnis - 6fd91af)*
- **ESP32-C6**: Fix get_pkg_version and get\_{major,minor}\_chip_version *(XiNGRZ - 555458c)*
- inconsistent usage of dirs separator *(Massimiliano Montagni - f558f22)*
- USB-JTAG-Serial PID detection error *(Dean Gardiner - 9a719f4)*
- Set flash parameters even with --flash_size keep *(radim.karnis - 0e9c85e)*

### 📖 Documentation

- **Boot log**: Add all esp targets to cover boot troubleshooting *(Peter Dragun - 5892496)*

---

## v4.5.1 (2023-02-28)

### ✨ New Features

- **stub**: Add ESP32-S3 octal flash support *(Roland Dobai - b746aa7)*
- **esp32h2**: Enable USB-JTAG/Serial mode in the stub flasher *(radim.karnis - cc06208)*
- **bootloader reset**: Allow custom reset strategy setting with a config file *(radim.karnis - a8586d0)*
- **bootloader reset**: Tighter transitions on Unix systems *(radim.karnis - 353cefc)*
- **ci**: Publish development releases with custom pipeline *(Roland Dobai - 3a77f1f)*
- **esp32c6 stub**: Increase CPU frequency and write/read speeds over USB-JTAG/Serial *(radim.karnis - 180695e)*
- **esp32c6 stub**: Enable USB-JTAG/Serial *(radim.karnis - b04cc52)*
- **flash_id**: Print the flash type if available for the chip *(Roland Dobai - b25606b)*
- **flasher_stub**: Increase CPU frequency and write/read speeds over native USB (USB-OTG) *(radim.karnis - 52278a9)*
- **flasher_stub**: Increase CPU frequency and write/read speeds over USB-JTAG/Serial *(radim.karnis - dccf4df)*
- **image_info**: Print application information if possible *(radim.karnis - 82bfe98)*
- **write_flash**: Prevent flashing incompatible images *(radim.karnis - 395fcb0)*
- **image_info**: Image type autodetection *(radim.karnis - 791a20b)*
- Allow configuration with a config file *(radim.karnis - 3ad680a)*
- Readable error message for serial-related issues *(radim.karnis - 1082852)*
- Detect Guru Meditation errors *(radim.karnis - 6fac261)*
- Add Macronix flash memory density definitions *(radim.karnis - 3190894)*
- Recover from serial errors when flashing *(radim.karnis - 2fb8d45)*
- Add stub flasher error messages definitions *(radim.karnis - 66502d5)*

### 🐛 Bug Fixes

- **ESP32-S3**: Temporarily disable increasing CPU freq *(radim.karnis - 23a5095)*
- **ESP32-S3**: Lower CPU freq to improve flasher stub stability *(radim.karnis - 7b28699)*
- **rfc2217_server**: Use new reset sequences *(radim.karnis - 4f13cf6)*
- **cmds**: Make clear that flash type is from eFuse and not detection *(Roland Dobai - caeab98)*
- **load config file**: Sort unknown config options *(radim.karnis - cc80ecd)*
- **esp32c6**: Workaround for bad MSPI frequency in HS mode *(wuzhenghui - 4738ef7)*
- **flasher_stub**: Correct boundaries for SPIWrite4B and SPIRead4B *(Roland Dobai - 21e5914)*
- **secure download mode**: Reconnect if ROM refuses to respond *(radim.karnis - 869740a)*
- **secure download mode**: Fix SDM detection on S2/S3 *(radim.karnis - b67e557)*
- **ci**: Merge two "ci" directories and build_tools into one *(Roland Dobai - 2ed1fc1)*
- **ci**: The development release job should not run by default *(Roland Dobai - 3f3a2d3)*
- **setup**: Use latest reedsolo package which can be installed with Python3.10 and Cython *(Roland Dobai - 5490b0b)*
- **write_flash**: Fix `--erase-all` option *(radim.karnis - d0af65f)*
- **espefuse**: Close serial port even when espefuse fails *(radim.karnis - 26df171)*
- **espefuse**: Fix compatibility with Bitstring>=4 *(Roland Dobai - ee27a64)*
- Unknown chip (ID or magic number) error *(radim.karnis - 11e6425)*
- Add workaround for breaking changes of bitstring==4 *(Roland Dobai - 09e41df)*
- close unused ports while get_default_connected_device *(Fu Hanxi - 76f491e)*

### 📖 Documentation

- **tests**: Add test suite description and instructions *(radim.karnis - 943b997)*
- **serial port**: Update basic-options with more linux instructions *(Robin Gower - b37496f)*
- espsecure remote signing using a HSM broken link fix *(harshal.patil - 0095a26)*
- Update serial protocol description *(radim.karnis - f4ed949)*
- Describe --chip option, fix small typos *(radim.karnis - 2eff1be)*

### 🔧 Code Refactoring

- **connection attempt**: Decouple reset sequence settings *(radim.karnis - cee66a2)*
- **elf2image**: Simplify bootloader image selection *(radim.karnis - 2e95f66)*
- Comply with black 23.1 style *(radim.karnis - ea61f8f)*
- Optimize unnecessary chip interrogations *(radim.karnis - f3437a3)*

---

<div align="center">
    <small>
        <b>
            <a href="https://www.github.com/espressif/cz-plugin-espressif">Commitizen Espressif plugin</a>
        </b>
    <br>
        <sup><a href="https://www.espressif.com">Espressif Systems CO LTD. (2025)</a><sup>
    </small>
</div>
