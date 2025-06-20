<a href="https://www.espressif.com">
    <img src="https://www.espressif.com/sites/all/themes/espressif/logo-black.svg" align="right" height="20" />
</a>

# CHANGELOG

> All notable changes to this project are documented in this file.
> This list is not exhaustive - only important changes, fixes, and new features in the code are reflected here.

<div align="center">
    <a href="https://keepachangelog.com/en/1.1.0/">
        <img alt="Static Badge" src="https://img.shields.io/badge/Keep%20a%20Changelog-v1.1.0-salmon?logo=keepachangelog&logoColor=black&labelColor=white&link=https%3A%2F%2Fkeepachangelog.com%2Fen%2F1.1.0%2F">
    </a>
    <a href="https://www.conventionalcommits.org/en/v1.0.0/">
        <img alt="Static Badge" src="https://img.shields.io/badge/Conventional%20Commits-v1.0.0-pink?logo=conventionalcommits&logoColor=black&labelColor=white&link=https%3A%2F%2Fwww.conventionalcommits.org%2Fen%2Fv1.0.0%2F">
    </a>
    <a href="https://semver.org/spec/v2.0.0.html">
        <img alt="Static Badge" src="https://img.shields.io/badge/Semantic%20Versioning-v2.0.0-grey?logo=semanticrelease&logoColor=black&labelColor=white&link=https%3A%2F%2Fsemver.org%2Fspec%2Fv2.0.0.html">
    </a>
</div>
<hr>

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
