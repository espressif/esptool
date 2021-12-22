This is the source of the software flasher stub.

esptool.py loads the flasher stub into memory and executes it to:

* Add features that the Espressif chips bootloader ROMs do not have.

* Add features to the ESP8266 bootloader ROM which are only in the ROM of newer chips.

* Improve flashing performance over the ROM bootloaders.

* Work around bugs in the ESP8266 ROM bootloader.

Thanks to [Cesanta](http://cesanta.com/) who provided the original ESP8266 stub loader upon which this loader is based.

# To Use

The stub loader is already automatically integrated into esptool.py. You don't need to do anything special to use it.

# To Build

If you want to build the stub to test modifications or updates, here's how:

* You will need an ESP8266 gcc toolchain (xtensa-lx106-elf-) and toolchains for ESP32 and later chips (xtensa-esp32-elf-, riscv32-esp-elf-) on your PATH.

* Set the environment variables SDK_PATH to the path to an ESP8266 IoT NON-OS SDK directory (last stub was built with SDK v1.5.1).

* Set the environment variable IDF_PATH to the path to an ESP-IDF directory.

* Set any other environment variables you'd like to override in the Makefile.

* To build type `make`

Activating an ESP-IDF environment takes care of most of these steps (only the ESP8266 gcc toolchain has to be manually added to PATH).

# To Test

To test the built stub, you can run `make embed`, which will update the stubs in `esptool.py` to the newly compiled ones. Or there are some convenience wrappers to make testing quicker to iterate on:

* Running `esptool_test_stub.py` is the same as running `esptool.py`, only it uses the just-compiled stubs from the build directory.

* Running `run_tests_with_stub.py` is the same as running `test/test_esptool.py`, only it uses the just-compiled stubs from the build directory.
