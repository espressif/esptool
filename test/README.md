# esptool.py test cases README

# test_elf2image.py

Exists to catch unexpected changes in elf2image or image_info output. Does not require an ESP8266 to verify.

## About Tests

Test method is fairly lo-fi:

Directory test/elf2image/ contains subdirectories esp8266-v1, esp8266-v2 and esp32. These contain test cases.

Each test case is a .elf file, which is stored alongside one or more .bin files representing the output of elf2image, and one .txt file representing the output of image_info when reading back the binary.

Default run of test_elf2image.py will re-run elf2image & image_info on all these images. Suitable --chip and --version args are supplied, determined by the directory name.

The test runner verifies that nothing in the output of either command has changed.

## Dealing With Output Changes

If changes are detected, we can check if valid images are still being produced. If the changes turn out to be OK, running "test_elf2image.py --regen" will regenerate all of the .bin and .txt files for the test cases.

(--regen can also be used to evaluate test failures, by looking at git diff output.)

