#!/usr/bin/env python
#
# HOST_TEST for espefuse.py [support esp32, esp32s2, esp32s3beta2, esp32c3]
#
# How to use it:
#
# 1. Run as HOST_TEST (without a physical connection to a chip):
#    - `python test_espefuse_host.py esp32`
#    - `python test_espefuse_host.py esp32s2`
#
# 2. Run as TEST on FPGA (connection to FPGA with an image ESP32 or ESP32-S2):
#    required two COM ports
#    - `python test_espefuse_host.py esp32   /dev/ttyUSB0 /dev/ttyUSB1`
#    - `python test_espefuse_host.py esp32s2 /dev/ttyUSB0 /dev/ttyUSB1`
#
# where  - ttyUSB0 - a port for espefuse.py operation
#        - ttyUSB1 - a port to clear efuses (connect RTS or DTR ->- J14 pin 39)
#
# Note: For FPGA with ESP32 image, need to add a line into esptool.py
#            time.sleep(7)  # FPGA delay
#       after this line:
#            self._setDTR(False)  # IO0=HIGH, done
#       because the long delay (~6 seconds) after resetting the FPGA.
#       For FPGA with ESP32-S2 image, it is not necessary
from __future__ import division, print_function

import os
import subprocess
import sys
import tempfile
import time
import unittest

from bitstring import BitString

import serial

TEST_DIR = os.path.abspath(os.path.dirname(__file__))
os.chdir(TEST_DIR)
sys.path.insert(0, os.path.join(TEST_DIR, ".."))

support_list_chips = ["esp32", "esp32s2", "esp32s3beta2", "esp32c3"]

try:
    chip_target = sys.argv[1]
except IndexError:
    chip_target = "esp32"

global reset_port
reset_port = None
global espefuse_port
espefuse_port = None


class EfuseTestCase(unittest.TestCase):

    def setUp(self):
        if reset_port is None:
            self.efuse_file = tempfile.NamedTemporaryFile()
            self.base_cmd = "python ../espefuse.py --chip {} --virt --path-efuse-file {} -d ".format(chip_target, self.efuse_file.name)
        else:
            self.base_cmd = "python ../espefuse.py --chip {} -p {} -d ".format(chip_target, espefuse_port)
            self.reset_efuses()

    def tearDown(self):
        if reset_port is None:
            self.efuse_file.close()

    def reset_efuses(self):
        # reset and zero efuses
        reset_port.dtr = False
        reset_port.rts = False
        time.sleep(0.05)
        reset_port.dtr = True
        reset_port.rts = True
        time.sleep(0.05)
        reset_port.dtr = False
        reset_port.rts = False

    def get_esptool(self):
        if espefuse_port is not None:
            import esptool
            esp = esptool.ESPLoader.detect_chip(port=espefuse_port)
            del esptool
        else:
            if chip_target == "esp32":
                import espressif.efuse.esp32 as efuse
            elif chip_target == "esp32s2":
                import espressif.efuse.esp32s2 as efuse
            elif chip_target == "esp32s3beta2":
                import espressif.efuse.esp32s3beta2 as efuse
            elif chip_target == "esp32c3":
                import espressif.efuse.esp32c3 as efuse
            else:
                efuse = None
            esp = efuse.EmulateEfuseController(self.efuse_file.name)
            del efuse
        return esp

    def _set_34_coding_scheme(self):
        self.espefuse_py('burn_efuse CODING_SCHEME 1')

    def check_data_block_in_log(self, log, file_path, repeat=1, reverse_order=False, offset=0):
        with open(file_path, 'rb') as f:
            data = BitString('0x00') * offset + BitString(f)
            blk = data.readlist("%d*uint:8" % (data.len // 8))
            blk = blk[::-1] if reverse_order else blk
            hex_blk = " ".join("{:02x}".format(num) for num in blk)
            self.assertEqual(repeat, log.count(hex_blk))

    def espefuse_not_virt_py(self, cmd, check_msg=None, ret_code=0):
        full_cmd = ' '.join(('python ../espefuse.py', cmd))
        return self._run_command(full_cmd, check_msg, ret_code)

    def espefuse_py(self, cmd, do_not_confirm=True, check_msg=None, ret_code=0):
        full_cmd = ' '.join((self.base_cmd, '--do-not-confirm' if do_not_confirm else '', cmd))
        return self._run_command(full_cmd, check_msg, ret_code)

    def _run_command(self, cmd, check_msg, ret_code):
        try:
            p = subprocess.Popen(cmd.split(), shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True)
            returncode = p.wait()
            output, _ = p.communicate()
            if check_msg:
                self.assertIn(check_msg, output)
            if returncode:
                print(output)
            self.assertEqual(ret_code, returncode)
            return output
        except subprocess.CalledProcessError as error:
            print(error)
            raise


class TestReadCommands(EfuseTestCase):

    def test_help(self):
        self.espefuse_not_virt_py("--help")
        self.espefuse_not_virt_py("--chip %s --help" % (chip_target))

    def test_dump(self):
        self.espefuse_py("dump -h")
        self.espefuse_py("dump")

    def test_summary(self):
        self.espefuse_py("summary -h")
        self.espefuse_py("summary")

    def test_summary_json(self):
        self.espefuse_py("summary --format json")

    def test_get_custom_mac(self):
        self.espefuse_py("get_custom_mac -h")
        if chip_target == "esp32":
            error_msg = None
            ret_code = 0
        else:
            error_msg = "get_custom_mac is not supported!"
            ret_code = 2
        self.espefuse_py("get_custom_mac", check_msg=error_msg, ret_code=ret_code)

    def test_adc_info(self):
        self.espefuse_py("adc_info -h")
        self.espefuse_py("adc_info")


class TestBurnCommands(EfuseTestCase):
    def test_read_protect_efuse(self):
        self.espefuse_py("read_protect_efuse -h")
        if chip_target == "esp32":
            cmd = 'read_protect_efuse \
                   CODING_SCHEME \
                   MAC_VERSION \
                   BLOCK1 \
                   BLOCK2 \
                   BLOCK3'
            count_protects = 5
        else:
            cmd = 'read_protect_efuse \
                   BLOCK_KEY0 \
                   BLOCK_KEY1 \
                   BLOCK_KEY2 \
                   BLOCK_KEY3 \
                   BLOCK_KEY4 \
                   BLOCK_KEY5'
            count_protects = 6
        self.espefuse_py(cmd)
        output = self.espefuse_py(cmd)
        self.assertEqual(count_protects, output.count("is already read protected"))

    def test_read_protect_efuse2(self):
        if chip_target == "esp32":
            self.espefuse_py('write_protect_efuse RD_DIS')
            self.espefuse_py('read_protect_efuse CODING_SCHEME',
                             check_msg='A fatal error occurred: This efuse cannot be read-disabled due the to RD_DIS field is already write-disabled',
                             ret_code=2)
        else:
            self.espefuse_py('write_protect_efuse RD_DIS')
            self.espefuse_py('read_protect_efuse BLOCK_KEY0',
                             check_msg='A fatal error occurred: This efuse cannot be read-disabled due the to RD_DIS field is already write-disabled',
                             ret_code=2)

    def test_write_protect_efuse(self):
        self.espefuse_py("write_protect_efuse -h")
        if chip_target == "esp32":
            efuse_lists = '''WR_DIS RD_DIS CODING_SCHEME CHIP_VERSION CHIP_PACKAGE XPD_SDIO_FORCE
                           XPD_SDIO_REG XPD_SDIO_TIEH SPI_PAD_CONFIG_CLK FLASH_CRYPT_CNT UART_DOWNLOAD_DIS
                           FLASH_CRYPT_CONFIG ADC_VREF BLOCK1 BLOCK2 BLOCK3'''
            efuse_lists2 = 'WR_DIS RD_DIS'
        else:
            efuse_lists = '''RD_DIS DIS_RTC_RAM_BOOT DIS_ICACHE DIS_DOWNLOAD_ICACHE DIS_FORCE_DOWNLOAD
                           DIS_USB DIS_CAN SOFT_DIS_JTAG DIS_DOWNLOAD_MANUAL_ENCRYPT USB_EXCHG_PINS
                           WDT_DELAY_SEL SPI_BOOT_CRYPT_CNT SECURE_BOOT_KEY_REVOKE0
                           SECURE_BOOT_KEY_REVOKE1 SECURE_BOOT_KEY_REVOKE2 KEY_PURPOSE_0 KEY_PURPOSE_1 KEY_PURPOSE_2 KEY_PURPOSE_3 KEY_PURPOSE_4 KEY_PURPOSE_5
                           SECURE_BOOT_EN SECURE_BOOT_AGGRESSIVE_REVOKE FLASH_TPUW DIS_DOWNLOAD_MODE DIS_LEGACY_SPI_BOOT UART_PRINT_CHANNEL
                           DIS_USB_DOWNLOAD_MODE ENABLE_SECURITY_DOWNLOAD UART_PRINT_CONTROL PIN_POWER_SELECTION FLASH_TYPE FORCE_SEND_RESUME SECURE_VERSION
                           MAC SPI_PAD_CONFIG_CLK SPI_PAD_CONFIG_Q SPI_PAD_CONFIG_D SPI_PAD_CONFIG_CS SPI_PAD_CONFIG_HD SPI_PAD_CONFIG_WP SPI_PAD_CONFIG_DQS
                           SPI_PAD_CONFIG_D4 SPI_PAD_CONFIG_D5 SPI_PAD_CONFIG_D6 SPI_PAD_CONFIG_D7 WAFER_VERSION PKG_VERSION BLOCK1_VERSION OPTIONAL_UNIQUE_ID
                           BLOCK2_VERSION BLOCK_USR_DATA BLOCK_KEY0 BLOCK_KEY1 BLOCK_KEY2 BLOCK_KEY3 BLOCK_KEY4 BLOCK_KEY5'''
            efuse_lists2 = 'RD_DIS DIS_RTC_RAM_BOOT'
        self.espefuse_py('write_protect_efuse {}'.format(efuse_lists))
        output = self.espefuse_py('write_protect_efuse {}'.format(efuse_lists2))
        self.assertEqual(2, output.count("is already write protected"))

    def test_write_protect_efuse2(self):
        if chip_target == "esp32":
            self.espefuse_py('write_protect_efuse WR_DIS')
            self.espefuse_py('write_protect_efuse CODING_SCHEME',
                             check_msg='A fatal error occurred: This efuse cannot be write-disabled due to the WR_DIS field is already write-disabled',
                             ret_code=2)

    def test_burn_custom_mac(self):
        self.espefuse_py("burn_custom_mac -h")
        cmd = 'burn_custom_mac AB:CD:EF:11:22:33'
        if chip_target == "esp32":
            self.espefuse_py(cmd, check_msg='Custom MAC Address version 1: ab:cd:ef:11:22:33 (CRC 0x54 OK)')
        else:
            self.espefuse_py(cmd, check_msg='burn_custom_mac is not supported!', ret_code=2)

    def test_burn_custom_mac2(self):
        if chip_target == "esp32":
            self.espefuse_py('burn_custom_mac AB:CD:EF:11:22:33:44',
                             check_msg='A fatal error occurred: MAC Address needs to be a 6-byte hexadecimal format separated by colons (:)!',
                             ret_code=2)

    def test_burn_custom_mac_with_34_coding_scheme(self):
        if chip_target == "esp32":
            self._set_34_coding_scheme()
            self.espefuse_py("burn_custom_mac -h")
            self.espefuse_py('burn_custom_mac AB:CD:EF:01:02:03', check_msg='Custom MAC Address version 1: ab:cd:ef:01:02:03 (CRC 0x61 OK)')
            self.espefuse_py('get_custom_mac', check_msg='Custom MAC Address version 1: ab:cd:ef:01:02:03 (CRC 0x61 OK)')

            self.espefuse_py('burn_custom_mac FF:22:33:44:55:66',
                             check_msg='New value contains some bits that cannot be cleared (value will be 0x675745ffefff)',
                             ret_code=2)

    @unittest.skipIf(chip_target == "esp32c3", "TODO: add support set_flash_voltage for ESP32-C3")
    def test_set_flash_voltage_1_8v(self):
        self.espefuse_py("set_flash_voltage -h")
        vdd = "VDD_SDIO" if chip_target == "esp32" else "VDD_SPI"
        self.espefuse_py('set_flash_voltage 1.8V', check_msg='Set internal flash voltage regulator (%s) to 1.8V.' % vdd)
        if chip_target == "esp32":
            error_msg = "A fatal error occurred: Can't set flash regulator to OFF as XPD_SDIO_REG efuse is already burned"
        else:
            error_msg = "A fatal error occurred: Can't set flash regulator to OFF as VDD_SPI_XPD efuse is already burned"
        self.espefuse_py('set_flash_voltage 3.3V', check_msg='Enable internal flash voltage regulator (%s) to 3.3V.' % vdd)
        self.espefuse_py('set_flash_voltage OFF', check_msg=error_msg, ret_code=2)

    @unittest.skipIf(chip_target == "esp32c3", "TODO: add support set_flash_voltage for ESP32-C3")
    def test_set_flash_voltage_3_3v(self):
        vdd = "VDD_SDIO" if chip_target == "esp32" else "VDD_SPI"
        self.espefuse_py('set_flash_voltage 3.3V', check_msg='Enable internal flash voltage regulator (%s) to 3.3V.' % vdd)
        if chip_target == "esp32":
            error_msg = "A fatal error occurred: Can't set regulator to 1.8V is XPD_SDIO_TIEH efuse is already burned"
        else:
            error_msg = "A fatal error occurred: Can't set regulator to 1.8V is VDD_SPI_TIEH efuse is already burned"
        self.espefuse_py('set_flash_voltage 1.8V', check_msg=error_msg, ret_code=2)

        if chip_target == "esp32":
            error_msg = "A fatal error occurred: Can't set flash regulator to OFF as XPD_SDIO_REG efuse is already burned"
        else:
            error_msg = "A fatal error occurred: Can't set flash regulator to OFF as VDD_SPI_XPD efuse is already burned"
        self.espefuse_py('set_flash_voltage OFF', check_msg=error_msg, ret_code=2)

    @unittest.skipIf(chip_target == "esp32c3", "TODO: add support set_flash_voltage for ESP32-C3")
    def test_set_flash_voltage_off(self):
        vdd = "VDD_SDIO" if chip_target == "esp32" else "VDD_SPI"
        self.espefuse_py('set_flash_voltage OFF', check_msg='Disable internal flash voltage regulator (%s)' % vdd)
        self.espefuse_py('set_flash_voltage 3.3V', check_msg='Enable internal flash voltage regulator (%s) to 3.3V.' % vdd)

    @unittest.skipIf(chip_target == "esp32c3", "TODO: add support set_flash_voltage for ESP32-C3")
    def test_set_flash_voltage_off2(self):
        vdd = "VDD_SDIO" if chip_target == "esp32" else "VDD_SPI"
        self.espefuse_py('set_flash_voltage OFF', check_msg='Disable internal flash voltage regulator (%s)' % vdd)
        self.espefuse_py('set_flash_voltage 1.8V', check_msg='Set internal flash voltage regulator (%s) to 1.8V.' % vdd)

    def test_burn_efuse(self):
        self.espefuse_py("burn_efuse -h")
        if chip_target == "esp32":
            self.espefuse_py('burn_efuse \
                              CHIP_VER_REV2 1 \
                              DISABLE_DL_ENCRYPT 1 \
                              CONSOLE_DEBUG_DISABLE 1')
            self.espefuse_py('burn_efuse MAC AB:CD:EF:01:02:03', check_msg="Writing Factory MAC address is not supported", ret_code=2)
            self.espefuse_py('burn_efuse MAC_VERSION 1')
            self.espefuse_py("burn_efuse -h")
            self.espefuse_py('burn_efuse CUSTOM_MAC AB:CD:EF:01:02:03')
            self.espefuse_py('get_custom_mac', check_msg='Custom MAC Address version 1: ab:cd:ef:01:02:03 (CRC 0x61 OK)')
            blk1 = "BLOCK1"
            blk2 = "BLOCK2"
        else:
            self.espefuse_py('burn_efuse \
                              SECURE_BOOT_EN 1 \
                              UART_PRINT_CONTROL 1')
            self.espefuse_py('burn_efuse \
                              OPTIONAL_UNIQUE_ID 0x2328ad5ac9145f698f843a26d6eae168',
                             check_msg="-> 0x2328ad5ac9145f698f843a26d6eae168")
            output = self.espefuse_py('summary -d')
            self.assertIn('read_regs: d6eae168 8f843a26 c9145f69 2328ad5a 00000000 00000000 00000000 00000000', output)
            self.assertIn('= 68 e1 ea d6 26 3a 84 8f 69 5f 14 c9 5a ad 28 23 R/W', output)
            self.espefuse_py('burn_efuse \
                              BLOCK2_VERSION  1',
                             check_msg="Burn into BLOCK_SYS_DATA is forbidden (RS coding scheme does not allow this).",
                             ret_code=2)
            blk1 = "BLOCK_KEY1"
            blk2 = "BLOCK_KEY2"
        output = self.espefuse_py('burn_efuse {} 0x00010203040506070809111111111111111111111111111111110000112233FF'.format(blk1))
        self.assertIn('-> 0x00010203040506070809111111111111111111111111111111110000112233ff', output)
        output = self.espefuse_py('summary -d')
        self.assertIn('read_regs: 112233ff 11110000 11111111 11111111 11111111 08091111 04050607 00010203', output)
        self.assertIn('= ff 33 22 11 00 00 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 09 08 07 06 05 04 03 02 01 00 R/W', output)

        output = self.espefuse_py('burn_efuse {}   00010203040506070809111111111111111111111111111111110000112233FF'.format(blk2))
        self.assertIn('-> 0xff33221100001111111111111111111111111111111109080706050403020100', output)
        output = self.espefuse_py('summary -d')
        self.assertIn('read_regs: 03020100 07060504 11110908 11111111 11111111 11111111 00001111 ff332211', output)
        self.assertIn('= 00 01 02 03 04 05 06 07 08 09 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 00 00 11 22 33 ff R/W', output)

    def test_burn_efuse_with_34_coding_scheme(self):
        if chip_target == "esp32":
            self._set_34_coding_scheme()
            self.espefuse_py("burn_efuse BLK3_PART_RESERVE 1")
            self.espefuse_py("burn_efuse ADC1_TP_LOW 50")
            self.espefuse_py("burn_efuse ADC1_TP_HIGH 55", check_msg="Burn into BLOCK3 is forbidden (3/4 coding scheme does not allow this)", ret_code=2)

    def test_burn_efuse_with_34_coding_scheme2(self):
        if chip_target == "esp32":
            self._set_34_coding_scheme()
            self.espefuse_py("burn_efuse BLK3_PART_RESERVE 1")
            self.espefuse_py("burn_efuse \
                              ADC1_TP_LOW 50 \
                              ADC1_TP_HIGH 55 \
                              ADC2_TP_LOW 40 \
                              ADC2_TP_HIGH 45")

    def test_burn_key(self):
        self.espefuse_py("burn_key -h")
        if chip_target == "esp32":
            self.espefuse_py('burn_key BLOCK1 images/efuse/192bit',
                             check_msg="A fatal error occurred: Incorrect key file size 24. Key file must be 32 bytes (256 bits) of raw binary key data.",
                             ret_code=2)
            self.espefuse_py('burn_key \
                              BLOCK1 images/efuse/256bit \
                              BLOCK2 images/efuse/256bit_1 \
                              BLOCK3 images/efuse/256bit_2 --no-protect-key')
            output = self.espefuse_py('summary -d')
            self.check_data_block_in_log(output, "images/efuse/256bit")
            self.check_data_block_in_log(output, "images/efuse/256bit_1")
            self.check_data_block_in_log(output, "images/efuse/256bit_2")

            self.espefuse_py('burn_key \
                              BLOCK1 images/efuse/256bit \
                              BLOCK2 images/efuse/256bit_1 \
                              BLOCK3 images/efuse/256bit_2')
            output = self.espefuse_py('summary -d')
            self.check_data_block_in_log(output, "images/efuse/256bit")
            self.check_data_block_in_log(output, "images/efuse/256bit_1")
            self.check_data_block_in_log(output, "images/efuse/256bit_2")
        else:
            self.espefuse_py('burn_key \
                              BLOCK_KEY0 images/efuse/256bit   XTS_AES_256_KEY_1 \
                              BLOCK_KEY1 images/efuse/256bit_1 XTS_AES_256_KEY_2 \
                              BLOCK_KEY2 images/efuse/256bit_2 XTS_AES_128_KEY   --no-read-protect --no-write-protect')
            output = self.espefuse_py('summary -d')
            self.check_data_block_in_log(output, "images/efuse/256bit", reverse_order=True)
            self.check_data_block_in_log(output, "images/efuse/256bit_1", reverse_order=True)
            self.check_data_block_in_log(output, "images/efuse/256bit_2", reverse_order=True)

            self.espefuse_py('burn_key \
                              BLOCK_KEY0 images/efuse/256bit   XTS_AES_256_KEY_1 \
                              BLOCK_KEY1 images/efuse/256bit_1 XTS_AES_256_KEY_2 \
                              BLOCK_KEY2 images/efuse/256bit_2 XTS_AES_128_KEY')
            output = self.espefuse_py('summary -d')
            self.assertIn('[4 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000', output)
            self.assertIn('[5 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000', output)
            self.assertIn('[6 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000', output)

            self.espefuse_py('burn_key \
                              BLOCK_KEY3 images/efuse/256bit   SECURE_BOOT_DIGEST0 \
                              BLOCK_KEY4 images/efuse/256bit_1 SECURE_BOOT_DIGEST1 \
                              BLOCK_KEY5 images/efuse/256bit_2 SECURE_BOOT_DIGEST2')
            output = self.espefuse_py('summary -d')
            self.check_data_block_in_log(output, "images/efuse/256bit")
            self.check_data_block_in_log(output, "images/efuse/256bit_1")
            self.check_data_block_in_log(output, "images/efuse/256bit_2")

    def test_burn_key_with_34_coding_scheme(self):
        if chip_target == "esp32":
            self._set_34_coding_scheme()
            self.espefuse_py('burn_key BLOCK1 images/efuse/256bit',
                             check_msg="A fatal error occurred: Incorrect key file size 32. Key file must be 24 bytes (192 bits) of raw binary key data.",
                             ret_code=2)
            self.espefuse_py('burn_key \
                              BLOCK1 images/efuse/192bit \
                              BLOCK2 images/efuse/192bit_1 \
                              BLOCK3 images/efuse/192bit_2 --no-protect-key')
            output = self.espefuse_py('summary -d')
            self.check_data_block_in_log(output, "images/efuse/192bit")
            self.check_data_block_in_log(output, "images/efuse/192bit_1")
            self.check_data_block_in_log(output, "images/efuse/192bit_2")

            self.espefuse_py('burn_key \
                              BLOCK1 images/efuse/192bit \
                              BLOCK2 images/efuse/192bit_1 \
                              BLOCK3 images/efuse/192bit_2')
            output = self.espefuse_py('summary -d')
            self.check_data_block_in_log(output, "images/efuse/192bit")
            self.check_data_block_in_log(output, "images/efuse/192bit_1")
            self.check_data_block_in_log(output, "images/efuse/192bit_2")

    def test_burn_block_data_check_args(self):
        self.espefuse_py("burn_block_data -h")
        if chip_target == "esp32":
            blk0 = "BLOCK0"
            blk1 = "BLOCK1"
        else:
            blk0 = "BLOCK0"
            blk1 = "BLOCK1"
        self.espefuse_py('burn_block_data \
                          %s images/efuse/224bit \
                          %s' % (blk0, blk1),
                         check_msg="A fatal error occurred: The number of block_name (2) and datafile (1) should be the same.",
                         ret_code=2)

    def test_burn_block_data(self):
        if chip_target == "esp32":
            self.espefuse_py('burn_block_data \
                              BLOCK0 images/efuse/224bit \
                              BLOCK3 images/efuse/256bit')
            output = self.espefuse_py('summary -d')
            self.assertIn('[3 ] read_regs: a3a2a1a0 a7a6a5a4 abaaa9a8 afaeadac b3b2b1b0 b7b6b5b4 bbbab9b8 bfbebdbc', output)
            self.check_data_block_in_log(output, "images/efuse/256bit")

            self.espefuse_py('burn_block_data \
                              BLOCK2 images/efuse/256bit_1')
            self.check_data_block_in_log(self.espefuse_py('summary -d'), "images/efuse/256bit_1")

            self.espefuse_py('burn_block_data \
                              BLOCK1 images/efuse/256bit_2')
            self.check_data_block_in_log(self.espefuse_py('summary -d'), "images/efuse/256bit_2")
        else:
            self.espefuse_py('burn_block_data \
                              BLOCK0 images/efuse/192bit \
                              BLOCK3 images/efuse/256bit')
            output = self.espefuse_py('summary -d')
            self.assertIn('[0 ] read_regs: 00000000 07060500 00000908 00000000 13000000 00161514', output)
            self.assertIn('[3 ] read_regs: a3a2a1a0 a7a6a5a4 abaaa9a8 afaeadac b3b2b1b0 b7b6b5b4 bbbab9b8 bfbebdbc', output)
            self.check_data_block_in_log(output, "images/efuse/256bit")

            self.espefuse_py('burn_block_data \
                              BLOCK10 images/efuse/256bit_1')
            self.check_data_block_in_log(self.espefuse_py('summary -d'), "images/efuse/256bit_1")

            self.espefuse_py('burn_block_data \
                              BLOCK1 images/efuse/192bit \
                              BLOCK5 images/efuse/256bit_1 \
                              BLOCK6 images/efuse/256bit_2')
            output = self.espefuse_py('summary -d')
            self.assertIn('[1 ] read_regs: 00000000 07060500 00000908 00000000 13000000 00161514', output)
            self.check_data_block_in_log(output, "images/efuse/256bit")
            self.check_data_block_in_log(output, "images/efuse/256bit_1", 2)
            self.check_data_block_in_log(output, "images/efuse/256bit_2")

    def test_burn_block_data_with_offset(self):
        if chip_target == "esp32":
            blk0 = "BLOCK0"
            blk1 = "BLOCK1"
            blk2 = "BLOCK2"
            blk3 = "BLOCK3"
        else:
            blk0 = "BLOCK0"
            blk1 = "BLOCK_KEY0"
            blk2 = "BLOCK_KEY1"
            blk3 = "BLOCK_KEY2"
        self.espefuse_py('burn_block_data \
                            --offset 4\
                            %s images/efuse/192bit \
                            %s images/efuse/192bit_1' % (blk1, blk1),
                         check_msg="A fatal error occurred: Found repeated",
                         ret_code=2)
        self.espefuse_py('burn_block_data \
                            --offset 4\
                            %s images/efuse/192bit \
                            %s images/efuse/192bit_1' % (blk1, blk2),
                         check_msg="A fatal error occurred: The 'offset' option is not applicable when a few blocks are passed.",
                         ret_code=2)
        self.espefuse_py('burn_block_data \
                            --offset 9 \
                            %s images/efuse/192bit' % (blk0),
                         check_msg="A fatal error occurred: Data does not fit:",
                         ret_code=2)
        if chip_target == "esp32":
            offset = 1
            self.espefuse_py('burn_block_data --offset %d BLOCK0 images/efuse/192bit' % offset)

        offset = 4
        self.espefuse_py('burn_block_data --offset %d %s images/efuse/192bit_1' % (offset, blk1))
        self.check_data_block_in_log(self.espefuse_py('summary -d'), "images/efuse/192bit_1", offset=offset)

        offset = 6
        self.espefuse_py('burn_block_data --offset %d %s images/efuse/192bit_2' % (offset, blk2))
        self.check_data_block_in_log(self.espefuse_py('summary -d'), "images/efuse/192bit_2", offset=offset)

        offset = 8
        self.espefuse_py('burn_block_data --offset %d %s images/efuse/192bit_2' % (offset, blk3))
        self.check_data_block_in_log(self.espefuse_py('summary -d'), "images/efuse/192bit_2", offset=offset)

    def test_burn_block_data_with_34_coding_scheme(self):
        if chip_target == "esp32":
            self._set_34_coding_scheme()
            self.espefuse_py('burn_block_data BLOCK1 images/efuse/256bit',
                             check_msg="A fatal error occurred: Data does not fit: the block1 size is 24 bytes, data file is 32 bytes, offset 0",
                             ret_code=2)

            self.espefuse_py('burn_block_data \
                              BLOCK1 images/efuse/192bit \
                              BLOCK2 images/efuse/192bit_1 \
                              BLOCK3 images/efuse/192bit_2')
            output = self.espefuse_py('summary -d')
            self.check_data_block_in_log(output, "images/efuse/192bit")
            self.check_data_block_in_log(output, "images/efuse/192bit_1")
            self.check_data_block_in_log(output, "images/efuse/192bit_2")

    def test_burn_block_data_with_34_coding_scheme_and_offset(self):
        if chip_target == "esp32":
            self._set_34_coding_scheme()

            offset = 4
            self.espefuse_py('burn_block_data --offset %d BLOCK1 images/efuse/128bit' % (offset))
            self.check_data_block_in_log(self.espefuse_py('summary -d'), "images/efuse/128bit", offset=offset)

            offset = 6
            self.espefuse_py('burn_block_data --offset %d BLOCK2 images/efuse/128bit' % (offset))
            self.check_data_block_in_log(self.espefuse_py('summary -d'), "images/efuse/128bit", offset=offset)

            offset = 8
            self.espefuse_py('burn_block_data --offset %d BLOCK3 images/efuse/128bit' % (offset))
            self.check_data_block_in_log(self.espefuse_py('summary -d'), "images/efuse/128bit", offset=offset)

    def test_burn_key_digest(self):
        self.espefuse_py("burn_key_digest -h")
        if chip_target == "esp32":
            esp = self.get_esptool()
            chip_revision = esp.get_chip_description()
            if "revision 3" in chip_revision:
                self.espefuse_py('burn_key_digest secure_images/rsa_secure_boot_signing_key.pem')
                output = self.espefuse_py('summary -d')
                self.assertEqual(1, output.count(" = cb 27 91 a3 71 b0 c0 32 2b f7 37 04 78 ba 09 62 22 4c ab 1c f2 28 78 79 e4 29 67 3e 7d a8 44 63 R/-"))
            else:
                self.espefuse_py('burn_key_digest secure_images/rsa_secure_boot_signing_key.pem',
                                 check_msg="Incorrect chip revision for Secure boot v2.",
                                 ret_code=2)
        else:
            self.espefuse_py('burn_key_digest \
                              BLOCK_KEY0 secure_images/rsa_secure_boot_signing_key.pem SECURE_BOOT_DIGEST0 \
                              BLOCK_KEY1 secure_images/rsa_secure_boot_signing_key2.pem SECURE_BOOT_DIGEST1 \
                              BLOCK_KEY2 ',
                             check_msg="A fatal error occurred: The number of blocks (3), datafile (2) and keypurpose (2) should be the same.",
                             ret_code=2)
            self.espefuse_py('burn_key_digest \
                              BLOCK_KEY0 secure_images/rsa_secure_boot_signing_key.pem SECURE_BOOT_DIGEST0 \
                              BLOCK_KEY1 secure_images/rsa_secure_boot_signing_key2.pem SECURE_BOOT_DIGEST1 \
                              BLOCK_KEY2 secure_images/rsa_secure_boot_signing_key2.pem SECURE_BOOT_DIGEST2')
            output = self.espefuse_py('summary -d')
            self.assertEqual(1, output.count(" = cb 27 91 a3 71 b0 c0 32 2b f7 37 04 78 ba 09 62 22 4c ab 1c f2 28 78 79 e4 29 67 3e 7d a8 44 63 R/-"))
            self.assertEqual(2, output.count(" = 90 1a 74 09 23 8d 52 d4 cb f9 6f 56 3f b3 f4 29 6d ab d6 6a 33 f5 3b 15 ee cd 8c b3 e7 ec 45 d3 R/-"))

    def test_burn_key_from_digest(self):
        #  python espsecure.py digest_rsa_public_key --keyfile test/secure_images/rsa_secure_boot_signing_key.pem \
        #                                            -o secure_images/rsa_public_key_digest.bin
        if chip_target == "esp32":
            self.espefuse_py('burn_key \
                              BLOCK2 secure_images/rsa_public_key_digest.bin --no-protect-key')
            output = self.espefuse_py('summary -d')
            print(output)
            self.assertEqual(1, output.count(" = cb 27 91 a3 71 b0 c0 32 2b f7 37 04 78 ba 09 62 22 4c ab 1c f2 28 78 79 e4 29 67 3e 7d a8 44 63 R/W"))

        elif chip_target == "esp32s2":
            self.espefuse_py('burn_key \
                              BLOCK_KEY0 secure_images/rsa_public_key_digest.bin SECURE_BOOT_DIGEST0')
            output = self.espefuse_py('summary -d')
            self.assertEqual(1, output.count(" = cb 27 91 a3 71 b0 c0 32 2b f7 37 04 78 ba 09 62 22 4c ab 1c f2 28 78 79 e4 29 67 3e 7d a8 44 63 R/-"))

            self.espefuse_py('burn_key_digest \
                              BLOCK_KEY1 secure_images/rsa_secure_boot_signing_key.pem SECURE_BOOT_DIGEST1')
            output = self.espefuse_py('summary -d')
            self.assertEqual(2, output.count(" = cb 27 91 a3 71 b0 c0 32 2b f7 37 04 78 ba 09 62 22 4c ab 1c f2 28 78 79 e4 29 67 3e 7d a8 44 63 R/-"))

    def test_burn_key_digest_with_34_coding_scheme(self):
        if chip_target == "esp32":
            self._set_34_coding_scheme()
            self.espefuse_py('burn_key_digest secure_images/rsa_secure_boot_signing_key.pem',
                             check_msg="burn_key_digest only works with 'None' coding scheme",
                             ret_code=2)

    def test_burn_bit(self):
        self.espefuse_py("burn_bit -h")
        if chip_target == "esp32":
            self.espefuse_py('burn_bit BLOCK3 0 1 2 4 8 16 32 64 96 128 160 192 224 255')
            self.espefuse_py('summary', check_msg="17 01 01 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 80")

            self.espefuse_py('burn_bit BLOCK3 3 5 6 7 9 10 11 12 13 14 15 31 63 95 127 159 191 223 254')
            self.espefuse_py('summary', check_msg="ff ff 01 80 01 00 00 80 01 00 00 80 01 00 00 80 01 00 00 80 01 00 00 80 01 00 00 80 01 00 00 c0")
        else:
            self.espefuse_py('burn_bit BLOCK3 0 1 2 4 8 16 32 64 96 128 160 192 224 255')
            self.espefuse_py('summary', check_msg="17 01 01 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 80")
            self.espefuse_py('burn_bit BLOCK3 100', check_msg="Burn into BLOCK_USR_DATA is forbidden (RS coding scheme does not allow this)", ret_code=2)

            self.espefuse_py('burn_bit BLOCK0 13')
            self.espefuse_py('summary', check_msg="[0 ] read_regs: 00002000 00000000 00000000 00000000 00000000 00000000")

            self.espefuse_py('burn_bit BLOCK0 24')
            self.espefuse_py('summary', check_msg="[0 ] read_regs: 01002000 00000000 00000000 00000000 00000000 00000000")

    def test_burn_bit_with_34_coding_scheme(self):
        if chip_target == "esp32":
            self._set_34_coding_scheme()
            self.espefuse_py('burn_bit BLOCK3 0 1 2 4 8 16 32 64 96 128 160 191')
            self.espefuse_py('summary', check_msg="17 01 01 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 80")
            self.espefuse_py('burn_bit BLOCK3 17', check_msg="Burn into BLOCK3 is forbidden (3/4 coding scheme does not allow this).", ret_code=2)


class TestByteOrderBurnKeyCommand(EfuseTestCase):
    def test_1_secure_boot_v1(self):
        if chip_target == "esp32":
            self.espefuse_py('burn_key \
                              flash_encryption images/efuse/256bit \
                              secure_boot_v1 images/efuse/256bit_1 --no-protect-key')
            output = self.espefuse_py('summary -d')
            self.check_data_block_in_log(output, "images/efuse/256bit", reverse_order=True)
            self.check_data_block_in_log(output, "images/efuse/256bit_1", reverse_order=True)

            self.espefuse_py('burn_key \
                              flash_encryption  images/efuse/256bit \
                              secure_boot_v1    images/efuse/256bit_1')
            output = self.espefuse_py('summary -d')
            self.assertIn('[1 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000', output)
            self.assertIn('[2 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000', output)
            self.assertIn('[3 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000', output)

    def test_2_secure_boot_v1(self):
        if chip_target == "esp32":
            self.espefuse_py('burn_key \
                              flash_encryption images/efuse/256bit \
                              secure_boot_v2 images/efuse/256bit_1 --no-protect-key')
            output = self.espefuse_py('summary -d')
            self.check_data_block_in_log(output, "images/efuse/256bit", reverse_order=True)
            self.check_data_block_in_log(output, "images/efuse/256bit_1", reverse_order=False)

            self.espefuse_py('burn_key \
                              flash_encryption images/efuse/256bit \
                              secure_boot_v2 images/efuse/256bit_1')
            output = self.espefuse_py('summary -d')
            self.assertIn('[1 ] read_regs: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000', output)
            self.check_data_block_in_log(output, "images/efuse/256bit_1", reverse_order=False)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        chip_target = sys.argv[1]
        if chip_target not in support_list_chips:
            print("Usage: %s - a wrong name of chip" % chip_target)
            sys.exit(1)
        if len(sys.argv) > 3:
            espefuse_port = sys.argv[2]
            reset_port = serial.Serial(sys.argv[3], 115200)
    else:
        chip_target = support_list_chips[0]  # ESP32 by default
    print("HOST_TEST of espefuse.py for %s" % chip_target)

    # unittest also uses argv, so trim the args we used
    sys.argv = [sys.argv[0]] + sys.argv[4:]
    print("Running espefuse.py tests...")
    unittest.main(buffer=True)
