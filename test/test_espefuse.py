# HOST_TEST for espefuse.py using the pytest framework
#
# Supports esp32, esp32s2, esp32s3, esp32c3,
#          esp32c2, esp32c6, esp32p4, esp32c61,
#          esp32c5,
#
# How to use:
#
# Run as HOST_TEST (without a physical connection to a chip):
#  - `pytest test_espefuse.py --chip esp32`
#  - `pytest test_espefuse.py --chip esp32s2`
#
# OR
#
# Run as TEST on FPGA (connection to FPGA with a flashed image):
# required two COM ports
#  - `pytest test_espefuse.py \
#     --chip esp32 --port /dev/ttyUSB0 --reset-port /dev/ttyUSB1`
#
# where  - --port       - a port for espefuse.py operation
#        - --reset-port - a port to clear efuses (connect RTS or DTR ->- J14 pin 39)
#
# Note: For FPGA with ESP32 image, you need to set an env variable ESPTOOL_ENV_FPGA to 1
#       to slow down the connection sequence
#       because of a long delay (~6 seconds) after resetting the FPGA.
#       This is not necessary when using other images than ESP32

import os
import subprocess
import sys
import tempfile
import time

from bitstring import BitStream

# Make command line options --port, --reset-port and --chip available
from conftest import arg_chip, arg_port, arg_reset_port, need_to_install_package_err

TEST_DIR = os.path.abspath(os.path.dirname(__file__))
IMAGES_DIR = os.path.join(TEST_DIR, "images", "efuse")
S_IMAGES_DIR = os.path.join(TEST_DIR, "secure_images")
EFUSE_S_DIR = os.path.join(TEST_DIR, "efuse_scripts")

import pytest

try:
    from espefuse import SUPPORTED_CHIPS
except ImportError:
    need_to_install_package_err()

SUPPORTED_CHIPS = list(SUPPORTED_CHIPS.keys())

import serial

# Set reset_port if --reset-port cmdline option is specified
# This activates testing with real hardware (FPGA)
reset_port = (
    serial.Serial(arg_reset_port, 115200) if arg_reset_port is not None else None
)

if arg_chip not in SUPPORTED_CHIPS:
    pytest.exit(f"{arg_chip} is not a supported target, choose from {SUPPORTED_CHIPS}")
print(f"\nHost tests of espefuse.py for {arg_chip}:")
print("Running espefuse.py tests...")

# The default value of the program name for argparse has changed in Python 3.14
# https://docs.python.org/dev/whatsnew/3.14.html#argparse
ESPEFUSE_MODNAME = (
    "__main__.py" if sys.version_info < (3, 14) else "python3 -m espefuse"
)


@pytest.mark.host_test
class EfuseTestCase:
    def setup_method(self):
        if reset_port is None:
            self.efuse_file = tempfile.NamedTemporaryFile(delete=False)
            self.base_cmd = (
                f"{sys.executable} -m espefuse --chip {arg_chip} "
                f"--virt --path-efuse-file {self.efuse_file.name} -d"
            )
            self._set_target_wafer_version()
        else:
            self.base_cmd = (
                f"{sys.executable} -m espefuse --chip {arg_chip} "
                f"--port {arg_port} -d"
            )
            self.reset_efuses()

    def teardown_method(self):
        if reset_port is None:
            self.efuse_file.close()
            os.unlink(self.efuse_file.name)

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
        if reset_port is not None:
            import esptool

            esp = esptool.cmds.detect_chip(port=arg_port)
            del esptool
        else:
            import espefuse

            efuse = espefuse.SUPPORTED_CHIPS[arg_chip].efuse_lib
            esp = efuse.EmulateEfuseController(self.efuse_file.name)
            del espefuse
            del efuse
        return esp

    def _set_34_coding_scheme(self):
        self.espefuse_py("burn_efuse CODING_SCHEME 1")

    def _set_none_recovery_coding_scheme(self):
        self.espefuse_py("burn_efuse CODING_SCHEME 3")

    def _set_target_wafer_version(self):
        # ESP32 has to be ECO3 (v3.0) for tests
        if arg_chip == "esp32":
            self.espefuse_py("burn_efuse CHIP_VER_REV1 1 CHIP_VER_REV2 1")

    def check_data_block_in_log(
        self, log, file_path, repeat=1, reverse_order=False, offset=0
    ):
        with open(file_path, "rb") as f:
            data = BitStream("0x00") * offset + BitStream(f)
            blk = data.readlist(f"{data.len // 8}*uint:8")
            blk = blk[::-1] if reverse_order else blk
            hex_blk = " ".join(f"{num:02x}" for num in blk)
            assert repeat == log.count(hex_blk)

    def espefuse_not_virt_py(self, cmd, check_msg=None, ret_code=0):
        full_cmd = " ".join((f"{sys.executable} -m espefuse", cmd))
        return self._run_command(full_cmd, check_msg, ret_code)

    def espefuse_py(self, cmd, do_not_confirm=True, check_msg=None, ret_code=0):
        full_cmd = " ".join(
            [self.base_cmd, "--do-not-confirm" if do_not_confirm else "", cmd]
        )
        output = self._run_command(full_cmd, check_msg, ret_code)
        self._run_command(
            " ".join([self.base_cmd, "check_error"]), "No errors detected", 0
        )
        print(output)
        return output

    def _run_command(self, cmd, check_msg, ret_code):
        try:
            p = subprocess.Popen(
                cmd.split(),
                shell=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
            )
            output, _ = p.communicate()
            returncode = p.returncode
            if check_msg:
                assert check_msg in output
            if returncode:
                print(output)
                print(cmd)
            assert ret_code == returncode
            return output
        except subprocess.CalledProcessError as error:
            print(error)
            raise


class TestReadCommands(EfuseTestCase):
    def test_help(self):
        self.espefuse_not_virt_py("--help", check_msg=f"usage: {ESPEFUSE_MODNAME} [-h]")
        self.espefuse_not_virt_py(f"--chip {arg_chip} --help")

    def test_help2(self):
        self.espefuse_not_virt_py(
            "", check_msg=f"usage: {ESPEFUSE_MODNAME} [-h]", ret_code=1
        )

    def test_dump(self):
        self.espefuse_py("dump -h")
        self.espefuse_py("dump")

    def test_dump_format_joint(self):
        tmp_file = tempfile.NamedTemporaryFile(delete=False)
        self.espefuse_py(f"dump --format joint --file_name {tmp_file.name}")

    def test_dump_split_default(self):
        tmp_file = tempfile.NamedTemporaryFile(delete=False)
        self.espefuse_py(f"dump --file_name {tmp_file.name}")

    def test_dump_split(self):
        tmp_file = tempfile.NamedTemporaryFile(delete=False)
        self.espefuse_py(f"dump --format split --file_name {tmp_file.name}")

    def test_summary(self):
        self.espefuse_py("summary -h")
        self.espefuse_py("summary")

    def test_summary_json(self):
        self.espefuse_py("summary --format json")

    def test_summary_filter(self):
        self.espefuse_py("summary MAC")
        self.espefuse_py("summary --format value_only MAC")
        self.espefuse_py(
            "summary --format value_only MAC WR_DIS",
            check_msg="The 'value_only' format can be used exactly for one efuse.",
            ret_code=2,
        )

    @pytest.mark.skipif(
        arg_chip == "esp32p4", reason="No Custom MAC Address defined yet"
    )
    def test_get_custom_mac(self):
        self.espefuse_py("get_custom_mac -h")
        if arg_chip == "esp32":
            right_msg = "Custom MAC Address is not set in the device."
        else:
            right_msg = "Custom MAC Address: 00:00:00:00:00:00 (OK)"
        self.espefuse_py("get_custom_mac", check_msg=right_msg)

    def test_adc_info(self):
        self.espefuse_py("adc_info -h")
        self.espefuse_py("adc_info")

    def test_adc_info_2(self):
        if arg_chip == "esp32":
            self.espefuse_py("burn_efuse BLK3_PART_RESERVE 1")
        elif arg_chip in ["esp32c3", "esp32s3"]:
            self.espefuse_py("burn_efuse BLK_VERSION_MAJOR 1")
        elif arg_chip in ["esp32c2", "esp32s2", "esp32c6"]:
            self.espefuse_py("burn_efuse BLK_VERSION_MINOR 1")
        elif arg_chip in ["esp32h2", "esp32p4"]:
            self.espefuse_py("burn_efuse BLK_VERSION_MINOR 2")
        self.espefuse_py("adc_info")

    def test_check_error(self):
        self.espefuse_py("check_error -h")
        self.espefuse_py("check_error")
        self.espefuse_py("check_error --recovery")


# TODO: [ESP32H21] IDF-11506
@pytest.mark.skipif(arg_chip == "esp32h21", reason="Not supported yet")
class TestReadProtectionCommands(EfuseTestCase):
    def test_read_protect_efuse(self):
        self.espefuse_py("read_protect_efuse -h")
        if arg_chip == "esp32":
            cmd = "read_protect_efuse \
                   CODING_SCHEME \
                   MAC_VERSION \
                   BLOCK1 \
                   BLOCK2 \
                   BLOCK3"
            count_protects = 5
        elif arg_chip == "esp32c2":
            cmd = "read_protect_efuse \
                   BLOCK_KEY0_LOW_128"
            count_protects = 1
        else:
            self.espefuse_py(
                "burn_efuse \
                KEY_PURPOSE_0 HMAC_UP \
                KEY_PURPOSE_1 XTS_AES_128_KEY \
                KEY_PURPOSE_2 XTS_AES_128_KEY \
                KEY_PURPOSE_3 HMAC_DOWN_ALL \
                KEY_PURPOSE_4 HMAC_DOWN_JTAG \
                KEY_PURPOSE_5 HMAC_DOWN_DIGITAL_SIGNATURE"
            )
            cmd = "read_protect_efuse \
                   BLOCK_KEY0 \
                   BLOCK_KEY1 \
                   BLOCK_KEY2 \
                   BLOCK_KEY3 \
                   BLOCK_KEY4 \
                   BLOCK_KEY5"
            count_protects = 6
        self.espefuse_py(cmd)
        output = self.espefuse_py(cmd)
        assert count_protects == output.count("is already read protected")

    @pytest.mark.skipif(
        arg_chip == "esp32p4", reason="BLOCK_SYS_DATA2 is used by ADC calib"
    )
    def test_read_protect_efuse2(self):
        self.espefuse_py("write_protect_efuse RD_DIS")
        if arg_chip == "esp32":
            efuse_name = "CODING_SCHEME"
        elif arg_chip == "esp32c2":
            efuse_name = "BLOCK_KEY0_HI_128"
        else:
            efuse_name = "BLOCK_SYS_DATA2"
        self.espefuse_py(
            f"read_protect_efuse {efuse_name}",
            check_msg="A fatal error occurred: This efuse cannot be read-disabled "
            "due the to RD_DIS field is already write-disabled",
            ret_code=2,
        )

    @pytest.mark.skipif(arg_chip != "esp32", reason="when the purpose of BLOCK2 is set")
    def test_read_protect_efuse3(self):
        self.espefuse_py("burn_efuse ABS_DONE_1 1")
        self.espefuse_py(f"burn_key BLOCK2 {IMAGES_DIR}/256bit")
        self.espefuse_py(
            "read_protect_efuse BLOCK2",
            check_msg="Secure Boot V2 is on (ABS_DONE_1 = True), "
            "BLOCK2 must be readable, stop this operation!",
            ret_code=2,
        )

    def test_read_protect_efuse4(self):
        if arg_chip == "esp32":
            self.espefuse_py(f"burn_key BLOCK2 {IMAGES_DIR}/256bit")
            msg = "must be readable, please stop this operation!"
            self.espefuse_py("read_protect_efuse BLOCK2", check_msg=msg)
        elif arg_chip == "esp32c2":
            self.espefuse_py(
                f"burn_key BLOCK_KEY0 {IMAGES_DIR}/128bit_key SECURE_BOOT_DIGEST"
            )
            self.espefuse_py(
                "read_protect_efuse BLOCK_KEY0",
                check_msg="A fatal error occurred: "
                "BLOCK_KEY0 must be readable, stop this operation!",
                ret_code=2,
            )
        else:
            key1_purpose = (
                "USER" if arg_chip in ["esp32p4", "esp32c61", "esp32c5"] else "RESERVED"
            )
            self.espefuse_py(
                f"burn_key BLOCK_KEY0 {IMAGES_DIR}/256bit USER \
                BLOCK_KEY1 {IMAGES_DIR}/256bit {key1_purpose} \
                BLOCK_KEY2 {IMAGES_DIR}/256bit SECURE_BOOT_DIGEST0 \
                BLOCK_KEY3 {IMAGES_DIR}/256bit SECURE_BOOT_DIGEST1 \
                BLOCK_KEY4 {IMAGES_DIR}/256bit SECURE_BOOT_DIGEST2 \
                BLOCK_KEY5 {IMAGES_DIR}/256bit HMAC_UP"
            )
            self.espefuse_py(
                "read_protect_efuse BLOCK_KEY0",
                check_msg="A fatal error occurred: "
                "BLOCK_KEY0 must be readable, stop this operation!",
                ret_code=2,
            )
            self.espefuse_py(
                "read_protect_efuse BLOCK_KEY1",
                check_msg="A fatal error occurred: "
                "BLOCK_KEY1 must be readable, stop this operation!",
                ret_code=2,
            )
            self.espefuse_py(
                "read_protect_efuse BLOCK_KEY2",
                check_msg="A fatal error occurred: "
                "BLOCK_KEY2 must be readable, stop this operation!",
                ret_code=2,
            )
            self.espefuse_py(
                "read_protect_efuse BLOCK_KEY3",
                check_msg="A fatal error occurred: "
                "BLOCK_KEY3 must be readable, stop this operation!",
                ret_code=2,
            )
            self.espefuse_py(
                "read_protect_efuse BLOCK_KEY4",
                check_msg="A fatal error occurred: "
                "BLOCK_KEY4 must be readable, stop this operation!",
                ret_code=2,
            )
            self.espefuse_py("read_protect_efuse BLOCK_KEY5")

    @pytest.mark.skipif(
        arg_chip != "esp32",
        reason="system parameters efuse read-protection is supported only by esp32, "
        "other chips protect whole blocks",
    )
    def test_burn_and_read_protect_efuse(self):
        self.espefuse_py(
            "burn_efuse FLASH_CRYPT_CONFIG 15 RD_DIS 8",
            check_msg="Efuse FLASH_CRYPT_CONFIG is read-protected. "
            "Read back the burn value is not possible.",
        )


# TODO: [ESP32H21] IDF-11506
@pytest.mark.skipif(arg_chip == "esp32h21", reason="Not supported yet")
class TestWriteProtectionCommands(EfuseTestCase):
    def test_write_protect_efuse(self):
        self.espefuse_py("write_protect_efuse -h")
        if arg_chip == "esp32":
            efuse_lists = """WR_DIS RD_DIS CODING_SCHEME
                           XPD_SDIO_FORCE XPD_SDIO_REG XPD_SDIO_TIEH SPI_PAD_CONFIG_CLK
                           FLASH_CRYPT_CNT UART_DOWNLOAD_DIS FLASH_CRYPT_CONFIG
                           ADC_VREF BLOCK1 BLOCK2 BLOCK3"""
            efuse_lists2 = "WR_DIS RD_DIS"
        elif arg_chip == "esp32c2":
            efuse_lists = """RD_DIS DIS_DOWNLOAD_ICACHE
                           XTS_KEY_LENGTH_256 UART_PRINT_CONTROL"""
            efuse_lists2 = "RD_DIS DIS_DOWNLOAD_ICACHE"
        elif arg_chip == "esp32p4":
            efuse_lists = """RD_DIS KEY_PURPOSE_0 SECURE_BOOT_KEY_REVOKE0
                           SPI_BOOT_CRYPT_CNT"""
            efuse_lists2 = "RD_DIS KEY_PURPOSE_0 KEY_PURPOSE_2"
        else:
            efuse_lists = """RD_DIS DIS_ICACHE DIS_FORCE_DOWNLOAD
                           DIS_DOWNLOAD_MANUAL_ENCRYPT
                           USB_EXCHG_PINS WDT_DELAY_SEL SPI_BOOT_CRYPT_CNT
                           SECURE_BOOT_KEY_REVOKE0 SECURE_BOOT_KEY_REVOKE1
                           SECURE_BOOT_KEY_REVOKE2 KEY_PURPOSE_0 KEY_PURPOSE_1
                           KEY_PURPOSE_2 KEY_PURPOSE_3 KEY_PURPOSE_4 KEY_PURPOSE_5
                           SECURE_BOOT_EN SECURE_BOOT_AGGRESSIVE_REVOKE FLASH_TPUW
                           DIS_DOWNLOAD_MODE
                           ENABLE_SECURITY_DOWNLOAD UART_PRINT_CONTROL
                           MAC
                           BLOCK_USR_DATA BLOCK_KEY0 BLOCK_KEY1
                           BLOCK_KEY2 BLOCK_KEY3 BLOCK_KEY4 BLOCK_KEY5"""
            if arg_chip not in [
                "esp32h2",
                "esp32c6",
                "esp32c61",
                "esp32c5",
            ]:
                efuse_lists += """ DIS_DOWNLOAD_ICACHE
                            SPI_PAD_CONFIG_CLK SPI_PAD_CONFIG_Q
                            SPI_PAD_CONFIG_D SPI_PAD_CONFIG_CS SPI_PAD_CONFIG_HD
                            SPI_PAD_CONFIG_WP SPI_PAD_CONFIG_DQS SPI_PAD_CONFIG_D4
                            SPI_PAD_CONFIG_D5 SPI_PAD_CONFIG_D6 SPI_PAD_CONFIG_D7"""
            efuse_lists2 = "RD_DIS DIS_ICACHE"
        self.espefuse_py(f"write_protect_efuse {efuse_lists}")
        output = self.espefuse_py(f"write_protect_efuse {efuse_lists2}")
        assert output.count("is already write protected") == 2

    def test_write_protect_efuse2(self):
        if arg_chip == "esp32":
            self.espefuse_py("write_protect_efuse WR_DIS")
            self.espefuse_py(
                "write_protect_efuse CODING_SCHEME",
                check_msg="A fatal error occurred: This efuse cannot be write-disabled "
                "due to the WR_DIS field is already write-disabled",
                ret_code=2,
            )


@pytest.mark.skipif(arg_chip == "esp32p4", reason="No Custom MAC Address defined yet")
class TestBurnCustomMacCommands(EfuseTestCase):
    def test_burn_custom_mac(self):
        self.espefuse_py("burn_custom_mac -h")
        cmd = "burn_custom_mac AA:CD:EF:11:22:33"
        mac = "aa:cd:ef:11:22:33"
        if arg_chip == "esp32":
            self.espefuse_py(
                cmd, check_msg=f"Custom MAC Address version 1: {mac} (CRC 0x63 OK)"
            )
        else:
            self.espefuse_py(cmd, check_msg=f"Custom MAC Address: {mac} (OK)")

    def test_burn_custom_mac2(self):
        self.espefuse_py(
            "burn_custom_mac AA:CD:EF:11:22:33:44",
            check_msg="A fatal error occurred: MAC Address needs to be a 6-byte "
            "hexadecimal format separated by colons (:)!",
            ret_code=2,
        )

    def test_burn_custom_mac3(self):
        self.espefuse_py(
            "burn_custom_mac AB:CD:EF:11:22:33",
            check_msg="A fatal error occurred: Custom MAC must be a unicast MAC!",
            ret_code=2,
        )

    @pytest.mark.skipif(
        arg_chip != "esp32", reason="3/4 coding scheme is only in esp32"
    )
    def test_burn_custom_mac_with_34_coding_scheme(self):
        self._set_34_coding_scheme()
        self.espefuse_py("burn_custom_mac -h")
        self.espefuse_py(
            "burn_custom_mac AA:CD:EF:01:02:03",
            check_msg="Custom MAC Address version 1: aa:cd:ef:01:02:03 (CRC 0x56 OK)",
        )
        self.espefuse_py(
            "get_custom_mac",
            check_msg="Custom MAC Address version 1: aa:cd:ef:01:02:03 (CRC 0x56 OK)",
        )

        self.espefuse_py(
            "burn_custom_mac FE:22:33:44:55:66",
            check_msg="New value contains some bits that cannot be cleared "
            "(value will be 0x675745ffeffe)",
            ret_code=2,
        )


@pytest.mark.skipif(
    arg_chip
    not in [
        "esp32",
        "esp32s2",
        "esp32s3",
    ],
    reason=f"{arg_chip} does not support set_flash_voltage",
)
class TestSetFlashVoltageCommands(EfuseTestCase):
    def test_set_flash_voltage_1_8v(self):
        self.espefuse_py("set_flash_voltage -h")
        vdd = "VDD_SDIO" if arg_chip == "esp32" else "VDD_SPI"
        self.espefuse_py(
            "set_flash_voltage 1.8V",
            check_msg=f"Set internal flash voltage regulator ({vdd}) to 1.8V.",
        )
        if arg_chip == "esp32":
            error_msg = "A fatal error occurred: "
            "Can't set flash regulator to OFF as XPD_SDIO_REG efuse is already burned"
        else:
            error_msg = "A fatal error occurred: "
            "Can't set flash regulator to OFF as VDD_SPI_XPD efuse is already burned"
        self.espefuse_py(
            "set_flash_voltage 3.3V",
            check_msg=f"Enable internal flash voltage regulator ({vdd}) to 3.3V.",
        )
        self.espefuse_py("set_flash_voltage OFF", check_msg=error_msg, ret_code=2)

    def test_set_flash_voltage_3_3v(self):
        vdd = "VDD_SDIO" if arg_chip == "esp32" else "VDD_SPI"
        self.espefuse_py(
            "set_flash_voltage 3.3V",
            check_msg=f"Enable internal flash voltage regulator ({vdd}) to 3.3V.",
        )
        if arg_chip == "esp32":
            error_msg = "A fatal error occurred: "
            "Can't set regulator to 1.8V is XPD_SDIO_TIEH efuse is already burned"
        else:
            error_msg = "A fatal error occurred: "
            "Can't set regulator to 1.8V is VDD_SPI_TIEH efuse is already burned"
        self.espefuse_py("set_flash_voltage 1.8V", check_msg=error_msg, ret_code=2)

        if arg_chip == "esp32":
            error_msg = "A fatal error occurred: "
            "Can't set flash regulator to OFF as XPD_SDIO_REG efuse is already burned"
        else:
            error_msg = "A fatal error occurred: "
            "Can't set flash regulator to OFF as VDD_SPI_XPD efuse is already burned"
        self.espefuse_py("set_flash_voltage OFF", check_msg=error_msg, ret_code=2)

    def test_set_flash_voltage_off(self):
        vdd = "VDD_SDIO" if arg_chip == "esp32" else "VDD_SPI"
        self.espefuse_py(
            "set_flash_voltage OFF",
            check_msg=f"Disable internal flash voltage regulator ({vdd})",
        )
        self.espefuse_py(
            "set_flash_voltage 3.3V",
            check_msg=f"Enable internal flash voltage regulator ({vdd}) to 3.3V.",
        )

    def test_set_flash_voltage_off2(self):
        vdd = "VDD_SDIO" if arg_chip == "esp32" else "VDD_SPI"
        self.espefuse_py(
            "set_flash_voltage OFF",
            check_msg=f"Disable internal flash voltage regulator ({vdd})",
        )
        self.espefuse_py(
            "set_flash_voltage 1.8V",
            check_msg=f"Set internal flash voltage regulator ({vdd}) to 1.8V.",
        )


@pytest.mark.skipif(arg_chip != "esp32c3", reason="Not necessary for all chips")
class TestValueArgForBurnEfuseCommands(EfuseTestCase):
    def test_efuse_is_bool_given_none(self):
        self.espefuse_py("burn_efuse SECURE_BOOT_KEY_REVOKE0")

    def test_efuse_is_bool_given_0(self):
        self.espefuse_py(
            "burn_efuse SECURE_BOOT_KEY_REVOKE0 0",
            check_msg="A fatal error occurred: "
            "New value is not accepted for efuse 'SECURE_BOOT_KEY_REVOKE0' "
            "(will always burn 0->1), given value=0",
            ret_code=2,
        )

    def test_efuse_is_bool_given_2(self):
        self.espefuse_py(
            "burn_efuse SECURE_BOOT_KEY_REVOKE0 2",
            check_msg="A fatal error occurred: "
            "New value is not accepted for efuse 'SECURE_BOOT_KEY_REVOKE0' "
            "(will always burn 0->1), given value=2",
            ret_code=2,
        )

    def test_efuse_is_bytes_ok(self):
        self.espefuse_py(
            "burn_efuse OPTIONAL_UNIQUE_ID 0x12345678123456781234567812345678"
        )

    def test_efuse_is_bytes_given_short_val(self):
        self.espefuse_py(
            "burn_efuse OPTIONAL_UNIQUE_ID 0x1234567812345678",
            check_msg="A fatal error occurred: "
            "The length of efuse 'OPTIONAL_UNIQUE_ID' (128 bits) "
            "(given len of the new value= 64 bits)",
            ret_code=2,
        )

    def test_efuse_is_bytes_given_none(self):
        self.espefuse_py(
            "burn_efuse OPTIONAL_UNIQUE_ID",
            check_msg="A fatal error occurred: "
            "New value required for efuse 'OPTIONAL_UNIQUE_ID' (given None)",
            ret_code=2,
        )

    def test_efuse_is_int_ok(self):
        self.espefuse_py("burn_efuse SPI_PAD_CONFIG_D 7")

    def test_efuse_is_int_given_out_of_range_val(self):
        self.espefuse_py(
            "burn_efuse SPI_PAD_CONFIG_D 200",
            check_msg="A fatal error occurred: "
            "200 is too large an unsigned integer for a bitstring "
            "of length 6. The allowed range is [0, 63].",
            ret_code=2,
        )

    def test_efuse_is_int_given_none(self):
        self.espefuse_py(
            "burn_efuse SPI_PAD_CONFIG_D",
            check_msg="A fatal error occurred: "
            "New value required for efuse 'SPI_PAD_CONFIG_D' (given None)",
            ret_code=2,
        )

    def test_efuse_is_int_given_0(self):
        self.espefuse_py(
            "burn_efuse SPI_PAD_CONFIG_D 0",
            check_msg="A fatal error occurred: "
            "New value should not be 0 for 'SPI_PAD_CONFIG_D' "
            "(given value= 0)",
            ret_code=2,
        )

    def test_efuse_is_bitcount_given_out_of_range_val(self):
        self.espefuse_py(
            "burn_efuse SPI_BOOT_CRYPT_CNT 9",
            check_msg="A fatal error occurred: "
            "9 is too large an unsigned integer for a bitstring "
            "of length 3. The allowed range is [0, 7].",
            ret_code=2,
        )

    def test_efuse_is_bitcount_given_increase_over_max(self):
        self.espefuse_py("burn_efuse SPI_BOOT_CRYPT_CNT")
        self.espefuse_py("burn_efuse SPI_BOOT_CRYPT_CNT")
        self.espefuse_py("burn_efuse SPI_BOOT_CRYPT_CNT")
        self.espefuse_py(
            "burn_efuse SPI_BOOT_CRYPT_CNT",
            check_msg="A fatal error occurred: "
            "15 is too large an unsigned integer for a bitstring "
            "of length 3. The allowed range is [0, 7].",
            ret_code=2,
        )


class TestBurnEfuseCommands(EfuseTestCase):
    @pytest.mark.skipif(
        arg_chip != "esp32",
        reason="IO pins 30 & 31 cannot be set for SPI flash only on esp32",
    )
    def test_set_spi_flash_pin_efuses(self):
        self.espefuse_py(
            "burn_efuse SPI_PAD_CONFIG_HD 30",
            check_msg="A fatal error occurred: "
            "IO pins 30 & 31 cannot be set for SPI flash. 0-29, 32 & 33 only.",
            ret_code=2,
        )
        self.espefuse_py(
            "burn_efuse SPI_PAD_CONFIG_Q 0x23",
            check_msg="A fatal error occurred: "
            "IO pin 35 cannot be set for SPI flash. 0-29, 32 & 33 only.",
            ret_code=2,
        )
        output = self.espefuse_py("burn_efuse SPI_PAD_CONFIG_CS0 33")
        assert "(Override SD_CMD pad (GPIO11/SPICS0)) 0b00000 -> 0b11111" in output
        assert "BURN BLOCK0  - OK (all write block bits are set)" in output

    @pytest.mark.skipif(
        arg_chip == "esp32p4", reason="No Custom MAC Address defined yet"
    )
    def test_burn_mac_custom_efuse(self):
        crc_msg = "(OK)"
        self.espefuse_py("burn_efuse -h")
        if arg_chip == "esp32":
            self.espefuse_py(
                "burn_efuse MAC AA:CD:EF:01:02:03",
                check_msg="Writing Factory MAC address is not supported",
                ret_code=2,
            )
            self.espefuse_py("burn_efuse MAC_VERSION 1")
            crc_msg = "(CRC 0x56 OK)"
        if arg_chip == "esp32c2":
            self.espefuse_py("burn_efuse CUSTOM_MAC_USED 1")
        self.espefuse_py("burn_efuse -h")
        self.espefuse_py(
            "burn_efuse CUSTOM_MAC AB:CD:EF:01:02:03",
            check_msg="A fatal error occurred: Custom MAC must be a unicast MAC!",
            ret_code=2,
        )
        self.espefuse_py("burn_efuse CUSTOM_MAC AA:CD:EF:01:02:03")
        self.espefuse_py("get_custom_mac", check_msg=f"aa:cd:ef:01:02:03 {crc_msg}")

    # TODO: [ESP32H21] IDF-11506
    @pytest.mark.skipif(
        arg_chip
        in [
            "esp32h21",
        ],
        reason="No such eFuses, will be defined later",
    )
    def test_burn_efuse(self):
        self.espefuse_py("burn_efuse -h")
        if arg_chip == "esp32":
            self.espefuse_py(
                "burn_efuse \
                CHIP_VER_REV2 1 \
                DISABLE_DL_ENCRYPT 1 \
                CONSOLE_DEBUG_DISABLE 1"
            )
            blk1 = "BLOCK1"
            blk2 = "BLOCK2"
        elif arg_chip == "esp32c2":
            self.espefuse_py(
                "burn_efuse \
                XTS_KEY_LENGTH_256 1 \
                UART_PRINT_CONTROL 1 \
                FORCE_SEND_RESUME 1"
            )
            blk1 = "BLOCK_KEY0"
            blk2 = None
        else:
            self.espefuse_py(
                "burn_efuse \
                SECURE_BOOT_EN 1 \
                UART_PRINT_CONTROL 1"
            )
            if arg_chip not in ["esp32c5", "esp32c61"]:
                # chips having the OPTIONAL_UNIQUE_ID field
                self.espefuse_py(
                    "burn_efuse \
                    OPTIONAL_UNIQUE_ID 0x2328ad5ac9145f698f843a26d6eae168",
                    check_msg="-> 0x2328ad5ac9145f698f843a26d6eae168",
                )
                output = self.espefuse_py("summary -d")
                assert (
                    "read_regs: d6eae168 8f843a26 c9145f69 2328ad5a "
                    "00000000 00000000 00000000 00000000"
                ) in output
                assert "= 68 e1 ea d6 26 3a 84 8f 69 5f 14 c9 5a ad 28 23 R/W" in output
                self.espefuse_py(
                    "burn_bit BLOCK_SYS_DATA 1",
                    check_msg="Burn into BLOCK_SYS_DATA is forbidden "
                    "(RS coding scheme does not allow this).",
                    ret_code=2,
                )
            blk1 = "BLOCK_KEY1"
            blk2 = "BLOCK_KEY2"
        output = self.espefuse_py(
            f"burn_efuse {blk1}"
            + " 0x00010203040506070809111111111111111111111111111111110000112233FF"
        )
        assert (
            "-> 0x00010203040506070809111111111111111111111111111111110000112233ff"
            in output
        )
        output = self.espefuse_py("summary -d")
        assert (
            "read_regs: 112233ff 11110000 11111111 11111111 "
            "11111111 08091111 04050607 00010203"
        ) in output
        assert (
            "= ff 33 22 11 00 00 11 11 11 11 11 11 11 11 11 11 "
            "11 11 11 11 11 11 09 08 07 06 05 04 03 02 01 00 R/W"
        ) in output

        if blk2 is not None:
            output = self.espefuse_py(
                f"burn_efuse {blk2}"
                + " 00010203040506070809111111111111111111111111111111110000112233FF"
            )
            assert (
                "-> 0xff33221100001111111111111111111111111111111109080706050403020100"
                in output
            )
            output = self.espefuse_py("summary -d")
            assert (
                "read_regs: 03020100 07060504 11110908 11111111 "
                "11111111 11111111 00001111 ff332211"
            ) in output
            assert (
                "= 00 01 02 03 04 05 06 07 08 09 11 11 11 11 11 11 "
                "11 11 11 11 11 11 11 11 11 11 00 00 11 22 33 ff R/W"
            ) in output

    @pytest.mark.skipif(
        arg_chip != "esp32", reason="3/4 coding scheme is only in esp32"
    )
    def test_burn_efuse_with_34_coding_scheme(self):
        self._set_34_coding_scheme()
        self.espefuse_py("burn_efuse BLK3_PART_RESERVE 1")
        self.espefuse_py("burn_efuse ADC1_TP_LOW 50")
        self.espefuse_py(
            "burn_efuse ADC1_TP_HIGH 55",
            check_msg="Burn into BLOCK3 is forbidden "
            "(3/4 coding scheme does not allow this)",
            ret_code=2,
        )

    @pytest.mark.skipif(
        arg_chip != "esp32", reason="3/4 coding scheme is only in esp32"
    )
    def test_burn_efuse_with_34_coding_scheme2(self):
        self._set_34_coding_scheme()
        self.espefuse_py("burn_efuse BLK3_PART_RESERVE 1")
        self.espefuse_py(
            "burn_efuse \
            ADC1_TP_LOW 50 \
            ADC1_TP_HIGH 55 \
            ADC2_TP_LOW 40 \
            ADC2_TP_HIGH 45"
        )

    @pytest.mark.skipif(
        arg_chip != "esp32s3",
        reason="Currently S3 only has this efuse incompatibility check",
    )
    def test_burn_efuse_incompatibility_check(self):
        self.espefuse_py(
            "burn_efuse DIS_USB_JTAG 1 DIS_USB_SERIAL_JTAG 1",
            check_msg="Incompatible eFuse settings detected, abort",
            ret_code=2,
        )
        self.espefuse_py("burn_efuse DIS_USB_JTAG 1")
        self.espefuse_py(
            "burn_efuse DIS_USB_SERIAL_JTAG 1",
            check_msg="Incompatible eFuse settings detected, abort",
            ret_code=2,
        )
        self.espefuse_py("burn_efuse DIS_USB_SERIAL_JTAG 1 --force")


class TestBurnKeyCommands(EfuseTestCase):
    @pytest.mark.skipif(arg_chip != "esp32", reason="ESP32-only")
    def test_burn_key_3_key_blocks(self):
        self.espefuse_py("burn_key -h")
        self.espefuse_py(
            f"burn_key BLOCK1 {IMAGES_DIR}/192bit",
            check_msg="A fatal error occurred: Incorrect key file size 24. "
            "Key file must be 32 bytes (256 bits) of raw binary key data.",
            ret_code=2,
        )
        self.espefuse_py(
            f"burn_key \
            BLOCK1 {IMAGES_DIR}/256bit \
            BLOCK2 {IMAGES_DIR}/256bit_1 \
            BLOCK3 {IMAGES_DIR}/256bit_2 --no-protect-key"
        )
        output = self.espefuse_py("summary -d")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/256bit")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/256bit_1")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/256bit_2")

        self.espefuse_py(
            f"burn_key \
            BLOCK1 {IMAGES_DIR}/256bit \
            BLOCK2 {IMAGES_DIR}/256bit_1 \
            BLOCK3 {IMAGES_DIR}/256bit_2"
        )
        output = self.espefuse_py("summary -d")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/256bit")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/256bit_1")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/256bit_2")

    @pytest.mark.skipif(arg_chip != "esp32c2", reason="ESP32-C2-only")
    def test_burn_key_1_key_block(self):
        self.espefuse_py("burn_key -h")
        self.espefuse_py(
            f"burn_key BLOCK_KEY0 {IMAGES_DIR}/128bit XTS_AES_128_KEY",
            check_msg="A fatal error occurred: Incorrect key file size 16. "
            "Key file must be 32 bytes (256 bits) of raw binary key data.",
            ret_code=2,
        )
        self.espefuse_py(
            f"burn_key BLOCK_KEY0 {IMAGES_DIR}/256bit XTS_AES_128_KEY --no-read-protect"
        )
        output = self.espefuse_py("summary -d")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/256bit", reverse_order=True)

        self.espefuse_py(f"burn_key BLOCK_KEY0 {IMAGES_DIR}/256bit XTS_AES_128_KEY")
        output = self.espefuse_py("summary -d")
        assert (
            "[3 ] read_regs: 00000000 00000000 00000000 00000000 "
            "00000000 00000000 00000000 00000000"
        ) in output

        assert (
            "= ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? "
            "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? -/-"
        ) in output

    @pytest.mark.skipif(arg_chip != "esp32c2", reason="ESP32-C2-only")
    def test_burn_key_one_key_block_with_fe_and_sb_keys(self):
        self.espefuse_py("burn_key -h")
        self.espefuse_py(
            f"burn_key BLOCK_KEY0 {IMAGES_DIR}/256bit XTS_AES_128_KEY \
            BLOCK_KEY0 {IMAGES_DIR}/128bit_key SECURE_BOOT_DIGEST",
            check_msg="A fatal error occurred: These keypurposes are incompatible "
            "['XTS_AES_128_KEY', 'SECURE_BOOT_DIGEST']",
            ret_code=2,
        )
        self.espefuse_py(
            f"burn_key BLOCK_KEY0 {IMAGES_DIR}/128bit_key "
            f"XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS "
            f"BLOCK_KEY0 {IMAGES_DIR}/128bit_key SECURE_BOOT_DIGEST --no-read-protect"
        )
        output = self.espefuse_py("summary -d")
        assert (
            "[3 ] read_regs: 0c0d0e0f 08090a0b 04050607 00010203 "
            "03020100 07060504 0b0a0908 0f0e0d0c"
        ) in output

        self.espefuse_py(
            f"burn_key BLOCK_KEY0 {IMAGES_DIR}/128bit_key "
            "XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS "
            f"BLOCK_KEY0 {IMAGES_DIR}/128bit_key SECURE_BOOT_DIGEST"
        )
        output = self.espefuse_py("summary -d")
        assert (
            "[3 ] read_regs: 00000000 00000000 00000000 00000000 "
            "03020100 07060504 0b0a0908 0f0e0d0c"
        ) in output

        assert (
            "= ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? "
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f -/-"
        ) in output
        assert "= ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? -/-" in output
        assert "= 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f R/-" in output

    @pytest.mark.skipif(
        arg_chip
        not in [
            "esp32s2",
            "esp32s3",
            "esp32c3",
            "esp32c6",
            "esp32h2",
            "esp32p4",
            "esp32c5",
            "esp32c61",
        ],
        reason="Only chips with 6 keys",
    )
    def test_burn_key_with_6_keys(self):
        cmd = f"burn_key \
               BLOCK_KEY0 {IMAGES_DIR}/256bit   XTS_AES_256_KEY_1 \
               BLOCK_KEY1 {IMAGES_DIR}/256bit_1 XTS_AES_256_KEY_2 \
               BLOCK_KEY2 {IMAGES_DIR}/256bit_2 XTS_AES_128_KEY"
        if arg_chip in [
            "esp32c3",
            "esp32c6",
            "esp32h2",
            "esp32c5",
        ]:
            cmd = cmd.replace("XTS_AES_256_KEY_1", "XTS_AES_128_KEY")
            cmd = cmd.replace("XTS_AES_256_KEY_2", "XTS_AES_128_KEY")
        self.espefuse_py(cmd + " --no-read-protect --no-write-protect")
        output = self.espefuse_py("summary -d")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/256bit", reverse_order=True)
        self.check_data_block_in_log(
            output, f"{IMAGES_DIR}/256bit_1", reverse_order=True
        )
        self.check_data_block_in_log(
            output, f"{IMAGES_DIR}/256bit_2", reverse_order=True
        )

        self.espefuse_py(cmd)
        output = self.espefuse_py("summary -d")
        assert (
            "[4 ] read_regs: 00000000 00000000 00000000 00000000 "
            "00000000 00000000 00000000 00000000"
        ) in output
        assert (
            "[5 ] read_regs: 00000000 00000000 00000000 00000000 "
            "00000000 00000000 00000000 00000000"
        ) in output
        assert (
            "[6 ] read_regs: 00000000 00000000 00000000 00000000 "
            "00000000 00000000 00000000 00000000"
        ) in output

        self.espefuse_py(
            f"burn_key \
            BLOCK_KEY3 {IMAGES_DIR}/256bit   SECURE_BOOT_DIGEST0 \
            BLOCK_KEY4 {IMAGES_DIR}/256bit_1 SECURE_BOOT_DIGEST1 \
            BLOCK_KEY5 {IMAGES_DIR}/256bit_2 SECURE_BOOT_DIGEST2"
        )
        output = self.espefuse_py("summary -d")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/256bit")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/256bit_1")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/256bit_2")

    @pytest.mark.skipif(
        arg_chip != "esp32", reason="3/4 coding scheme is only in esp32"
    )
    def test_burn_key_with_34_coding_scheme(self):
        self._set_34_coding_scheme()
        self.espefuse_py(
            f"burn_key BLOCK1 {IMAGES_DIR}/256bit",
            check_msg="A fatal error occurred: Incorrect key file size 32. "
            "Key file must be 24 bytes (192 bits) of raw binary key data.",
            ret_code=2,
        )
        self.espefuse_py(
            f"burn_key \
            BLOCK1 {IMAGES_DIR}/192bit \
            BLOCK2 {IMAGES_DIR}/192bit_1 \
            BLOCK3 {IMAGES_DIR}/192bit_2 --no-protect-key"
        )
        output = self.espefuse_py("summary -d")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/192bit")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/192bit_1")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/192bit_2")

        self.espefuse_py(
            f"burn_key \
            BLOCK1 {IMAGES_DIR}/192bit \
            BLOCK2 {IMAGES_DIR}/192bit_1 \
            BLOCK3 {IMAGES_DIR}/192bit_2"
        )
        output = self.espefuse_py("summary -d")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/192bit")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/192bit_1")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/192bit_2")

    @pytest.mark.skipif(
        arg_chip not in ["esp32s2", "esp32s3", "esp32p4", "esp32c61"],
        reason="512 bit keys are only supported on ESP32-S2, S3, P4, C61",
    )
    def test_burn_key_512bit(self):
        self.espefuse_py(
            f"burn_key \
            BLOCK_KEY0 {IMAGES_DIR}/256bit_1_256bit_2_combined \
            XTS_AES_256_KEY --no-read-protect --no-write-protect"
        )
        output = self.espefuse_py("summary -d")
        self.check_data_block_in_log(
            output, f"{IMAGES_DIR}/256bit_1", reverse_order=True
        )
        self.check_data_block_in_log(
            output, f"{IMAGES_DIR}/256bit_2", reverse_order=True
        )

    @pytest.mark.skipif(
        arg_chip not in ["esp32s2", "esp32s3", "esp32p4", "esp32c61"],
        reason="512 bit keys are only supported on ESP32-S2, S3, P4, C61",
    )
    def test_burn_key_512bit_non_consecutive_blocks(self):
        # Burn efuses separately to test different kinds
        # of "key used" detection criteria
        self.espefuse_py(
            f"burn_key \
            BLOCK_KEY2 {IMAGES_DIR}/256bit XTS_AES_128_KEY"
        )
        self.espefuse_py(
            f"burn_key \
            BLOCK_KEY4 {IMAGES_DIR}/256bit SECURE_BOOT_DIGEST0"
        )
        self.espefuse_py(
            f"burn_key \
            BLOCK_KEY1 {IMAGES_DIR}/256bit_1_256bit_2_combined \
            XTS_AES_256_KEY --no-read-protect --no-write-protect"
        )
        self.espefuse_py(
            f"burn_key \
            BLOCK_KEY5 {IMAGES_DIR}/256bit USER --no-read-protect --no-write-protect"
        )

        # Second half of key should burn to first available key block (BLOCK_KEY5)
        output = self.espefuse_py("summary -d")
        self.check_data_block_in_log(
            output, f"{IMAGES_DIR}/256bit_1", reverse_order=True
        )
        self.check_data_block_in_log(
            output, f"{IMAGES_DIR}/256bit_2", reverse_order=True
        )

        assert (
            "[5 ] read_regs: bcbd11bf b8b9babb b4b5b6b7 "
            "b0b1b2b3 acadaeaf a8a9aaab a4a5a6a7 11a1a2a3"
        ) in output
        assert (
            "[7 ] read_regs: bcbd22bf b8b9babb b4b5b6b7 "
            "b0b1b2b3 acadaeaf a8a9aaab a4a5a6a7 22a1a2a3"
        ) in output

    @pytest.mark.skipif(
        arg_chip not in ["esp32s2", "esp32s3", "esp32p4", "esp32c61"],
        reason="512 bit keys are only supported on ESP32-S2, S3, P4, C61",
    )
    def test_burn_key_512bit_non_consecutive_blocks_loop_around(self):
        self.espefuse_py(
            f"burn_key \
            BLOCK_KEY2 {IMAGES_DIR}/256bit XTS_AES_128_KEY \
            BLOCK_KEY3 {IMAGES_DIR}/256bit USER \
            BLOCK_KEY4 {IMAGES_DIR}/256bit SECURE_BOOT_DIGEST0 \
            BLOCK_KEY5 {IMAGES_DIR}/256bit SECURE_BOOT_DIGEST1 \
            BLOCK_KEY1 {IMAGES_DIR}/256bit_1_256bit_2_combined \
            XTS_AES_256_KEY --no-read-protect --no-write-protect"
        )

        # Second half of key should burn to first available key block (BLOCK_KEY0)
        output = self.espefuse_py("summary -d")
        self.check_data_block_in_log(
            output, f"{IMAGES_DIR}/256bit_1", reverse_order=True
        )
        self.check_data_block_in_log(
            output, f"{IMAGES_DIR}/256bit_2", reverse_order=True
        )

        assert (
            "[5 ] read_regs: bcbd11bf b8b9babb b4b5b6b7 b0b1b2b3 "
            "acadaeaf a8a9aaab a4a5a6a7 11a1a2a3"
        ) in output
        assert (
            "[4 ] read_regs: bcbd22bf b8b9babb b4b5b6b7 b0b1b2b3 "
            "acadaeaf a8a9aaab a4a5a6a7 22a1a2a3"
        ) in output

    @pytest.mark.skipif(
        arg_chip not in ["esp32h2", "esp32c5", "esp32c61", "esp32p4"],
        reason="These chips support ECDSA_KEY",
    )
    def test_burn_key_ecdsa_key(self):
        self.espefuse_py(
            f"burn_key \
            BLOCK_KEY0 {S_IMAGES_DIR}/ecdsa192_secure_boot_signing_key_v2.pem \
            ECDSA_KEY \
            BLOCK_KEY1 {S_IMAGES_DIR}/ecdsa256_secure_boot_signing_key_v2.pem \
            ECDSA_KEY"
        )
        output = self.espefuse_py("summary -d")
        assert 2 == output.count(
            "= ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? "
            "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? -/-"
        )
        assert (
            "[4 ] read_regs: 00000000 00000000 00000000 00000000 "
            "00000000 00000000 00000000 00000000"
        ) in output
        assert (
            "[5 ] read_regs: 00000000 00000000 00000000 00000000 "
            "00000000 00000000 00000000 00000000"
        ) in output

    @pytest.mark.skipif(
        arg_chip not in ["esp32h2", "esp32c5", "esp32c61", "esp32p4"],
        reason="These chips support ECDSA_KEY",
    )
    def test_burn_key_ecdsa_key_check_byte_order(self):
        self.espefuse_py(
            f"burn_key \
            BLOCK_KEY0 {S_IMAGES_DIR}/ecdsa192_secure_boot_signing_key_v2.pem \
            ECDSA_KEY \
            BLOCK_KEY1 {S_IMAGES_DIR}/ecdsa256_secure_boot_signing_key_v2.pem \
            ECDSA_KEY \
            --no-read-protect"
        )
        output = self.espefuse_py("summary -d")
        assert (
            "= c8 c4 5d 62 9e 05 05 bd cb 04 a4 7c 06 f5 86 14 "
            "cb 23 81 23 95 b7 71 4f 00 00 00 00 00 00 00 00 R/-"
        ) in output
        assert (
            "= fc 6b ec 75 64 37 7d 3b 88 8d 34 05 ed 91 06 1b "
            "38 c2 50 84 7a 08 9d c3 66 6a 06 90 23 8b 54 b4 R/-"
        ) in output
        assert (
            "[4 ] read_regs: 625dc4c8 bd05059e 7ca404cb 1486f506 "
            "238123cb 4f71b795 00000000 00000000"
        ) in output
        assert (
            "[5 ] read_regs: 75ec6bfc 3b7d3764 05348d88 1b0691ed "
            "8450c238 c39d087a 90066a66 b4548b23"
        ) in output


class TestBurnBlockDataCommands(EfuseTestCase):
    def test_burn_block_data_check_args(self):
        self.espefuse_py("burn_block_data -h")
        blk0 = "BLOCK0"
        blk1 = "BLOCK1"
        self.espefuse_py(
            f"burn_block_data {blk0} {IMAGES_DIR}/224bit {blk1}",
            check_msg="A fatal error occurred: "
            "The number of block_name (2) and datafile (1) should be the same.",
            ret_code=2,
        )

    @pytest.mark.skipif(arg_chip != "esp32", reason="ESP32-only")
    def test_burn_block_data_with_3_key_blocks(self):
        self.espefuse_py(
            f"burn_block_data \
            BLOCK0 {IMAGES_DIR}/224bit \
            BLOCK3 {IMAGES_DIR}/256bit"
        )
        output = self.espefuse_py("summary -d")
        assert (
            "[3 ] read_regs: a3a2a1a0 a7a6a5a4 abaaa9a8 afaeadac "
            "b3b2b1b0 b7b6b5b4 bbbab9b8 bfbebdbc"
        ) in output
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/256bit")

        self.espefuse_py(
            f"burn_block_data \
            BLOCK2 {IMAGES_DIR}/256bit_1"
        )
        self.check_data_block_in_log(
            self.espefuse_py("summary -d"), f"{IMAGES_DIR}/256bit_1"
        )

        self.espefuse_py(
            f"burn_block_data \
            BLOCK1 {IMAGES_DIR}/256bit_2"
        )
        self.check_data_block_in_log(
            self.espefuse_py("summary -d"), f"{IMAGES_DIR}/256bit_2"
        )

    @pytest.mark.skipif(arg_chip != "esp32c2", reason="ESP32-C2-only")
    def test_burn_block_data_with_1_key_block(self):
        self.espefuse_py(
            f"burn_block_data \
            BLOCK0 {IMAGES_DIR}/64bit \
            BLOCK1 {IMAGES_DIR}/96bit \
            BLOCK2 {IMAGES_DIR}/256bit \
            BLOCK3 {IMAGES_DIR}/256bit"
        )
        output = self.espefuse_py("summary -d")
        assert "[0 ] read_regs: 00000001 0000000c" in output
        assert "[1 ] read_regs: 03020100 07060504 000a0908" in output
        assert (
            "[2 ] read_regs: a3a2a1a0 a7a6a5a4 abaaa9a8 afaeadac "
            "b3b2b1b0 b7b6b5b4 bbbab9b8 bfbebdbc"
        ) in output
        assert (
            "[3 ] read_regs: a3a2a1a0 a7a6a5a4 abaaa9a8 afaeadac "
            "b3b2b1b0 b7b6b5b4 bbbab9b8 bfbebdbc"
        ) in output

    @pytest.mark.skipif(
        arg_chip
        not in [
            "esp32s2",
            "esp32s3",
            "esp32c3",
            "esp32c6",
            "esp32h2",
            "esp32p4",
            "esp32c5",
            "esp32c61",
        ],
        reason="Only chip with 6 keys",
    )
    def test_burn_block_data_with_6_keys(self):
        self.espefuse_py(
            f"burn_block_data \
            BLOCK0 {IMAGES_DIR}/192bit \
            BLOCK3 {IMAGES_DIR}/256bit"
        )
        output = self.espefuse_py("summary -d")
        assert (
            "[0 ] read_regs: 00000000 07060500 00000908 00000000 13000000 00161514"
            in output
        )
        assert (
            "[3 ] read_regs: a3a2a1a0 a7a6a5a4 abaaa9a8 afaeadac "
            "b3b2b1b0 b7b6b5b4 bbbab9b8 bfbebdbc"
        ) in output
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/256bit")

        if arg_chip != "esp32p4":
            # BLOCK10 is free. In P4 it is used for ADC calib data.
            self.espefuse_py(
                f"burn_block_data \
                BLOCK10 {IMAGES_DIR}/256bit_3"
            )
            self.check_data_block_in_log(
                self.espefuse_py("summary -d"), f"{IMAGES_DIR}/256bit_3"
            )

        self.espefuse_py(
            f"burn_block_data \
            BLOCK1 {IMAGES_DIR}/192bit \
            BLOCK5 {IMAGES_DIR}/256bit_1 \
            BLOCK6 {IMAGES_DIR}/256bit_2"
        )
        output = self.espefuse_py("summary -d")
        assert (
            "[1 ] read_regs: 00000000 07060500 00000908 00000000 13000000 00161514"
            in output
        )
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/256bit")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/256bit_1")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/256bit_2")

    def test_burn_block_data_check_errors(self):
        self.espefuse_py(
            f"burn_block_data \
            BLOCK2 {IMAGES_DIR}/192bit \
            BLOCK2 {IMAGES_DIR}/192bit_1",
            check_msg="A fatal error occurred: Found repeated",
            ret_code=2,
        )
        self.espefuse_py(
            f"burn_block_data \
            BLOCK2 {IMAGES_DIR}/192bit \
            BLOCK3 {IMAGES_DIR}/192bit_1 \
            --offset 4",
            check_msg="A fatal error occurred: "
            "The 'offset' option is not applicable when a few blocks are passed.",
            ret_code=2,
        )
        self.espefuse_py(
            f"burn_block_data BLOCK0 {IMAGES_DIR}/192bit --offset 33",
            check_msg="A fatal error occurred: Invalid offset: the block0 only holds",
            ret_code=2,
        )
        self.espefuse_py(
            f"burn_block_data BLOCK0 {IMAGES_DIR}/256bit --offset 4",
            check_msg="A fatal error occurred: Data does not fit:",
            ret_code=2,
        )

    @pytest.mark.skipif(arg_chip != "esp32", reason="ESP32-only")
    def test_burn_block_data_with_offset_for_3_key_blocks(self):
        offset = 1
        self.espefuse_py(
            f"burn_block_data --offset {offset} BLOCK0 {IMAGES_DIR}/192bit"
        )

        offset = 4
        self.espefuse_py(
            f"burn_block_data --offset {offset} BLOCK1 {IMAGES_DIR}/192bit_1"
        )
        self.check_data_block_in_log(
            self.espefuse_py("summary -d"), f"{IMAGES_DIR}/192bit_1", offset=offset
        )

        offset = 6
        self.espefuse_py(
            f"burn_block_data --offset {offset} BLOCK2 {IMAGES_DIR}/192bit_2"
        )
        self.check_data_block_in_log(
            self.espefuse_py("summary -d"), f"{IMAGES_DIR}/192bit_2", offset=offset
        )

        offset = 8
        self.espefuse_py(
            f"burn_block_data --offset {offset} BLOCK3 {IMAGES_DIR}/192bit_2"
        )
        self.check_data_block_in_log(
            self.espefuse_py("summary -d"), f"{IMAGES_DIR}/192bit_2", offset=offset
        )

    @pytest.mark.skipif(arg_chip != "esp32c2", reason="ESP32-C2-only")
    def test_burn_block_data_with_offset_1_key_block(self):
        offset = 4
        self.espefuse_py(f"burn_block_data --offset {offset} BLOCK1 {IMAGES_DIR}/92bit")
        output = self.espefuse_py("summary -d")
        assert "[1 ] read_regs: 00000000 03020100 00060504" in output

        offset = 6
        self.espefuse_py(
            f"burn_block_data --offset {offset} BLOCK2 {IMAGES_DIR}/192bit_1"
        )
        output = self.espefuse_py("summary -d")
        assert (
            "[2 ] read_regs: 00000000 00110000 05000000 09080706 "
            "0d0c0b0a 11100f0e 15141312 00002116"
        ) in output

        offset = 8
        self.espefuse_py(
            f"burn_block_data --offset {offset} BLOCK3 {IMAGES_DIR}/192bit_2"
        )
        self.check_data_block_in_log(
            self.espefuse_py("summary -d"), f"{IMAGES_DIR}/192bit_2", offset=offset
        )

    @pytest.mark.skipif(
        arg_chip
        not in [
            "esp32s2",
            "esp32s3",
            "esp32c3",
            "esp32c6",
            "esp32h2",
            "esp32p4",
            "esp32c5",
            "esp32c61",
        ],
        reason="Only chips with 6 keys",
    )
    def test_burn_block_data_with_offset_6_keys(self):
        offset = 4
        self.espefuse_py(
            f"burn_block_data --offset {offset} BLOCK_KEY0 {IMAGES_DIR}/192bit_1"
        )
        self.check_data_block_in_log(
            self.espefuse_py("summary -d"), f"{IMAGES_DIR}/192bit_1", offset=offset
        )

        offset = 6
        self.espefuse_py(
            f"burn_block_data --offset {offset} BLOCK_KEY1 {IMAGES_DIR}/192bit_2"
        )
        self.check_data_block_in_log(
            self.espefuse_py("summary -d"), f"{IMAGES_DIR}/192bit_2", offset=offset
        )

        offset = 8
        self.espefuse_py(
            f"burn_block_data --offset {offset} BLOCK_KEY2 {IMAGES_DIR}/192bit_2"
        )
        self.check_data_block_in_log(
            self.espefuse_py("summary -d"), f"{IMAGES_DIR}/192bit_2", offset=offset
        )

    @pytest.mark.skipif(
        arg_chip != "esp32", reason="3/4 coding scheme is only in esp32"
    )
    def test_burn_block_data_with_34_coding_scheme(self):
        self._set_34_coding_scheme()
        self.espefuse_py(
            f"burn_block_data BLOCK1 {IMAGES_DIR}/256bit",
            check_msg="A fatal error occurred: Data does not fit: "
            "the block1 size is 24 bytes, data file is 32 bytes, offset 0",
            ret_code=2,
        )

        self.espefuse_py(
            f"burn_block_data \
            BLOCK1 {IMAGES_DIR}/192bit \
            BLOCK2 {IMAGES_DIR}/192bit_1 \
            BLOCK3 {IMAGES_DIR}/192bit_2"
        )
        output = self.espefuse_py("summary -d")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/192bit")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/192bit_1")
        self.check_data_block_in_log(output, f"{IMAGES_DIR}/192bit_2")

    @pytest.mark.skipif(
        arg_chip != "esp32", reason="3/4 coding scheme is only in esp32"
    )
    def test_burn_block_data_with_34_coding_scheme_and_offset(self):
        self._set_34_coding_scheme()

        offset = 4
        self.espefuse_py(
            f"burn_block_data --offset {offset} BLOCK1 {IMAGES_DIR}/128bit"
        )
        self.check_data_block_in_log(
            self.espefuse_py("summary -d"), f"{IMAGES_DIR}/128bit", offset=offset
        )

        offset = 6
        self.espefuse_py(
            f"burn_block_data --offset {offset} BLOCK2 {IMAGES_DIR}/128bit"
        )
        self.check_data_block_in_log(
            self.espefuse_py("summary -d"), f"{IMAGES_DIR}/128bit", offset=offset
        )

        offset = 8
        self.espefuse_py(
            f"burn_block_data --offset {offset} BLOCK3 {IMAGES_DIR}/128bit"
        )
        self.check_data_block_in_log(
            self.espefuse_py("summary -d"), f"{IMAGES_DIR}/128bit", offset=offset
        )


@pytest.mark.skipif(arg_chip != "esp32", reason="ESP32-only, supports 2 key blocks")
class TestBurnKeyDigestCommandsEsp32(EfuseTestCase):
    def test_burn_key_digest(self):
        self.espefuse_py("burn_key_digest -h")
        esp = self.get_esptool()
        if esp.get_chip_revision() >= 300:
            self.espefuse_py(
                f"burn_key_digest {S_IMAGES_DIR}/rsa_secure_boot_signing_key.pem"
            )
            output = self.espefuse_py("summary -d")
            assert (
                " = cb 27 91 a3 71 b0 c0 32 2b f7 37 04 78 ba 09 62 "
                "22 4c ab 1c f2 28 78 79 e4 29 67 3e 7d a8 44 63 R/-"
            ) in output
        else:
            self.espefuse_py(
                f"burn_key_digest {S_IMAGES_DIR}/rsa_secure_boot_signing_key.pem",
                check_msg="Incorrect chip revision for Secure boot v2.",
                ret_code=2,
            )

    def test_burn_key_from_digest(self):
        # python espsecure.py digest_rsa_public_key
        # --keyfile test/{S_IMAGES_DIR}/rsa_secure_boot_signing_key.pem
        # -o {S_IMAGES_DIR}/rsa_public_key_digest.bin
        self.espefuse_py(
            f"burn_key \
            BLOCK2 {S_IMAGES_DIR}/rsa_public_key_digest.bin --no-protect-key"
        )
        output = self.espefuse_py("summary -d")
        assert 1 == output.count(
            " = cb 27 91 a3 71 b0 c0 32 2b f7 37 04 78 ba 09 62 "
            "22 4c ab 1c f2 28 78 79 e4 29 67 3e 7d a8 44 63 R/W"
        )

    def test_burn_key_digest_with_34_coding_scheme(self):
        self._set_34_coding_scheme()
        self.espefuse_py(
            f"burn_key_digest {S_IMAGES_DIR}/rsa_secure_boot_signing_key.pem",
            check_msg="burn_key_digest only works with 'None' coding scheme",
            ret_code=2,
        )


@pytest.mark.skipif(arg_chip != "esp32c2", reason="ESP32-C2-only, supports 1 key block")
class TestBurnKeyDigestCommandsEsp32C2(EfuseTestCase):
    def test_burn_key_digest1(self):
        # python espsecure.py generate_signing_key --version 2
        # secure_images/ecdsa192_secure_boot_signing_key_v2.pem --scheme ecdsa192
        self.espefuse_py("burn_key_digest -h")
        self.espefuse_py(
            f"burn_key_digest {S_IMAGES_DIR}/ecdsa192_secure_boot_signing_key_v2.pem"
        )
        output = self.espefuse_py("summary -d")
        assert " = 1e 3d 15 16 96 ca 7f 22 a6 e8 8b d5 27 a0 3b 3b R/-" in output
        assert (
            " = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "1e 3d 15 16 96 ca 7f 22 a6 e8 8b d5 27 a0 3b 3b R/-"
        ) in output

    def test_burn_key_digest2(self):
        # python espsecure.py generate_signing_key --version 2
        # secure_images/ecdsa256_secure_boot_signing_key_v2.pem   --scheme ecdsa256
        self.espefuse_py("burn_key_digest -h")
        self.espefuse_py(
            f"burn_key_digest {S_IMAGES_DIR}/ecdsa256_secure_boot_signing_key_v2.pem"
        )
        output = self.espefuse_py("summary -d")
        assert " = bf 0f 6a f6 8b d3 6d 8b 53 b3 da a9 33 f6 0a 04 R/-" in output
        assert (
            " = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "bf 0f 6a f6 8b d3 6d 8b 53 b3 da a9 33 f6 0a 04 R/-"
        ) in output

    def test_burn_key_from_digest1(self):
        # python espsecure.py digest_sbv2_public_key --keyfile
        # secure_images/ecdsa192_secure_boot_signing_key_v2.pem
        # -o secure_images/ecdsa192_public_key_digest_v2.bin
        self.espefuse_py(
            "burn_key BLOCK_KEY0 "
            f"{S_IMAGES_DIR}/ecdsa192_public_key_digest_v2.bin SECURE_BOOT_DIGEST"
        )
        output = self.espefuse_py("summary -d")
        assert (
            " = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "1e 3d 15 16 96 ca 7f 22 a6 e8 8b d5 27 a0 3b 3b R/-"
        ) in output

    def test_burn_key_from_digest2(self):
        # python espsecure.py digest_sbv2_public_key --keyfile
        # secure_images/ecdsa256_secure_boot_signing_key_v2.pem
        # -o secure_images/ecdsa256_public_key_digest_v2.bin
        self.espefuse_py(
            "burn_key BLOCK_KEY0 "
            f"{S_IMAGES_DIR}/ecdsa256_public_key_digest_v2.bin SECURE_BOOT_DIGEST"
        )
        output = self.espefuse_py("summary -d")
        assert (
            " = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "bf 0f 6a f6 8b d3 6d 8b 53 b3 da a9 33 f6 0a 04 R/-"
        ) in output


@pytest.mark.skipif(
    arg_chip
    not in [
        "esp32s2",
        "esp32s3",
        "esp32c3",
        "esp32c6",
        "esp32h2",
        "esp32p4",
        "esp32c5",
        "esp32c61",
    ],
    reason="Supports 6 key blocks",
)
class TestBurnKeyDigestCommands(EfuseTestCase):
    def test_burn_key_digest(self):
        self.espefuse_py("burn_key_digest -h")
        self.espefuse_py(
            f"burn_key_digest \
            BLOCK_KEY0 \
            {S_IMAGES_DIR}/rsa_secure_boot_signing_key.pem SECURE_BOOT_DIGEST0 \
            BLOCK_KEY1 \
            {S_IMAGES_DIR}/rsa_secure_boot_signing_key2.pem SECURE_BOOT_DIGEST1 \
            BLOCK_KEY2 ",
            check_msg="A fatal error occurred: The number of blocks (3), "
            "datafile (2) and keypurpose (2) should be the same.",
            ret_code=2,
        )
        self.espefuse_py(
            f"burn_key_digest \
            BLOCK_KEY0 \
            {S_IMAGES_DIR}/rsa_secure_boot_signing_key.pem SECURE_BOOT_DIGEST0 \
            BLOCK_KEY1 \
            {S_IMAGES_DIR}/rsa_secure_boot_signing_key2.pem SECURE_BOOT_DIGEST1 \
            BLOCK_KEY2 \
            {S_IMAGES_DIR}/rsa_secure_boot_signing_key2.pem SECURE_BOOT_DIGEST2"
        )
        output = self.espefuse_py("summary -d")
        assert 1 == output.count(
            " = cb 27 91 a3 71 b0 c0 32 2b f7 37 04 78 ba 09 62 "
            "22 4c ab 1c f2 28 78 79 e4 29 67 3e 7d a8 44 63 R/-"
        )
        assert 2 == output.count(
            " = 90 1a 74 09 23 8d 52 d4 cb f9 6f 56 3f b3 f4 29 "
            "6d ab d6 6a 33 f5 3b 15 ee cd 8c b3 e7 ec 45 d3 R/-"
        )

    def test_burn_key_from_digest(self):
        #  python espsecure.py digest_rsa_public_key
        # --keyfile test/secure_images/rsa_secure_boot_signing_key.pem
        # -o secure_images/rsa_public_key_digest.bin
        self.espefuse_py(
            f"burn_key \
            BLOCK_KEY0 {S_IMAGES_DIR}/rsa_public_key_digest.bin SECURE_BOOT_DIGEST0"
        )
        output = self.espefuse_py("summary -d")
        assert 1 == output.count(
            " = cb 27 91 a3 71 b0 c0 32 2b f7 37 04 78 ba 09 62 "
            "22 4c ab 1c f2 28 78 79 e4 29 67 3e 7d a8 44 63 R/-"
        )

        self.espefuse_py(
            f"burn_key_digest \
            BLOCK_KEY1 \
            {S_IMAGES_DIR}/rsa_secure_boot_signing_key.pem SECURE_BOOT_DIGEST1"
        )
        output = self.espefuse_py("summary -d")
        assert 2 == output.count(
            " = cb 27 91 a3 71 b0 c0 32 2b f7 37 04 78 ba 09 62 "
            "22 4c ab 1c f2 28 78 79 e4 29 67 3e 7d a8 44 63 R/-"
        )


class TestBurnBitCommands(EfuseTestCase):
    @pytest.mark.skipif(arg_chip != "esp32", reason="ESP32-only")
    def test_burn_bit_for_chips_with_3_key_blocks(self):
        self.espefuse_py("burn_bit -h")
        self.espefuse_py("burn_bit BLOCK3 0 1 2 4 8 16 32 64 96 128 160 192 224 255")
        self.espefuse_py(
            "summary",
            check_msg="17 01 01 00 01 00 00 00 01 00 00 00 01 00 00 "
            "00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 80",
        )

        self.espefuse_py(
            "burn_bit BLOCK3 3 5 6 7 9 10 11 12 13 14 15 31 63 95 127 159 191 223 254"
        )
        self.espefuse_py(
            "summary",
            check_msg="ff ff 01 80 01 00 00 80 01 00 00 80 01 "
            "00 00 80 01 00 00 80 01 00 00 80 01 00 00 80 01 00 00 c0",
        )

    @pytest.mark.skipif(arg_chip != "esp32c2", reason="ESP32-C2-only")
    def test_burn_bit_for_chips_with_1_key_block(self):
        self.espefuse_py("burn_bit -h")
        self.espefuse_py("burn_bit BLOCK3 0 1 2 4 8 16 32 64 96 128 160 192 224 255")
        self.espefuse_py(
            "summary",
            check_msg="17 01 01 00 01 00 00 00 01 00 00 00 01 00 "
            "00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 80",
        )
        self.espefuse_py(
            "burn_bit BLOCK3 100",
            check_msg="Burn into BLOCK_KEY0 is forbidden "
            "(RS coding scheme does not allow this)",
            ret_code=2,
        )

        self.espefuse_py("burn_bit BLOCK0 0 1 2")
        self.espefuse_py("summary", check_msg="[0 ] read_regs: 00000007 00000000")

    @pytest.mark.skipif(
        arg_chip
        not in [
            "esp32s2",
            "esp32s3",
            "esp32c3",
            "esp32c6",
            "esp32h2",
            "esp32p4",
            "esp32c5",
            "esp32c61",
        ],
        reason="Only chip with 6 keys",
    )
    def test_burn_bit_for_chips_with_6_key_blocks(self):
        self.espefuse_py("burn_bit -h")
        self.espefuse_py("burn_bit BLOCK3 0 1 2 4 8 16 32 64 96 128 160 192 224 255")
        self.espefuse_py(
            "summary",
            check_msg="17 01 01 00 01 00 00 00 01 00 00 00 01 00 "
            "00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 80",
        )
        self.espefuse_py(
            "burn_bit BLOCK3 100",
            check_msg="Burn into BLOCK_USR_DATA is forbidden "
            "(RS coding scheme does not allow this)",
            ret_code=2,
        )

        self.espefuse_py("burn_bit BLOCK0 13")
        self.espefuse_py(
            "summary",
            check_msg="[0 ] read_regs: 00002000 00000000 00000000 "
            "00000000 00000000 00000000",
        )

        self.espefuse_py("burn_bit BLOCK0 24")
        self.espefuse_py(
            "summary",
            check_msg="[0 ] read_regs: 01002000 00000000 00000000 "
            "00000000 00000000 00000000",
        )

    @pytest.mark.skipif(
        arg_chip != "esp32", reason="3/4 coding scheme is only in esp32"
    )
    def test_burn_bit_with_34_coding_scheme(self):
        self._set_34_coding_scheme()
        self.espefuse_py("burn_bit BLOCK3 0 1 2 4 8 16 32 64 96 128 160 191")
        self.espefuse_py(
            "summary",
            check_msg="17 01 01 00 01 00 00 00 01 00 00 00 01 00 "
            "00 00 01 00 00 00 01 00 00 80",
        )
        self.espefuse_py(
            "burn_bit BLOCK3 17",
            check_msg="Burn into BLOCK3 is forbidden "
            "(3/4 coding scheme does not allow this).",
            ret_code=2,
        )

    @pytest.mark.skipif(arg_chip != "esp32", reason="ESP32-only")
    def test_burn_bit_with_none_recovery_coding_scheme(self):
        self._set_none_recovery_coding_scheme()
        self.espefuse_py("burn_bit BLOCK3 0 1 2 4 8 16 32 64 96 128 160 192 224 255")
        self.espefuse_py(
            "summary",
            check_msg="17 01 01 00 01 00 00 00 01 00 00 00 01 00 00 "
            "00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 80",
        )


@pytest.mark.skipif(
    arg_chip != "esp32", reason="Tests are only for esp32. (TODO: add for all chips)"
)
class TestByteOrderBurnKeyCommand(EfuseTestCase):
    def test_1_secure_boot_v1(self):
        if arg_chip == "esp32":
            self.espefuse_py(
                f"burn_key \
                flash_encryption {IMAGES_DIR}/256bit \
                secure_boot_v1 {IMAGES_DIR}/256bit_1 --no-protect-key"
            )
            output = self.espefuse_py("summary -d")
            self.check_data_block_in_log(
                output, f"{IMAGES_DIR}/256bit", reverse_order=True
            )
            self.check_data_block_in_log(
                output, f"{IMAGES_DIR}/256bit_1", reverse_order=True
            )

            self.espefuse_py(
                f"burn_key \
                flash_encryption  {IMAGES_DIR}/256bit \
                secure_boot_v1    {IMAGES_DIR}/256bit_1"
            )
            output = self.espefuse_py("summary -d")
            assert (
                "[1 ] read_regs: 00000000 00000000 00000000 00000000 "
                "00000000 00000000 00000000 00000000"
            ) in output
            assert (
                "[2 ] read_regs: 00000000 00000000 00000000 00000000 "
                "00000000 00000000 00000000 00000000"
            ) in output
            assert (
                "[3 ] read_regs: 00000000 00000000 00000000 00000000 "
                "00000000 00000000 00000000 00000000"
            ) in output

    def test_2_secure_boot_v1(self):
        if arg_chip == "esp32":
            self.espefuse_py(
                f"burn_key \
                flash_encryption {IMAGES_DIR}/256bit \
                secure_boot_v2 {IMAGES_DIR}/256bit_1 --no-protect-key"
            )
            output = self.espefuse_py("summary -d")
            self.check_data_block_in_log(
                output, f"{IMAGES_DIR}/256bit", reverse_order=True
            )
            self.check_data_block_in_log(
                output, f"{IMAGES_DIR}/256bit_1", reverse_order=False
            )

            self.espefuse_py(
                f"burn_key \
                flash_encryption {IMAGES_DIR}/256bit \
                secure_boot_v2 {IMAGES_DIR}/256bit_1"
            )
            output = self.espefuse_py("summary -d")
            assert (
                "[1 ] read_regs: 00000000 00000000 00000000 00000000 "
                "00000000 00000000 00000000 00000000"
            ) in output
            self.check_data_block_in_log(
                output, f"{IMAGES_DIR}/256bit_1", reverse_order=False
            )


# TODO: [ESP32H21] IDF-11506
@pytest.mark.skipif(arg_chip == "esp32h21", reason="Not supported yet")
class TestExecuteScriptsCommands(EfuseTestCase):
    @classmethod
    def setup_class(self):
        # Save the current working directory to be restored later
        self.stored_dir = os.getcwd()

    @classmethod
    def teardown_class(self):
        # Restore the stored working directory
        os.chdir(self.stored_dir)

    @pytest.mark.skipif(
        arg_chip in ["esp32c2", "esp32p4"],
        reason="These chips do not have eFuses used in this test",
    )
    def test_execute_scripts_with_check_that_only_one_burn(self):
        self.espefuse_py("execute_scripts -h")
        name = arg_chip if arg_chip in ["esp32", "esp32c2"] else "esp32xx"
        os.chdir(os.path.join(TEST_DIR, "efuse_scripts", name))
        self.espefuse_py("execute_scripts execute_efuse_script2.py")

    @pytest.mark.skipif(
        arg_chip in ["esp32c2", "esp32p4"],
        reason="These chips do not have eFuses used in this test",
    )
    def test_execute_scripts_with_check(self):
        self.espefuse_py("execute_scripts -h")
        name = arg_chip if arg_chip in ["esp32", "esp32c2"] else "esp32xx"
        os.chdir(os.path.join(TEST_DIR, "efuse_scripts", name))
        self.espefuse_py("execute_scripts execute_efuse_script.py")

    def test_execute_scripts_with_index_and_config(self):
        os.chdir(TEST_DIR)
        if arg_chip in ["esp32", "esp32c2"]:
            cmd = f"execute_scripts {EFUSE_S_DIR}/efuse_burn1.py --index 10 \
            --configfiles {EFUSE_S_DIR}/esp32/config1.json"
        else:
            cmd = f"execute_scripts {EFUSE_S_DIR}/efuse_burn1.py --index 10 \
            --configfiles {EFUSE_S_DIR}/esp32xx/config1.json"
        self.espefuse_py(cmd)
        output = self.espefuse_py("summary -d")
        if arg_chip in ["esp32", "esp32c2"]:
            assert (
                "[3 ] read_regs: e00007ff 00000000 00000000 00000000 "
                "00000000 00000000 00000000 00000000"
            ) in output
        else:
            assert (
                "[8 ] read_regs: e00007ff 00000000 00000000 00000000 "
                "00000000 00000000 00000000 00000000"
            ) in output

    def test_execute_scripts_nesting(self):
        os.chdir(TEST_DIR)
        if arg_chip in ["esp32", "esp32c2"]:
            cmd = f"execute_scripts {EFUSE_S_DIR}/efuse_burn2.py --index 28 \
            --configfiles {EFUSE_S_DIR}/esp32/config2.json"
        else:
            cmd = f"execute_scripts {EFUSE_S_DIR}/efuse_burn2.py --index 28 \
            --configfiles {EFUSE_S_DIR}/esp32xx/config2.json"
        self.espefuse_py(cmd)
        output = self.espefuse_py("summary -d")
        if arg_chip in ["esp32", "esp32c2"]:
            assert (
                "[2 ] read_regs: 10000000 00000000 00000000 00000000 "
                "00000000 00000000 00000000 00000000"
            ) in output
            assert (
                "[3 ] read_regs: ffffffff 00000000 00000000 00000000 "
                "00000000 00000000 00000000 00000000"
            ) in output
        else:
            assert (
                "[7 ] read_regs: 10000000 00000000 00000000 00000000 "
                "00000000 00000000 00000000 00000000"
            ) in output
            assert (
                "[8 ] read_regs: ffffffff 00000000 00000000 00000000 "
                "00000000 00000000 00000000 00000000"
            ) in output


class TestMultipleCommands(EfuseTestCase):
    def test_multiple_cmds_help(self):
        if arg_chip == "esp32c2":
            command1 = (
                f"burn_key_digest {S_IMAGES_DIR}"
                "/ecdsa256_secure_boot_signing_key_v2.pem"
            )
            command2 = (
                f"burn_key BLOCK_KEY0 {IMAGES_DIR}/128bit_key "
                "XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS"
            )
        elif arg_chip == "esp32":
            command1 = f"burn_key_digest {S_IMAGES_DIR}/rsa_secure_boot_signing_key.pem"
            command2 = f"burn_key flash_encryption {IMAGES_DIR}/256bit"
        else:
            command1 = f"burn_key_digest BLOCK_KEY0 \
            {S_IMAGES_DIR}/rsa_secure_boot_signing_key.pem SECURE_BOOT_DIGEST0"
            command2 = f"burn_key BLOCK_KEY0 \
            {S_IMAGES_DIR}/rsa_public_key_digest.bin SECURE_BOOT_DIGEST0"

        self.espefuse_py(
            f"-h {command1} {command2}",
            check_msg=f"usage: {ESPEFUSE_MODNAME} [-h]",
        )

        self.espefuse_py(
            f"{command1} -h {command2}",
            check_msg=f"usage: {ESPEFUSE_MODNAME} burn_key_digest [-h]",
        )

        self.espefuse_py(
            f"{command1} {command2} -h",
            check_msg=f"usage: {ESPEFUSE_MODNAME} burn_key [-h]",
        )

    @pytest.mark.skipif(
        arg_chip != "esp32c2", reason="For this chip, FE and SB keys go into one BLOCK"
    )
    def test_1_esp32c2(self):
        self.espefuse_py(
            f"burn_key_digest {S_IMAGES_DIR}/ecdsa256_secure_boot_signing_key_v2.pem \
            burn_key BLOCK_KEY0 {IMAGES_DIR}/128bit_key \
            XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS --no-read-protect \
            summary"
        )
        output = self.espefuse_py("summary -d")
        assert (
            "[3 ] read_regs: 0c0d0e0f 08090a0b 04050607 00010203 "
            "f66a0fbf 8b6dd38b a9dab353 040af633"
        ) in output
        assert " = 0f 0e 0d 0c 0b 0a 09 08 07 06 05 04 03 02 01 00 R/-" in output
        assert " = bf 0f 6a f6 8b d3 6d 8b 53 b3 da a9 33 f6 0a 04 R/-" in output

    @pytest.mark.skipif(
        arg_chip != "esp32c2", reason="For this chip, FE and SB keys go into one BLOCK"
    )
    def test_2_esp32c2(self):
        self.espefuse_py(
            f"burn_key_digest {S_IMAGES_DIR}/ecdsa256_secure_boot_signing_key_v2.pem \
            burn_key BLOCK_KEY0 \
            {IMAGES_DIR}/128bit_key XTS_AES_128_KEY_DERIVED_FROM_128_EFUSE_BITS \
            summary"
        )
        output = self.espefuse_py("summary -d")
        assert (
            "[3 ] read_regs: 00000000 00000000 00000000 00000000 "
            "f66a0fbf 8b6dd38b a9dab353 040af633"
        ) in output
        assert " = ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? -/-" in output
        assert " = bf 0f 6a f6 8b d3 6d 8b 53 b3 da a9 33 f6 0a 04 R/-" in output

    def test_burn_bit(self):
        if arg_chip == "esp32":
            self._set_34_coding_scheme()
        self.espefuse_py(
            "burn_bit BLOCK2 0 1 2 3 \
            burn_bit BLOCK2 4 5 6 7 \
            burn_bit BLOCK2 8 9 10 11 \
            burn_bit BLOCK2 12 13 14 15 \
            summary"
        )
        output = self.espefuse_py("summary -d")
        assert "[2 ] read_regs: 0000ffff 00000000" in output

    def test_not_burn_cmds(self):
        self.espefuse_py(
            "summary \
            dump \
            get_custom_mac \
            adc_info \
            check_error"
        )


@pytest.mark.skipif(
    arg_chip not in ["esp32c3", "esp32c6", "esp32h2", "esp32s3"],
    reason="These chips have a hardware bug that limits the use of the KEY5",
)
class TestKeyPurposes(EfuseTestCase):
    def test_burn_xts_aes_key_purpose(self):
        self.espefuse_py(
            "burn_efuse KEY_PURPOSE_5 XTS_AES_128_KEY",
            check_msg="A fatal error occurred: "
            "KEY_PURPOSE_5 can not have XTS_AES_128_KEY "
            "key due to a hardware bug (please see TRM for more details)",
            ret_code=2,
        )

    @pytest.mark.skipif(
        arg_chip != "esp32h2", reason="esp32h2 can not have ECDSA key in KEY5"
    )
    def test_burn_ecdsa_key_purpose(self):
        self.espefuse_py(
            "burn_efuse KEY_PURPOSE_5 ECDSA_KEY",
            check_msg="A fatal error occurred: "
            "KEY_PURPOSE_5 can not have ECDSA_KEY "
            "key due to a hardware bug (please see TRM for more details)",
            ret_code=2,
        )

    def test_burn_xts_aes_key(self):
        self.espefuse_py(
            f"burn_key \
            BLOCK_KEY5 {IMAGES_DIR}/256bit XTS_AES_128_KEY",
            check_msg="A fatal error occurred: "
            "KEY_PURPOSE_5 can not have XTS_AES_128_KEY "
            "key due to a hardware bug (please see TRM for more details)",
            ret_code=2,
        )

    @pytest.mark.skipif(
        arg_chip != "esp32h2", reason="esp32h2 can not have ECDSA key in KEY5"
    )
    def test_burn_ecdsa_key(self):
        self.espefuse_py(
            f"burn_key \
            BLOCK_KEY5 {S_IMAGES_DIR}/ecdsa192_secure_boot_signing_key_v2.pem \
            ECDSA_KEY",
            check_msg="A fatal error occurred: "
            "KEY_PURPOSE_5 can not have ECDSA_KEY "
            "key due to a hardware bug (please see TRM for more details)",
            ret_code=2,
        )


class TestPostponedEfuses(EfuseTestCase):
    def test_postpone_efuses(self):
        if arg_chip == "esp32":
            cmd = f"--postpone \
                    burn_efuse UART_DOWNLOAD_DIS 1 \
                    burn_key BLOCK1 {IMAGES_DIR}/256bit \
                    burn_efuse ABS_DONE_1 1 FLASH_CRYPT_CNT 1"
            num = 1
        else:
            sb_digest_name = (
                "SECURE_BOOT_DIGEST" if arg_chip == "esp32c2" else "SECURE_BOOT_DIGEST0"
            )
            cmd = f"--postpone \
                burn_efuse ENABLE_SECURITY_DOWNLOAD 1 DIS_DOWNLOAD_MODE 1 \
                SECURE_VERSION 1 \
                burn_key BLOCK_KEY0 {IMAGES_DIR}/256bit {sb_digest_name} \
                burn_efuse SPI_BOOT_CRYPT_CNT 1 SECURE_BOOT_EN 1"
            num = 3 if arg_chip == "esp32c2" else 4
        output = self.espefuse_py(cmd)
        assert f"BURN BLOCK{num}  - OK" in output
        assert "BURN BLOCK0  - OK" in output
        assert "Burn postponed efuses from BLOCK0" in output
        assert "BURN BLOCK0  - OK" in output
        assert "Successful" in output


class TestCSVEfuseTable(EfuseTestCase):
    def test_extend_efuse_table_with_csv_file(self):
        csv_file = f"{IMAGES_DIR}/esp_efuse_custom_table.csv"
        output = self.espefuse_py(f" --extend-efuse-table {csv_file} summary")
        assert "MODULE_VERSION (BLOCK3)" in output
        assert "DEVICE_ROLE (BLOCK3)" in output
        assert "SETTING_2 (BLOCK3)" in output
        assert "ID_NUM_0 (BLOCK3)" in output
        assert "ID_NUM_1 (BLOCK3)" in output
        assert "ID_NUM_2 (BLOCK3)" in output
        assert "CUSTOM_SECURE_VERSION (BLOCK3)" in output
        assert "ID_NUMK_0 (BLOCK3)" in output
        assert "ID_NUMK_1 (BLOCK3)" in output

        self.espefuse_py(
            f"--extend-efuse-table {csv_file} burn_efuse \
                         MODULE_VERSION 1 \
                         CUSTOM_SECURE_VERSION 4 \
                         SETTING_1_ALT_NAME 7 \
                         SETTING_2 1 \
                         ID_NUM_0 1 \
                         ID_NUM_1 1 \
                         ID_NUM_2 1 \
                         MY_ID_NUMK_0 1 \
                         MY_ID_NUMK_1 1 \
                         MY_DATA_FIELD1 1"
        )
