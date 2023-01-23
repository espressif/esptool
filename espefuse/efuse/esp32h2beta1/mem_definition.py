# This file describes eFuses fields and registers for ESP32-H2 chip
#
# SPDX-FileCopyrightText: 2021-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from ..mem_definition_base import EfuseBlocksBase, EfuseFieldsBase, EfuseRegistersBase


# fmt: off
class EfuseDefineRegisters(EfuseRegistersBase):

    EFUSE_MEM_SIZE = (0x01FC + 4)

    # EFUSE registers & command/conf values
    DR_REG_EFUSE_BASE       = 0x6001A000
    EFUSE_PGM_DATA0_REG     = DR_REG_EFUSE_BASE
    EFUSE_CHECK_VALUE0_REG  = DR_REG_EFUSE_BASE + 0x020
    EFUSE_CLK_REG           = DR_REG_EFUSE_BASE + 0x1C8
    EFUSE_CONF_REG          = DR_REG_EFUSE_BASE + 0x1CC
    EFUSE_STATUS_REG        = DR_REG_EFUSE_BASE + 0x1D0
    EFUSE_CMD_REG           = DR_REG_EFUSE_BASE + 0x1D4
    EFUSE_RD_RS_ERR0_REG    = DR_REG_EFUSE_BASE + 0x1C0
    EFUSE_RD_RS_ERR1_REG    = DR_REG_EFUSE_BASE + 0x1C4
    EFUSE_RD_REPEAT_ERR0_REG = DR_REG_EFUSE_BASE + 0x17C
    EFUSE_RD_REPEAT_ERR1_REG = DR_REG_EFUSE_BASE + 0x180
    EFUSE_RD_REPEAT_ERR2_REG = DR_REG_EFUSE_BASE + 0x184
    EFUSE_RD_REPEAT_ERR3_REG = DR_REG_EFUSE_BASE + 0x188
    EFUSE_RD_REPEAT_ERR4_REG = DR_REG_EFUSE_BASE + 0x18C
    EFUSE_DAC_CONF_REG = DR_REG_EFUSE_BASE + 0x1E8
    EFUSE_RD_TIM_CONF_REG = DR_REG_EFUSE_BASE + 0x1EC
    EFUSE_WR_TIM_CONF1_REG = DR_REG_EFUSE_BASE + 0x1F0
    EFUSE_WR_TIM_CONF2_REG = DR_REG_EFUSE_BASE + 0x1F4
    EFUSE_DATE_REG = DR_REG_EFUSE_BASE + 0x1FC
    EFUSE_WRITE_OP_CODE     = 0x5A5A
    EFUSE_READ_OP_CODE      = 0x5AA5
    EFUSE_PGM_CMD_MASK      = 0x3
    EFUSE_PGM_CMD           = 0x2
    EFUSE_READ_CMD          = 0x1

    BLOCK_ERRORS = [
        # error_reg,               err_num_mask, err_num_offs,     fail_bit
        (EFUSE_RD_REPEAT_ERR0_REG, None,         None,             None),  # BLOCK0
        (EFUSE_RD_RS_ERR0_REG,     0x7,          0,                3),     # MAC_SPI_8M_0
        (EFUSE_RD_RS_ERR0_REG,     0x7,          4,                7),     # BLOCK_SYS_DATA
        (EFUSE_RD_RS_ERR0_REG,     0x7,          8,                11),    # BLOCK_USR_DATA
        (EFUSE_RD_RS_ERR0_REG,     0x7,          12,               15),    # BLOCK_KEY0
        (EFUSE_RD_RS_ERR0_REG,     0x7,          16,               19),    # BLOCK_KEY1
        (EFUSE_RD_RS_ERR0_REG,     0x7,          20,               23),    # BLOCK_KEY2
        (EFUSE_RD_RS_ERR0_REG,     0x7,          24,               27),    # BLOCK_KEY3
        (EFUSE_RD_RS_ERR0_REG,     0x7,          28,               31),    # BLOCK_KEY4
        (EFUSE_RD_RS_ERR1_REG,     0x7,          0,                3),     # BLOCK_KEY5
        (EFUSE_RD_RS_ERR1_REG,     0x7,          4,                7),     # BLOCK_SYS_DATA2
    ]

    # EFUSE_WR_TIM_CONF2_REG
    EFUSE_PWR_OFF_NUM_S = 0
    EFUSE_PWR_OFF_NUM_M = 0xFFFF << EFUSE_PWR_OFF_NUM_S


class EfuseDefineBlocks(EfuseBlocksBase):

    __base_rd_regs = EfuseDefineRegisters.DR_REG_EFUSE_BASE
    __base_wr_regs = EfuseDefineRegisters.EFUSE_PGM_DATA0_REG
    # List of efuse blocks
    BLOCKS = [
        # Name,             Alias,     Index,  Read address,           Write address,  Write protect bit, Read protect bit, Len, key_purpose
        ("BLOCK0",          [],          0,  __base_rd_regs + 0x02C, __base_wr_regs, None, None, 6, None),
        ("MAC_SPI_8M_0",    ["BLOCK1"],  1,  __base_rd_regs + 0x044, __base_wr_regs, 20,   None, 6, None),
        ("BLOCK_SYS_DATA",  ["BLOCK2"],  2,  __base_rd_regs + 0x05C, __base_wr_regs, 21,   None, 8, None),
        ("BLOCK_USR_DATA",  ["BLOCK3"],  3,  __base_rd_regs + 0x07C, __base_wr_regs, 22,   None, 8, None),
        ("BLOCK_KEY0",      ["BLOCK4"],  4,  __base_rd_regs + 0x09C, __base_wr_regs, 23,   0,    8, "KEY_PURPOSE_0"),
        ("BLOCK_KEY1",      ["BLOCK5"],  5,  __base_rd_regs + 0x0BC, __base_wr_regs, 24,   1,    8, "KEY_PURPOSE_1"),
        ("BLOCK_KEY2",      ["BLOCK6"],  6,  __base_rd_regs + 0x0DC, __base_wr_regs, 25,   2,    8, "KEY_PURPOSE_2"),
        ("BLOCK_KEY3",      ["BLOCK7"],  7,  __base_rd_regs + 0x0FC, __base_wr_regs, 26,   3,    8, "KEY_PURPOSE_3"),
        ("BLOCK_KEY4",      ["BLOCK8"],  8,  __base_rd_regs + 0x11C, __base_wr_regs, 27,   4,    8, "KEY_PURPOSE_4"),
        ("BLOCK_KEY5",      ["BLOCK9"],  9,  __base_rd_regs + 0x13C, __base_wr_regs, 28,   5,    8, "KEY_PURPOSE_5"),
        ("BLOCK_SYS_DATA2", ["BLOCK10"], 10, __base_rd_regs + 0x15C, __base_wr_regs, 29,   6,    8, None),
    ]

    def get_burn_block_data_names(self):
        list_of_names = []
        for block in self.BLOCKS:
            blk = self.get(block)
            if blk.name:
                list_of_names.append(blk.name)
            if blk.alias:
                for alias in blk.alias:
                    list_of_names.append(alias)
        return list_of_names


class EfuseDefineFields(EfuseFieldsBase):

    # List of efuse fields from TRM the chapter eFuse Controller.
    EFUSES = [
        #
        # Table 51: Parameters in BLOCK0
        # Name                           Category Block Word Pos Type:len   WR_DIS RD_DIS Class        Description                Dictionary
        ("WR_DIS",                       "efuse",    0,  0,  0,  "uint:32",  None, None, None,         "Disables programming of individual eFuses", None),
        ("RD_DIS",                       "efuse",    0,  1,  0,  "uint:7",   0,    None, None,         "Disables software reading from BLOCK4-10", None),
        ("DIS_ICACHE",                   "config",   0,  1,  8,  "bool",     2,    None, None,         "Disables ICache", None),
        ("DIS_USB_JTAG",             "usb config",   0,  1,  9,  "bool",     2,    None, None,         "Disables USB JTAG. "
                                                                                                       "JTAG access via pads is controlled separately", None),
        ("DIS_DOWNLOAD_ICACHE",          "config",   0,  1,  10, "bool",     2,    None, None,         "Disables Icache when SoC is in Download mode", None),
        ("DIS_USB_DEVICE",           "usb config",   0,  1,  11, "bool",     2,    None, None,         "Disables USB DEVICE", None),
        ("DIS_FORCE_DOWNLOAD",           "config",   0,  1,  12, "bool",     2,    None, None,         "Disables forcing chip into Download mode", None),
        ("DIS_CAN",                      "config",   0,  1,  14, "bool",     2,    None, None,         "Disables the TWAI Controller hardware", None),
        ("JTAG_SEL_ENABLE",         "jtag config",   0,  1,  15, "bool",     2,    None, None,         "Set this bit to enable selection between "
                                                                                                       "usb_to_jtag and pad_to_jtag through strapping "
                                                                                                       "gpio10 when both reg_dis_usb_jtag and "
                                                                                                       "reg_dis_pad_jtag are equal to 0.", None),
        ("SOFT_DIS_JTAG",           "jtag config",   0,  1,  16, "uint:3",   2,    None, None,         "Software disables JTAG. When software disabled, "
                                                                                                       "JTAG can be activated temporarily by HMAC peripheral",
                                                                                                       None),
        ("DIS_PAD_JTAG",            "jtag config",   0,  1,  19, "bool",     2,    None, None,         "Permanently disable JTAG access via pads. "
                                                                                                       "USB JTAG is controlled separately.", None),
        ("DIS_DOWNLOAD_MANUAL_ENCRYPT", "security",  0,  1,  20, "bool",     2,    None, None,         "Disables flash encryption when in download boot modes",
                                                                                                       None),
        ("USB_EXCHG_PINS",           "usb config",   0,  1,  25, "bool",     30,   None, None,         "Exchanges USB D+ and D- pins", None),
        ("VDD_SPI_AS_GPIO",              "config",   0,  1,  26, "bool",     30,   None, None,         "Set this bit to vdd spi pin function as gpio", None),
        ("BTLC_GPIO_ENABLE",             "config",   0,  1,  27, "uint:2",   30,   None, None,         "Enable btlc gpio", None),
        ("POWERGLITCH_EN",               "config",   0,  1,  29, "bool",     30,   None, None,         "Set this bit to enable power glitch function", None),
        ("POWER_GLITCH_DSENSE",          "config",   0,  1,  30, "uint:2",   30,   None, None,         "Sample delay configuration of power glitch", None),
        ("WDT_DELAY_SEL",            "WDT config",   0,  2,  16, "bool",     3,    None, None,         "Selects RTC WDT timeout threshold at startup", None),
        ("SPI_BOOT_CRYPT_CNT",           "security", 0,  2,  18, "uint:3",   4,    None, "bitcount",   "Enables encryption and decryption, when an SPI boot "
                                                                                                       "mode is set. Enabled when 1 or 3 bits are set,"
                                                                                                       "disabled otherwise",
         {0: "Disable",
          1: "Enable",
          3: "Disable",
          7: "Enable"}),
        ("SECURE_BOOT_KEY_REVOKE0",      "security", 0,  2, 21,  "bool",     5,    None, None,         "If set, revokes use of secure boot key digest 0", None),
        ("SECURE_BOOT_KEY_REVOKE1",      "security", 0,  2, 22,  "bool",     6,    None, None,         "If set, revokes use of secure boot key digest 1", None),
        ("SECURE_BOOT_KEY_REVOKE2",      "security", 0,  2, 23,  "bool",     7,    None, None,         "If set, revokes use of secure boot key digest 2", None),
        ("KEY_PURPOSE_0",                "security", 0,  2, 24,  "uint:4",   8,    None, "keypurpose", "KEY0 purpose", None),
        ("KEY_PURPOSE_1",                "security", 0,  2, 28,  "uint:4",   9,    None, "keypurpose", "KEY1 purpose", None),
        ("KEY_PURPOSE_2",                "security", 0,  3, 0,   "uint:4",   10,   None, "keypurpose", "KEY2 purpose", None),
        ("KEY_PURPOSE_3",                "security", 0,  3, 4,   "uint:4",   11,   None, "keypurpose", "KEY3 purpose", None),
        ("KEY_PURPOSE_4",                "security", 0,  3, 8,   "uint:4",   12,   None, "keypurpose", "KEY4 purpose", None),
        ("KEY_PURPOSE_5",                "security", 0,  3, 12,  "uint:4",   13,   None, "keypurpose", "KEY5 purpose", None),
        ("SECURE_BOOT_EN",               "security", 0,  3, 20,  "bool",     15,   None, None,         "Enables secure boot", None),
        ("SECURE_BOOT_AGGRESSIVE_REVOKE", "security", 0, 3, 21,  "bool",     16,   None, None,         "Enables aggressive secure boot key revocation mode",
                                                                                                       None),
        ("FLASH_TPUW",               "flash config", 0,  3, 28,  "uint:4",   18,   None, None,         "Configures flash startup delay after SoC power-up, "
                                                                                                       "unit is (ms/2). When the value is 15, delay is 7.5 ms",
                                                                                                       None),
        ("DIS_DOWNLOAD_MODE",            "security", 0,  4, 0,   "bool",     18,   None, None,         "Disables all Download boot modes", None),
        ("DIS_DIRECT_BOOT",              "config",   0,  4, 1,   "bool",     18,   None, None,         "Disables direct boot mode", None),
        ("DIS_USB_SERIAL_JTAG_ROM_PRINT", "config",  0,  4, 2,   "bool",     18,   None, None,         "Disables USB-Serial-JTAG ROM printing", None),
        ("DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE", "usb config", 0, 4, 4, "bool", 18,   None, None,         "Disables USB-Serial-JTAG download feature in "
                                                                                                       "UART download boot mode", None),
        ("ENABLE_SECURITY_DOWNLOAD",   "security",   0,  4, 5,   "bool",     18,   None, None,         "Enables secure UART download mode "
                                                                                                       "(read/write flash only)", None),
        ("UART_PRINT_CONTROL",           "config",   0,  4, 6,   "uint:2",   18,   None, None,         "Sets the default UART boot message output mode",
         {0: "Enabled",
          1: "Enable when GPIO8 is low at reset",
          2: "Enable when GPIO8 is high at reset",
          3: "Disabled"}),
        ("FORCE_SEND_RESUME",            "config",   0,  4, 13,  "bool",     18,   None, None,         "Force ROM code to send a resume command during SPI boot"
                                                                                                       "during SPI boot", None),
        ("SECURE_VERSION",             "identity",   0,  4, 14,  "uint:16",  18,   None, "bitcount",   "Secure version (used by ESP-IDF anti-rollback feature)",
                                                                                                       None),
        ("DISABLE_WAFER_VERSION_MAJOR", "config",    0,  5, 0,   "bool",     19,   None, None,         "Disables check of wafer version major", None),
        ("DISABLE_BLK_VERSION_MAJOR",   "config",    0,  5, 1,   "bool",     19,   None, None,         "Disables check of blk version major", None),
        #
        # Table 53: Parameters in BLOCK1-10
        # Name                          Category  Block Word Pos  Type:len WR_DIS RD_DIS Class         Description                Dictionary
        ("MAC",                        "identity",   1,  0, 0,   "bytes:6",  20,   None, "mac",        "Factory MAC Address", None),
        ("SPI_PAD_CONFIG_CLK",   "spi_pad_config",   1,  1, 16,  "uint:6",   20,   None, None,         "SPI CLK pad", None),
        ("SPI_PAD_CONFIG_Q",     "spi_pad_config",   1,  1, 22,  "uint:6",   20,   None, None,         "SPI Q (D1) pad", None),
        ("SPI_PAD_CONFIG_D",     "spi_pad_config",   1,  1, 28,  "uint:6",   20,   None, None,         "SPI D (D0) pad", None),
        ("SPI_PAD_CONFIG_CS",    "spi_pad_config",   1,  2, 2,   "uint:6",   20,   None, None,         "SPI CS pad", None),
        ("SPI_PAD_CONFIG_HD",    "spi_pad_config",   1,  2, 8,   "uint:6",   20,   None, None,         "SPI HD (D3) pad", None),
        ("SPI_PAD_CONFIG_WP",    "spi_pad_config",   1,  2, 14,  "uint:6",   20,   None, None,         "SPI WP (D2) pad", None),
        ("SPI_PAD_CONFIG_DQS",   "spi_pad_config",   1,  2, 20,  "uint:6",   20,   None, None,         "SPI DQS pad", None),
        ("SPI_PAD_CONFIG_D4",    "spi_pad_config",   1,  2, 26,  "uint:6",   20,   None, None,         "SPI D4 pad", None),
        ("SPI_PAD_CONFIG_D5",    "spi_pad_config",   1,  3, 0,   "uint:6",   20,   None, None,         "SPI D5 pad", None),
        ("SPI_PAD_CONFIG_D6",    "spi_pad_config",   1,  3, 6,   "uint:6",   20,   None, None,         "SPI D6 pad", None),
        ("SPI_PAD_CONFIG_D7",    "spi_pad_config",   1,  3, 12,  "uint:6",   20,   None, None,         "SPI D7 pad", None),
        ("WAFER_VERSION",              "identity",   1,  3, 18,  "uint:3",   20,   None, None,         "WAFER version",
         {0: "(revision 0)", 1: "(revision 1)"}),
        ("PKG_VERSION",                "identity",   1,  3, 21,  "uint:4",   20,   None, None,         "Package version",
         {0: "ESP32-H2(beta1)"}),
        ("BLOCK1_VERSION",             "identity",   1,  3, 24,  "uint:3",   20,   None, None,         "BLOCK1 efuse version", None),
        ("MAC_EXT",                    "identity",   1,  3, 27,  "bytes:2",  20,   None, "mac",        "MAC extension", None),
        ("OPTIONAL_UNIQUE_ID",         "identity",   2,  0, 0,   "bytes:16", 21,   None, "keyblock",   "Optional unique 128-bit ID", None),
        ("BLOCK2_VERSION",             "identity",   2,  4, 4,   "uint:3",   21,   None, None,         "Version of BLOCK2",
         {0: "No calibration",
          1: "With calibration"}),
        ("CUSTOM_MAC",                 "identity",   3,  6, 8,   "bytes:6",  22,   None, "mac",        "Custom MAC Address", None),
    ]

    KEYBLOCKS = [
        # Name                      Category      Block Word Pos Type:len  WR_DIS RD_DIS Class         Description                Dictionary
        ('BLOCK_USR_DATA',               "config",   3,  0, 0,   "bytes:32", 22,   None, None,         "User data", None),
        ('BLOCK_KEY0',                   "security", 4,  0, 0,   "bytes:32", 23,   0,    "keyblock",   "Encryption key0 or user data", None),
        ('BLOCK_KEY1',                   "security", 5,  0, 0,   "bytes:32", 24,   1,    "keyblock",   "Encryption key1 or user data", None),
        ('BLOCK_KEY2',                   "security", 6,  0, 0,   "bytes:32", 25,   2,    "keyblock",   "Encryption key2 or user data", None),
        ('BLOCK_KEY3',                   "security", 7,  0, 0,   "bytes:32", 26,   3,    "keyblock",   "Encryption key3 or user data", None),
        ('BLOCK_KEY4',                   "security", 8,  0, 0,   "bytes:32", 27,   4,    "keyblock",   "Encryption key4 or user data", None),
        ('BLOCK_KEY5',                   "security", 9,  0, 0,   "bytes:32", 28,   5,    "keyblock",   "Encryption key5 or user data", None),
        ('BLOCK_SYS_DATA2',              "security", 10, 0, 0,   "bytes:32", 29,   6,    "keyblock",   "System data (part 2)", None),
    ]

    # if BLOCK2_VERSION is 1, these efuse fields are in BLOCK2
    BLOCK2_CALIBRATION_EFUSES = [
        # Name                      Category      Block Word Pos Type:len  WR_DIS RD_DIS Class         Description                Dictionary
        ('TEMP_SENSOR_CAL',         "calibration",   2,  4, 7,   "uint:9",   21,   None, "t_sensor",   "Temperature calibration", None),
        ('ADC1_MODE0_D2',           "calibration",   2,  4, 16,  "uint:8",   21,   None, "adc_tp",     "ADC1 calibration 1", None),
        ('ADC1_MODE1_D2',           "calibration",   2,  4, 24,  "uint:8",   21,   None, "adc_tp",     "ADC1 calibration 2", None),
        ('ADC1_MODE2_D2',           "calibration",   2,  5, 0,   "uint:8",   21,   None, "adc_tp",     "ADC1 calibration 3", None),
        ('ADC1_MODE3_D2',           "calibration",   2,  5, 8,   "uint:8",   21,   None, "adc_tp",     "ADC1 calibration 4", None),
        ('ADC2_MODE0_D2',           "calibration",   2,  5, 16,  "uint:8",   21,   None, "adc_tp",     "ADC2 calibration 5", None),
        ('ADC2_MODE1_D2',           "calibration",   2,  5, 24,  "uint:8",   21,   None, "adc_tp",     "ADC2 calibration 6", None),
        ('ADC2_MODE2_D2',           "calibration",   2,  6, 0,   "uint:8",   21,   None, "adc_tp",     "ADC2 calibration 7", None),
        ('ADC2_MODE3_D2',           "calibration",   2,  6, 8,   "uint:8",   21,   None, "adc_tp",     "ADC2 calibration 8", None),
        ('ADC1_MODE0_D1',           "calibration",   2,  6, 16,  "uint:6",   21,   None, "adc_tp",     "ADC1 calibration 9", None),
        ('ADC1_MODE1_D1',           "calibration",   2,  6, 22,  "uint:6",   21,   None, "adc_tp",     "ADC1 calibration 10", None),
        ('ADC1_MODE2_D1',           "calibration",   2,  6, 28,  "uint:6",   21,   None, "adc_tp",     "ADC1 calibration 11", None),
        ('ADC1_MODE3_D1',           "calibration",   2,  7, 2,   "uint:6",   21,   None, "adc_tp",     "ADC1 calibration 12", None),
        ('ADC2_MODE0_D1',           "calibration",   2,  7, 8,   "uint:6",   21,   None, "adc_tp",     "ADC2 calibration 13", None),
        ('ADC2_MODE1_D1',           "calibration",   2,  7, 14,  "uint:6",   21,   None, "adc_tp",     "ADC2 calibration 14", None),
        ('ADC2_MODE2_D1',           "calibration",   2,  7, 20,  "uint:6",   21,   None, "adc_tp",     "ADC2 calibration 15", None),
        ('ADC2_MODE3_D1',           "calibration",   2,  7, 26,  "uint:6",   21,   None, "adc_tp",     "ADC2 calibration 16", None),
    ]
# fmt: on
