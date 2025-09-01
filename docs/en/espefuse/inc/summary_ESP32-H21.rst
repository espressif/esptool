.. code-block:: none

    > espefuse -p PORT summary

    Connecting....
    Detecting chip type... ESP32-H21

    === Run "summary" command ===
    EFUSE_NAME (Block) Description  = [Meaningful Value] [Readable/Writeable] (Hex Value)
    ----------------------------------------------------------------------------------------
    Config fuses:
    WR_DIS (BLOCK0)                                    Disable programming of individual eFuses           = 0 R/W (0x00000000)
    RD_DIS (BLOCK0)                                    Disable reading from BlOCK4-10                     = 0 R/W (0b0000000)
    DIS_ICACHE (BLOCK0)                                Represents whether icache is disabled or enabled.\ = False R/W (0b0)
                                                      \ 1: disabled\\ 0: enabled\\
    DIS_DIRECT_BOOT (BLOCK0)                           Represents whether direct boot mode is disabled or = False R/W (0b0)
                                                      enabled.\\ 1: disabled\\ 0: enabled\\
    UART_PRINT_CONTROL (BLOCK0)                        Set the default UARTboot message output mode       = Enable R/W (0b00)
    HYS_EN_PAD (BLOCK0)                                Represents whether the hysteresis function of corr = False R/W (0b0)
                                                      esponding PAD is enabled.\\ 1: enabled\\ 0:disable
                                                      d\\
    ECC_FORCE_CONST_TIME (BLOCK0)                      Represents whether to force ecc to use const-time  = False R/W (0b0)
                                                      calculation mode. \\ 1: Enable. \\ 0: Disable
    PSRAM_CAP (BLOCK1)                                 PSRAM capacity                                     = 0 R/W (0b000)
    PSRAM_VENDOR (BLOCK1)                              PSRAM vendor                                       = 0 R/W (0b00)
    TEMP (BLOCK1)                                      Temperature                                        = 0 R/W (0b00)
    BLOCK_USR_DATA (BLOCK3)                            User data
       = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W
    BLOCK_SYS_DATA2 (BLOCK10)                          System data part 2 (reserved)
       = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W

    Flash fuses:
    FLASH_TPUW (BLOCK0)                                Represents the flash waiting time after power-up;  = 0 R/W (0x0)
                                                      in unit of ms. When the value less than 15; the wa
                                                      iting time is the programmed value. Otherwise; the wai
                                                      ting time is 2 times the programmed value
    FORCE_SEND_RESUME (BLOCK0)                         Represents whether ROM code is forced to send a re = False R/W (0b0)
                                                      sume command during SPI boot
    FLASH_CAP (BLOCK1)                                 Flash capacity                                     = 0 R/W (0b000)
    FLASH_VENDOR (BLOCK1)                              Flash vendor                                       = 0 R/W (0b000)

    Identity fuses:
    WAFER_VERSION_MINOR (BLOCK1)                       Minor chip version                                 = 0 R/W (0x0)
    WAFER_VERSION_MAJOR (BLOCK1)                       Major chip version                                 = 0 R/W (0b00)
    DISABLE_WAFER_VERSION_MAJOR (BLOCK1)               Disables check of wafer version major              = False R/W (0b0)
    DISABLE_BLK_VERSION_MAJOR (BLOCK1)                 Disables check of blk version major                = False R/W (0b0)
    BLK_VERSION_MINOR (BLOCK1)                         BLK_VERSION_MINOR of BLOCK2                        = 0 R/W (0b000)
    BLK_VERSION_MAJOR (BLOCK1)                         BLK_VERSION_MAJOR of BLOCK2                        = 0 R/W (0b00)
    PKG_VERSION (BLOCK1)                               Package version                                    = 0 R/W (0b000)
    OPTIONAL_UNIQUE_ID (BLOCK2)                        Optional unique 128-bit ID
       = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W

    Jtag fuses:
    JTAG_SEL_ENABLE (BLOCK0)                           Represents whether the selection between usb_to_jt = False R/W (0b0)
                                                      ag and pad_to_jtag through strapping gpio15 when b
                                                      oth EFUSE_DIS_PAD_JTAG and EFUSE_DIS_USB_JTAG are
                                                      equal to 0 is enabled or disabled.\\ 1: enabled\\
                                                      0: disabled\\
    DIS_PAD_JTAG (BLOCK0)                              Represents whether JTAG is disabled in the hard wa = False R/W (0b0)
                                                      y(permanently).\\ 1: disabled\\ 0: enabled\\

    Mac fuses:
    MAC (BLOCK1)                                       MAC address
       = 60:55:f9:f9:54:1c (OK) R/W
    MAC_EXT (BLOCK1)                                   Represents the extended bits of MAC address        = ff:fe (OK) R/W
    CUSTOM_MAC (BLOCK3)                                Custom MAC
       = 00:00:00:00:00:00 (OK) R/W
    MAC_EUI64 (BLOCK1)                                 calc MAC_EUI64 = MAC[0]:MAC[1]:MAC[2]:MAC_EXT[0]:M
       = 60:55:f9:ff:fe:f9:54:1c (OK) R/W
                                                      AC_EXT[1]:MAC[3]:MAC[4]:MAC[5]

    Security fuses:
    DIS_FORCE_DOWNLOAD (BLOCK0)                        Represents whether the function that forces chip i = False R/W (0b0)
                                                      nto download mode is disabled or enabled.\\ 1: dis
                                                      abled\\ 0: enabled\\
    SPI_DOWNLOAD_MSPI_DIS (BLOCK0)                     Represents whether SPI0 controller during boot_mod = False R/W (0b0)
                                                      e_download is disabled or enabled.\\ 1: disabled\\
                                                      0: enabled\\
    DIS_DOWNLOAD_MANUAL_ENCRYPT (BLOCK0)               Represents whether flash encrypt function is disab = False R/W (0b0)
                                                      led or enabled(except in SPI boot mode).\\ 1: disa
                                                      bled\\ 0: enabled\\
    SPI_BOOT_CRYPT_CNT (BLOCK0)                        Enables flash encryption when 1 or 3 bits are set  = Disable R/W (0b000)
                                                      and disables otherwise
    SECURE_BOOT_KEY_REVOKE0 (BLOCK0)                   Revoke 1st secure boot key                         = False R/W (0b0)
    SECURE_BOOT_KEY_REVOKE1 (BLOCK0)                   Revoke 2nd secure boot key                         = False R/W (0b0)
    SECURE_BOOT_KEY_REVOKE2 (BLOCK0)                   Revoke 3rd secure boot key                         = False R/W (0b0)
    KEY_PURPOSE_0 (BLOCK0)                             Represents the purpose of Key0                     = USER R/W (0x0)
    KEY_PURPOSE_1 (BLOCK0)                             Represents the purpose of Key1                     = USER R/W (0x0)
    KEY_PURPOSE_2 (BLOCK0)                             Represents the purpose of Key2                     = USER R/W (0x0)
    KEY_PURPOSE_3 (BLOCK0)                             Represents the purpose of Key3                     = USER R/W (0x0)
    KEY_PURPOSE_4 (BLOCK0)                             Represents the purpose of Key4                     = USER R/W (0x0)
    KEY_PURPOSE_5 (BLOCK0)                             Represents the purpose of Key5                     = USER R/W (0x0)
    SEC_DPA_LEVEL (BLOCK0)                             Represents the spa secure level by configuring the = 0 R/W (0b00)
                                                      clock random divide mode
    SECURE_BOOT_EN (BLOCK0)                            Represents whether secure boot is enabled or disab = False R/W (0b0)
                                                      led.\\ 1: enabled\\ 0: disabled\\
    SECURE_BOOT_AGGRESSIVE_REVOKE (BLOCK0)             Represents whether revoking aggressive secure boot = False R/W (0b0)
                                                      is enabled or disabled.\\ 1: enabled.\\ 0: disabl
                                                      ed\\
    DIS_DOWNLOAD_MODE (BLOCK0)                         Represents whether Download mode is disabled or en = False R/W (0b0)
                                                      abled.\\ 1: disabled\\ 0: enabled\\
    ENABLE_SECURITY_DOWNLOAD (BLOCK0)                  Represents whether security download is enabled or = False R/W (0b0)
                                                      disabled.\\ 1: enabled\\ 0: disabled\\
    SECURE_VERSION (BLOCK0)                            Represents the version used by ESP-IDF anti-rollba = 0 R/W (0x0000)
                                                      ck feature
    SECURE_BOOT_DISABLE_FAST_WAKE (BLOCK0)             Represents whether FAST_VERIFY_ON_WAKE is disable  = False R/W (0b0)
                                                      or enable when Secure Boot is enable
    XTS_DPA_PSEUDO_LEVEL (BLOCK0)                      Represents the anti-dpa attack pseudo function lev = 0 R/W (0b00)
                                                      el.\\ 3:High\\ 2: Moderate\\ 1: Low\\ 0: Decided b
                                                      y register configuration\\
    BLOCK_KEY0 (BLOCK4)
    Purpose: USER
                   Key0 or user data
       = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W
    BLOCK_KEY1 (BLOCK5)
    Purpose: USER
                   Key1 or user data
       = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W
    BLOCK_KEY2 (BLOCK6)
    Purpose: USER
                   Key2 or user data
       = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W
    BLOCK_KEY3 (BLOCK7)
    Purpose: USER
                   Key3 or user data
       = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W
    BLOCK_KEY4 (BLOCK8)
    Purpose: USER
                   Key4 or user data
       = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W
    BLOCK_KEY5 (BLOCK9)
    Purpose: USER
                   Key5 or user data
       = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W

    Usb fuses:
    DIS_USB_JTAG (BLOCK0)                              Represents whether the function of usb switch to j = False R/W (0b0)
                                                      tag is disabled or enabled.\\ 1: disabled\\ 0: ena
                                                      bled\\
    USB_EXCHG_PINS (BLOCK0)                            Represents whether the D+ and D- pins is exchanged = False R/W (0b0)
                                                      .\\ 1: exchanged\\ 0: not exchanged\\
    DIS_USB_SERIAL_JTAG_ROM_PRINT (BLOCK0)             Represents whether print from USB-Serial-JTAG is d = False R/W (0b0)
                                                      isabled or enabled.\\ 1. Disable\\ 0: Enable\\
    DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE (BLOCK0)         Represents whether the USB-Serial-JTAG download fu = False R/W (0b0)
                                                      nction is disabled or enabled.\\ 1: Disable\\ 0: E
                                                      nable\\

    Vdd fuses:
    VDD_SPI_AS_GPIO (BLOCK0)                           Represents whether vdd spi pin is functioned as gp = False R/W (0b0)
                                                      io.\\ 1: functioned\\ 0: not functioned\\

    Wdt fuses:
    WDT_DELAY_SEL (BLOCK0)                             Represents the threshold level of the RTC watchdog = 0 R/W (0b00)
                                                   STG0 timeout.\\ 0: Original threshold configurati
                                                  on value of STG0 *2 \\1: Original threshold config
                                                  uration value of STG0 *4 \\2: Original threshold c
                                                  onfiguration value of STG0 *8 \\3: Original thresh
                                                  old configuration value of STG0 *16 \\
