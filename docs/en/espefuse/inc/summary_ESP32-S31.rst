.. code-block:: none

    > espefuse -p PORT summary

   Connecting....
   Detecting chip type... ESP32-S31

   === Run "summary" command ===
   EFUSE_NAME (Block) Description  = [Meaningful Value] [Readable/Writeable] (Hex Value)
   ----------------------------------------------------------------------------------------
   Config fuses:
   WR_DIS (BLOCK0)                                    Disable programming of individual eFuses           = 0 R/W (0x00000000)
   RD_DIS (BLOCK0)                                    Disable reading from BlOCK4-9                      = 0 R/W (0b0000000)
   DIS_TWAI (BLOCK0)                                  Represents whether TWAI function is disabled or en = False R/W (0b0)
                                                      abled. 1: disabled 0: enabled
   HUK_GEN_STATE (BLOCK0)                             Represents the control of validation of HUK genera = 0 R/W (0b00000)
                                                      te mode. Odd of 1 is invalid; even of 1 is valid
   KM_RND_SWITCH_CYCLE (BLOCK0)                       Represents the control of key manager random numbe = False R/W (0b0)
                                                      r switch cycle. 0: control by register. 1: 8 km cl
                                                      k cycles. 2: 16 km cycles. 3: 32 km cycles
   KM_DISABLE_DEPLOY_MODE (BLOCK0)                    Represents whether the deploy mode of key manager  = 0 R/W (0b00000)
                                                      is disable or not.  1: disabled  0: enabled. bit 0
                                                      : ecsda; bit 1: flash & spi boot srambler; bit2: h
                                                      mac & aes; bit3: ds & SDC nonce; bit4: psram
   KM_DEPLOY_ONLY_ONCE (BLOCK0)                       Represents whether corresponding key can only be d = 0 R/W (0b00000)
                                                      eployed once. 1 is true; 0 is false.  0: ecsda 1:
                                                      flash & spi boot srambler 2: hmac & aes 3: ds & SD
                                                      C nonce 4: psram
   DIS_SM_CRYPT (BLOCK0)                              Represents whether to disable all the SM crypto fu = False R/W (0b0)
                                                      nctions; including SM2; SM3. 1: disabled 0: enable
                                                      d
   ECC_FORCE_CONST_TIME (BLOCK0)                      Represents whether permanently turn on ECC const-t = False R/W (0b0)
                                                      ime mode.  1: turn on 0: turn off
   DIS_DIRECT_BOOT (BLOCK0)                           Represents whether direct boot mode is disabled or = False R/W (0b0)
                                                      enabled. 1: disabled 0: enabled
   UART_PRINT_CONTROL (BLOCK0)                        Represents the type of UART printing. 00: force en = 0 R/W (0b00)
                                                      able printing 01: enable printing when GPIO8 is re
                                                      set at low level 10: enable printing when GPIO8 is
                                                      reset at high level 11: force disable printing
   HYS_EN_PAD (BLOCK0)                                Represents whether the hysteresis function of corr = False R/W (0b0)
                                                      esponding PAD is enabled. 1: enabled 0:disabled
   DCDC_VSET_EN (BLOCK0)                              Select dcdc vset use efuse_dcdc_vset               = False R/W (0b0)
   DIS_SWD (BLOCK0)                                   Set this bit to disable super-watchdog             = False R/W (0b0)
   BOOTLOADER_ANTI_ROLLBACK_EN (BLOCK0)               Represents whether the ani-rollback check for the  = False R/W (0b0)
                                                      2nd stage bootloader is enabled.1: Enabled0: Disab
                                                      led
   BOOTLOADER_ANTI_ROLLBACK_UPDATE_IN_ROM (BLOCK0)    Represents whether the ani-rollback SECURE_VERSION = False R/W (0b0)
                                                      will be updated from the ROM bootloader.1: Enable
                                                      0: Disable
   SDC_ENA (BLOCK0)                                   Represents whether SDC function is supported in do = 0 R/W (0b00)
                                                      wnload mode. 2'b01/2'b10: enabled2'b00/2'b11: disa
                                                      bled
   SDC_SESSION_COUNTER (BLOCK0)                       Represents the number of times the SDC session has = 0 R/W (0b000)
                                                      been entered
   SDC_NONCE_ENA (BLOCK0)                             Represents whether random number NONCE is used in  = 0 R/W (0b00)
                                                      SDC and whether the KM module is used to generate
                                                      the NONCE. 2'bx0: No NONCE 2'b1x: Use KM generate
                                                      NONCE.
   SDC_CHIP_INFO_SOURCE (BLOCK0)                      Represents whether HUK_info is selected as the sou = False R/W (0b0)
                                                      rce for calculating CHIP_info in SDC.1: use HUK_in
                                                      fo 0: use UNIQ_id
   SDC_DISABLE_FAST_VEF (BLOCK0)                      Represents whether disable FAST_VEF in SDC session = False R/W (0b0)
                                                      .1: disable0: enable
   PVT_0_GLITCH_EN (BLOCK0)                           Represents whether to enable PVT power glitch moni = False R/W (0b0)
                                                      tor function.1:Enable. 0:Disable
   PVT_0_GLITCH_MODE (BLOCK0)                         Use to configure glitch mode                       = 0 R/W (0b00)
   PVT_1_GLITCH_EN (BLOCK0)                           Represents whether to enable PVT power glitch moni = False R/W (0b0)
                                                      tor function.1:Enable. 0:Disable
   PVT_1_GLITCH_MODE (BLOCK0)                         Use to configure glitch mode                       = 0 R/W (0b00)
   POWER_GLITCH_EN (BLOCK0)                           set these bit enable power glitch enable           = 0 R/W (0x0)
   ENA_XTS_SHADOW (BLOCK0)                            Represents whether to enable XTS-AES shadow core c = False R/W (0b0)
                                                      ountermeasure against fault injection attacks.  0:
                                                      Disabled 1: Enabled
   ENA_SPI_BOOT_CRYPT_SCRAMBLER (BLOCK0)              Represents whether to enable ciphertext scrambler  = False R/W (0b0)
                                                      for external memory .  0: Disabled 1: Enabled
   PSRAM_CAP (BLOCK1)                                 Psram capacity                                     = 0 R/W (0b000)
   TEMP (BLOCK1)                                      Maximum ambient temperature that ESP Chip can work = 0 R/W (0b00)
                                                      properly
   PSRAM_VENDOR (BLOCK1)                              Psram vendor                                       = 0 R/W (0b00)
   BLOCK_USR_DATA (BLOCK3)                            User data
      = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W
   BLOCK_SYS_DATA2 (BLOCK9)                           System data part 2 (reserved)                      = 0 R/W (0x00000000)

   Flash fuses:
   FLASH_TYPE (BLOCK0)                                flash type: 0: nor flash; 1: nand flash            = False R/W (0b0)
   FLASH_TPUW (BLOCK0)                                Represents the flash waiting time after power-up;  = 0 R/W (0x0)
                                                      in unit of ms. When the value less than 15; the wa
                                                      iting time is the programmed value. Otherwise; the
                                                      waiting time is 2 times the programmed value
   FORCE_SEND_RESUME (BLOCK0)                         Represents whether ROM code is forced to send a re = False R/W (0b0)
                                                      sume command during SPI boot. 1: forced 0:not forc
                                                      ed
   RECOVERY_BOOTLOADER_FLASH_SECTOR (BLOCK0)          Represents the starting flash sector (flash sector = 0 R/W (0x000)
                                                      size is 0x1000) of the recovery bootloader used b
                                                      y the ROM bootloader If the primary bootloader fai
                                                      ls. 0 and 0xFFF - this feature is disabled
   PMU_FLASH_POWER_SEL (BLOCK0)                       FLASH power select. 1'b1: use 3.3V1'b0: use 1.8V   = False R/W (0b0)
   PMU_FLASH_POWER_SEL_EN (BLOCK0)                    FLASH power select enable signal. 1'b1 : validates = False R/W (0b0)
                                                      EFUSE_PMU_FLASH_POWER_SEL 1'b0: invalidates EFUSE
                                                      _PMU_FLASH_POWER_SEL

   Identity fuses:
   WAFER_VERSION_MINOR (BLOCK1)                       Minor chip version                                 = 0 R/W (0x0)
   WAFER_VERSION_MAJOR (BLOCK1)                       Major chip version                                 = 0 R/W (0b00)
   DISABLE_WAFER_VERSION_MAJOR (BLOCK1)               Disables check of wafer version major              = False R/W (0b0)
   DISABLE_BLK_VERSION_MAJOR (BLOCK1)                 Disables check of blk version major                = False R/W (0b0)
   BLK_VERSION_MINOR (BLOCK1)                         BLK_VERSION_MINOR of BLOCK2                        = 0 R/W (0b000)
   BLK_VERSION_MAJOR (BLOCK1)                         BLK_VERSION_MAJOR of BLOCK2                        = 0 R/W (0b00)
   PKG_VERSION (BLOCK1)                               Package version                                    = 0 R/W (0b00)
   OPTIONAL_UNIQUE_ID (BLOCK2)                        Optional unique 128-bit ID
      = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W

   Jtag fuses:
   JTAG_SEL_ENABLE (BLOCK0)                           Represents whether the selection between usb_to_jt = False R/W (0b0)
                                                      ag and pad_to_jtag through strapping gpio15 when b
                                                      oth EFUSE_DIS_PAD_JTAG and EFUSE_DIS_USB_JTAG are
                                                      equal to 0 is enabled or disabled. 1: enabled 0: d
                                                      isabled
   SOFT_DIS_JTAG (BLOCK0)                             Represents whether JTAG is disabled in soft way. O = 0 R/W (0b000)
                                                      dd number: disabled Even number: enabled
   DIS_PAD_JTAG (BLOCK0)                              Represents whether JTAG is disabled in the hard wa = False R/W (0b0)
                                                      y(permanently). 1: disabled 0: enabled
   RE_ENABLE_JTAG_SOURCE (BLOCK0)                     Represents which Crypto peripheral is selected for = False R/W (0b0)
                                                      re-enabling JTAG.  0: SDC 1: HMAC

   Mac fuses:
   MAC (BLOCK1)                                       MAC address
      = 30:ed:a0:ed:4d:5c (OK) R/W
   MAC_EXT (BLOCK1)                                   Represents the extended bits of MAC address        = 00:00 (OK) R/W
   CUSTOM_MAC (BLOCK3)                                Custom MAC
      = 00:00:00:00:00:00 (OK) R/W

   Security fuses:
   DIS_FORCE_DOWNLOAD (BLOCK0)                        Represents whether the function that forces chip i = False R/W (0b0)
                                                      nto download mode is disabled or enabled. 1: disab
                                                      led 0: enabled
   SPI_DOWNLOAD_MSPI_DIS (BLOCK0)                     Represents whether SPI0 controller during boot_mod = False R/W (0b0)
                                                      e_download is disabled or enabled. 1: disabled 0:
                                                      enabled
   DIS_DOWNLOAD_MANUAL_ENCRYPT (BLOCK0)               Represents whether flash encrypt function is disab = False R/W (0b0)
                                                      led or enabled(except in SPI boot mode). 1: disabl
                                                      ed 0: enabled
   FORCE_USE_KEY_MANAGER_KEY (BLOCK0)                 Represents whether corresponding key must come fro = 0 R/W (0b00000)
                                                      m key manager. 1 is true; 0 is false. 0: ecsda 1:
                                                      flash 2: reserved 3: reserved 4: psram
   FORCE_DISABLE_SW_INIT_KEY (BLOCK0)                 Represents whether to disable software written ini = False R/W (0b0)
                                                      t key; and force use efuse_init_key
   KM_XTS_KEY_LENGTH_256 (BLOCK0)                     Represents whether to configure flash encryption u = False R/W (0b0)
                                                      se xts-128 key. else use xts-256 key.  0: 128-bit
                                                      key  1: 256-bit key
   SPI_BOOT_CRYPT_CNT (BLOCK0)                        Enables flash encryption when 1 or 3 bits are set  = Disable R/W (0b000)
                                                      and disables otherwise
   SECURE_BOOT_KEY_REVOKE0 (BLOCK0)                   Revoke 1st secure boot key                         = False R/W (0b0)
   SECURE_BOOT_KEY_REVOKE1 (BLOCK0)                   Revoke 2nd secure boot key                         = False R/W (0b0)
   SECURE_BOOT_KEY_REVOKE2 (BLOCK0)                   Revoke 3rd secure boot key                         = False R/W (0b0)
   KEY_PURPOSE_0 (BLOCK0)                             Represents the purpose of Key0                     = USER R/W (0b00000)
   KEY_PURPOSE_1 (BLOCK0)                             Represents the purpose of Key1                     = USER R/W (0b00000)
   KEY_PURPOSE_2 (BLOCK0)                             Represents the purpose of Key2                     = USER R/W (0b00000)
   KEY_PURPOSE_3 (BLOCK0)                             Represents the purpose of Key3                     = USER R/W (0b00000)
   KEY_PURPOSE_4 (BLOCK0)                             Represents the purpose of Key4                     = USER R/W (0b00000)
   ECDSA_DISABLE_SOFT_K (BLOCK0)                      Represents whether permanently turn off ECDSA soft = False R/W (0b0)
                                                      ware set KEY. 1: turn off 0: turn on
   SEC_DPA_LEVEL (BLOCK0)                             Represents the spa secure level by configuring the = 0 R/W (0b00)
                                                      clock random divide mode
   XTS_DPA_CLK_ENABLE (BLOCK0)                        Represents whether to enable xts clock anti-dpa at = False R/W (0b0)
                                                      tack function.0: Disabled. 1: Enabled
   XTS_DPA_PSEUDO_LEVEL (BLOCK0)                      Represents the control of the xts pseudo-round ant = 0 R/W (0b00)
                                                      i-dpa attack function. 0: controlled by register.
                                                      1-3: the higher the value is; the more pseudo-roun
                                                      ds are inserted to the xts-aes calculation
   SECURE_BOOT_EN (BLOCK0)                            Represents whether secure boot is enabled or disab = False R/W (0b0)
                                                      led. 1: enabled 0: disabled
   SECURE_BOOT_AGGRESSIVE_REVOKE (BLOCK0)             Represents whether revoking aggressive secure boot = False R/W (0b0)
                                                      is enabled or disabled. 1: enabled. 0: disabled
   DIS_DOWNLOAD_MODE (BLOCK0)                         Represents whether Download mode is disabled or en = False R/W (0b0)
                                                      abled. 1: disabled 0: enabled
   LOCK_KM_KEY (BLOCK0)                               Represetns whether to lock the efuse xts key. 1. L = False R/W (0b0)
                                                      ock 0: Unlock
   ENABLE_SECURITY_DOWNLOAD (BLOCK0)                  Represents whether security download is enabled or = False R/W (0b0)
                                                      disabled. 1: enabled 0: disabled
   SECURE_VERSION (BLOCK0)                            Represents the version used by ESP-IDF anti-rollba = 0 R/W (0x0000)
                                                      ck feature
   SECURE_BOOT_DISABLE_FAST_WAKE (BLOCK0)             Represents whether FAST VERIFY ON WAKE is disabled = False R/W (0b0)
                                                      or enabled when Secure Boot is enabled. 1: disabl
                                                      ed 0: enabled
   SECURE_BOOT_SHA384_EN (BLOCK0)                     Represents whether secure boot using SHA-384 is en = False R/W (0b0)
                                                      abled. 0: Disable 1: Enable
   BOOTLOADER_ANTI_ROLLBACK_SECURE_VERSION (BLOCK0)   Represents the anti-rollback secure version of the = 0 R/W (0x0)
                                                      2nd stage bootloader used by the ROM bootloader
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

   Usb fuses:
   DIS_USB_JTAG (BLOCK0)                              Represents whether the function of usb switch to j = False R/W (0b0)
                                                      tag is disabled or enabled. 1: disabled 0: enabled
   DIS_USB_OTG_DOWNLOAD_MODE (BLOCK0)                 Set this bit to disable download via USB-OTG       = False R/W (0b0)
   DIS_USB_SERIAL_JTAG_ROM_PRINT (BLOCK0)             Represents whether print from USB-Serial-JTAG is d = False R/W (0b0)
                                                      isabled or enabled. 1: disabled 0: enabled
   DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE (BLOCK0)         Represents whether the USB-Serial-JTAG download fu = False R/W (0b0)
                                                      nction is disabled or enabled. 1: Disable 0: Enabl
                                                      e
   USB_DEVICE_EXCHG_PINS (BLOCK9)                     Represents whether enable usb device exchange pins = False R/W (0b0)
                                                      of D+ and D- or not.  1: enabled 0: disabled

   Wdt fuses:
   WDT_DELAY_SEL (BLOCK0)                             Represents the threshold level of the RTC watchdog = False R/W (0b0)
                                                      STG0 timeout.0: Original threshold configuration
                                                      value of STG0 *2 1: Original threshold configurati
                                                      on value of STG0 *4 2: Original threshold configur
                                                      ation value of STG0 *8 3: Original threshold confi
                                                      guration value of STG0 *16
   DIS_WDT (BLOCK0)                                   Set this bit to disable watch dog                  = False R/W (0b0)
