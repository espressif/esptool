.. code-block:: none

    > espefuse.py -p PORT summary

    Connecting...................
    Detecting chip type... ESP32-C2

    === Run "summary" command ===
    EFUSE_NAME (Block) Description  = [Meaningful Value] [Readable/Writeable] (Hex Value)
    ----------------------------------------------------------------------------------------
    Config fuses:
    WR_DIS (BLOCK0)                                    Disable programming of individual eFuses           = 0 R/W (0x00)
    RD_DIS (BLOCK0)                                    Disable reading from BlOCK3                        = 0 R/W (0b00)
    UART_PRINT_CONTROL (BLOCK0)                        Set the default UARTboot message output mode       = Enable R/W (0b00)
    DIS_DIRECT_BOOT (BLOCK0)                           This bit set means disable direct_boot mode        = False R/W (0b0)

    Flash fuses:
    FORCE_SEND_RESUME (BLOCK0)                         Set this bit to force ROM code to send a resume co = False R/W (0b0)
                                                       mmand during SPI boot                             
    FLASH_TPUW (BLOCK0)                                Configures flash waiting time after power-up; in u = 0 R/W (0x0)
                                                       nit of ms. If the value is less than 15; the waiti
                                                       ng time is the configurable value.  Otherwise; the
                                                        waiting time is twice the configurable value     

    Identity fuses:
    DISABLE_WAFER_VERSION_MAJOR (BLOCK0)               Disables check of wafer version major              = False R/W (0b0)
    DISABLE_BLK_VERSION_MAJOR (BLOCK0)                 Disables check of blk version major                = False R/W (0b0)
    WAFER_VERSION_MINOR (BLOCK2)                       WAFER_VERSION_MINOR                                = 0 R/W (0x0)
    WAFER_VERSION_MAJOR (BLOCK2)                       WAFER_VERSION_MAJOR                                = 1 R/W (0b01)
    PKG_VERSION (BLOCK2)                               EFUSE_PKG_VERSION                                  = 1 R/W (0b001)
    BLK_VERSION_MINOR (BLOCK2)                         Minor version of BLOCK2                            = No calib R/W (0b000)
    BLK_VERSION_MAJOR (BLOCK2)                         Major version of BLOCK2                            = 0 R/W (0b00)

    Jtag fuses:
    DIS_PAD_JTAG (BLOCK0)                              Set this bit to disable pad jtag                   = False R/W (0b0)

    Mac fuses:
    CUSTOM_MAC_USED (BLOCK0)                           True if MAC_CUSTOM is burned                       = False R/W (0b0)
    CUSTOM_MAC (BLOCK1)                                Custom MAC address                                
    = 00:00:00:00:00:00 (OK) R/W 
    MAC (BLOCK2)                                       MAC address                                       
    = 10:97:bd:f0:e5:28 (OK) R/W 

    Security fuses:
    DIS_DOWNLOAD_ICACHE (BLOCK0)                       The bit be set to disable icache in download mode  = False R/W (0b0)
    DIS_DOWNLOAD_MANUAL_ENCRYPT (BLOCK0)               The bit be set to disable manual encryption        = False R/W (0b0)
    SPI_BOOT_CRYPT_CNT (BLOCK0)                        Enables flash encryption when 1 or 3 bits are set  = Disable R/W (0b000)
                                                       and disables otherwise                            
    XTS_KEY_LENGTH_256 (BLOCK0)                        Flash encryption key length                        = 128 bits key R/W (0b0)
    DIS_DOWNLOAD_MODE (BLOCK0)                         Set this bit to disable download mode (boot_mode[3 = False R/W (0b0)
                                                       :0] = 0; 1; 2; 4; 5; 6; 7)                        
    ENABLE_SECURITY_DOWNLOAD (BLOCK0)                  Set this bit to enable secure UART download mode   = False R/W (0b0)
    SECURE_BOOT_EN (BLOCK0)                            The bit be set to enable secure boot               = False R/W (0b0)
    SECURE_VERSION (BLOCK0)                            Secure version for anti-rollback                   = 0 R/W (0x0)
    BLOCK_KEY0 (BLOCK3)                                BLOCK_KEY0 - 256-bits. 256-bit key of Flash Encryp
    = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W 
                                                    tion                                              
    BLOCK_KEY0_LOW_128 (BLOCK3)                        BLOCK_KEY0 - lower 128-bits. 128-bit key of Flash 
    = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W 
                                                    Encryption                                        
    BLOCK_KEY0_HI_128 (BLOCK3)                         BLOCK_KEY0 - higher 128-bits. 128-bits key of Secu
    = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W 
                                                       re Boot                                           

    Wdt fuses:
    WDT_DELAY_SEL (BLOCK0)                             RTC watchdog timeout threshold; in unit of slow cl = 40000 R/W (0b00)
                                                       ock cycle
