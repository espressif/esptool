Flashing from your python code
==============================

The following is an example on how to flash the ESP32 from a custom application:

```
#############################################################
# Example code functionally equivalent to
# esptool.py -p /dev/ttyACM0 write_flash 0x10000 firmware.bin
#############################################################
from esptool.cmds import detect_chip

# the port of the connected ESP32
port = "/dev/ttyACM0"

# The firmware file
filename = "./firmware.bin"

# Typical block size (16 KB)
BLOCK_SIZE = 0x4000

#beginning of flash address
FLASH_BEGIN = 0x10000

def progress_callback(percent):
    print(f"percent {int(percent)}")
    
with detect_chip(port) as esp:
    chip_desc = esp.get_chip_description()
    features = esp.get_chip_features()
    print(f"Detected bootloader on port {port} : {chip_desc}")
    print(f"Features {features}")
    
    stub = esp.run_stub()
    with open(filename, 'rb') as firmware:
        firmware_data = firmware.read()
        print(f"firmware length {len(firmware_data)}")
        total_size = len(firmware_data)
        stub.flash_begin(total_size, FLASH_BEGIN)

        # Flash in blocks using flash_block
        block_size = BLOCK_SIZE
        for i in range(0, total_size, block_size):
            block = firmware_data[i:i + block_size]
            # pad the last block
            block = block + bytes([0xFF]) * (BLOCK_SIZE - len(block))
            stub.flash_block(block, i + FLASH_BEGIN)
            progress_callback(float(i + len(block)) / total_size * 100)
        stub.flash_finish()
        
        stub.hard_reset()
```
