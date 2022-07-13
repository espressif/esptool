from .esp32 import ESP32ROM
from .esp32c2 import ESP32C2ROM
from .esp32c3 import ESP32C3ROM
from .esp32c6 import ESP32C6ROM
from .esp32c6beta import ESP32C6BETAROM
from .esp32h2beta1 import ESP32H2BETA1ROM
from .esp32h2beta2 import ESP32H2BETA2ROM
from .esp32s2 import ESP32S2ROM
from .esp32s3 import ESP32S3ROM
from .esp32s3beta2 import ESP32S3BETA2ROM
from .esp8266 import ESP8266ROM


CHIP_DEFS = {
    "esp8266": ESP8266ROM,
    "esp32": ESP32ROM,
    "esp32s2": ESP32S2ROM,
    "esp32s3beta2": ESP32S3BETA2ROM,
    "esp32s3": ESP32S3ROM,
    "esp32c3": ESP32C3ROM,
    "esp32c6beta": ESP32C6BETAROM,
    "esp32h2beta1": ESP32H2BETA1ROM,
    "esp32h2beta2": ESP32H2BETA2ROM,
    "esp32c2": ESP32C2ROM,
    "esp32c6": ESP32C6ROM,
}

CHIP_LIST = list(CHIP_DEFS.keys())
ROM_LIST = list(CHIP_DEFS.values())
