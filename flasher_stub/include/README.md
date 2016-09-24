These header files for ESP register access are adapted from BSD licensed headers of the esp-open-rtos project:
https://github.com/SuperHouse/esp-open-rtos

The actual headers can be found here:
https://github.com/SuperHouse/esp-open-rtos/tree/master/core/include/esp

Why use these?
* They're BSD licensed not "Espressif MIT License" which only works on ESP8266 (not even ESP32 in its current wording).
* They're BSD licensed so GPL compatible.
* The syntax is (subjectively) a lot nicer to use than Espressif's register headers.
