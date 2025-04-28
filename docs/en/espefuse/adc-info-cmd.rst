.. _adc-info-cmd:

Adc Info
========

The ``espefuse.py adc-info`` command displays information about ADC calibration data stored in eFuse.

.. only:: esp32

    .. code-block:: none

        > espefuse.py adc-info

        === Run "adc-info" command ===
        ADC VRef calibration: 1121mV

.. only:: esp32c3 or esp32s2 or esp32s3

    .. code-block:: none

        > espefuse.py adc-info

        === Run "adc-info" command ===
        Temperature Sensor Calibration = -2.1C

        ADC1 readings stored in efuse BLOCK2:
            MODE0 D1 reading  (250mV):  76
            MODE0 D2 reading  (600mV):  340
            MODE1 D1 reading  (250mV):  -100
            MODE1 D2 reading  (800mV):  356
            MODE2 D1 reading  (250mV):  116
            MODE2 D2 reading  (1000mV): -136
            MODE3 D1 reading  (250mV):  8
            MODE3 D2 reading  (2000mV): 304

        ADC2 readings stored in efuse BLOCK2:
            MODE0 D1 reading  (250mV):  0
            MODE0 D2 reading  (600mV):  168
            MODE1 D1 reading  (250mV):  0
            MODE1 D2 reading  (800mV):  300
            MODE2 D1 reading  (250mV):  0
            MODE2 D2 reading  (1000mV): -404
            MODE3 D1 reading  (250mV):  0
            MODE3 D2 reading  (2000mV): -32

.. only:: esp32c2

    .. code-block:: none

        > espefuse.py adc-info

        === Run "adc-info" command ===
            RF_REF_I_BIAS_CONFIG:        0
            LDO_VOL_BIAS_CONFIG_LOW:     0
            LDO_VOL_BIAS_CONFIG_HIGH:    0
            PVT_LOW:                     0
            PVT_HIGH:                    0
            ADC_CALIBRATION_0:           0
            ADC_CALIBRATION_1:           0
            ADC_CALIBRATION_2:           0
