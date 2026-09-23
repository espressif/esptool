# test/images fixtures

Licensing: see [`../LICENSE`](../LICENSE).

- IDF/SDK-built binaries follow ESP-IDF licensing (Apache-2.0 for IDF code,
  plus third-party components such as newlib) — not CC0.
- Size/fill blobs from [`../bin_builder.py`](../bin_builder.py) and RAM hello
  world images from [`../ram_helloworld_builder.py`](../ram_helloworld_builder.py)
  are generated at test time and are not committed.

Do not invent firmware goldens with `esptool`/`espsecure` when running the
suite (circular). Rebuild from the recipes below only when updating a fixture.

## `ram_helloworld/helloworld-*.bin` (not committed)

`test_esptool.py` runs these images in the on-device `load-ram` tests and
writes the ESP32 image in the encrypted `write-flash` tests. With
`--preload-port`, it also loads the chip's image through that port with
`--no-stub load-ram` before each test, which disables the RTC watchdog on chips
connected through USB-Serial/JTAG. `test_merge_bin.py` and `test_image_info.py`
read the ESP32 images.

```bash
python test/ram_helloworld_builder.py   # also run automatically at pytest start
```

[`../ram_helloworld_builder.py`](../ram_helloworld_builder.py) is the only
definition of these images; there is no C source or linker script. Each image
has a `.text` segment that calls the ROM `ets_printf` in a loop and a 16-byte
segment holding `"Hello world!\n"`. The builder takes the machine code from one
of three fixed templates, two for Xtensa and one for RISC-V, and fills in the
per-chip addresses from its `CHIPS` table. It writes the image header, checksum
and SHA-256 (none on ESP8266) without running esptool.

### Adding a chip

Add one `ChipParams` entry to `CHIPS` in the builder. The key is the chip name
that `--chip` takes, for example `esp32c61`. The tests open
`helloworld-<chip>.bin` by that name.

```python
"<chip>": ChipParams(iram, dram, ets_printf, RISCV, chip_id),
```

1. `chip_id`: `IMAGE_CHIP_ID` from `esptool/targets/<chip>.py`, written in hex.
2. `isa`: `RISCV` for a RISC-V chip. `XTENSA_WINDOWED` is for ESP32,
   ESP32-S2 and ESP32-S3, and `XTENSA_LX106` is for ESP8266.
3. `ets_printf`: the address on the `ets_printf = 0x...;` line of the chip's
   ROM linker script. The script is `src/target/<chip>/ld/<chip>.rom.ld` in
   [esp-stub-lib](https://github.com/espressif/esp-stub-lib), or
   `components/esp_rom/<chip>/ld/<chip>.rom.ld` in ESP-IDF. Do not take the
   address from the `ets_printf` symbol of a ROM ELF file. On chips with a ROM
   jump table (all except ESP8266, ESP32 and ESP32-S2), that symbol is the
   function body, which can move between chip revisions. The linker script
   gives the function's entry in the jump table, which has the same address on
   every revision.
4. `iram` and `dram`: where `load-ram` writes the code (32 bytes with `RISCV`,
   24 with `XTENSA_WINDOWED`, 28 with `XTENSA_LX106`) and the string (16
   bytes). Pick 4-byte-aligned addresses that meet all of the conditions below.
   On chips where instruction and data RAM share one address range, such as
   ESP32-C6 and ESP32-C61, `dram = iram + 0x100` works.
   - `iram` is in the chip's instruction RAM and `dram` is in its data RAM.
     The ranges are `SOC_IRAM_LOW` to `SOC_IRAM_HIGH` and `SOC_DRAM_LOW` to
     `SOC_DRAM_HIGH` in `soc.h`: `components/soc/<chip>/include/soc/soc.h` in
     ESP-IDF, or `src/target/<chip>/include/soc/soc.h` in esp-stub-lib. Do not
     use `MEMORY_MAP` in `esptool/targets/<chip>.py`. Some chips inherit it
     from another chip, and on several chips it is larger than the real RAM.
   - Neither segment overlaps a flasher stub. For each
     `esptool/targets/stub_flasher/*/<chip>.json` and `<chip>-rev*.json`, the
     stub occupies `text_start` up to `text_start` plus the decoded length of
     `text`, and `bss_start` up to `data_start` plus the decoded length of
     `data`. `TestLoadRAM` loads the image with the stub running, and esptool
     refuses a segment that overlaps the stub. Leave room for the stub to grow.
   - Neither segment overlaps the RAM the ROM uses in download mode (shared
     buffers, stack, `.bss` and `.data`). The "ROM static data usage" comment
     in ESP-IDF
     `components/bootloader/subproject/main/ld/<chip>/bootloader.memory.ld.in`
     lists that region. ESP32 and ESP32-S2 have no such comment, and on
     ESP32-P4 it describes chip revisions before v3.
   - On chips whose `soc.h` defines `SOC_I_D_OFFSET` (ESP32-C2, ESP32-C3,
     ESP32-S2 and ESP32-S3), the same SRAM also has a data address. Subtract
     `SOC_I_D_OFFSET` from `iram` to get it (`MAP_IRAM_TO_DRAM` in the same
     file). The code segment at that data address must not overlap a flasher
     stub, the ROM region above, or the `dram` segment. Esptool compares only
     the addresses written in the image, so it does not report these overlaps.
   - The two segments do not overlap each other.

   The ESP32-C2, ESP32-C3, ESP32-C61 and ESP32-S3 entries meet all of these
   conditions. Several older entries do not, so do not copy another chip's
   addresses without checking them.

Then check the image and enable its tests:

1. Run the builder and inspect the new image:

   ```bash
   python test/ram_helloworld_builder.py
   esptool image-info test/images/ram_helloworld/helloworld-<chip>.bin
   ```

   The output must name the chip and show the entry point at `iram`
   (`iram + 8` on Xtensa), and the checksum and validation hash must be marked
   valid.
2. In `test_esptool.py`, find the `TestLoadRAM` skip marker whose reason is
   "No RAM helloworld binary available". Delete the marker if it skips only
   this chip; otherwise remove the chip from its condition.
3. On a board, run the `TestLoadRAM` tests. They load the image with the
   flasher stub and check the serial port for `Hello world!`:

   ```bash
   pytest test/test_esptool.py -k TestLoadRAM --chip <chip> --port <port>
   ```

4. Load the image through the ROM loader, without the stub, the way the
   `--preload-port` step does:

   ```bash
   esptool --chip <chip> --port <port> --no-stub load-ram test/images/ram_helloworld/helloworld-<chip>.bin
   ```

   Open the port at 115200 baud and check that the chip prints `Hello world!`.

## Size/fill blobs (not committed)

`one_kb.bin`, `one_mb.bin`, `fifty_kb.bin`, `sector.bin`, `zerolength.bin`,
`onebyte.bin`, `one_kb_all_ef.bin`, `aes_key.bin`:

```bash
python test/bin_builder.py   # also run automatically at pytest start
```

Generated with fixed xorshift seeds in [`../bin_builder.py`](../bin_builder.py)
(not bit-identical to the old committed files). `one_kb.bin` still starts with
`0xED` for `test_image_info.py` invalid-magic coverage.

## Bootloaders

| File                        | How to rebuild                                                                                                                                                                 |
|-----------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `bootloader_esp32_v5_2.bin` | ESP-IDF `examples/get-started/hello_world` for esp32 → `idf.py bootloader` → copy `build/bootloader/bootloader.bin`. Update `test_image_info.py` if embedded metadata changes. |
| `bootloader_esp32.bin`      | ESP-IDF bootloader for esp32. Tests pin size **7888** bytes — update asserts if the new build differs.                                                                         |
| `bootloader_esp32c3.bin`    | ESP-IDF bootloader for esp32c3. `image-info` asserts pin layout/checksum — update them if refreshing.                                                                          |
| `bootloader_esp8266.bin`    | ESP8266 SDK bootloader for that chip.                                                                                                                                          |

## Apps and other IDF artifacts

| File                                               | How to rebuild                                                                                                                                   |
|----------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| `esp_idf_blink_esp32s2.bin`                        | ESP-IDF blink example for esp32s2; copy the app binary. Update `test_image_info.py` app-info asserts if metadata changes.                        |
| `partitions_singleapp.bin`                         | See partition CSV below → `gen_esp32part.py`.                                                                                                    |
| `esp32c3_header_min_rev.bin`, `esp32s3_header.bin` | 48-byte header-only stubs (`0xE9` magic) for chip/revision write-flash checks — not full firmware. Edit header fields or truncate a known image. |

`partitions_singleapp.bin` CSV equivalent:

```csv
# Name,   Type, SubType, Offset,  Size
factory,  app,  factory, 0x10000, 1M
rfdata,   data, phy,     0x110000, 0x40000
wifidata, data, nvs,     0x150000, 0x40000
```

```bash
python $IDF_PATH/components/partition_table/gen_esp32part.py singleapp.csv partitions_singleapp.bin
```

## No in-tree rebuild recipe

| File | Notes |
|--------------------------|------------------------------------------------------------------------------|
| `not_4_byte_aligned.bin` | ESP8266 `image-info` golden; no source here.                                 |
| `esp8266_deepsleep.bin`  | Historical deep-sleep regression image; no complete source here.             |
| `efuse/*`                | Opaque test key blobs + `esp_efuse_custom_table.csv` (CSV is the editable form). |

These paths are listed under “Third-party or incomplete-source fixtures” in
[`../LICENSE`](../LICENSE).
