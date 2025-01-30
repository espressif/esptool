# SPDX-FileCopyrightText: 2014-2025 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import hashlib
import io
import os
import struct
import sys
import time
import zlib
import itertools
import re

from intelhex import IntelHex
from serial import SerialException

from .bin_image import ELFFile, ImageSegment, LoadFirmwareImage
from .bin_image import (
    ESP8266ROMFirmwareImage,
    ESP8266V2FirmwareImage,
    ESP8266V3FirmwareImage,
)
from .loader import (
    DEFAULT_CONNECT_ATTEMPTS,
    DEFAULT_TIMEOUT,
    ERASE_WRITE_TIMEOUT_PER_MB,
    ESPLoader,
    timeout_per_mb,
)
from .logger import log

from .targets import CHIP_DEFS, CHIP_LIST, ROM_LIST
from .uf2_writer import UF2Writer
from .util import (
    FatalError,
    NotImplementedInROMError,
    NotSupportedError,
    UnsupportedCommandError,
)
from .util import (
    div_roundup,
    flash_size_bytes,
    get_file_size,
    hexify,
    pad_to,
)

DETECTED_FLASH_SIZES = {
    0x12: "256KB",
    0x13: "512KB",
    0x14: "1MB",
    0x15: "2MB",
    0x16: "4MB",
    0x17: "8MB",
    0x18: "16MB",
    0x19: "32MB",
    0x1A: "64MB",
    0x1B: "128MB",
    0x1C: "256MB",
    0x20: "64MB",
    0x21: "128MB",
    0x22: "256MB",
    0x32: "256KB",
    0x33: "512KB",
    0x34: "1MB",
    0x35: "2MB",
    0x36: "4MB",
    0x37: "8MB",
    0x38: "16MB",
    0x39: "32MB",
    0x3A: "64MB",
}

FLASH_MODES = {"qio": 0, "qout": 1, "dio": 2, "dout": 3}


def detect_chip(
    port=ESPLoader.DEFAULT_PORT,
    baud=ESPLoader.ESP_ROM_BAUD,
    connect_mode="default_reset",
    trace_enabled=False,
    connect_attempts=DEFAULT_CONNECT_ATTEMPTS,
):
    """Use serial access to detect the chip type.

    First, get_security_info command is sent to detect the ID of the chip
    (supported only by ESP32-C3 and later, works even in the Secure Download Mode).
    If this fails, we reconnect and fall-back to reading the magic number.
    It's mapped at a specific ROM address and has a different value on each chip model.
    This way we use one memory read and compare it to the magic number for each chip.

    This routine automatically performs ESPLoader.connect() (passing
    connect_mode parameter) as part of querying the chip.
    """
    inst = None
    detect_port = ESPLoader(port, baud, trace_enabled=trace_enabled)
    if detect_port.serial_port.startswith("rfc2217:"):
        detect_port.USES_RFC2217 = True
    detect_port.connect(connect_mode, connect_attempts, detecting=True)

    def check_if_stub(instance):
        log.print(f" {instance.CHIP_NAME}")
        if detect_port.sync_stub_detected:
            instance = instance.STUB_CLASS(instance)
            instance.sync_stub_detected = True
        return instance

    try:
        log.print("Detecting chip type...", end="")
        chip_id = detect_port.get_chip_id()
        for cls in ROM_LIST:
            # cmd not supported on ESP8266 and ESP32 + ESP32-S2 doesn't return chip_id
            if cls.USES_MAGIC_VALUE:
                continue
            if chip_id == cls.IMAGE_CHIP_ID:
                inst = cls(detect_port._port, baud, trace_enabled=trace_enabled)
                try:
                    inst.read_reg(
                        ESPLoader.CHIP_DETECT_MAGIC_REG_ADDR
                    )  # Dummy read to check Secure Download mode
                except UnsupportedCommandError:
                    inst.secure_download_mode = True
                inst = check_if_stub(inst)
                inst._post_connect()
                break
        else:
            err_msg = f"Unexpected chip ID value {chip_id}."
    except (UnsupportedCommandError, struct.error, FatalError) as e:
        # UnsupportedCommandError: ESP8266/ESP32 ROM
        # struct.error: ESP32-S2
        # FatalError: ESP8266/ESP32 STUB
        log.print(" Unsupported detection protocol, switching and trying again...")
        try:
            # ESP32/ESP8266 are reset after an unsupported command, need to reconnect
            # (not needed on ESP32-S2)
            if not isinstance(e, struct.error):
                detect_port.connect(
                    connect_mode, connect_attempts, detecting=True, warnings=False
                )
            log.print("Detecting chip type...", end="")
            sys.stdout.flush()
            chip_magic_value = detect_port.read_reg(
                ESPLoader.CHIP_DETECT_MAGIC_REG_ADDR
            )

            for cls in ROM_LIST:
                if not cls.USES_MAGIC_VALUE:
                    continue
                if chip_magic_value == cls.MAGIC_VALUE:
                    inst = cls(detect_port._port, baud, trace_enabled=trace_enabled)
                    inst = check_if_stub(inst)
                    inst._post_connect()
                    break
            else:
                err_msg = f"Unexpected chip magic value {chip_magic_value:#010x}."
        except UnsupportedCommandError:
            raise FatalError(
                "Unsupported Command Error received. "
                "Probably this means Secure Download Mode is enabled, "
                "autodetection will not work. Need to manually specify the chip."
            )
    if inst is not None:
        return inst

    raise FatalError(
        f"{err_msg} Failed to autodetect chip type."
        "\nProbably it is unsupported by this version of esptool."
    )


# "Operation" commands, executable at command line. One function each
#
# Each function takes either two args (<ESPLoader instance>, <args>) or a single <args>
# argument.


def load_ram(esp, args):
    image = LoadFirmwareImage(esp.CHIP_NAME, args.filename)

    log.print("RAM boot...")
    for seg in image.segments:
        size = len(seg.data)
        log.print(f"Downloading {size} bytes at {seg.addr:08x}...", end=" ")
        sys.stdout.flush()
        esp.mem_begin(
            size, div_roundup(size, esp.ESP_RAM_BLOCK), esp.ESP_RAM_BLOCK, seg.addr
        )

        seq = 0
        while len(seg.data) > 0:
            esp.mem_block(seg.data[0 : esp.ESP_RAM_BLOCK], seq)
            seg.data = seg.data[esp.ESP_RAM_BLOCK :]
            seq += 1
        log.print("done!")

    log.print(f"All segments done, executing at {image.entrypoint:08x}")
    esp.mem_finish(image.entrypoint)


def read_mem(esp, args):
    log.print(f"0x{args.address:08x} = 0x{esp.read_reg(args.address):08x}")


def write_mem(esp, args):
    esp.write_reg(args.address, args.value, args.mask, 0)
    log.print(f"Wrote {args.value:08x}, mask {args.mask:08x} to {args.address:08x}")


def dump_mem(esp, args):
    with open(args.filename, "wb") as f:
        log.set_progress(0)
        for i in range(args.size // 4):
            d = esp.read_reg(args.address + (i * 4))
            f.write(struct.pack(b"<I", d))
            if f.tell() % 1024 == 0:
                percent = f.tell() * 100 // args.size
                log.set_progress(percent)
                log.print_overwrite(f"{f.tell()} bytes read... ({percent} %)")
            sys.stdout.flush()
        log.print_overwrite(f"Read {f.tell()} bytes", last_line=True)
    log.print("Done!")


def detect_flash_size(esp, args=None):
    # TODO: Remove the dependency on args in the next major release (v5.0)
    if esp.secure_download_mode:
        if args is not None and args.flash_size == "detect":
            raise FatalError(
                "Detecting flash size is not supported in secure download mode. "
                "Need to manually specify flash size."
            )
        else:
            return None
    flash_id = esp.flash_id()
    size_id = flash_id >> 16
    flash_size = DETECTED_FLASH_SIZES.get(size_id)
    if args is not None and args.flash_size == "detect":
        if flash_size is None:
            flash_size = "4MB"
            log.warning(
                "Could not auto-detect Flash size "
                f"(FlashID={flash_id:#x}, SizeID={size_id:#x}), defaulting to 4MB"
            )
        else:
            log.print("Auto-detected Flash size:", flash_size)
        args.flash_size = flash_size
    return flash_size


def _update_image_flash_params(esp, address, args, image):
    """
    Modify the flash mode & size bytes if this looks like an executable bootloader image
    """
    if len(image) < 8:
        return image  # not long enough to be a bootloader image

    # unpack the (potential) image header
    magic, _, flash_mode, flash_size_freq = struct.unpack("BBBB", image[:4])
    if address != esp.BOOTLOADER_FLASH_OFFSET:
        return image  # not flashing bootloader offset, so don't modify this

    if (args.flash_mode, args.flash_freq, args.flash_size) == ("keep",) * 3:
        return image  # all settings are 'keep', not modifying anything

    # easy check if this is an image: does it start with a magic byte?
    if magic != esp.ESP_IMAGE_MAGIC:
        log.warning(
            f"Image file at 0x{address:x} doesn't look like an image file, "
            "so not changing any flash settings."
        )

        return image

    # make sure this really is an image, and not just data that
    # starts with esp.ESP_IMAGE_MAGIC (mostly a problem for encrypted
    # images that happen to start with a magic byte
    try:
        test_image = esp.BOOTLOADER_IMAGE(io.BytesIO(image))
        test_image.verify()
    except Exception:
        log.warning(
            "Image file at 0x{address:x} is not a valid {esp.CHIP_NAME} image,"
            " so not changing any flash settings."
        )
        return image

    # After the 8-byte header comes the extended header for chips others than ESP8266.
    # The 15th byte of the extended header indicates if the image is protected by
    # a SHA256 checksum. In that case we recalculate the SHA digest after modifying the header.
    sha_appended = args.chip != "esp8266" and image[8 + 15] == 1

    if args.flash_mode != "keep":
        flash_mode = FLASH_MODES[args.flash_mode]

    flash_freq = flash_size_freq & 0x0F
    if args.flash_freq != "keep":
        flash_freq = esp.parse_flash_freq_arg(args.flash_freq)

    flash_size = flash_size_freq & 0xF0
    if args.flash_size != "keep":
        flash_size = esp.parse_flash_size_arg(args.flash_size)

    flash_params = struct.pack(b"BB", flash_mode, flash_size + flash_freq)
    if flash_params != image[2:4]:
        log.print(f"Flash params set to 0x{struct.unpack('>H', flash_params)[0]:04x}")
        image = image[0:2] + flash_params + image[4:]

    # recalculate the SHA digest if it was appended
    if sha_appended:
        # Since the changes are only made for images located in the bootloader offset,
        # we can assume that the image is always a bootloader image.
        # For merged binaries, we check the bootloader SHA when parameters are changed.
        image_object = esp.BOOTLOADER_IMAGE(io.BytesIO(image))
        # get the image header, extended header (if present) and data
        image_data_before_sha = image[: image_object.data_length]
        # get the image data after the SHA digest (primary for merged binaries)
        image_data_after_sha = image[
            (image_object.data_length + image_object.SHA256_DIGEST_LEN) :
        ]

        sha_digest_calculated = hashlib.sha256(image_data_before_sha).digest()
        image = bytes(
            itertools.chain(
                image_data_before_sha, sha_digest_calculated, image_data_after_sha
            )
        )

        # get the SHA digest newly stored in the image and compare it to the calculated one
        image_stored_sha = image[
            image_object.data_length : image_object.data_length
            + image_object.SHA256_DIGEST_LEN
        ]

        if hexify(sha_digest_calculated) == hexify(image_stored_sha):
            log.print("SHA digest in image updated")
        else:
            log.warning(
                "SHA recalculation for binary failed!\n"
                f"\tExpected calculated SHA: {hexify(sha_digest_calculated)}\n"
                f"\tSHA stored in binary:    {hexify(image_stored_sha)}"
            )

    return image


def write_flash(esp, args):
    # set args.compress based on default behaviour:
    # -> if either --compress or --no-compress is set, honour that
    # -> otherwise, set --compress unless --no-stub is set
    if args.compress is None and not args.no_compress:
        args.compress = not args.no_stub

    if not args.force and esp.CHIP_NAME != "ESP8266" and not esp.secure_download_mode:
        # Check if secure boot is active
        if esp.get_secure_boot_enabled():
            for address, _ in args.addr_filename:
                if address < 0x8000:
                    raise FatalError(
                        "Secure Boot detected, writing to flash regions < 0x8000 "
                        "is disabled to protect the bootloader. "
                        "Use --force to override, "
                        "please use with caution, otherwise it may brick your device!"
                    )
        # Check if chip_id and min_rev in image are valid for the target in use
        for _, argfile in args.addr_filename:
            try:
                image = LoadFirmwareImage(esp.CHIP_NAME, argfile)
            except (FatalError, struct.error, RuntimeError):
                continue
            finally:
                argfile.seek(0)  # LoadFirmwareImage changes the file handle position
            if image.chip_id != esp.IMAGE_CHIP_ID:
                raise FatalError(
                    f"{argfile.name} is not an {esp.CHIP_NAME} image. "
                    "Use --force to flash anyway."
                )

            # this logic below decides which min_rev to use, min_rev or min/max_rev_full
            if image.max_rev_full == 0:  # image does not have max/min_rev_full fields
                use_rev_full_fields = False
            elif image.max_rev_full == 65535:  # image has default value of max_rev_full
                use_rev_full_fields = True
                if (
                    image.min_rev_full == 0 and image.min_rev != 0
                ):  # min_rev_full is not set, min_rev is used
                    use_rev_full_fields = False
            else:  # max_rev_full set to a version
                use_rev_full_fields = True

            if use_rev_full_fields:
                rev = esp.get_chip_revision()
                if rev < image.min_rev_full or rev > image.max_rev_full:
                    error_str = f"{argfile.name} requires chip revision in range "
                    error_str += (
                        f"[v{image.min_rev_full // 100}.{image.min_rev_full % 100} - "
                    )
                    if image.max_rev_full == 65535:
                        error_str += "max rev not set] "
                    else:
                        error_str += (
                            f"v{image.max_rev_full // 100}.{image.max_rev_full % 100}] "
                        )
                    error_str += f"(this chip is revision v{rev // 100}.{rev % 100})"
                    raise FatalError(f"{error_str}. Use --force to flash anyway.")
            else:
                # In IDF, image.min_rev is set based on Kconfig option.
                # For C3 chip, image.min_rev is the Minor revision
                # while for the rest chips it is the Major revision.
                if esp.CHIP_NAME == "ESP32-C3":
                    rev = esp.get_minor_chip_version()
                else:
                    rev = esp.get_major_chip_version()
                if rev < image.min_rev:
                    raise FatalError(
                        f"{argfile.name} requires chip revision "
                        f"{image.min_rev} or higher (this chip is revision {rev}). "
                        "Use --force to flash anyway."
                    )

    # In case we have encrypted files to write,
    # we first do few sanity checks before actual flash
    if args.encrypt or args.encrypt_files is not None:
        do_write = True

        if not esp.secure_download_mode:
            if esp.get_encrypted_download_disabled():
                raise FatalError(
                    "This chip has encrypt functionality "
                    "in UART download mode disabled. "
                    "This is the Flash Encryption configuration for Production mode "
                    "instead of Development mode."
                )

            crypt_cfg_efuse = esp.get_flash_crypt_config()

            if crypt_cfg_efuse is not None and crypt_cfg_efuse != 0xF:
                log.print(f"Unexpected FLASH_CRYPT_CONFIG value: 0x{crypt_cfg_efuse:x}")
                do_write = False

            enc_key_valid = esp.is_flash_encryption_key_valid()

            if not enc_key_valid:
                log.print("Flash encryption key is not programmed")
                do_write = False

        # Determine which files list contain the ones to encrypt
        files_to_encrypt = args.addr_filename if args.encrypt else args.encrypt_files

        for address, argfile in files_to_encrypt:
            if address % esp.FLASH_ENCRYPTED_WRITE_ALIGN:
                log.print(
                    f"File {argfile.name} address 0x{address:x} is not "
                    f"{esp.FLASH_ENCRYPTED_WRITE_ALIGN} byte aligned, "
                    "can't flash encrypted"
                )

                do_write = False

        if not do_write and not args.ignore_flash_encryption_efuse_setting:
            raise FatalError(
                "Can't perform encrypted flash write, "
                "consult Flash Encryption documentation for more information"
            )
    else:
        if not args.force and esp.CHIP_NAME != "ESP8266":
            # ESP32 does not support `get_security_info()` and `secure_download_mode`
            if (
                esp.CHIP_NAME != "ESP32"
                and esp.secure_download_mode
                and bin(esp.get_security_info()["flash_crypt_cnt"]).count("1") & 1 != 0
            ):
                raise FatalError(
                    "WARNING: Detected flash encryption and "
                    "secure download mode enabled.\n"
                    "Flashing plaintext binary may brick your device! "
                    "Use --force to override the warning."
                )

            if (
                not esp.secure_download_mode
                and esp.get_encrypted_download_disabled()
                and esp.get_flash_encryption_enabled()
            ):
                raise FatalError(
                    "WARNING: Detected flash encryption enabled and "
                    "download manual encrypt disabled.\n"
                    "Flashing plaintext binary may brick your device! "
                    "Use --force to override the warning."
                )

    set_flash_size = (
        flash_size_bytes(args.flash_size)
        if args.flash_size not in ["detect", "keep"]
        else None
    )
    if esp.secure_download_mode:
        flash_end = set_flash_size
    else:  # Check against real flash chip size if not in SDM
        flash_end_str = detect_flash_size(esp)
        flash_end = flash_size_bytes(flash_end_str)
        if set_flash_size and flash_end and set_flash_size > flash_end:
            log.warning(
                f"Set --flash_size {args.flash_size} "
                f"is larger than the available flash size of {flash_end_str}."
            )

    # Verify file sizes fit in the set --flash_size, or real flash size if smaller
    flash_end = min(set_flash_size, flash_end) if set_flash_size else flash_end
    if flash_end is not None:
        for address, argfile in args.addr_filename:
            argfile.seek(0, os.SEEK_END)
            if address + argfile.tell() > flash_end:
                raise FatalError(
                    f"File {argfile.name} (length {argfile.tell()}) at offset "
                    f"{address} will not fit in {flash_end} bytes of flash. "
                    "Change the --flash_size argument, or flashing address."
                )
            argfile.seek(0)

    if args.erase_all:
        erase_flash(esp, args)
    else:
        for address, argfile in args.addr_filename:
            argfile.seek(0, os.SEEK_END)
            write_end = address + argfile.tell()
            argfile.seek(0)
            bytes_over = address % esp.FLASH_SECTOR_SIZE
            if bytes_over != 0:
                log.note(
                    f"Flash address {address:#010x} is not aligned "
                    f"to a {esp.FLASH_SECTOR_SIZE:#x} byte flash sector. "
                    f"{bytes_over:#x} bytes before this address will be erased."
                )
            # Print the address range of to-be-erased flash memory region
            log.print(
                "Flash will be erased from {:#010x} to {:#010x}...".format(
                    address - bytes_over,
                    div_roundup(write_end, esp.FLASH_SECTOR_SIZE)
                    * esp.FLASH_SECTOR_SIZE
                    - 1,
                )
            )

    """ Create a list describing all the files we have to flash.
    Each entry holds an "encrypt" flag marking whether the file needs encryption or not.
    This list needs to be sorted.

    First, append to each entry of our addr_filename list the flag args.encrypt
    E.g., if addr_filename is [(0x1000, "partition.bin"), (0x8000, "bootloader")],
    all_files will be [
        (0x1000, "partition.bin", args.encrypt),
        (0x8000, "bootloader", args.encrypt)
        ],
    where, of course, args.encrypt is either True or False
    """
    all_files = [
        (offs, filename, args.encrypt) for (offs, filename) in args.addr_filename
    ]

    """
    Now do the same with encrypt_files list, if defined.
    In this case, the flag is True
    """
    if args.encrypt_files is not None:
        encrypted_files_flag = [
            (offs, filename, True) for (offs, filename) in args.encrypt_files
        ]

        # Concatenate both lists and sort them.
        # As both list are already sorted, we could simply do a merge instead,
        # but for the sake of simplicity and because the lists are very small,
        # let's use sorted.
        all_files = sorted(all_files + encrypted_files_flag, key=lambda x: x[0])

    for address, argfile, encrypted in all_files:
        compress = args.compress

        # Check whether we can compress the current file before flashing
        if compress and encrypted:
            log.print("\n")
            log.warning("Compress and encrypt options are mutually exclusive.")
            log.print(f"Will flash {argfile.name} uncompressed.")
            compress = False

        image = argfile.read()

        if len(image) == 0:
            log.warning(f"File {argfile.name} is empty")
            continue

        image = pad_to(image, esp.FLASH_ENCRYPTED_WRITE_ALIGN if encrypted else 4)

        if args.no_stub:
            log.print("Erasing flash...")

            # It is not possible to write to not aligned addresses without stub,
            # so there are added 0xFF (erase) bytes at the beginning of the image
            # to align it.
            bytes_over = address % esp.FLASH_SECTOR_SIZE
            address -= bytes_over
            image = b"\xFF" * bytes_over + image

        if not esp.secure_download_mode and not esp.get_secure_boot_enabled():
            image = _update_image_flash_params(esp, address, args, image)
        else:
            log.warning(
                "Security features enabled, so not changing any flash settings."
            )
        calcmd5 = hashlib.md5(image).hexdigest()
        uncsize = len(image)
        if compress:
            uncimage = image
            image = zlib.compress(uncimage, 9)
        original_image = image  # Save the whole image in case retry is needed
        # Try again if reconnect was successful
        for attempt in range(1, esp.WRITE_FLASH_ATTEMPTS + 1):
            try:
                if compress:
                    # Decompress the compressed binary a block at a time,
                    # to dynamically calculate the timeout based on the real write size
                    decompress = zlib.decompressobj()
                    blocks = esp.flash_defl_begin(uncsize, len(image), address)
                else:
                    blocks = esp.flash_begin(
                        uncsize, address, begin_rom_encrypted=encrypted
                    )
                argfile.seek(0)  # in case we need it again
                seq = 0
                bytes_sent = 0  # bytes sent on wire
                bytes_written = 0  # bytes written to flash
                t = time.time()

                timeout = DEFAULT_TIMEOUT

                log.set_progress(0)

                while len(image) > 0:
                    percent = 100 * (seq + 1) // blocks
                    log.set_progress(percent)
                    log.print_overwrite(
                        "Writing at 0x%08x... (%d %%)"
                        % (address + bytes_written, percent)
                    )
                    sys.stdout.flush()
                    block = image[0 : esp.FLASH_WRITE_SIZE]
                    if compress:
                        # feeding each compressed block into the decompressor lets us
                        # see block-by-block how much will be written
                        block_uncompressed = len(decompress.decompress(block))
                        bytes_written += block_uncompressed
                        block_timeout = max(
                            DEFAULT_TIMEOUT,
                            timeout_per_mb(
                                ERASE_WRITE_TIMEOUT_PER_MB, block_uncompressed
                            ),
                        )
                        if not esp.IS_STUB:
                            timeout = block_timeout  # ROM code writes block to flash before ACKing
                        esp.flash_defl_block(block, seq, timeout=timeout)
                        if esp.IS_STUB:
                            # Stub ACKs when block is received,
                            # then writes to flash while receiving the block after it
                            timeout = block_timeout
                    else:
                        # Pad the last block
                        block = block + b"\xff" * (esp.FLASH_WRITE_SIZE - len(block))
                        if encrypted:
                            esp.flash_encrypt_block(block, seq)
                        else:
                            esp.flash_block(block, seq)
                        bytes_written += len(block)
                    bytes_sent += len(block)
                    image = image[esp.FLASH_WRITE_SIZE :]
                    seq += 1
                break
            except SerialException:
                if attempt == esp.WRITE_FLASH_ATTEMPTS or encrypted:
                    # Already retried once or encrypted mode is disabled because of security reasons
                    raise
                log.print("\nLost connection, retrying...")
                esp._port.close()
                log.print("Waiting for the chip to reconnect", end="")
                for _ in range(DEFAULT_CONNECT_ATTEMPTS):
                    try:
                        time.sleep(1)
                        esp._port.open()
                        log.print()  # Print new line which was suppressed by print(".")
                        esp.connect()
                        if esp.IS_STUB:
                            # Hack to bypass the stub overwrite check
                            esp.IS_STUB = False
                            # Reflash stub because chip was reset
                            esp = esp.run_stub()
                        image = original_image
                        break
                    except SerialException:
                        log.print(".", end="")
                        sys.stdout.flush()
                else:
                    raise  # Reconnect limit reached

        if esp.IS_STUB:
            # Stub only writes each block to flash after 'ack'ing the receive,
            # so do a final dummy operation which will not be 'ack'ed
            # until the last block has actually been written out to flash
            esp.read_reg(ESPLoader.CHIP_DETECT_MAGIC_REG_ADDR, timeout=timeout)

        t = time.time() - t
        speed_msg = ""
        if compress:
            if t > 0.0:
                speed_msg = f" (effective {uncsize / t * 8 / 1000:.1f} kbit/s)"
            log.print_overwrite(
                f"Wrote {uncsize} bytes ({bytes_sent} compressed) at 0x{address:08x} "
                f"in {t:.1f} seconds{speed_msg}...",
                last_line=True,
            )
        else:
            if t > 0.0:
                speed_msg = " (%.1f kbit/s)" % (bytes_written / t * 8 / 1000)
            log.print_overwrite(
                f"Wrote {bytes_written} bytes at 0x{address:08x} in {t:.1f} "
                f"seconds{speed_msg}...",
                last_line=True,
            )

        if not encrypted and not esp.secure_download_mode:
            try:
                res = esp.flash_md5sum(address, uncsize)
                if res != calcmd5:
                    log.print(f"File  MD5: {calcmd5}")
                    log.print(f"Flash MD5: {res}")
                    if res == hashlib.md5(b"\xFF" * uncsize).hexdigest():
                        raise FatalError(
                            "Write failed, the written flash region is empty."
                        )
                    raise FatalError("MD5 of file does not match data in flash!")
                else:
                    log.print("Hash of data verified.")
            except NotImplementedInROMError:
                pass
        else:
            log.print(
                "Cannot verify written data if encrypted or in secure download mode."
            )

    if esp.IS_STUB:
        # skip sending flash_finish to ROM loader here,
        # as it causes the loader to exit and run user code
        esp.flash_begin(0, 0)

        # Get the "encrypted" flag for the last file flashed
        # Note: all_files list contains triplets like:
        # (address: Integer, filename: String, encrypted: Boolean)
        last_file_encrypted = all_files[-1][2]

        # Check whether the last file flashed was compressed or not
        if args.compress and not last_file_encrypted:
            esp.flash_defl_finish(False)
        else:
            esp.flash_finish(False)


def image_info(args):
    log.print(f"File size: {get_file_size(args.filename)} (bytes)")
    with open(args.filename, "rb") as f:
        # magic number
        try:
            common_header = f.read(8)
            magic = common_header[0]
        except IndexError:
            raise FatalError("File is empty")
        if magic not in [
            ESPLoader.ESP_IMAGE_MAGIC,
            ESP8266V2FirmwareImage.IMAGE_V2_MAGIC,
        ]:
            raise FatalError(
                f"This is not a valid image (invalid magic number: {magic:#x})"
            )

        if args.chip == "auto":
            try:
                extended_header = f.read(16)

                # append_digest, either 0 or 1
                if extended_header[-1] not in [0, 1]:
                    raise FatalError("Append digest field not 0 or 1")

                chip_id = int.from_bytes(extended_header[4:5], "little")
                for rom in [n for n in ROM_LIST if n.CHIP_NAME != "ESP8266"]:
                    if chip_id == rom.IMAGE_CHIP_ID:
                        args.chip = rom.CHIP_NAME
                        break
                else:
                    raise FatalError(f"Unknown image chip ID ({chip_id})")
            except FatalError:
                args.chip = "esp8266"

            log.print(f"Detected image type: {args.chip.upper()}")

    image = LoadFirmwareImage(args.chip, args.filename)

    def get_key_from_value(dict, val):
        """Get key from value in dictionary"""
        for key, value in dict.items():
            if value == val:
                return key
        return None

    log.print()
    title = f"{args.chip.upper()} image header".format()
    log.print(title)
    log.print("=" * len(title))
    log.print(f"Image version: {image.version}")
    log.print(
        f"Entry point: {image.entrypoint:#8x}"
        if image.entrypoint != 0
        else "Entry point not set"
    )

    log.print(f"Segments: {len(image.segments)}")

    # Flash size
    flash_s_bits = image.flash_size_freq & 0xF0  # high four bits
    flash_s = get_key_from_value(image.ROM_LOADER.FLASH_SIZES, flash_s_bits)
    if flash_s is not None:
        log.print(f"Flash size: {flash_s}")
    else:
        log.warning(f"Invalid flash size ({flash_s_bits:#02x})")

    # Flash frequency
    flash_fr_bits = image.flash_size_freq & 0x0F  # low four bits
    flash_fr = get_key_from_value(image.ROM_LOADER.FLASH_FREQUENCY, flash_fr_bits)
    if flash_fr is not None:
        log.print(f"Flash freq: {flash_fr}")
    else:
        log.warning(f"Invalid flash frequency ({flash_fr_bits:#02x})")

    # Flash mode
    flash_mode = get_key_from_value(FLASH_MODES, image.flash_mode)
    if flash_mode is not None:
        log.print(f"Flash mode: {flash_mode.upper()}")
    else:
        log.warning(f"Invalid flash mode ({image.flash_mode})")

    # Extended header (ESP32 and later only)
    if args.chip != "esp8266":
        log.print()
        title = f"{args.chip.upper()} extended image header"
        log.print(title)
        log.print("=" * len(title))
        log.print(
            f"WP pin: {image.wp_pin:#02x}",
            *["(disabled)"] if image.wp_pin == image.WP_PIN_DISABLED else [],
        )
        log.print(
            "Flash pins drive settings: "
            "clk_drv: {:#02x}, q_drv: {:#02x}, d_drv: {:#02x}, "
            "cs0_drv: {:#02x}, hd_drv: {:#02x}, wp_drv: {:#02x}".format(
                image.clk_drv,
                image.q_drv,
                image.d_drv,
                image.cs_drv,
                image.hd_drv,
                image.wp_drv,
            )
        )
        try:
            chip = next(
                chip
                for chip in CHIP_DEFS.values()
                if getattr(chip, "IMAGE_CHIP_ID", None) == image.chip_id
            )
            log.print(f"Chip ID: {image.chip_id} ({chip.CHIP_NAME})")
        except StopIteration:
            log.print(f"Chip ID: {image.chip_id} (Unknown ID)")
        log.print(
            "Minimal chip revision: "
            f"v{image.min_rev_full // 100}.{image.min_rev_full % 100}, "
            f"(legacy min_rev = {image.min_rev})"
        )
        log.print(
            "Maximal chip revision: "
            f"v{image.max_rev_full // 100}.{image.max_rev_full % 100}"
        )
    log.print()

    # Segments overview
    title = "Segments information"
    log.print(title)
    log.print("=" * len(title))
    headers_str = "{:>7}  {:>7}  {:>10}  {:>10}  {:10}"
    log.print(
        headers_str.format(
            "Segment", "Length", "Load addr", "File offs", "Memory types"
        )
    )
    log.print(
        "{}  {}  {}  {}  {}".format("-" * 7, "-" * 7, "-" * 10, "-" * 10, "-" * 12)
    )
    format_str = "{:7}  {:#07x}  {:#010x}  {:#010x}  {}"
    app_desc = None
    bootloader_desc = None
    for idx, seg in enumerate(image.segments):
        segs = seg.get_memory_type(image)
        seg_name = ", ".join(segs)
        # The DROM segment starts with the esp_app_desc_t struct
        if "DROM" in segs and app_desc is None:
            app_desc = seg.data[:256]
        elif "DRAM" in segs:
            # The DRAM segment starts with the esp_bootloader_desc_t struct
            if len(seg.data) >= 80:
                bootloader_desc = seg.data[:80]
        log.print(
            format_str.format(idx, len(seg.data), seg.addr, seg.file_offs, seg_name)
        )
    log.print()

    # Footer
    title = f"{args.chip.upper()} image footer"
    log.print(title)
    log.print("=" * len(title))
    calc_checksum = image.calculate_checksum()
    log.print(
        "Checksum: 0x{:02x} ({})".format(
            image.checksum,
            (
                "valid"
                if image.checksum == calc_checksum
                else f"invalid - calculated 0x{calc_checksum:02x}"
            ),
        )
    )
    try:
        digest_msg = "Not appended"
        if image.append_digest:
            is_valid = image.stored_digest == image.calc_digest
            digest_msg = "{} ({})".format(
                hexify(image.calc_digest, uppercase=False),
                "valid" if is_valid else "invalid",
            )
            log.print(f"Validation hash: {digest_msg}")
    except AttributeError:
        pass  # ESP8266 image has no append_digest field

    if app_desc:
        APP_DESC_STRUCT_FMT = "<II" + "8s" + "32s32s16s16s32s32sHHB" + "3s" + "72s"
        (
            magic_word,
            secure_version,
            reserv1,
            version,
            project_name,
            time,
            date,
            idf_ver,
            app_elf_sha256,
            min_efuse_blk_rev_full,
            max_efuse_blk_rev_full,
            mmu_page_size,
            reserv3,
            reserv2,
        ) = struct.unpack(APP_DESC_STRUCT_FMT, app_desc)

        if magic_word == 0xABCD5432:
            log.print()
            title = "Application information"
            log.print(title)
            log.print("=" * len(title))
            log.print(f'Project name: {project_name.decode("utf-8")}')
            log.print(f'App version: {version.decode("utf-8")}')
            log.print(f'Compile time: {date.decode("utf-8")} {time.decode("utf-8")}')
            log.print(f"ELF file SHA256: {hexify(app_elf_sha256, uppercase=False)}")
            log.print(f'ESP-IDF: {idf_ver.decode("utf-8")}')
            log.print(
                f"Minimal eFuse block revision: "
                f"{min_efuse_blk_rev_full // 100}.{min_efuse_blk_rev_full % 100}"
            )
            log.print(
                f"Maximal eFuse block revision: "
                f"{max_efuse_blk_rev_full // 100}.{max_efuse_blk_rev_full % 100}"
            )

            # MMU page size is only available in ESP-IDF v5.4 and later
            # regex matches major and minor version numbers, idf_ver can look like "v5.4.1-dirty"
            ver = re.match(r"v(\d+)\.(\d+)", idf_ver.decode("utf-8"))
            if ver:
                major, minor = ver.groups()
                if int(major) >= 5 and int(minor) >= 4:
                    log.print(f"MMU page size: {2 ** mmu_page_size // 1024} KB")

            log.print(f"Secure version: {secure_version}")

    elif bootloader_desc:
        BOOTLOADER_DESC_STRUCT_FMT = "<B" + "3s" + "I32s24s" + "16s"
        (
            magic_byte,
            reserved,
            version,
            idf_ver,
            date_time,
            reserved2,
        ) = struct.unpack(BOOTLOADER_DESC_STRUCT_FMT, bootloader_desc)

        if magic_byte == 80:
            log.print()
            title = "Bootloader information"
            log.print(title)
            log.print("=" * len(title))
            log.print(f"Bootloader version: {version}")
            log.print(f'ESP-IDF: {idf_ver.decode("utf-8")}')
            log.print(f'Compile time: {date_time.decode("utf-8")}')


def make_image(args):
    log.print(f"Creating {args.chip} image...")
    image = ESP8266ROMFirmwareImage()
    if len(args.segfile) == 0:
        raise FatalError("No segments specified")
    if len(args.segfile) != len(args.segaddr):
        raise FatalError(
            "Number of specified files does not match number of specified addresses"
        )
    for seg, addr in zip(args.segfile, args.segaddr):
        with open(seg, "rb") as f:
            data = f.read()
            image.segments.append(ImageSegment(addr, data))
    image.entrypoint = args.entrypoint
    image.save(args.output)
    log.print(f"Successfully created {args.chip} image.")


def elf2image(args):
    e = ELFFile(args.input)
    if args.chip == "auto":  # Default to ESP8266 for backwards compatibility
        args.chip = "esp8266"

    log.print(f"Creating {args.chip} image...")

    if args.chip != "esp8266":
        image = CHIP_DEFS[args.chip].BOOTLOADER_IMAGE()
        if args.chip == "esp32" and args.secure_pad:
            image.secure_pad = "1"
        if args.secure_pad_v2:
            image.secure_pad = "2"
        image.min_rev = args.min_rev
        image.min_rev_full = args.min_rev_full
        image.max_rev_full = args.max_rev_full
        image.ram_only_header = args.ram_only_header
        if image.ram_only_header:
            image.append_digest = False
        else:
            image.append_digest = args.append_digest
    elif args.version == "1":  # ESP8266
        image = ESP8266ROMFirmwareImage()
    elif args.version == "2":
        image = ESP8266V2FirmwareImage()
    else:
        image = ESP8266V3FirmwareImage()
    image.entrypoint = e.entrypoint
    image.flash_mode = FLASH_MODES[args.flash_mode]

    if args.flash_mmu_page_size:
        image.set_mmu_page_size(flash_size_bytes(args.flash_mmu_page_size))

    # ELFSection is a subclass of ImageSegment, so can use interchangeably
    image.segments = e.segments if args.use_segments else e.sections
    if args.pad_to_size:
        image.pad_to_size = flash_size_bytes(args.pad_to_size)
    image.flash_size_freq = image.ROM_LOADER.parse_flash_size_arg(args.flash_size)
    image.flash_size_freq += image.ROM_LOADER.parse_flash_freq_arg(args.flash_freq)

    if args.elf_sha256_offset:
        image.elf_sha256 = e.sha256()
        image.elf_sha256_offset = args.elf_sha256_offset

    if args.ram_only_header:
        log.print(
            "Image has only RAM segments visible. "
            "ROM segments are hidden and SHA256 digest is not appended."
        )
        image.sort_segments()

    before = len(image.segments)
    image.merge_adjacent_segments()
    if len(image.segments) != before:
        delta = before - len(image.segments)
        log.print(f"Merged {delta} ELF section{'s' if delta > 1 else ''}")

    image.verify()

    if args.output is None:
        args.output = image.default_output_name(args.input)
    image.save(args.output)

    log.print(f"Successfully created {args.chip} image.")


def read_mac(esp, args):
    def print_mac(label, mac):
        log.print(f"{label}: {':'.join(f'{x:02x}' for x in mac)}")

    eui64 = esp.read_mac("EUI64")
    if eui64:
        print_mac("MAC", eui64)
        print_mac("BASE MAC", esp.read_mac("BASE_MAC"))
        print_mac("MAC_EXT", esp.read_mac("MAC_EXT"))
    else:
        print_mac("MAC", esp.read_mac("BASE_MAC"))


def chip_id(esp, args):
    try:
        chipid = esp.chip_id()
        log.print(f"Chip ID: 0x{chipid:08x}")
    except NotSupportedError:
        log.warning(f"{esp.CHIP_NAME} has no Chip ID. Reading MAC instead.")
        read_mac(esp, args)


def erase_flash(esp, args):
    if not args.force and esp.CHIP_NAME != "ESP8266" and not esp.secure_download_mode:
        if esp.get_flash_encryption_enabled() or esp.get_secure_boot_enabled():
            raise FatalError(
                "Active security features detected, "
                "erasing flash is disabled as a safety measure. "
                "Use --force to override, "
                "please use with caution, otherwise it may brick your device!"
            )
    log.print("Erasing flash (this may take a while)...")
    if esp.CHIP_NAME != "ESP8266" and not esp.IS_STUB:
        log.note(
            "You can use the erase_region command in ROM bootloader "
            "mode to erase a specific region."
        )
    t = time.time()
    esp.erase_flash()
    log.print(f"Chip erase completed successfully in {time.time() - t:.1f} seconds.")


def erase_region(esp, args):
    if args.address % ESPLoader.FLASH_SECTOR_SIZE != 0:
        raise FatalError(
            "Offset to erase from must be a multiple "
            f"of {ESPLoader.FLASH_SECTOR_SIZE}"
        )
    if args.size % ESPLoader.FLASH_SECTOR_SIZE != 0:
        raise FatalError(
            "Size of data to erase must be a multiple "
            f"of {ESPLoader.FLASH_SECTOR_SIZE}"
        )
    if not args.force and esp.CHIP_NAME != "ESP8266" and not esp.secure_download_mode:
        if esp.get_flash_encryption_enabled() or esp.get_secure_boot_enabled():
            raise FatalError(
                "Active security features detected, "
                "erasing flash is disabled as a safety measure. "
                "Use --force to override, "
                "please use with caution, otherwise it may brick your device!"
            )
    log.print("Erasing region (may be slow depending on size)...")
    t = time.time()
    if esp.CHIP_NAME != "ESP8266" and not esp.IS_STUB:
        # flash_begin triggers a flash erase, enabling erasing in ROM and SDM
        esp.flash_begin(args.size, args.address, logging=False)
    else:
        esp.erase_region(args.address, args.size)
    log.print(f"Erase completed successfully in {time.time() - t:.1f} seconds.")


def run(esp, args):
    esp.run()


def detect_flash_id(esp):
    flash_id = esp.flash_id()
    log.print("Manufacturer: %02x" % (flash_id & 0xFF))
    flid_lowbyte = (flash_id >> 16) & 0xFF
    log.print("Device: %02x%02x" % ((flash_id >> 8) & 0xFF, flid_lowbyte))
    log.print(
        "Detected flash size: %s" % (DETECTED_FLASH_SIZES.get(flid_lowbyte, "Unknown"))
    )


def flash_id(esp, args):
    detect_flash_id(esp)
    flash_type = esp.flash_type()
    flash_type_dict = {0: "quad (4 data lines)", 1: "octal (8 data lines)"}
    flash_type_str = flash_type_dict.get(flash_type)
    if flash_type_str:
        log.print(f"Flash type set in eFuse: {flash_type_str}")
    esp.get_flash_voltage()


def read_flash_sfdp(esp, args):
    detect_flash_id(esp)

    sfdp = esp.read_spiflash_sfdp(args.addr, args.bytes * 8)
    log.print(f"SFDP[{args.addr}..{args.addr+args.bytes-1}]: ", end="")
    for _ in range(args.bytes):
        log.print(f"{sfdp&0xff:02X} ", end="")
        sfdp = sfdp >> 8
    log.print()


def read_flash(esp, args):
    if args.no_progress:
        flash_progress = None
    else:

        def flash_progress(progress, length):
            percent = progress * 100.0 / length
            log.set_progress(percent)

            msg = f"{progress} ({percent:.0f} %)"
            padding = "\b" * len(msg)

            if progress != length:
                log.print_overwrite(f"{msg}{padding}")
            else:
                log.print_overwrite(f"{msg}", last_line=True)

    log.set_progress(0)
    t = time.time()
    data = esp.read_flash(args.address, args.size, flash_progress)
    t = time.time() - t
    speed_msg = " ({:.1f} kbit/s)".format(len(data) / t * 8 / 1000) if t > 0.0 else ""
    log.print_overwrite(
        "Read {:d} bytes at {:#010x} in {:.1f} seconds{}...".format(
            len(data), args.address, t, speed_msg
        ),
        last_line=True,
    )
    with open(args.filename, "wb") as f:
        f.write(data)


def verify_flash(esp, args):
    differences = False

    for address, argfile in args.addr_filename:
        image = pad_to(argfile.read(), 4)
        argfile.seek(0)  # rewind in case we need it again

        image = _update_image_flash_params(esp, address, args, image)

        image_size = len(image)
        log.print(
            f"Verifying 0x{image_size:x} ({image_size}) bytes "
            f"at 0x{address:08x} in flash against {argfile.name}..."
        )
        # Try digest first, only read if there are differences.
        digest = esp.flash_md5sum(address, image_size)
        expected_digest = hashlib.md5(image).hexdigest()
        if digest == expected_digest:
            log.print("-- verify OK (digest matched)")
            continue
        else:
            differences = True
            if getattr(args, "diff", "no") != "yes":
                log.print("-- verify FAILED (digest mismatch)")
                continue

        flash = esp.read_flash(address, image_size)
        assert flash != image
        diff = [i for i in range(image_size) if flash[i] != image[i]]
        log.print(
            f"-- verify FAILED: {len(diff)} differences, first at 0x{address + diff[0]:08x}"
        )
        for d in diff:
            flash_byte = flash[d]
            image_byte = image[d]
            log.print(f"   {address + d:08x} {flash_byte:02x} {image_byte:02x}")
    if differences:
        raise FatalError("Verify failed.")


def read_flash_status(esp, args):
    log.print(f"Status value: 0x{esp.read_status(args.bytes):04x}")


def write_flash_status(esp, args):
    fmt = f"0x%0{args.bytes * 2}x"
    args.value = args.value & ((1 << (args.bytes * 8)) - 1)
    log.print(f"Initial flash status: {fmt % esp.read_status(args.bytes)}")
    log.print(f"Setting flash status: {fmt % args.value}")
    esp.write_status(args.value, args.bytes, args.non_volatile)
    log.print(f"After flash status:   {fmt % esp.read_status(args.bytes)}")


# The following mapping was taken from the ROM code
# This mapping is same across all targets in the ROM
SECURITY_INFO_FLAG_MAP = {
    "SECURE_BOOT_EN": (1 << 0),
    "SECURE_BOOT_AGGRESSIVE_REVOKE": (1 << 1),
    "SECURE_DOWNLOAD_ENABLE": (1 << 2),
    "SECURE_BOOT_KEY_REVOKE0": (1 << 3),
    "SECURE_BOOT_KEY_REVOKE1": (1 << 4),
    "SECURE_BOOT_KEY_REVOKE2": (1 << 5),
    "SOFT_DIS_JTAG": (1 << 6),
    "HARD_DIS_JTAG": (1 << 7),
    "DIS_USB": (1 << 8),
    "DIS_DOWNLOAD_DCACHE": (1 << 9),
    "DIS_DOWNLOAD_ICACHE": (1 << 10),
}


# Get the status of respective security flag
def get_security_flag_status(flag_name, flags_value):
    try:
        return (flags_value & SECURITY_INFO_FLAG_MAP[flag_name]) != 0
    except KeyError:
        raise ValueError(f"Invalid flag name: {flag_name}")


def get_security_info(esp, args):
    si = esp.get_security_info()
    log.print()
    title = "Security Information:"
    log.print(title)
    log.print("=" * len(title))
    log.print("Flags: {:#010x} ({})".format(si["flags"], bin(si["flags"])))
    if esp.KEY_PURPOSES:
        log.print(f"Key Purposes: {si['key_purposes']}")
        desc = "\n  ".join(
            [
                f"BLOCK_KEY{key_num} - {esp.KEY_PURPOSES.get(purpose, 'UNKNOWN')}"
                for key_num, purpose in enumerate(si["key_purposes"])
                if key_num <= esp.EFUSE_MAX_KEY
            ]
        )
        log.print(f"  {desc}")
    if si["chip_id"] is not None and si["api_version"] is not None:
        log.print("Chip ID: {}".format(si["chip_id"]))
        log.print("API Version: {}".format(si["api_version"]))

    flags = si["flags"]

    if get_security_flag_status("SECURE_BOOT_EN", flags):
        log.print("Secure Boot: Enabled")
        if get_security_flag_status("SECURE_BOOT_AGGRESSIVE_REVOKE", flags):
            log.print("Secure Boot Aggressive key revocation: Enabled")

        revoked_keys = []
        for i, key in enumerate(
            [
                "SECURE_BOOT_KEY_REVOKE0",
                "SECURE_BOOT_KEY_REVOKE1",
                "SECURE_BOOT_KEY_REVOKE2",
            ]
        ):
            if get_security_flag_status(key, flags):
                revoked_keys.append(i)

        if len(revoked_keys) > 0:
            log.print("Secure Boot Key Revocation Status:\n")
            for i in revoked_keys:
                log.print(f"\tSecure Boot Key{i} is Revoked\n")

    else:
        log.print("Secure Boot: Disabled")

    flash_crypt_cnt = bin(si["flash_crypt_cnt"])
    if (flash_crypt_cnt.count("1") % 2) != 0:
        log.print("Flash Encryption: Enabled")
    else:
        log.print("Flash Encryption: Disabled")

    CRYPT_CNT_STRING = "SPI Boot Crypt Count (SPI_BOOT_CRYPT_CNT)"
    if esp.CHIP_NAME == "esp32":
        CRYPT_CNT_STRING = "Flash Crypt Count (FLASH_CRYPT_CNT)"

    log.print(f"{CRYPT_CNT_STRING}: {si['flash_crypt_cnt']:#x}")

    if get_security_flag_status("DIS_DOWNLOAD_DCACHE", flags):
        log.print("Dcache in UART download mode: Disabled")

    if get_security_flag_status("DIS_DOWNLOAD_ICACHE", flags):
        log.print("Icache in UART download mode: Disabled")

    hard_dis_jtag = get_security_flag_status("HARD_DIS_JTAG", flags)
    soft_dis_jtag = get_security_flag_status("SOFT_DIS_JTAG", flags)
    if hard_dis_jtag:
        log.print("JTAG: Permanently Disabled")
    elif soft_dis_jtag:
        log.print("JTAG: Software Access Disabled")
    if get_security_flag_status("DIS_USB", flags):
        log.print("USB Access: Disabled")


def merge_bin(args):
    try:
        chip_class = CHIP_DEFS[args.chip]
    except KeyError:
        msg = (
            "Please specify the chip argument"
            if args.chip == "auto"
            else f"Invalid chip choice: '{args.chip}'"
        )
        msg = f"{msg} (choose from {', '.join(CHIP_LIST)})"
        raise FatalError(msg)

    # sort the files by offset.
    # The AddrFilenamePairAction has already checked for overlap
    input_files = sorted(args.addr_filename, key=lambda x: x[0])
    if not input_files:
        raise FatalError("No input files specified")
    first_addr = input_files[0][0]
    if first_addr < args.target_offset:
        raise FatalError(
            f"Output file target offset is {args.target_offset:#x}. "
            f"Input file offset {first_addr:#x} is before this."
        )

    if args.format == "uf2":
        with UF2Writer(
            chip_class.UF2_FAMILY_ID,
            args.output,
            args.chunk_size,
            md5_enabled=not args.md5_disable,
        ) as writer:
            for addr, argfile in input_files:
                log.print(f"Adding {argfile.name} at {addr:#x}")
                image = argfile.read()
                image = _update_image_flash_params(chip_class, addr, args, image)
                writer.add_file(addr, image)
        log.print(
            f"Wrote {os.path.getsize(args.output):#x} bytes to file {args.output}, "
            f"ready to be flashed with any ESP USB Bridge"
        )

    elif args.format == "raw":
        with open(args.output, "wb") as of:

            def pad_to(flash_offs):
                # account for output file offset if there is any
                of.write(b"\xFF" * (flash_offs - args.target_offset - of.tell()))

            for addr, argfile in input_files:
                pad_to(addr)
                image = argfile.read()
                image = _update_image_flash_params(chip_class, addr, args, image)
                of.write(image)
            if args.fill_flash_size:
                pad_to(flash_size_bytes(args.fill_flash_size))
            log.print(
                f"Wrote {of.tell():#x} bytes to file {args.output}, "
                f"ready to flash to offset {args.target_offset:#x}"
            )
    elif args.format == "hex":
        out = IntelHex()
        if len(input_files) == 1:
            log.warning(
                "Only one input file specified, output may include "
                "additional padding if input file was previously merged. "
                "Please refer to the documentation for more information: "
                "https://docs.espressif.com/projects/esptool/en/latest/esptool/basic-commands.html#hex-output-format"  # noqa E501
            )
        for addr, argfile in input_files:
            ihex = IntelHex()
            image = argfile.read()
            image = _update_image_flash_params(chip_class, addr, args, image)
            ihex.frombytes(image, addr)
            out.merge(ihex)
        out.write_hex_file(args.output)
        log.print(
            f"Wrote {os.path.getsize(args.output):#x} bytes to file {args.output}, "
            f"ready to flash to offset {args.target_offset:#x}"
        )


def version(args):
    from . import __version__

    log.print(__version__)
