#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: GPL-2.0-or-later

import glob
import os
import sys
import urllib.request

STUBS = (
    {
        "STUB_SET_VERSION": "1",
        "URL": "https://github.com/espressif/esptool-legacy-flasher-stub/",
        "VERSION": "v1.11.1",
        "FILE_LIST": (
            "esp32",
            "esp32c2",
            "esp32c3",
            "esp32c5",
            "esp32c6",
            "esp32c61",
            "esp32h2",
            "esp32p4rc1",
            "esp32p4",
            "esp32s2",
            "esp32s3",
            "esp8266",
        ),
        "LICENSE": "released as Free Software under GNU General Public License "
        "Version 2 or later",
    },
    {
        "STUB_SET_VERSION": "2",
        "URL": "https://github.com/espressif/esp-flasher-stub/",
        "VERSION": "v0.2.0",
        "FILE_LIST": (
            "esp32",
            "esp32c2",
            "esp32c3",
            "esp32c5",
            "esp32c6",
            "esp32c61",
            "esp32h2",
            "esp32h4",
            "esp32p4-rev1",
            "esp32p4",
            "esp32s2",
            "esp32s3",
            "esp8266",
        ),
        "LICENSE": "dual licensed under the Apache License Version 2.0 or the MIT "
        "license",
    },
)

DESTINATION_DIR = os.path.join("esptool", "targets", "stub_flasher")

README_TEMPLATE = """# Licensing

The binaries in JSON format distributed in this directory are {LICENSE}. They were released at {URL} from where the sources can be obtained.
"""  # noqa: E501


def main():
    for stub_set in STUBS:
        download_url = f"{stub_set['URL']}releases/download"
        tag_url = f"{stub_set['URL']}releases/tag"
        dest_sub_dir = os.path.join(DESTINATION_DIR, stub_set["STUB_SET_VERSION"])
        print(
            f"Downloading stubs from {stub_set['URL']} as version "
            f"{stub_set['STUB_SET_VERSION']}:"
        )

        """ The directory is cleaned up so we would detect if a stub was just committed
        into the repository but the name was not added into the FILE_LIST of STUBS.
        This would be an unwanted state because the checker would not detect any
        changes in that stub."""
        for old_file in glob.glob(os.path.join(dest_sub_dir, "*.json")):
            print(f"Removing old file {old_file}")
            os.remove(old_file)

        for file_name in stub_set["FILE_LIST"]:
            file = ".".join((file_name, "json"))
            url = "/".join((download_url, stub_set["VERSION"], file))
            # TODO: Remove the "rc" renaming
            # when naming in the legacy flasher stub is updated.
            dest = os.path.join(
                dest_sub_dir, file.replace("rc", "-rev") if "rc" in file else file
            )
            print(f"Downloading {url} to {dest}")
            try:
                urllib.request.urlretrieve(url, dest)
            except urllib.error.URLError as e:
                print(
                    f'ERROR: Stub file "{file}" could not be downloaded: {e}',
                    file=sys.stderr,
                )
                exit(1)

        with open(os.path.join(dest_sub_dir, "README.md"), "w") as f:
            print(f"Writing README to {f.name}")
            f.write(
                README_TEMPLATE.format(
                    LICENSE=stub_set["LICENSE"],
                    URL="/".join((tag_url, stub_set["VERSION"])),
                )
            )
        print()


if __name__ == "__main__":
    main()
