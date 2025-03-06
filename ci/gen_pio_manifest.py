import argparse
import json
import os
import re
import sys
import datetime

MANIFEST_DATA = {
    "name": "tool-esptoolpy",
    "description": "A serial utility to communicate & flash code to Espressif chips",
    "keywords": ["tools", "uploader", "tasmota", "espressif", "esp8266", "esp32"],
    "license": "GPL-2.0-or-later",
    "repository": {
        "type": "git",
        "url": "https://github.com/tasmota/esptool",
    },
}


def convert_version(version_string):
    """A helper function that converts a custom version string
    to a suitable SemVer alternative. For example:
    'release/v5.1' becomes '5.1.0',
    'v7.7.7' becomes '7.7.7'
    """

    regex_pattern = (
        r"v(?P<MAJOR>0|[1-9]\d*)\.(?P<MINOR>0|[1-9]\d*)\.*(?P<PATCH>0|[1-9]\d*)*"
    )
    match = re.search(regex_pattern, version_string)
    if not match:
        sys.stderr.write(
            f"No regex match found for '{regex_pattern}' in '{version_string}'\n"
        )
        return ""

    major, minor, patch = match.groups()
    if not patch:
        patch = "0"

    return ".".join((major, minor, patch))


def main(dst_dir, version_string):

    converted_version = convert_version(version_string)
    if not converted_version:
        sys.stderr.write(f"Failed to convert version '{version_string}'\n")
        return -1

    manifest_file_path = os.path.join(dst_dir, "package.json")
    build_date = datetime.date.today()
    with open(manifest_file_path, "w", encoding="utf8") as fp:
        MANIFEST_DATA["version"] = f"{converted_version}"
        MANIFEST_DATA["date"] = f"{build_date}"
        json.dump(MANIFEST_DATA, fp, indent=2)

    print(
        f"Generated '{manifest_file_path}' with '{converted_version}' version"
    )
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-o",
        "--dst-dir",
        dest="dst_dir",
        required=True,
        help="Destination where the 'package.json' will be located",
    )
    parser.add_argument(
        "-s",
        "--version-string",
        dest="version_string",
        required=True,
        help="Version string in format v*.*.*",
    )
    args = parser.parse_args()

    sys.exit(main(args.dst_dir, args.version_string))
