# SPDX-FileCopyrightText: 2022-2023 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import re

LINE_RE = re.compile(r"^__version__ = ['\"]([^'\"]*)['\"]")
NEW_LINE = '__version__ = "{}"\n'


def patch_file(path, new_version):
    assert ".dev" in new_version
    new_version = new_version.lstrip("v")

    with open(path) as fin:
        lines = fin.readlines()

    for i, line in enumerate(lines, start=0):
        m = LINE_RE.search(line)
        if m:
            lines[i] = NEW_LINE.format(new_version)
            break

    with open(path, "w") as fout:
        fout.writelines(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Path to script with __version__")
    parser.add_argument(
        "--version", help="Development version specifier to patch the version to"
    )
    args = parser.parse_args()
    patch_file(args.file, args.version)


if __name__ == "__main__":
    main()
