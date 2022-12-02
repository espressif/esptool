# SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import re

LINE_RE = re.compile(r"^__version__ = ['\"]([^'\"]*)['\"]")
NEW_LINE = '__version__ = "{}"'


def get_new_version(old_version, dev_number):
    assert old_version.endswith("-dev")
    return old_version.replace("-dev", ".dev{}".format(dev_number), 1)


def patch_file(path, dev_number):
    with open(path, "r") as fin:
        lines = fin.readlines()

    for i, line in enumerate(lines, start=0):
        m = LINE_RE.search(line)
        if m:
            old_version = m.group(1)
            lines[i] = NEW_LINE.format(get_new_version(old_version, dev_number))
            break

    with open(path, "w") as fout:
        fout.writelines(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Path to script with __version__")
    parser.add_argument(
        "--dev-no", type=int, help="Number N to patch the version to '.devN'"
    )
    args = parser.parse_args()
    patch_file(args.file, args.dev_no)


if __name__ == "__main__":
    main()
