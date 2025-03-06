#!/usr/bin/env python

import shutil
import subprocess


def main():

    # remove not needed for plain python use
    shutil.rmtree("ci", ignore_errors=True)
    shutil.rmtree("docs", ignore_errors=True)
    shutil.rmtree("flasher_stub", ignore_errors=True)
    shutil.rmtree("test", ignore_errors=True)

    zipfile = "esptool.zip"

    print("Zip needed files into {}...".format(zipfile))
    subprocess.run(["/usr/bin/7z", "a", "-mx=9", "-tzip", "-xr!.*", zipfile, "./"], check=True) # noqa: E501


if __name__ == "__main__":
    main()
