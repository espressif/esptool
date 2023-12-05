# SPDX-FileCopyrightText: 2014-2023 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import io
import os
import re
import sys

try:
    from setuptools import find_packages, setup
except ImportError:
    print(
        "Package setuptools is missing from your Python installation. "
        "Please see the installation section in the esptool documentation"
        " for instructions on how to install it."
    )
    sys.exit(1)


# Example code to pull version from esptool module with regex, taken from
# https://packaging.python.org/en/latest/guides/single-sourcing-package-version/
def read(*names, **kwargs):
    with io.open(
        os.path.join(os.path.dirname(__file__), *names),
        encoding=kwargs.get("encoding", "utf8"),
    ) as fp:
        return fp.read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


if os.name != "nt":
    scripts = ["esptool.py", "espefuse.py", "espsecure.py", "esp_rfc2217_server.py"]
    entry_points = {}
else:
    scripts = []
    entry_points = {
        "console_scripts": [
            "esptool.py=esptool.__init__:_main",
            "espsecure.py=espsecure.__init__:_main",
            "espefuse.py=espefuse.__init__:_main",
            "esp_rfc2217_server.py=esp_rfc2217_server:main",
        ],
    }


long_description = """
==========
esptool.py
==========
A Python-based, open-source, platform-independent utility to communicate with \
the ROM bootloader in Espressif chips.

The esptool.py project is `hosted on github <https://github.com/espressif/esptool>`_.

Documentation
-------------
Visit online `esptool documentation <https://docs.espressif.com/projects/esptool/>`_ \
or run ``esptool.py -h``.

Contributing
------------
Please see the `contributions guide \
<https://docs.espressif.com/projects/esptool/en/latest/contributing.html>`_.
"""

setup(
    name="esptool",
    version=find_version("esptool/__init__.py"),
    description="A serial utility to communicate & flash code to Espressif chips.",
    long_description=long_description,
    url="https://github.com/espressif/esptool/",
    project_urls={
        "Documentation": "https://docs.espressif.com/projects/esptool/",
        "Source": "https://github.com/espressif/esptool/",
        "Tracker": "https://github.com/espressif/esptool/issues/",
    },
    author="Fredrik Ahlberg (themadinventor) & Angus Gratton (projectgus) "
    "& Espressif Systems",
    author_email="",
    license="GPLv2+",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Operating System :: POSIX",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS :: MacOS X",
        "Topic :: Software Development :: Embedded Systems",
        "Environment :: Console",
        "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.7",
    setup_requires=(["wheel"] if "bdist_wheel" in sys.argv else []),
    extras_require={
        "dev": [
            "flake8>=3.2.0",
            "flake8-import-order",
            "flake8-gl-codeclimate",
            "pyelftools",
            "coverage~=6.0",
            "black",
            "pre-commit",
            "pytest",
            "pytest-rerunfailures",
            "requests",
            "commitizen",
        ],
        "hsm": [
            "python-pkcs11",
        ],
    },
    install_requires=[
        "bitstring>=3.1.6",
        "cryptography>=2.1.4",
        "ecdsa>=0.16.0",
        "pyserial>=3.0",
        "reedsolo>=1.5.3,<1.8",
        "PyYAML>=5.1",
        "intelhex",
    ],
    packages=find_packages(),
    include_package_data=True,
    package_data={"": ["esptool/targets/stub_flasher/*.json"]},
    entry_points=entry_points,
    scripts=scripts,
)
