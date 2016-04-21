from setuptools import setup
from codecs import open
from os import path
import io
import os
import re

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


# Example code to pull version from esptool.py with regex, taken from
# http://python-packaging-user-guide.readthedocs.org/en/latest/single_source_version/
def read(*names, **kwargs):
    with io.open(
            os.path.join(os.path.dirname(__file__), *names),
            encoding=kwargs.get("encoding", "utf8")
    ) as fp:
        return fp.read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


setup(
    name='esptool',
    version=find_version('esptool.py'),
    description='A utility to communicate with the ROM bootloader in Espressif ESP8266.',
    long_description=long_description,
    url='https://github.com/themadinventor/esptool',
    author='Fredrik Ahlberg',
    author_email='fredrik@z80.se',
    license='GPLv2+',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Embedded Systems',
        'Environment :: Console',
        'License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)',
        'Programming Language :: Python :: 2.7',
    ],
    setup_requires=[
        'flake8',
    ],
    install_requires=[
        'pyserial',
    ],
    scripts=[
        'esptool.py',
    ],
)
