from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='esptool',
    version='0.1.0',
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
    install_requires=[
        'pyserial',
    ],
    scripts=[
        'esptool.py',
    ],
)
