import os
import sys
import platform
import subprocess
import multiprocessing
import cx_Freeze
import inspect


def freeze_esptool(custom_python_path, local_modules, target_name, build_directory):
    builtin_modules = [
        'ctypes',
        'serial',
        'serial.tools',
        'serial.tools.list_ports',
        'division',
        'print_function',
        'argparse',
        'base64',
        'binascii',
        'copy',
        'hashlib',
        'inspect',
        'io',
        'itertools',
        'os',
        'shlex',
        'string',
        'struct',
        'sys',
        'time',
        'zlib',
        'argparse',
        'hashlib',
        'operator',
        'os',
        'struct',
        'sys',
        'zlib',
        'collections',
        'collections.namedtuple',
        'cryptography',
        'cryptography.exceptions',
        'cryptography.hazmat.backends',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.asymmetric',
        'cryptography.hazmat.primitives.ciphers',
        'cryptography.utils',
        'ecdsa',
        'esptool',
        'espressif.efuse.esp32',
        'espressif.efuse.esp32c3',
        'espressif.efuse.esp32s2',
        'espressif.efuse.esp32s3beta2',
        'espressif.efuse.esp32s3beta3',
    ]
    if platform.system().lower() == 'windows':
        builtin_modules.extend(
            [
                'win32api',
                'win32con',
                'win32file',
            ]
        )
    # Add the local modules
    modules = local_modules + builtin_modules
    print('All used local modules:')
    for m in local_modules:
        print(' -', m)

    executables = [
        cx_Freeze.Executable(
            'embeetle.py',
            initScript = None,
            base       = None,
            icon       = 'espressif.ico',
            targetName = f'{target_name}.exe',
        )
    ]

    search_path = []

    #* Invoke Freezer()
    print(
        f'\n\nfreezer = cx_Freeze.Freezer(\n'
        f'    {executables},\n'
        f'    includes     = {modules},\n'
        f'    replacePaths = [],\n'
        f'    compress     = True,\n'
        f'    optimizeFlag = True,\n'
        f'    path         = {search_path},\n'
        f'    targetDir    = {build_directory},\n'
        f'    includeFiles = [],\n'
        f'    zipIncludes  = [],\n'
        f'    silent       = False,\n'
        f')\n\n'
    )


if __name__ == '__main__':
    # Directories
    toplevel_directory = os.path.realpath(
        os.path.dirname(
            inspect.getfile(inspect.currentframe())
        )
    )
