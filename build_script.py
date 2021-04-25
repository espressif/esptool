#!/usr/bin/env python
#
# Description: Build script for espefuse.py, espsecure.py and esptool.py to
# create executables that can run on any computer - even without Python
# installation. Run this script with the -h flag to see more info and optional
# arguments.
#
# Author: Kristof Mulier (just this file)
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA 02110-1301 USA.

import os
import sys
import platform
import cx_Freeze
import inspect
import shutil
import argparse
import esptool
q = "'"

__version__ = '0.1'

__doc__ = '''
                      ESPTOOL BUILD SCRIPT
                      ====================

description:
  This build script compiles the following Python scripts into exe-
  cutables:
  
    espefuse.py  -> build/espefuse(.exe)
    espsecure.py -> build/espsecure(.exe)
    esptool.py   -> build/esptool(.exe)
  
  The build script uses cx_Freeze (https://cx-freeze.readthedocs.io)
  for this operation. It produces a 'build/' subfolder containing an
  executable for each of the compiled scripts, along with the shared
  libraries (DLLs or .so files) needed to run them. The target com-
  puter doesn't need Python anymore.
  
cross-platform:
  This build script works on both Windows and Linux. Only on Windows,
  the executables get the '.exe' suffix.

'''

def parse_arguments():
    '''
    Parse the command line arguments and store them as members of the
    'parsed_options' object.
    '''
    arg_parser = argparse.ArgumentParser(
        description     = __doc__,
        formatter_class = argparse.RawTextHelpFormatter,
    )
    # -v, --version
    arg_parser.add_argument(
        '-v',
        '--version',
        action  = 'version',
        version = str(
            f'build script version: {__version__}\n'
            f'esptool version: {esptool.__version__}\n'
            f'\n'
        ),
    )
    # -o, --output
    arg_parser.add_argument(
        '-o',
        '--output',
        action  = 'store',
        dest    = 'output',
        help    = f'define a custom output location instead of {q}/build{q}',
    )
    # -c, --clean
    arg_parser.add_argument(
        '-c',
        '--clean',
        action  = 'store_true',
        default = False,
        dest    = 'clean',
        help    = 'clean all build output and exit',
    )
    parsed_options = arg_parser.parse_args()
    return parsed_options

def clean_all(toplevel_directory, build_directory):
    '''
    Clean the given build-directory. This function has a built-in safety mechan-
    ism to avoid deleting important folders:
        - If the selected build-directory is an important system folder,
          deny permission to clean.
        - If the selected build-directory is *outside* the toplevel
          'esptool/' folder, ask the user permission to clean.

    :return: True if the clean operation was successful (or nothing needed to
             be cleaned). False if no permission was given for cleaning the
             specified folder.

    '''
    if not os.path.isdir(build_directory):
        os.makedirs(build_directory)
        return True

    #* Sanitize input
    build_directory = build_directory.replace('\\', '/')
    if build_directory.endswith('/'):
        build_directory = build_directory[0:-1]
    toplevel_directory = toplevel_directory.replace('\\', '/')
    if toplevel_directory.endswith('/'):
        toplevel_directory = toplevel_directory[0:-1]

    def yes_or_no():
        reply = str(
            input(
                f'The following directory will be cleaned: \n'
                f'{q}{build_directory}{q}\n'
                f'type {q}y{q} to continue, {q}n{q} to cancel (y/n): '
            )
        ).lower().strip()
        if reply[0] == 'y':
            return True
        if reply[0] == 'n':
            return False
        return yes_or_no()

    def allow_delete():
        #* Check for important system folders
        # If the build folder is actually one of these important system folders,
        # the permission to delete will always be denied!
        if sys.platform.lower().startswith('win'):
            important_folders = [
                '/program files', '/program files (x86)', '/windows', '/windows/system32',
                '/windows/winsxs', '/system volume information', '/appdata/local',
            ]
        else:
            important_folders = [
                '/bin', '/boot', '/cdrom', '/dev', '/etc', '/home', '/lib', '/lib32', '/lib64',
                '/libx32', '/lost+found', '/media', '/mnt', '/opt', '/proc', '/root', '/run',
                '/sbin', '/snap', '/srv', '/sys', '/tmp', '/usr', '/var',
                '/usr/bin', '/usr/local/bin', '/usr/sbin', '/etc/rc.d', '/usr/share/doc',
                '/usr/man', '/var/log', '/var/spool/mail', '/usr/lib', '/tmp', '/boot',
            ]
        if any(build_directory.lower().endswith(e) for e in important_folders):
            if '/esptool/' in build_directory.lower():
                # Example: a folder like '~/esptool/tmp' should be allowed
                # to clean.
                pass
            else:
                return False

        #* Check if build folder is outside toplevel folder
        # If the build folder is a subfolder of the toplevel 'esptool/' folder,
        # eg. '~/esptool/build', then permission to delete will always be gran-
        # ted. Otherwise, if the build folder is somewhere else, more precau-
        # tions are advisable. A yes/no prompt will be shown.
        if build_directory.startswith(toplevel_directory) and \
                build_directory != toplevel_directory:
            return True
        return yes_or_no()

    if allow_delete():
        print(
            f'clean build-directory\n'
        )
        for e in os.listdir(build_directory):
            abspath = os.path.join(
                build_directory,
                e,
            ).replace('\\', '/')
            if os.path.isdir(abspath):
                shutil.rmtree(abspath)
            else:
                os.remove(abspath)
        return True
    print(
        f'cannot clean build-directory\n'
    )
    return False

def build_all(toplevel_directory, build_directory):
    '''
    Given the toplevel directory (eg. '~/esptool') and the build-directory (eg.
    '~/esptool/build'), this function builds the following scripts with
    cx_Freeze:
        - espefuse.py
        - espsecure.py
        - esptool.py

    :param toplevel_directory: The toplevel 'esptool' directory, eg. '~/esptool'.
                               The scripts to be built can be found directly in
                               this toplevel directory, eg:
                                   - ~/esptool/espefuse.py
                                   - ~/esptool/espsecure.py
                                   - ~/esptool/esptool.py

    :param build_directory: The directory where the build output gets generated,
                            eg. '~/esptool/build'.

    :return: None
    '''
    print(
        f'build executables...\n'
    )
    #* Define executables
    #* ------------------
    is_windows = platform.system().lower() == 'windows'
    executables = [
        cx_Freeze.Executable(
            'espefuse.py',
            initScript = None,
            base       = None,
            icon       = 'espressif.ico',
            targetName = 'espefuse.exe' if is_windows else 'espefuse',
        ),
        cx_Freeze.Executable(
            'espsecure.py',
            initScript = None,
            base       = None,
            icon       = 'espressif.ico',
            targetName = 'espsecure.exe' if is_windows else 'espsecure',
        ),
        cx_Freeze.Executable(
            'esptool.py',
            initScript = None,
            base       = None,
            icon       = 'espressif.ico',
            targetName = 'esptool.exe' if is_windows else 'esptool',
        ),
    ]

    #* Define 'search_path'
    #* --------------------
    search_path = []
    temp = sys.path
    temp.append(toplevel_directory)
    for p in temp:
        p = p.replace('\\', '/')
        search_path.append(p)

    #* Invoke Freezer()
    #* ----------------
    freezer = cx_Freeze.Freezer(
        executables,
        replacePaths      = [],
        compress          = True,
        optimizeFlag      = True,
        path              = search_path,
        targetDir         = build_directory,
        includeFiles      = [],
        zipIncludes       = [],
        silent            = False,
    )
    freezer.Freeze()
    print(
        '\n'
        'finish build\n'
    )
    return

if __name__ == '__main__':
    #* Define directories
    #* ------------------
    # Extract the toplevel 'esptool' directory, which should be the directory
    # from where this 'build_script.py' runs. Also, define the default build
    # directory. Note that the default build-directory can be overridden by the
    # '--output' argument!
    _toplevel_directory = os.path.realpath(
        os.path.dirname(
            inspect.getfile(inspect.currentframe())
        )
    ).replace('\\', '/')
    _build_directory = os.path.join(
        _toplevel_directory,
        'build',
    ).replace('\\', '/')

    #* Parse arguments
    #* ---------------
    options = parse_arguments()
    # -o, --output
    # Define a custom output location. This argument overrules the default
    # build folder selection.
    if options.output:
        # Assume the user passed an absolute path.
        # If the absolute path doesn't exist, then
        # assume that the user passed a relative path.
        _build_directory = options.output.replace('\\', '/')
        if os.path.isabs(_build_directory) and os.path.isdir(_build_directory):
            _build_directory = os.path.realpath(
                _build_directory
            ).replace('\\', '/')
        else:
            _build_directory = '/'.join([
                _toplevel_directory,
                options.output.replace('\\', '/'),
            ]).replace('\\', '/').replace('//', '/')
            if not os.path.isdir(_build_directory):
                os.makedirs(_build_directory)
        # Print new build location
        print(
            f'Custom build-directory selected: {q}{_build_directory}{q}\n'
        )
    else:
        # Print default build location
        print(
            f'Default build-directory selected: {q}{_build_directory}{q}\n'
        )

    # -c, --clean
    # Clean all build output and exit. The build output is supposed to be in the
    # default build folder, or in the argument passed through --output (see pre-
    # vious).
    if options.clean:
        clean_all(
            _toplevel_directory,
            _build_directory,
        )
        sys.exit()

    #* Start build
    #* -----------
    # The clean operation is super fast. So we'll just clean before each build.
    success = clean_all(
        _toplevel_directory,
        _build_directory,
    )
    if not success:
        # Clean operation didn't complete, probably because one has no per-
        # mission to clean the selected build-directory.
        print(f'don{q} build - stop')
        sys.exit()

    build_all(
        _toplevel_directory,
        _build_directory,
    )
    sys.exit()
