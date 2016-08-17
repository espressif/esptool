#!/usr/bin/env python
import os.path
import glob
import sys
import subprocess
import difflib
import warnings

from elftools.elf.elffile import ELFFile

TESTS_DIR = os.path.join(os.path.dirname(__file__), "elf2image")
ESPTOOL_PY = os.path.join(os.path.dirname(__file__), "..", "esptool.py")


def get_irom_offset(elf_file):
    """ For ESP8266, return the offset of the IROM section in the ELF """
    with open(elf_file, "rb") as f:
        e = ELFFile(f)
        for s in e.iter_sections():
            try:
                sh_addr = s.header["sh_addr"]
                if 0x40200000 < sh_addr < 0x40300000:
                    return sh_addr - 0x40200000
            except AttributeError:
                pass
    return None

# ESP8266 test cases declared as:
# "esp8266", ELF file, version, binaries as list
#
# ESP32 test cases declared as
# "esp32", ELF file

class Test(object):
    def __init__(self, elf):
        self.test_dir = os.path.dirname(elf)
        self.elf = os.path.split(elf)[-1]
        self.txt = os.path.splitext(self.elf)[0] + ".txt"

    def verify_files(self):
        elf_path = os.path.join(self.test_dir, self.elf)
        if not os.path.exists(elf_path):
            raise TestError("ELF file %s not found! (%s)" % (elf_path, self))
        if len(self.bins) == 0:
            raise TestError("No binary files found for %s (%s)" % (elf_path, self))
        for b in self.bins:
            bin_path = os.path.join(self.test_dir, b)
            if not os.path.exists(bin_path):
                raise TestError("No binary %s found for ELF file %s (%s)" % (bin_path, self.elf, self))


    def get_elf_path(self):
        return os.path.join(self.test_dir, self.elf)

    def get_bin_paths(self):
        return [ os.path.join(self.test_dir, b) for b in self.bins ]

    def get_txt_path(self):
        return os.path.join(self.test_dir, self.txt)

class ESP8266V1Test(Test):
    def __init__(self, elf):
        super(ESP8266V1Test, self).__init__(elf)
        self.bins = [ self.elf + "-0x00000.bin", "%s-0x%05x.bin" % (self.elf, get_irom_offset(elf)) ]

    def get_esptool_args(self, cmd):
        return [ "--chip", "esp8266", cmd, "--version", "1" ]

class ESP8266V2Test(Test):
    def __init__(self, elf):
        super(ESP8266V2Test, self).__init__(elf)
        # only expect one bin file per V2 ELF, but base address is determined by ELF contents
        self.bins = [ "%s-0x%05x.bin" % (os.path.splitext(self.elf)[0], get_irom_offset(elf)-0x10) ]

    def get_esptool_args(self, cmd):
        return [ "--chip", "esp8266", cmd, "--version", "2" ]

class ESP32Test(Test):
    def __init__(self, elf):
        super(ESP32Test, self).__init__(elf)
        self.bins = [ os.path.splitext(elf)[0] + ".bin" ]

    def get_esptool_args(self, cmd):
        return [ "--chip", "esp32", cmd ]

def collect_tests():
    """ Returns a list of all test objects, by searching elf files in subdirectories of TESTS_DIR """
    def inner_generator():
        for testdir,cls in [ ("esp8266-v1", ESP8266V1Test), ("esp8266-v2", ESP8266V2Test), ("esp32", ESP32Test) ]:
            for elf in glob.glob(os.path.join(TESTS_DIR, testdir, "*.elf")):
                yield cls(elf)
    return list(inner_generator())

def regenerate_all(tests):
    """ Regenerates the .bin & .txt output from all the input files. Useful if the format changes
    in some legitimate way. Output should be reviewed (via git diff, etc.) to make sure that this
    isn't actually introducing a bug!
    """
    for t in tests:
        # run elf2image
        cmd = [sys.executable, ESPTOOL_PY ] + t.get_esptool_args("elf2image")[2:] + [ t.get_elf_path() ]
        print "Executing %s" % (" ".join(cmd))
        subprocess.check_output(cmd)

        # run image_info to regenerate txt file
        cmd = [sys.executable, ESPTOOL_PY, "image_info", t.get_bin_paths()[0] ]
        image_info = subprocess.check_output(cmd)
        with open(t.get_txt_path(), "w") as f:
            f.write(image_info)
        t.verify_files()

def run_tests(tests):
    """ Run all tests supplied as argument (from collect_tests()), return number of failures. """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        binfile = os.tempnam(None, "test_elf2image")
    failed = 0
    for t in tests:
        print "*"*80
        print "Testing %s ..." % t.get_elf_path()
        # run elf2image
        cmd = [sys.executable, ESPTOOL_PY ] + t.get_esptool_args("elf2image")[2:] + [ "-o", binfile, t.get_elf_path() ]
        print "Executing %s" % (" ".join(cmd))
        subprocess.check_output(cmd)
        try:
            bins = list(sorted(glob.glob(binfile + "*")))
            main_binfile = bins[0]
        except:
            raise TestError("elf2image %s failed to generate bin file" % t.elf)

        if len(bins) != len(t.get_bin_paths()):
            print "FAIL: Expected %s to make %d binary files but got %d binary files." % (t.elf, len(t.get_bin_paths()), len(bins))
            failed += 1
        for b,ob in zip(bins, t.get_bin_paths()):
            with open(b, "r") as f:
                generated = f.read()
            with open(ob, "r") as f:
                original = f.read()
            if len(generated) != len(original):
                print "FAIL: Binary %s has different length to expected binary %s" % (b, ob)
                failed += 1
            elif generated != original:
                print "FAIL: Binary %s has same length but different content to expected %s" % (b,ob)
                failed += 1
            else:
                print "PASS: Generated binary %s identical" % b

        # run image_info
        cmd = [sys.executable, ESPTOOL_PY, "image_info", main_binfile ]
        print "Executing %s" % (" ".join(cmd))
        image_info = subprocess.check_output(cmd)
        with open(t.get_txt_path(), "r") as f:
            original_image_info = f.read()

        if image_info != original_image_info:
            failed += 1
            print "FAIL: image_info output changed for %s" % t.elf
            for line in difflib.unified_diff(original_image_info.split("\n"),image_info.split("\n")):
                print(line)
        else:
            print "PASS: image_info output is identical"
        for b in bins:
            os.remove(b)

    return failed



class TestError(RuntimeError):
    pass

if __name__ == "__main__":
    tests = collect_tests()
    if len(sys.argv) == 2 and sys.argv[1].startswith("--regen"):
        regenerate_all(tests)
    elif len(sys.argv) == 1:
        failed = run_tests(tests)
        print "*"*80
        if failed > 0:
            print "%d test failures" % failed
            sys.exit(1)
        else:
            print "All elf2image test cases passed."
    else:
        print "Usage: %s [--regen]" % sys.argv[0]

