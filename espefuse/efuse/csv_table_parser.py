# This file helps to parse CSV eFuse tables
#
# SPDX-FileCopyrightText: 2024 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import re
import sys


class CSVFuseTable(list):
    @classmethod
    def from_csv(cls, csv_contents):
        res = CSVFuseTable()
        lines = csv_contents.splitlines()

        def expand_vars(f):
            f = os.path.expandvars(f)
            m = re.match(r"(?<!\\)\$([A-Za-z_]\w*)", f)
            if m:
                raise InputError(f"unknown variable '{m.group(1)}'")
            return f

        for line_no, line in enumerate(lines):
            line = expand_vars(line).strip()
            if line.startswith("#") or len(line) == 0:
                continue
            try:
                res.append(FuseDefinition.from_csv(line))
            except InputError as err:
                raise InputError(f"Error at line {line_no + 1}: {err}")
            except Exception:
                sys.stderr.write(f"Unexpected error parsing line {line_no + 1}: {line}")
                raise

        # fix up missing bit_start
        last_efuse_block = None
        for i in res:
            if last_efuse_block != i.efuse_block:
                last_end = 0
            if i.bit_start is None:
                i.bit_start = last_end
            last_end = i.bit_start + i.bit_count
            last_efuse_block = i.efuse_block

        res.verify_duplicate_name()

        # fix up missing field_name
        last_field = None
        for i in res:
            if i.field_name == "":
                if last_field is None:
                    raise InputError(
                        f"Error at line {line_no + 1}: {i} missing field name"
                    )
                elif last_field is not None:
                    i.field_name = last_field.field_name
            last_field = i

        # fill group
        names = [p.field_name for p in res]
        duplicates = set(n for n in names if names.count(n) > 1)
        for dname in duplicates:
            i_count = 0
            for p in res:
                if p.field_name != dname:
                    continue
                if len(duplicates.intersection([p.field_name])) != 0:
                    p.field_name = f"{p.field_name}_{i_count}"
                    if p.alt_names:
                        p.alt_names = f"{p.alt_names}_{i_count}"
                    i_count += 1
                else:
                    i_count = 0

        for p in res:
            p.field_name = p.field_name.replace(".", "_")
            if p.alt_names:
                p.alt_names = p.alt_names.replace(".", "_")
        res.verify_duplicate_name()
        return res

    def verify_duplicate_name(self):
        # check on duplicate name
        names = [p.field_name for p in self]
        names += [name.replace(".", "_") for name in names if "." in name]
        duplicates = set(n for n in names if names.count(n) > 1)

        # print sorted duplicate partitions by name
        if len(duplicates) != 0:
            fl_error = False
            for p in self:
                field_name = p.field_name + p.group
                if field_name != "" and len(duplicates.intersection([field_name])) != 0:
                    fl_error = True
                    print(
                        f"Field at {p.field_name}, {p.efuse_block}, "
                        f"{p.bit_start}, {p.bit_count} have duplicate field_name"
                    )
            if fl_error is True:
                raise InputError("Field names must be unique")

    def check_struct_field_name(self):
        # check that structured fields have a root field
        for p in self:
            if "." in p.field_name:
                name = ""
                for sub in p.field_name.split(".")[:-1]:
                    name = sub if name == "" else name + "." + sub
                    missed_name = True
                    for d in self:
                        if (
                            p is not d
                            and p.efuse_block == d.efuse_block
                            and name == d.field_name
                        ):
                            missed_name = False
                    if missed_name:
                        raise InputError(f"{name} is not found")

    def verify(self, type_table=None):
        def check(p, n):
            left = n.bit_start
            right = n.bit_start + n.bit_count - 1
            start = p.bit_start
            end = p.bit_start + p.bit_count - 1
            if left <= start <= right:
                if left <= end <= right:
                    return "included in"  # [n  [p...p]  n]
                return "intersected with"  # [n  [p..n]..p]
            if left <= end <= right:
                return "intersected with"  # [p..[n..p] n]
            if start <= left and right <= end:
                return "wraps"  # [p  [n...n]  p]
            return "ok"  # [p] [n]  or  [n] [p]

        def print_error(p, n, state):
            raise InputError(
                f"Field at {p.field_name}, {p.efuse_block}, {p.bit_start}, {p.bit_count}  {state}  {n.field_name}, {n.efuse_block}, {n.bit_start}, {n.bit_count}"
            )

        for p in self:
            p.verify(type_table)

        self.verify_duplicate_name()
        if type_table != "custom_table":
            # check will be done for common and custom tables together
            self.check_struct_field_name()

        # check for overlaps
        for p in self:
            for n in self:
                if p is not n and p.efuse_block == n.efuse_block:
                    state = check(p, n)
                    if state != "ok":
                        if "." in p.field_name:
                            name = ""
                            for sub in p.field_name.split("."):
                                name = sub if name == "" else name + "." + sub
                                for d in self:
                                    if (
                                        p is not d
                                        and p.efuse_block == d.efuse_block
                                        and name == d.field_name
                                    ):
                                        state = check(p, d)
                                        if state == "included in":
                                            break
                                        elif state != "intersected with":
                                            state = "out of range"
                                        print_error(p, d, state)
                            continue
                        elif "." in n.field_name:
                            continue
                        print_error(p, n, state)


class FuseDefinition(object):
    def __init__(self):
        self.field_name = ""
        self.group = ""
        self.efuse_block = ""
        self.bit_start = None
        self.bit_count = None
        self.define = None
        self.comment = ""
        self.alt_names = ""
        self.MAX_BITS_OF_BLOCK = 256

    @classmethod
    def from_csv(cls, line):
        """Parse a line from the CSV"""
        line_w_defaults = line + ",,,,"
        fields = [f.strip() for f in line_w_defaults.split(",")]

        res = FuseDefinition()
        res.field_name = fields[0]
        res.efuse_block = res.parse_block(fields[1])
        res.bit_start = res.parse_num(fields[2])
        res.bit_count = res.parse_bit_count(fields[3])
        if res.bit_count is None or res.bit_count == 0:
            raise InputError("Field bit_count can't be empty")
        res.comment = fields[4].rstrip("\\").rstrip()
        res.comment += f" ({res.bit_start}-{res.bit_start + res.bit_count - 1})"
        res.alt_names = res.get_alt_names(res.comment)
        return res

    def parse_num(self, strval):
        if strval == "":
            return None
        return self.parse_int(strval)

    def parse_bit_count(self, strval):
        if strval == "MAX_BLK_LEN":
            self.define = strval
            return self.MAX_BITS_OF_BLOCK
        else:
            return self.parse_num(strval)

    def parse_int(self, v):
        try:
            return int(v, 0)
        except ValueError:
            raise InputError(f"Invalid field value {v}")

    def parse_block(self, strval):
        if strval == "":
            raise InputError("Field 'efuse_block' can't be left empty.")
        return self.parse_int(strval.lstrip("EFUSE_BLK"))

    def verify(self, type_table):
        if self.efuse_block is None:
            raise ValidationError(self, "efuse_block field is not set")
        if self.bit_count is None:
            raise ValidationError(self, "bit_count field is not set")
        max_bits = self.MAX_BITS_OF_BLOCK
        if self.bit_start + self.bit_count > max_bits:
            raise ValidationError(
                self,
                f"The field is outside the boundaries(max_bits = {max_bits}) of the {self.efuse_block} block",
            )

    def get_bit_count(self, check_define=True):
        if check_define is True and self.define is not None:
            return self.define
        else:
            return self.bit_count

    def get_alt_names(self, comment):
        result = re.search(r"^\[(.*?)\]", comment)
        if result:
            return result.group(1)
        return ""


class InputError(RuntimeError):
    def __init__(self, e):
        super(InputError, self).__init__(e)


class ValidationError(InputError):
    def __init__(self, p, message):
        super(ValidationError, self).__init__(
            f"Entry {p.field_name} invalid: {message}"
        )
