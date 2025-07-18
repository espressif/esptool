#!/usr/bin/env python

# SPDX-FileCopyrightText: 2014-2025 Fredrik Ahlberg, Angus Gratton,
# Espressif Systems (Shanghai) CO LTD, other contributors as noted.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from esptool.cli_util import parse_port_filters
from esptool.util import FatalError


class TestPortFilter:
    def test_parse_port_filters_basic(self):
        """Test basic port filter parsing"""
        vids, pids, names, serials = parse_port_filters(['vid=0x303a'])
        assert vids == [0x303a]
        assert pids == []
        assert names == []
        assert serials == []

    def test_parse_port_filters_multiple(self):
        """Test parsing multiple port filters"""
        vids, pids, names, serials = parse_port_filters([
            'vid=0x303a', 'pid=123', 'name=ESP32', 'serial=ABC123'
        ])
        assert vids == [0x303a]
        assert pids == [123]
        assert names == ['ESP32']
        assert serials == ['ABC123']

    def test_parse_port_filters_decimal_vid(self):
        """Test VID parsing with decimal value"""
        vids, pids, names, serials = parse_port_filters(['vid=12346'])
        assert vids == [12346]

    def test_parse_port_filters_hex_pid(self):
        """Test PID parsing with hex value"""
        vids, pids, names, serials = parse_port_filters(['pid=0x1234'])
        assert pids == [0x1234]

    def test_parse_port_filters_malformed_input_from_optioneatall(self):
        """Test parsing malformed input from OptionEatAll class"""
        # This simulates the bug where OptionEatAll passes tuple with string representation
        vids, pids, names, serials = parse_port_filters(("['vid=0x303a']",))
        assert vids == [0x303a]
        assert pids == []
        assert names == []
        assert serials == []

    def test_parse_port_filters_malformed_multiple(self):
        """Test parsing malformed input with multiple filters"""
        vids, pids, names, serials = parse_port_filters(("['vid=0x303a', 'name=ESP32']",))
        assert vids == [0x303a]
        assert pids == []
        assert names == ['ESP32']
        assert serials == []

    def test_parse_port_filters_invalid_key(self):
        """Test error handling for invalid filter keys"""
        with pytest.raises(FatalError, match="Option --port-filter argument key not recognized"):
            parse_port_filters(['invalidkey=123'])

    def test_parse_port_filters_invalid_format(self):
        """Test error handling for invalid filter format"""
        with pytest.raises(FatalError, match="Option --port-filter argument must consist of key=value"):
            parse_port_filters(['invalidformat'])

    def test_parse_port_filters_case_sensitivity(self):
        """Test that filter keys are case sensitive"""
        with pytest.raises(FatalError, match="Option --port-filter argument key not recognized"):
            parse_port_filters(['VID=0x303a'])  # Uppercase should fail

    def test_parse_port_filters_empty_list(self):
        """Test handling of empty filter list"""
        vids, pids, names, serials = parse_port_filters([])
        assert vids == []
        assert pids == []
        assert names == []
        assert serials == []