import pytest
from unittest.mock import patch
import esptool

# Espressif VID constant (same as in esptool/__init__.py)
ESPRESSIF_VID = 0x303A


class MockPort:
    """Mock serial port object that mimics pyserial's ListPortInfo"""

    def __init__(self, device, vid=None, pid=None, name=None, serial_number=None):
        self.device = device
        self.vid = vid
        self.pid = pid
        self.name = name
        self.serial_number = serial_number


@pytest.mark.host_test
class TestPortSorting:
    """Test the port sorting algorithm in get_port_list function"""

    def test_linux_port_sorting(self):
        """Test port sorting on Linux platform"""
        mock_ports = [
            MockPort("/dev/ttyS0", vid=0x1234),
            MockPort("/dev/ttyS1", vid=0x1234),
            MockPort("/dev/ttyUSB0", vid=0x1234),
            MockPort("/dev/ttyUSB1", vid=0x1234),
            MockPort("/dev/ttyACM1", vid=ESPRESSIF_VID),
            MockPort("/dev/ttyACM0", vid=0x1234),
        ]

        with (
            patch("sys.platform", "linux"),
            patch("esptool.list_ports") as mock_list_ports,
        ):
            mock_list_ports.comports.return_value = mock_ports

            result = esptool.get_port_list()

            # Expected sorting order (alphabetically within each group):
            # 1. Other devices (priority 1)
            # 2. ttyUSB*/ttyACM* devices (priority 2)
            # 3. Espressif VID devices (priority 3) - highest priority, appear LAST
            expected = [
                "/dev/ttyS0",  # Other
                "/dev/ttyS1",  # Other
                "/dev/ttyACM0",  # USB/ACM
                "/dev/ttyUSB0",  # USB/ACM
                "/dev/ttyUSB1",  # USB/ACM
                "/dev/ttyACM1",  # Espressif VID
            ]

            assert result == expected

    def test_macos_port_sorting(self):
        """Test port sorting on macOS platform"""
        mock_ports = [
            MockPort("/dev/cu.wlan-debug", vid=0x1234),  # Excluded by macOS filter
            MockPort(
                "/dev/cu.Bluetooth-Incoming-Port", vid=0x1234
            ),  # Excluded by macOS filter
            MockPort("/dev/cu.debug-console", vid=0x1234),  # Excluded by macOS filter
            MockPort("/dev/cu.usbserial2", vid=0x1234),
            MockPort("/dev/cu.usbmodem1", vid=0x1234),
            MockPort("/dev/cu.usbmodem2", vid=ESPRESSIF_VID),
            MockPort("/dev/cu.usbserial1", vid=0x1234),
        ]

        with (
            patch("sys.platform", "darwin"),
            patch("esptool.list_ports") as mock_list_ports,
        ):
            mock_list_ports.comports.return_value = mock_ports

            result = esptool.get_port_list()

            # Expected sorting order (alphabetically within each group):
            # 1. Other devices (priority 1)
            # 2. usbserial*/usbmodem* devices (priority 2)
            # 3. Espressif VID devices (priority 3) - highest priority, appear LAST
            # Note: wlan-debug, Bluetooth-Incoming-Port, debug-console are excluded
            expected = [
                "/dev/cu.usbmodem1",  # usbmodem
                "/dev/cu.usbserial1",  # usbserial
                "/dev/cu.usbserial2",  # usbserial
                "/dev/cu.usbmodem2",  # Espressif VID
            ]

            assert result == expected

    def test_windows_port_sorting(self):
        """Test port sorting on Windows platform"""
        mock_ports = [
            MockPort("COM3", vid=0x1234),
            MockPort("COM1", vid=0x1234),
            MockPort("COM10", vid=0x1234),
            MockPort("COM5", vid=ESPRESSIF_VID),
            MockPort("COM2", vid=0x1234),
        ]

        with (
            patch("sys.platform", "win32"),
            patch("esptool.list_ports") as mock_list_ports,
        ):
            mock_list_ports.comports.return_value = mock_ports

            result = esptool.get_port_list()

            # Expected sorting order (alphabetically within each group):
            # 1. All other COM ports (priority 1)
            # 2. Espressif VID devices (priority 2) - highest priority, appear LAST
            expected = [
                "COM1",  # Other
                "COM10",  # Other
                "COM2",  # Other
                "COM3",  # Other
                "COM5",  # Espressif VID
            ]

            assert result == expected

    def test_port_filtering_parameters(self):
        """Test port filtering with various parameters while maintaining sorting"""
        mock_ports = [
            MockPort(
                "/dev/ttyUSB0",
                vid=0x1234,
                pid=0x5678,
                name="USB Serial",
                serial_number="ABC123",
            ),
            MockPort(
                "/dev/ttyUSB1",
                vid=ESPRESSIF_VID,
                pid=0x1001,
                name="ESP32",
                serial_number="ESP001",
            ),
            MockPort(
                "/dev/ttyUSB2",
                vid=ESPRESSIF_VID,
                pid=0x1002,
                name="ESP32-S3",
                serial_number="ESP002",
            ),
        ]

        with (
            patch("sys.platform", "linux"),
            patch("esptool.list_ports") as mock_list_ports,
        ):
            mock_list_ports.comports.return_value = mock_ports

            # Test VID filtering - Espressif devices appear last
            result = esptool.get_port_list(vids=[ESPRESSIF_VID])
            expected = ["/dev/ttyUSB1", "/dev/ttyUSB2"]
            assert result == expected

            # Test PID filtering
            result = esptool.get_port_list(pids=[0x1001])
            expected = ["/dev/ttyUSB1"]
            assert result == expected

            # Test name filtering
            result = esptool.get_port_list(names=["ESP32"])
            expected = ["/dev/ttyUSB1", "/dev/ttyUSB2"]
            assert result == expected

            # Test serial filtering
            result = esptool.get_port_list(serials=["ESP"])
            expected = ["/dev/ttyUSB1", "/dev/ttyUSB2"]
            assert result == expected
