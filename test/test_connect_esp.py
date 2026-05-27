from unittest.mock import MagicMock, patch

import pytest

import esptool
from esptool import FatalError, connect_esp
from esptool.loader import ESPLoader
from esptool.logger import log


@pytest.mark.host_test
class TestConnectEsp:
    def _make_esp(self):
        return MagicMock(spec=ESPLoader)

    def test_uses_default_path(self):
        mock_esp = self._make_esp()
        with (
            patch("esptool.cmds.connect_with_retries") as mock_loop,
            patch(
                "esptool.cmds.connect_first_available", return_value=mock_esp
            ) as mock_default,
            patch.object(log, "print"),
        ):
            result = connect_esp(port="/dev/ttyUSB0")
        assert result is mock_esp
        mock_loop.assert_not_called()
        mock_default.assert_called_once()

    def test_uses_connect_with_retries(self):
        mock_esp = self._make_esp()
        with (
            patch(
                "esptool.cmds.connect_with_retries", return_value=mock_esp
            ) as mock_loop,
            patch("esptool.cmds.connect_first_available") as mock_default,
            patch.object(log, "print"),
        ):
            result = connect_esp(
                port="/dev/ttyUSB0", chip="esp32", open_port_attempts=3
            )
        assert result is mock_esp
        mock_loop.assert_called_once_with(
            "/dev/ttyUSB0", ESPLoader.ESP_ROM_BAUD, "esp32", 3, False, "default-reset"
        )
        mock_default.assert_not_called()

    def test_connect_with_retries_warning_no_port(self):
        mock_esp = self._make_esp()
        with (
            patch("esptool.cmds.connect_with_retries") as mock_loop,
            patch("esptool.cmds.connect_first_available", return_value=mock_esp),
            patch("esptool.cmds.get_port_list", return_value=["/dev/ttyUSB0"]),
            patch("esptool.cmds.parse_port_filters", return_value=[]),
            patch.object(log, "print"),
            patch.object(log, "warning") as mock_warning,
        ):
            result = connect_esp(port=None, open_port_attempts=3)
        assert result is mock_esp
        mock_loop.assert_not_called()
        mock_warning.assert_called_once()
        assert "open_port_attempts" in mock_warning.call_args.args[0]

    def test_connect_with_retries_warning_auto_chip(self):
        mock_esp = self._make_esp()
        with (
            patch("esptool.cmds.connect_with_retries") as mock_loop,
            patch("esptool.cmds.connect_first_available", return_value=mock_esp),
            patch.object(log, "print"),
            patch.object(log, "warning") as mock_warning,
        ):
            result = connect_esp(port="/dev/ttyUSB0", chip="auto", open_port_attempts=3)
        assert result is mock_esp
        mock_loop.assert_not_called()
        mock_warning.assert_called_once()

    def test_raises_fatal_error_no_device(self):
        with (
            patch("esptool.cmds.connect_first_available", return_value=None),
            patch.object(log, "print"),
        ):
            with pytest.raises(FatalError, match="Could not connect"):
                connect_esp(port="/dev/ttyUSB0")

    def test_initial_baud_passed_through(self):
        mock_esp = self._make_esp()
        with (
            patch(
                "esptool.cmds.connect_first_available", return_value=mock_esp
            ) as mock_default,
            patch.object(log, "print"),
        ):
            connect_esp(port="/dev/ttyUSB0", initial_baud=921600)
        assert mock_default.call_args.kwargs["initial_baud"] == 921600

    def test_port_discovery(self):
        mock_esp = self._make_esp()
        with (
            patch("esptool.cmds.parse_port_filters", return_value=[]) as mock_parse,
            patch(
                "esptool.cmds.get_port_list",
                return_value=["/dev/ttyUSB0", "/dev/ttyUSB1"],
            ) as mock_ports,
            patch(
                "esptool.cmds.connect_first_available", return_value=mock_esp
            ) as mock_default,
            patch.object(log, "print"),
        ):
            connect_esp(port=None, port_filter=["vid=0x303A"])
        mock_parse.assert_called_once_with(["vid=0x303A"])
        mock_ports.assert_called_once()
        assert mock_default.call_args.args[0] == ["/dev/ttyUSB0", "/dev/ttyUSB1"]

    def test_legacy_aliases_still_importable(self):
        # Downstream projects (e.g. pytest-embedded) import these names from
        # the esptool package directly; the regression to guard against is
        # `from esptool import get_default_connected_device` breaking.
        assert callable(esptool.connect_loop)
        assert callable(esptool.get_default_connected_device)
