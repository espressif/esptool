import pytest
from io import StringIO
from unittest.mock import patch
from esptool import __version__
from esptool.logger import EsptoolLogger, log, TemplateLogger
from esptool.cmds import version


# Custom logger that implements all methods
class CustomLogger(TemplateLogger):
    def print(self, *args, **kwargs):
        print("Custom logger:", *args, **kwargs)

    def note(self, message: str):
        """
        Logs a Note: message.
        """
        pass

    def warning(self, message: str):
        """
        Logs a Warning: message.
        """
        pass

    def error(self, message: str):
        """
        Logs an error message.
        """
        pass

    def print_overwrite(self, message: str, last_line: bool = False):
        """
        Prints a message, overwriting the currently printed line.
        """
        pass

    def set_progress(self, percentage: float):
        """
        Sets the progress of long-running operations to a specific percentage.
        """
        pass


# Custom logger that doesn't implement all methods
class CustomLoggerIncomplete:
    def print(self, *args, **kwargs):
        pass


@pytest.mark.host_test
class TestLogger:
    @pytest.fixture
    def logger(self):
        return EsptoolLogger()

    def test_singleton(self, logger):
        logger2 = EsptoolLogger()
        assert logger is logger2
        assert logger is log

    def test_print(self, logger):
        with patch("sys.stdout", new=StringIO()) as fake_out:
            logger.print("With newline")
            logger.print("Without newline", end="")
            assert fake_out.getvalue() == "With newline\nWithout newline"

    def test_note_message(self, logger):
        with patch("sys.stdout", new=StringIO()) as fake_out:
            logger.note("This is a note")
            assert (
                fake_out.getvalue()
                == f"{logger.ansi_blue}Note:{logger.ansi_normal} This is a note\n"
            )

    def test_warning_message(self, logger):
        with patch("sys.stdout", new=StringIO()) as fake_out:
            logger.warning("This is a warning")
            assert (
                fake_out.getvalue()
                == f"{logger.ansi_yellow}Warning:{logger.ansi_normal} "
                "This is a warning\n"
            )

    def test_error_message(self, logger):
        with patch("sys.stderr", new=StringIO()) as fake_out:
            logger.error("This is an error")
            assert (
                fake_out.getvalue()
                == f"{logger.ansi_red}This is an error{logger.ansi_normal}\n"
            )

    def test_print_overwrite_tty(self, logger):
        with (
            patch("sys.stdout", new=StringIO()) as fake_out,
            patch("sys.stdout.isatty", return_value=True),
        ):
            logger.print_overwrite("msg1", last_line=False)
            logger.print_overwrite("msg2", last_line=True)
            output = fake_out.getvalue()
            assert "msg1\n" not in output  # msg1 should not have a newline
            assert f"\r{logger.ansi_clear}msg1" in output
            assert f"\r{logger.ansi_clear}msg2\n" in output

    def test_print_overwrite_non_tty(self, logger):
        with (
            patch("sys.stdout", new=StringIO()) as fake_out,
            patch("sys.stdout.isatty", return_value=False),
        ):
            logger.print_overwrite("msg1", last_line=False)
            logger.print_overwrite("msg2", last_line=True)
            assert fake_out.getvalue() == "msg1\nmsg2\n"  # Acting as a normal print()

    def test_set_progress(self, logger):
        logger.set_progress(50.0)
        # Since set_progress is not implemented - just ensure it doesn't raise an error
        assert True

    def test_set_incomplete_logger(self, logger):
        with pytest.raises(
            TypeError,
            match="'CustomLoggerIncomplete' object layout differs from 'EsptoolLogger'",
        ):
            logger.set_logger(CustomLoggerIncomplete())

    def test_set_logger(self, logger):
        # Original logger
        with patch("sys.stdout", new=StringIO()) as fake_out:
            version()  # This will log.print the estool version
            output = fake_out.getvalue()
            assert output == f"{__version__}\n"

        # Replace logger with custom one
        with patch("sys.stdout", new=StringIO()) as fake_out:
            logger.set_logger(CustomLogger())
            assert isinstance(logger, CustomLogger)
            version()  # This will use print from CustomLogger
            output = fake_out.getvalue()
            assert output == f"Custom logger: {__version__}\n"
