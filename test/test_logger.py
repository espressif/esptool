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

    def stage(self, finish=False):
        pass

    def progress_bar(
        self,
        cur_iter: int,
        total_iters: int,
        prefix: str = "",
        suffix: str = "",
        bar_length: int = 30,
    ):
        pass


# Custom logger that doesn't implement all methods
class CustomLoggerIncomplete:
    def print(self, *args, **kwargs):
        pass


@pytest.mark.host_test
class TestLogger:
    @pytest.fixture
    def logger(self):
        log = EsptoolLogger()
        log._set_smart_features(True)
        return log

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

    def test_stage(self, logger):
        with patch("sys.stdout", new=StringIO()) as fake_out:
            logger.stage()
            assert logger._stage_active
            logger.print("Line1")
            logger.print("Line2")
            logger.stage(finish=True)
            assert not logger._stage_active
            logger.print("Line3")

            output = fake_out.getvalue()
            assert f"{logger.ansi_line_up}{logger.ansi_line_clear}" * 2 in output
            assert "Line1\nLine2\n" in output
            assert "Line1\nLine2\nLine3\n" not in output

    def test_progress_bar(self, logger):
        with patch("sys.stdout", new=StringIO()) as fake_out:
            logger.progress_bar(
                cur_iter=2,
                total_iters=4,
                prefix="Progress: ",
                suffix=" (2/4)",
                bar_length=10,
            )
            logger.progress_bar(
                cur_iter=4,
                total_iters=4,
                prefix="Progress: ",
                suffix=" (4/4)",
                bar_length=10,
            )
            output = fake_out.getvalue()
            assert "Progress: [====>     ]  50.0% (2/4)" in output
            assert "Progress: [==========] 100.0% (4/4) \n" in output

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
