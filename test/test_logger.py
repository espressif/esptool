from io import StringIO
from unittest.mock import patch

import pytest
from esp_pylib.logger import (
    ASCII_PROGRESS_CHAR,
    UNICODE_PROGRESS_CHAR,
    EspLog,
    EspLogBase,
)

from esptool import __version__
from esptool.cmds import version
from esptool.logger import EsptoolLogger, TemplateLogger, log


class CustomLogger(EspLogBase):
    """Minimal `EspLogBase` implementation used by ``test_set_logger``.

    Implements every abstract method so :func:`EspLog.set_logger` accepts
    the instance. ``print`` prepends a sentinel so the test can confirm
    that the swap actually takes effect.
    """

    def print(self, *args, **kwargs):
        print("Custom logger:", *args, **kwargs)

    def note(self, message):
        pass

    def warn(self, message, suggestion=None):
        pass

    def err(self, message, suggestion=None):
        pass

    def debug(self, message):
        pass

    def hint(self, message):
        pass

    def stage(self, finish=False):
        pass

    def progress_bar(
        self,
        cur_iter,
        total_iters,
        prefix="",
        suffix="",
        bar_length=30,
    ):
        pass

    def set_verbosity(self, verbosity):
        pass


class CustomLoggerIncomplete:
    """Plain class that implements neither `TemplateLogger` nor
    `EspLogBase`. ``set_logger`` should reject it."""

    def print(self, *args, **kwargs):
        pass


class RecordingLegacyLogger(TemplateLogger):
    """Records every `TemplateLogger` hook for backward-compat tests.

    Matches the seven-method contract documented in ``scripting.rst`` —
    integrators subclass ``TemplateLogger`` with ``warning`` / ``error``
    (not ``warn`` / ``err``) and install via ``log.set_logger(...)``.
    """

    def __init__(self) -> None:
        self.prints: list[tuple[tuple, dict]] = []
        self.notes: list[str] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []
        self.stages: list[bool] = []
        self.progress_bars: list[tuple] = []
        self.verbosity: list[str] = []

    def print(self, *args, **kwargs):
        self.prints.append((args, kwargs))

    def note(self, message):
        self.notes.append(message)

    def warning(self, message):
        self.warnings.append(message)

    def error(self, message):
        self.errors.append(message)

    def stage(self, finish=False):
        self.stages.append(finish)

    def progress_bar(
        self,
        cur_iter,
        total_iters,
        prefix="",
        suffix="",
        bar_length=30,
    ):
        self.progress_bars.append((cur_iter, total_iters, prefix, suffix, bar_length))

    def set_verbosity(self, verbosity):
        self.verbosity.append(verbosity)


@pytest.fixture(autouse=True)
def _reset_singleton_after_each_test():
    """Restore the default singleton after each test.

    ``test_set_logger`` swaps the global logger; without this fixture the
    swap would leak into later tests (and into other ``test_logger.py``
    modules within the same process).

    The reinstall has to set ``EspLog.instance`` explicitly because
    ``EspLog.__new__`` only assigns to ``cls.instance`` (i.e.
    ``EsptoolLogger.instance``) and esp-pylib's ``log`` proxy reads from
    ``EspLog.instance``.
    """
    yield
    # Wipe both the parent slot and esptool's own slot before re-installing,
    # otherwise ``EsptoolLogger()`` would short-circuit on the cached
    # ``EsptoolLogger.instance`` left over from the previous test.
    EspLog._reset()
    if "instance" in EsptoolLogger.__dict__:
        del EsptoolLogger.instance
    EsptoolLogger._initialized = False
    EspLog.instance = EsptoolLogger()


@pytest.mark.host_test
class TestLogger:
    @pytest.fixture
    def logger(self):
        # ``EsptoolLogger`` is a subclass of `EspLog`; constructing it
        # both installs it as the active singleton and returns the instance.
        return EsptoolLogger()

    def test_singleton(self, logger):
        # `log` is the proxy from esp-pylib; comparing instances goes
        # through ``EspLog.instance`` and resolves to the same object.
        logger2 = EsptoolLogger()
        assert logger is logger2

    def test_print(self, logger):
        # The shared Rich console is captured via Rich's capture API: the
        # plain `patch("sys.stdout", ...)` trick from the pre-migration
        # tests no longer works because `Console` holds a reference to
        # the original stdout taken at construction time.
        with logger._stdout.capture() as captured:
            logger.print("With newline")
            logger.print("Without newline", end="")
        assert captured.get() == "With newline\nWithout newline"

    def test_print_follows_reassigned_stdout(self, logger):
        # The builtin `print` esptool historically used resolved
        # `sys.stdout` lazily on every call, so scripts wrapping
        # `esptool.main()` in `contextlib.redirect_stdout(...)` captured
        # esptool's output. Rich's `Console` instead binds `sys.stdout`
        # once at construction, so `EsptoolLogger.print` reroutes through a
        # fresh `Console(file=sys.stdout)` when it detects the stream has
        # been swapped. This guards that behaviour against regressions.
        fake_out = StringIO()
        with patch("sys.stdout", new=fake_out):
            logger.print("redirected line")
        assert fake_out.getvalue() == "redirected line\n"

    def test_warning_alias(self, logger):
        with logger._stderr.capture() as captured:
            logger.warning("This is a warning")
        # The new EspLog renders warnings as `WARNING: ...` via Rich. We
        # check the human-readable substring rather than the exact ANSI
        # output since Rich's color escape sequences are environment-
        # dependent.
        assert "WARNING:" in captured.get()
        assert "This is a warning" in captured.get()

    def test_error_alias(self, logger):
        with logger._stderr.capture() as captured:
            logger.error("This is an error")
        assert "ERROR:" in captured.get()
        assert "This is an error" in captured.get()

    def test_warn(self, logger):
        with logger._stderr.capture() as captured:
            logger.warn("This is a warn")
        assert "WARNING:" in captured.get()
        assert "This is a warn" in captured.get()

    def test_err(self, logger):
        with logger._stderr.capture() as captured:
            logger.err("This is an err")
        assert "ERROR:" in captured.get()
        assert "This is an err" in captured.get()

    def test_warn_err_dispatches_to_legacy_warning(self, logger):
        """`log.warn` and `log.err` must reach `TemplateLogger.warning`
        and ``TemplateLogger.error`` on custom loggers."""
        legacy = RecordingLegacyLogger()
        logger.set_logger(legacy)
        log.warn("via warn")
        log.err("via err")
        assert legacy.warnings == ["via warn"]
        assert legacy.errors == ["via err"]

    def test_warning_alias_reaches_legacy_logger(self, logger):
        """`log.warning` must work after `set_logger(TemplateLogger(...))`."""
        legacy = RecordingLegacyLogger()
        logger.set_logger(legacy)
        log.warning("via warning alias")
        assert legacy.warnings == ["via warning alias"]

    def test_error_alias_reaches_legacy_logger(self, logger):
        """`log.error` must work after `set_logger(TemplateLogger(...))`."""
        legacy = RecordingLegacyLogger()
        logger.set_logger(legacy)
        log.error("via error alias")
        assert legacy.errors == ["via error alias"]

    def test_debug_reaches_legacy_logger_with_multiple_args(self, logger):
        """`log.debug` must accept multiple args (e.g. `ESPLoader.trace`)."""
        legacy = RecordingLegacyLogger()
        logger.set_logger(legacy)
        log.debug("", " TRACE +0.000  hello")
        assert legacy.prints == [((" TRACE +0.000  hello",), {})]

    def test_legacy_template_logger_all_methods_via_log_proxy(self, logger):
        """Pre-migration `TemplateLogger` subclasses receive every `log.*` call.

        External integrators follow the documented scripting recipe: subclass
        `TemplateLogger` with `warning` / `error` / `print` / … and
        install via `log.set_logger(...)`. Internal esptool code now calls
        `log.warn` / `log.err`, but the adapter must still forward those
        (and the legacy aliases) to the same hooks as before migration.
        """
        legacy = RecordingLegacyLogger()
        logger.set_logger(legacy)

        log.print("hello", end="")
        log.note("a note")
        log.warn("warn msg")
        log.warning("warning alias")
        log.err("err msg")
        log.error("error alias")
        log.stage()
        log.stage(finish=True)
        log.progress_bar(1, 10, prefix="p", suffix="s", bar_length=5)
        log.set_verbosity("silent")

        assert legacy.prints == [(("hello",), {"end": ""})]
        assert legacy.notes == ["a note"]
        assert legacy.warnings == ["warn msg", "warning alias"]
        assert legacy.errors == ["err msg", "error alias"]
        assert legacy.stages == [False, True]
        assert legacy.progress_bars == [(1, 10, "p", "s", 5)]
        assert legacy.verbosity == ["silent"]

    def test_default_esptool_logger_via_log_proxy(self):
        """The module-level `log` proxy must drive `EsptoolLogger` unchanged."""
        with log._stdout.capture() as captured:
            log.print("via proxy")
            log.note("note msg")
        stdout = captured.get()
        assert "via proxy" in stdout
        assert "NOTE:" in stdout and "note msg" in stdout

        with log._stderr.capture() as captured:
            log.warn("warn msg")
            log.warning("warning alias")
            log.err("err msg")
            log.error("error alias")
        stderr = captured.get()
        assert "WARNING:" in stderr
        assert "warn msg" in stderr
        assert "warning alias" in stderr
        assert "ERROR:" in stderr
        assert "err msg" in stderr
        assert "error alias" in stderr

    def test_verbose_enables_debug(self, logger):
        """`--verbose` maps to esp-pylib `VERBOSE` (`debug()` output)."""
        with logger._stdout.capture() as captured:
            logger.debug("hidden by default")
        assert captured.get() == ""

        logger.set_verbosity("verbose")
        with logger._stdout.capture() as captured:
            logger.debug("shown in verbose")
        assert "shown in verbose" in captured.get()

    @staticmethod
    def _simulate_stage_erase_stdout(logger: EsptoolLogger) -> None:
        """`StringIO` does not interpret Rich cursor controls — drop staged lines."""
        count = logger._stage_newline_count
        if getattr(logger, "_stage_progress_visible", False):
            count += 1
        if count <= 0:
            return
        f = logger._stdout.file
        lines = f.getvalue().splitlines(keepends=True)
        f.truncate(0)
        f.seek(0)
        if count < len(lines):
            f.write("".join(lines[:-count]))

    def test_trace_disables_stage_collapsing_via_esplog_instance(self, logger):
        """`--trace` must set `_smart_features` on `EspLog.instance`.

        `EsptoolLogger()` can return a different object when the subclass
        ctor cache (`EsptoolLogger.instance`) diverges from the active
        singleton (`EspLog.instance`). The `log` proxy assignment
        `log._smart_features = ...` is also wrong — it sets the proxy, not
        the singleton.
        """
        active = EspLog.instance
        assert active is logger
        logger._smart_features = True
        assert logger._stage_can_collapse()

        # Diverge the subclass ctor cache from the active singleton.
        EsptoolLogger.instance = None
        discarded = EsptoolLogger()
        assert discarded is not active

        # Broken approaches must not affect the active logger.
        discarded._smart_features = False
        assert active._smart_features is True
        assert logger._stage_can_collapse()
        log._smart_features = False
        assert active._smart_features is True
        assert logger._stage_can_collapse()

        # Correct approach (as in `prepare_esp_object` for `--trace`).
        if hasattr(active, "_smart_features"):
            active._smart_features = False
        assert active._smart_features is False
        assert not logger._stage_can_collapse()

    def test_stage(self, logger):
        # Collapsible stages use esp-pylib's Rich cursor controls on
        # `logger._stdout`; force a TTY and enable smart features so
        # `_stage_can_collapse` is true in the test runner.
        from rich.console import Console

        logger._smart_features = True
        out = StringIO()
        logger._stdout = Console(
            file=out, force_terminal=True, highlight=False, emoji=False
        )
        with patch.object(
            logger,
            "_stage_erase_stdout",
            side_effect=lambda: self._simulate_stage_erase_stdout(logger),
        ):
            logger.stage()
            assert logger._stage_active
            logger.print("Line1")
            logger.print("Line2")
            logger.stage(finish=True)
            assert not logger._stage_active
        assert "Line1" not in out.getvalue()
        assert "Line2" not in out.getvalue()

    def test_progress_bar_stage_bookkeeping(self, logger):
        """Completed progress inside a stage must count toward line erase."""
        logger._smart_features = True
        # Route progress through Rich capture so this bookkeeping test does not
        # depend on the host stdout encoding (Windows cp1252 cannot encode the
        # Unicode bar glyphs Rich would otherwise emit on a real console).
        logger._stdout._force_terminal = True
        with logger._stdout.capture():
            logger.stage()
            logger.progress_bar(4, 4, prefix="Reading: ", bar_length=10)
            assert logger._stage_newline_count == 1
            assert not logger._stage_progress_visible
            logger.stage(finish=True)
            assert logger._stage_newline_count == 0

            logger.stage()
            logger.progress_bar(2, 4, prefix="Reading: ", bar_length=10)
            assert logger._stage_newline_count == 0
            assert logger._stage_progress_visible
            logger.stage(finish=True)
            assert not logger._stage_progress_visible

    def test_progress_bar(self, logger):
        # Progress rendering is inherited from `esp_pylib.logger.EspLog`
        # (Rich bar, or a fixed-width plain bar when `no_color` is set).
        #
        # `EspLog.progress_bar` picks its output Console based on
        # `self._stdout.is_terminal`: on an interactive terminal it writes
        # through `self._stdout` (and `Console.capture()` sees the output),
        # but on a non-TTY stream it creates a *fresh* `Console(file=sys.stdout)`
        # and writes there, bypassing capture. GitLab CI runs without a TTY
        # and without `FORCE_COLOR`, so without forcing terminal mode here
        # the captured buffer ends up empty and the assertions below would
        # fail. Force the interactive code path so the test is independent
        # of the surrounding terminal / env-var state.
        #
        # On legacy Windows consoles Rich uses ASCII glyphs (`=`) instead of
        # Unicode (`━`) for the plain `no_color` bar. The active console
        # may not be `logger._stdout` itself, so accept either glyph set.
        logger._stdout._force_terminal = True
        logger._stdout.no_color = True
        logger.no_color = True
        with logger._stdout.capture() as captured:
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
        output = captured.get()
        half_bar = (
            f"Progress: {UNICODE_PROGRESS_CHAR * 5}       50.0% (2/4)" in output
            or f"Progress: {ASCII_PROGRESS_CHAR * 5}       50.0% (2/4)" in output
        )
        full_bar = (
            f"Progress: {UNICODE_PROGRESS_CHAR * 10} 100.0% (4/4)" in output
            or f"Progress: {ASCII_PROGRESS_CHAR * 10} 100.0% (4/4)" in output
        )
        assert half_bar
        assert full_bar
        assert output.endswith("\n")

    def test_set_incomplete_logger(self, logger):
        with pytest.raises(
            TypeError,
            match="New logger must implement the TemplateLogger interface, "
            "got 'CustomLoggerIncomplete'",
        ):
            logger.set_logger(CustomLoggerIncomplete())

    def test_set_logger(self, logger):
        with logger._stdout.capture() as captured:
            version()
        assert captured.get() == f"{__version__}\n"

        # Installing a custom EspLogBase reroutes log.* through the new
        # instance. We don't try to capture this stream (the CustomLogger
        # writes directly via `print`) — we just confirm the swap
        # happened and that ``version()`` runs to completion through it.
        with patch("sys.stdout", new=StringIO()) as fake_out:
            logger.set_logger(CustomLogger())
            version()
            output = fake_out.getvalue()
            assert output == f"Custom logger: {__version__}\n"

    def test_template_logger_not_pylib_subclass(self):
        """`TemplateLogger` must stay independent of `EspLogBase`."""
        assert not issubclass(TemplateLogger, EspLogBase)

    def test_template_logger_still_accepted(self, logger):
        """Backward-compat: `TemplateLogger` subclasses must still install.

        External integrators following the documented "Custom Logger"
        scripting recipe define a `TemplateLogger` subclass with
        `warning` / `error` methods. `set_logger` wraps them for
        esp-pylib while keeping the legacy seven-method contract.
        """
        legacy = RecordingLegacyLogger()
        logger.set_logger(legacy)
        log.print("installed")
        assert legacy.prints == [(("installed",), {})]
