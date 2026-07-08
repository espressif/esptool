# SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""Esptool logger.

`EsptoolLogger` is a thin subclass over `esp_pylib.logger.EspLog` with
esptool-specific collapsible-stage gating (``_smart_features``, ``--trace``,
``compact`` / ``auto`` verbosity). Collapsible stages themselves are
implemented in esp-pylib; this module only overrides `_stage_can_collapse`
and `print` where esptool behaviour diverges from the shared default.

Internal code should call `warn` / `err` (esp-pylib canonical API,
including optional IDE ``suggestion``). `warning` / `error` remain
as backward-compatible aliases on `EsptoolLogger`.

`TemplateLogger` is a **standalone** ABC (it does not subclass
`EspLogBase`) so the documented scripting recipe keeps a stable,
seven-method contract even as esp-pylib evolves. `set_logger` wraps
legacy instances in `_LegacyLoggerAdapter`, which implements
`EspLogBase` and delegates to the template while inheriting esp-pylib
helpers such as `die` and `progress`.

``log`` is re-exported from `esp_pylib.logger` (same proxy object
that reads ``EspLog.instance``) after installing `EsptoolLogger`.
"""

from abc import ABC, abstractmethod
from typing import Any

from esp_pylib.logger import EspLog, EspLogBase, Verbosity, log

__all__ = [
    "EsptoolLogger",
    "TemplateLogger",
    "log",
]


class TemplateLogger(ABC):
    """Legacy abstract interface for custom loggers used with ``log.set_logger``.

    Preserved for the documented "Custom Logger" scripting recipe (and
    third-party integrations following it). Intentionally **not** a subclass
    of `esp_pylib.logger.EspLogBase` so esp-pylib 1.x interface growth
    (``hint``, ``progress``, signature tweaks) does not break subclasses
    that only implement the seven historical methods.

    New integrations should subclass `EspLogBase` and call
    ``log.set_logger(...)`` with that instance directly.

    Default `warn` / `err` forward to ``warning`` / ``error``; ``debug`` is
    a no-op so esptool can call the esp-pylib names on installed legacy
    loggers without requiring extra methods on the subclass.
    """

    @abstractmethod
    def print(self, *args, **kwargs):
        """
        Log a plain message.
        """
        pass

    @abstractmethod
    def note(self, message: str):
        """
        Log a Note: message.
        """
        pass

    @abstractmethod
    def warning(self, message: str):
        """
        Log a Warning: message.
        """
        pass

    @abstractmethod
    def error(self, message: str):
        """
        Log an error message.
        """
        pass

    @abstractmethod
    def stage(self, finish: bool = False):
        """
        Start or finish a new collapsible stage.
        """
        pass

    @abstractmethod
    def progress_bar(
        self,
        cur_iter: int,
        total_iters: int,
        prefix: str = "",
        suffix: str = "",
        bar_length: int = 30,
    ):
        """
        Print a progress bar.
        """
        pass

    @abstractmethod
    def set_verbosity(self, verbosity: str):
        """
        Set the verbosity level.
        """
        pass

    def warn(self, message: str, suggestion: str | None = None) -> None:
        """Forward to `warning` for legacy custom loggers.

        ``suggestion`` is accepted for API compatibility with esp-pylib but
        is not passed through — legacy integrators only implement
        `warning(message)`.
        """
        self.warning(message)

    def err(self, message: str, suggestion: str | None = None) -> None:
        """Forward to `error` for legacy custom loggers."""
        self.error(message)

    def debug(self, *args: Any) -> None:
        """Fallback to `print` for legacy custom loggers."""
        self.print("".join(str(a) for a in args))


class _LegacyLoggerAdapter(EspLogBase):
    """`EspLogBase` facade installed when ``set_logger`` receives a `TemplateLogger`.

    Delegates the seven legacy hooks to the wrapped logger. Inherits
    esp-pylib's default ``die``, ``progress``, and ``counter`` so internal
    callers can use the full pylib API without extending the public
    `TemplateLogger` contract. Exposes ``warning`` / ``error`` aliases
    (matching `EsptoolLogger`) so esptool can keep calling those names
    after a legacy logger is installed. ``hint`` is a no-op because legacy
    loggers have no corresponding hook.
    """

    __slots__ = ("_legacy",)

    def __init__(self, legacy: TemplateLogger) -> None:
        self._legacy = legacy

    def print(self, *args, **kwargs) -> None:
        self._legacy.print(*args, **kwargs)

    def note(self, message: str) -> None:
        self._legacy.note(message)

    def warn(self, *args: Any, suggestion: str | None = None) -> None:
        self._legacy.warn(" ".join(str(a) for a in args), suggestion=suggestion)

    def err(self, *args: Any, suggestion: str | None = None) -> None:
        self._legacy.err(" ".join(str(a) for a in args), suggestion=suggestion)

    def warning(self, message: str, suggestion: str | None = None) -> None:
        """Backward-compatible alias used by esptool and scripting docs."""
        self.warn(message, suggestion=suggestion)

    def error(self, message: str, suggestion: str | None = None) -> None:
        """Backward-compatible alias used by esptool and scripting docs."""
        self.err(message, suggestion=suggestion)

    def debug(self, *args: Any) -> None:
        self._legacy.debug("".join(str(a) for a in args))

    def hint(self, message: str) -> None:
        self.print(message)

    def stage(self, finish: bool = False) -> None:
        self._legacy.stage(finish=finish)

    def progress_bar(
        self,
        cur_iter: int,
        total_iters: int,
        prefix: str = "",
        suffix: str = "",
        bar_length: int = 30,
    ) -> None:
        self._legacy.progress_bar(
            cur_iter,
            total_iters,
            prefix=prefix,
            suffix=suffix,
            bar_length=bar_length,
        )

    def set_verbosity(self, mode: int | str) -> None:
        self._legacy.set_verbosity(mode)  # type: ignore[arg-type]


# Legacy CLI / scripting strings mapped onto `Verbosity`. ``verbose``
# uses `Verbosity.VERBOSE` so ``--verbose`` matches esp-pylib (``debug()``
# output, non-collapsing progress bars). Stage collapsing is disabled for
# VERBOSE via `EsptoolLogger._stage_can_collapse` (and for ``--trace``
# via ``_smart_features`` in `esptool.__init__`).
_VERBOSITY_LEVEL_MAP = {
    "auto": Verbosity.NORMAL,
    "verbose": Verbosity.VERBOSE,
    "silent": Verbosity.SILENT,
    "compact": Verbosity.NORMAL,
}


class EsptoolLogger(EspLog):
    """Esptool's default logger.

    Subclasses `esp_pylib.logger.EspLog` so Rich rendering, IDE
    WebSocket forwarding, collapsible stages, and ``--silent`` gating are
    shared with the rest of the Espressif tools, while keeping esptool-specific
    behaviour:

    * `_stage_can_collapse` honours ``_smart_features``: ``auto`` defers to
      esp-pylib's TTY detection, ``compact`` forces collapsing on, and
      ``--trace`` forces it off.
    * `print` keeps historical builtin-``print`` semantics (``flush``,
      ``soft_wrap``, lazy ``sys.stdout``).
    * `warn` / `err` are inherited from `EspLog` (canonical).
    * `warning` / `error` forward to them for backward compatibility.
    """

    instance: EspLogBase | None = None

    # Tri-state compatibility override for collapsible stages, consumed by
    # `_stage_can_collapse`:
    #   * ``None``  — auto: fallback to esp-pylib's detection
    #   * ``True``  — force collapsing on (``compact`` mode).
    #   * ``False`` — force collapsing off, set by the CLI in trace mode
    _smart_features: bool | None = None

    def _stage_can_collapse(self) -> bool:
        """Whether `stage` may rewind transient output.

        In ``auto`` mode (``_smart_features is None``) this defers to
        esp-pylib's default (normal verbosity + interactive stdout).
        ``compact`` (``True``) and ``--trace`` (``False``) force the
        decision instead.
        """
        if self._smart_features is None:
            return super()._stage_can_collapse()  # type: ignore[no-any-return]
        return self._smart_features and self._verbosity == Verbosity.NORMAL

    # ------------------------------------------------------------------
    # Backward-compatible aliases
    # ------------------------------------------------------------------

    def warning(self, message: str, suggestion: str | None = None) -> None:
        """Backward-compatible alias for `warn`."""
        self.warn(message, suggestion=suggestion)

    def error(self, message: str, suggestion: str | None = None) -> None:
        """Backward-compatible alias for `err`."""
        self.err(message, suggestion=suggestion)

    # ------------------------------------------------------------------
    # Verbosity + custom logger swap
    # ------------------------------------------------------------------

    def set_verbosity(self, verbosity):  # type: ignore[override]
        """Accept esptool's CLI verbosity strings + esp-pylib levels.

        Historical values (``auto``, ``verbose``, ``silent``, ``compact``) map
        onto `Verbosity`. ``verbose`` is :data:`Verbosity.VERBOSE` so
        it enables `debug` and full progress-bar lines like other
        esp-pylib tools. ``compact`` / ``auto`` only adjust stage collapsing
        (``_smart_features``); ``silent`` is :data:`Verbosity.SILENT`.
        """
        if isinstance(verbosity, str):
            key = verbosity.lower()
            if key in _VERBOSITY_LEVEL_MAP:
                super().set_verbosity(_VERBOSITY_LEVEL_MAP[key])
                if key == "compact":
                    self._smart_features = True
                elif key == "auto":
                    # Defer to esp-pylib's TTY-based detection.
                    self._smart_features = None
                return
        super().set_verbosity(verbosity)

    def set_logger(self, new_logger):  # type: ignore[override]
        """Install a custom logger instance as the active singleton.

        Accepts a `TemplateLogger` (wrapped for esp-pylib) or any
        `EspLogBase` implementation. Assignment goes to ``EspLog.instance``,
        which the shared ``log`` proxy reads.
        """
        if isinstance(new_logger, EspLogBase):
            instance: EspLogBase = new_logger
        elif isinstance(new_logger, TemplateLogger):
            instance = _LegacyLoggerAdapter(new_logger)
        else:
            raise TypeError(
                f"New logger must implement the TemplateLogger interface, "
                f"got {type(new_logger).__name__!r}"
            )
        EspLog.instance = instance

    # ------------------------------------------------------------------
    # Print — esptool-specific stdout semantics only
    # ------------------------------------------------------------------

    def print(self, *args, **kwargs) -> None:  # type: ignore[override]
        """Plain output with esptool's historical ``print`` semantics.

        ``soft_wrap=True`` is the default so Rich does not break long lines
        at the console width. A ``flush=True`` kwarg some callers pass is
        stripped here: Rich's ``Console.print`` already flushes the
        underlying stream once per call (the consoles are never used in a
        buffering context) and rejects an explicit ``flush`` argument.

        Following a reassigned ``sys.stdout`` (e.g. ``redirect_stdout``) and
        stage newline accounting are both handled by `EspLog.print`.
        """
        kwargs.pop("flush", None)
        kwargs.setdefault("soft_wrap", True)
        super().print(*args, **kwargs)


# Wire esptool's subclass into the shared singleton before anything imports
# ``log`` (re-exported from esp-pylib; it delegates to ``EspLog.instance``).
#
# Only install when no logger has been set yet, so that importing esptool as a
# library does not hijack a consumer tool's already-installed logger. When esptool
# is the top-level application, nothing has touched ``log`` yet, so ``EspLog.instance``
# is ``None`` here and esptool gets its own logger as before.
if EspLog.instance is None:
    EspLog.instance = EsptoolLogger()
