# SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from abc import ABC, abstractmethod
import sys
import os


class TemplateLogger(ABC):
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


class EsptoolLogger(TemplateLogger):
    ansi_red: str = ""
    ansi_yellow: str = ""
    ansi_blue: str = ""
    ansi_normal: str = ""
    ansi_clear: str = ""
    ansi_line_up: str = ""
    ansi_line_clear: str = ""

    _stage_active: bool = False
    _newline_count: int = 0
    _kept_lines: list[str] = []

    _smart_features: bool = False
    _verbosity: str | None = None
    _print_anyway: bool = False

    def __new__(cls):
        """
        Singleton to ensure only one instance of the logger exists.
        """
        if not hasattr(cls, "instance"):
            cls.instance = super(EsptoolLogger, cls).__new__(cls)
            cls.instance.set_verbosity("auto")
        return cls.instance

    @classmethod
    def _del(cls) -> None:
        if hasattr(cls, "instance"):
            del cls.instance

    @classmethod
    def _set_smart_features(cls, override: bool | None = None):
        # Check for smart terminal and color support
        if override is not None:
            cls.instance._smart_features = override
        else:
            is_tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
            term_supports_color = os.getenv("TERM", "").lower() in (
                "xterm",
                "xterm-256color",
                "screen",
                "screen-256color",
                "linux",
                "vt100",
            )
            no_color = os.getenv("NO_COLOR", "").strip().lower() in ("1", "true", "yes")

            # Determine if colors should be enabled
            cls.instance._smart_features = (
                is_tty and term_supports_color and not no_color
            )
            # Handle Windows specifically
            if sys.platform == "win32" and cls.instance._smart_features:
                try:
                    from colorama import init

                    init()  # Enable ANSI support on Windows
                except ImportError:
                    cls.instance._smart_features = False

        if cls.instance._smart_features:
            cls.instance.ansi_red = "\033[1;31m"
            cls.instance.ansi_yellow = "\033[0;33m"
            cls.instance.ansi_blue = "\033[1;36m"
            cls.instance.ansi_normal = "\033[0m"
            cls.instance.ansi_clear = "\033[K"
            cls.instance.ansi_line_up = "\033[1A"
            cls.instance.ansi_line_clear = "\x1b[2K"
        else:
            cls.instance.ansi_red = ""
            cls.instance.ansi_yellow = ""
            cls.instance.ansi_blue = ""
            cls.instance.ansi_normal = ""
            cls.instance.ansi_clear = ""
            cls.instance.ansi_line_up = ""
            cls.instance.ansi_line_clear = ""

    def print(self, *args, **kwargs):
        """
        Log a plain message. Count newlines if in a collapsing stage.
        """
        if self._verbosity == "silent" and not self._print_anyway:
            return
        if self._stage_active:
            # Count the number of newlines in the message
            message = "".join(map(str, args))
            self._newline_count += message.count("\n")
            if kwargs.get("end", "\n") == "\n":
                self._newline_count += 1
        print(*args, **kwargs)
        self._print_anyway = False

    def note(self, message: str):
        """
        Log a Note: message in blue and white.
        """
        formatted_message = f"{self.ansi_blue}Note:{self.ansi_normal} {message}"
        if self._stage_active:
            self._kept_lines.append(formatted_message)
        self.print(formatted_message)

    def warning(self, message: str):
        """
        Log a Warning: message in yellow and white.
        """
        formatted_message = f"{self.ansi_yellow}Warning:{self.ansi_normal} {message}"
        if self._stage_active:
            self._kept_lines.append(formatted_message)
        self.print(formatted_message)

    def error(self, message: str):
        """
        Log an error message in red to stderr.
        """
        formatted_message = f"{self.ansi_red}{message}{self.ansi_normal}"
        self._print_anyway = True
        self.print(formatted_message, file=sys.stderr)

    def stage(self, finish: bool = False):
        """
        Start or finish a collapsible stage.
        Any log messages printed between the start and finish will be deleted
        when the stage is successfully finished.
        Warnings and notes will be saved and printed at the end of the stage.
        If terminal doesn't support ANSI escape codes, no collapsing happens.
        """
        if finish:
            if not self._stage_active:
                return
            # Deactivate stage to stop collecting input
            self._stage_active = False

            if self._smart_features:
                # Delete printed lines
                self.print(
                    f"{self.ansi_line_up}{self.ansi_line_clear}"
                    * (self._newline_count),
                    end="",
                    flush=True,
                )
                # Print saved warnings and notes
                for line in self._kept_lines:
                    self.print(line)

            # Clean the buffers for next stage
            self._kept_lines.clear()
            self._newline_count = 0
        else:
            self._stage_active = True

    def progress_bar(
        self,
        cur_iter: int,
        total_iters: int,
        prefix: str = "",
        suffix: str = "",
        bar_length: int = 30,
    ):
        """
        Call in a loop to print a progress bar overwriting itself in place.
        If terminal doesn't support ANSI escape codes, no overwriting happens.
        """
        filled = int(bar_length * cur_iter // total_iters)
        if filled == bar_length:
            bar = "=" * bar_length
        elif filled == 0:
            bar = " " * bar_length
        else:
            bar = f"{'=' * (filled - 1)}>{' ' * (bar_length - filled)}"

        percent = f"{100 * (cur_iter / float(total_iters)):.1f}"
        self.print(
            f"\r{self.ansi_clear}{prefix}[{bar}] {percent:>5}%{suffix} ",
            end="\n" if not self._smart_features or cur_iter == total_iters else "",
            flush=True,
        )

    def set_logger(self, new_logger):
        self.__class__ = new_logger.__class__

    def set_verbosity(self, verbosity: str):
        """
        Set the verbosity level to one of the following:
        - "auto": Enable smart terminal features and colors if supported by the terminal
        - "verbose": Enable verbose output (no collapsing output)
        - "silent": Disable all output except errors
        - "compact": Enable smart terminal features and colors even if not supported
        """
        if verbosity == self._verbosity:
            return

        self._verbosity = verbosity
        if verbosity == "auto":
            self._set_smart_features()
        elif verbosity == "verbose":
            self._set_smart_features(override=False)
        elif verbosity == "silent":
            pass
        elif verbosity == "compact":
            self._set_smart_features(override=True)
        else:
            raise ValueError(f"Invalid verbosity level: {verbosity}")


log = EsptoolLogger()
