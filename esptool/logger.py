# SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

from abc import ABC, abstractmethod
import sys


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
    def print_overwrite(self, message: str, last_line: bool = False):
        """
        Print a message, overwriting the currently printed line.
        """
        pass

    @abstractmethod
    def set_progress(self, percentage: float):
        """
        Set the progress of long-running operations to a specific percentage.
        """
        pass


class EsptoolLogger(TemplateLogger):
    ansi_red = "\033[1;31m"
    ansi_yellow = "\033[0;33m"
    ansi_blue = "\033[0;34m"
    ansi_normal = "\033[0m"
    ansi_clear = "\033[K"

    def __new__(cls):
        """
        Singleton to ensure only one instance of the logger exists.
        """
        if not hasattr(cls, "instance"):
            cls.instance = super(EsptoolLogger, cls).__new__(cls)
        return cls.instance

    @classmethod
    def _del(cls) -> None:
        if hasattr(cls, "instance"):
            del cls.instance

    def print(self, *args, **kwargs):
        """
        Log a plain message.
        """
        print(*args, **kwargs)

    def note(self, message: str):
        """
        Log a Note: message in blue and white.
        """

        formatted_message = f"{self.ansi_blue}Note:{self.ansi_normal} {message}"
        print(formatted_message)

    def warning(self, message: str):
        """
        Log a Warning: message in yellow and white.
        """

        formatted_message = f"{self.ansi_yellow}Warning:{self.ansi_normal} {message}"
        print(formatted_message)

    def error(self, message: str):
        """
        Log an error message in red to stderr.
        """

        formatted_message = f"{self.ansi_red}{message}{self.ansi_normal}"
        print(formatted_message, file=sys.stderr)

    def print_overwrite(self, message: str, last_line: bool = False):
        """
        Print a message, overwriting the currently printed line.

        If last_line is False, don't append a newline at the end
        (expecting another subsequent call will overwrite this one).

        After a sequence of calls with last_line=False, call once with last_line=True.

        If output is not a TTY (for example redirected a pipe),
        no overwriting happens and this function is the same as print().
        """
        if hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
            # ansi_clear clears the line to prevent artifacts from previous lines
            print(
                f"\r{self.ansi_clear}{message}",
                end="\n" if last_line else "",
                flush=True,
            )
        else:
            print(message)

    def set_progress(self, percentage: float):
        """
        Set the progress of long-running operations to a specific percentage.
        Overwrite this method in a custom logger to implement e.g. a progress bar.

        Percentage is a float between 0 and 100.
        """
        pass

    def set_logger(self, new_logger):
        self.__class__ = new_logger.__class__


log = EsptoolLogger()
