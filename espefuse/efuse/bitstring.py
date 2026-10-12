# SPDX-FileCopyrightText: 2006-2025 Scott Griffiths <dr.scottgriffiths@gmail.com>
# SPDX-FileContributor: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: MIT
#
# Minimal subset of bitstring 4.3.1 (https://github.com/scott-griffiths/bitstring)
# used by espefuse.
#
# The MIT License
#
# Copyright (c) 2006 Scott Griffiths (dr.scottgriffiths@gmail.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import builtins
import io
import operator
import re
import typing as t
from collections.abc import Iterable

# The bits are kept in a Python int plus an explicit length. Bit 0 is the most
# significant bit of the first byte (MSB0), which is upstream's default mode.

MAX_CHARS = 250

# A token name followed by optional : then an integer number
NAME_INT_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9_]*?):?(\d*)$")
# A token name followed by optional : then an arbitrary keyword
NAME_KWARG_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9_]*?):?([a-zA-Z0-9_]+)$")
MULTIPLICATIVE_RE = re.compile(r"^(?P<factor>.*)\*(?P<token>.+)")
# Hex or binary literals (upstream also accepts octal)
LITERAL_RE = re.compile(r"^(?P<name>0([xb]))(?P<value>.+)", re.IGNORECASE)

# Literal prefix: (name used in error messages, base, bits per digit)
_LITERALS = {"0x": ("hex", 16, 4), "0b": ("bin", 2, 1)}

_T = t.TypeVar("_T", bound="Bits")


class Error(Exception):
    """Base class for errors in the bitstring module."""

    def __init__(self, *params: object) -> None:
        self.msg = params[0] if params else ""
        self.params = params[1:]


class ReadError(Error, IndexError):
    """Reading or peeking past the end of a bitstring."""


InterpretError = ValueError
"""Inappropriate interpretation of binary data."""

CreationError = ValueError
"""Inappropriate argument during bitstring creation."""


def _preprocess_tokens(fmt: str) -> list[str]:
    # Upstream also expands brackets and struct-style codes such as '>2H'. espefuse
    # uses neither, and such tokens raise ValueError later.
    tokens = []
    for meta_token in "".join(fmt.split()).split(","):
        if meta_token == "":
            continue
        factor = 1
        if m := MULTIPLICATIVE_RE.match(meta_token):
            factor = int(m.group("factor"))
            meta_token = m.group("token")
        tokens.extend([meta_token] * factor)
    return tokens


def _literal_to_bits(name: str, value: str) -> tuple[int, int]:
    kind, base, bits_per_digit = _LITERALS[name.lower()]
    digits = "".join(value.split()).lower().replace("_", "")
    digits = digits.replace(name.lower(), "")
    if any(c not in "0123456789abcdef"[:base] for c in digits):
        if kind == "bin":
            raise CreationError(f"Invalid character in bin initialiser {digits}.")
        raise CreationError(f"Invalid symbol in {kind} initialiser.")
    return int(digits or "0", base), len(digits) * bits_per_digit


def _parse_token(token: str) -> tuple[str, int | None, str | None]:
    """Split a creation token such as '0x1f', 'uint:8=5' or 'bool=1' into
    (name, length, value).
    """
    if m := LITERAL_RE.match(token):
        return m.group("name"), None, m.group("value")

    value = None
    if (equals_pos := token.find("=")) != -1:
        value = token[equals_pos + 1 :]
        token = token[:equals_pos]
    length_str: str | None
    if m := NAME_INT_RE.match(token):
        name, length_str = m.group(1), m.group(2) or None
    elif m := NAME_KWARG_RE.match(token):
        name, length_str = m.group(1), m.group(2)
    else:
        # A token without a name is a bare length of upstream's 'bits' type
        name, length_str = "bits", token
    if length_str is None:
        return name, None, value
    try:
        return name, int(length_str), value
    except ValueError:
        raise ValueError(f"Don't understand length '{length_str}' of token.")


def _build_token(name: str, length: int | None, value: str | None) -> tuple[int, int]:
    if name.lower() in _LITERALS:
        # LITERAL_RE only matches with at least one digit
        return _literal_to_bits(name, t.cast(str, value))
    if name == "uint":
        if value is None:
            raise ValueError(f"Token {name} requires a value.")
        if not length:
            raise CreationError(
                "A non-zero length must be specified with a uint initialiser."
            )
        i = int(value)
        if i >= (1 << length):
            raise CreationError(
                f"{i} is too large an unsigned integer for a bitstring of length "
                f"{length}. The allowed range is [0, {(1 << length) - 1}]."
            )
        if i < 0:
            raise CreationError("uint cannot be initialised with a negative number.")
        return i, length
    if name == "bool":
        if length not in (None, 1):
            raise CreationError(
                f"Can't parse token: A length of {length} was supplied for the "
                "'bool' dtype, but its only allowed length is 1."
            )
        if value is None:
            raise ValueError(f"Token {name} requires a value.")
        # No implicit conversion to bool, so that 'False' is not truthy
        if value in ("True", "1"):
            return 1, 1
        if value in ("False", "0"):
            return 0, 1
        raise CreationError(f"Cannot initialise boolean with {value}.")
    if name == "bits" and value is None:
        # Upstream knows 'bits' and so reports the missing value first, e.g. for
        # the '2' in 'uint:4=1,2'
        raise ValueError(f"Token {name} requires a value.")
    raise CreationError(
        f"Can't parse token: Unknown Dtype name '{name}'. "
        "Names available: ['bool', 'uint']."
    )


def _tokens_to_bits(fmt: str) -> tuple[int, int]:
    # Parse all tokens before building any, so that an error message names the
    # same token as upstream's
    parsed = [_parse_token(token) for token in _preprocess_tokens(fmt)]
    value = length = 0
    for token in parsed:
        token_value, token_length = _build_token(*token)
        value = (value << token_length) | token_value
        length += token_length
    return value, length


def _bytes_to_bits(data: bytes | bytearray, length: int | None) -> tuple[int, int]:
    data = bytes(data)
    available = len(data) * 8
    if length is None:
        length = available
    elif length > available:
        raise CreationError(
            f"Not enough data present. Need {length} bits, have {available}."
        )
    # Data beyond length is dropped
    return int.from_bytes(data, "big") >> (available - length), length


def _auto_to_bits(auto: object) -> tuple[int, int]:
    if isinstance(auto, int):
        if auto < 0:
            raise CreationError(f"Can't create bitstring of negative length {auto}.")
        return 0, int(auto)
    if isinstance(auto, Bits):
        return auto._value, auto._len
    if isinstance(auto, str):
        return _tokens_to_bits(auto)
    if isinstance(auto, io.BufferedReader):
        # Upstream reopens the file by name, so the handle position is ignored
        with open(auto.name, "rb") as f:
            return _bytes_to_bits(f.read(), None)
    raise TypeError(f"Cannot initialise bitstring from type '{type(auto)}'.")


class Bits:
    """An immutable sequence of bits."""

    __slots__ = ("_value", "_len")

    def __init__(
        self,
        auto: t.Any = None,
        /,
        length: int | None = None,
        bytes: "builtins.bytes | bytearray | None" = None,
    ) -> None:
        """Create from an int (that many zero bits), a token string such as
        '0x00' or 'uint:8=5', another bitstring or a binary file object.
        Without auto, create length zero bits, or the first length bits of bytes.
        """
        if length is not None and length < 0:
            raise CreationError(f"Can't create bitstring of negative length {length}.")
        if bytes is not None:
            if auto is not None:
                raise CreationError("Give either auto or bytes, not both.")
            value, length = _bytes_to_bits(bytes, length)
        elif auto is None:
            value, length = 0, length or 0
        elif length is not None:
            raise CreationError(
                f"Cannot initialise bitstring from type '{type(auto)}' when using "
                "explicit lengths or offsets."
            )
        else:
            value, length = _auto_to_bits(auto)
        self._value = value
        self._len = length

    @classmethod
    def _create(cls: type[_T], value: int, length: int) -> _T:
        obj = cls()
        obj._value = value
        obj._len = length
        return obj

    @staticmethod
    def _convert(other: object) -> "Bits":
        """Accept a bitstring or a token string where a bitstring is expected."""
        if isinstance(other, Bits):
            return other
        if isinstance(other, str):
            return Bits(other)
        raise TypeError(f"Cannot initialise bitstring from type '{type(other)}'.")

    def _same_length(self, other: "Bits | str") -> "Bits":
        bs = self._convert(other)
        if bs._len != self._len:
            raise ValueError("bitarrays of equal length expected")
        return bs

    def _slice_value(self, start: int, end: int) -> int:
        return (self._value >> (self._len - end)) & ((1 << (end - start)) - 1)

    def _getbit(self, i: int) -> bool:
        return bool((self._value >> (self._len - 1 - i)) & 1)

    def _getbin(self) -> str:
        return format(self._value, f"0{self._len}b") if self._len else ""

    def _gethex(self) -> str:
        return format(self._value, f"0{self._len // 4}x") if self._len else ""

    def _tobytes(self) -> builtins.bytes:
        # Zero bits pad the end to a whole byte
        nbytes = (self._len + 7) // 8
        return (self._value << (nbytes * 8 - self._len)).to_bytes(nbytes, "big")

    @property
    def len(self) -> int:
        """Length of the bitstring in bits."""
        return self._len

    @property
    def length(self) -> int:
        """Length of the bitstring in bits."""
        return self._len

    @property
    def bytes(self) -> builtins.bytes:
        if self._len % 8:
            raise InterpretError(
                "Cannot interpret as bytes unambiguously - not multiple of 8 bits."
            )
        return self._value.to_bytes(self._len // 8, "big")

    @property
    def hex(self) -> str:
        if self._len % 4:
            raise InterpretError(
                "'hex' dtypes must have a length in (0, 4, ...), but received a "
                f"length of {self._len}."
            )
        return self._gethex()

    @property
    def uint(self) -> int:
        if not self._len:
            raise InterpretError(
                "Cannot interpret a zero length bitstring as an integer."
            )
        return self._value

    def all(self, value: object) -> bool:
        """Return True if every bit equals bool(value)."""
        return self._value == ((1 << self._len) - 1 if value else 0)

    def any(self, value: object) -> bool:
        """Return True if at least one bit equals bool(value)."""
        return self._value != (0 if value else (1 << self._len) - 1)

    def count(self, value: object) -> int:
        """Return the number of bits equal to bool(value)."""
        ones = self._value.bit_count()
        return ones if value else self._len - ones

    def tofile(self, f: t.BinaryIO) -> None:
        """Write the bits to a binary file, padded with zero bits to a whole byte."""
        if self._len:
            f.write(self._tobytes())

    def __len__(self) -> int:
        return self._len

    def __bytes__(self) -> builtins.bytes:
        # Without this, bytes() would iterate over the bits one by one
        return self._tobytes()

    @t.overload
    def __getitem__(self, key: int) -> bool: ...

    @t.overload
    def __getitem__(self: _T, key: slice) -> _T: ...

    def __getitem__(self: _T, key: int | slice) -> _T | bool:
        # A slice is always a copy, never a view
        if isinstance(key, slice):
            start, stop, step = key.indices(self._len)
            if step == 1:
                length = max(stop - start, 0)
                return self._create(self._slice_value(start, start + length), length)
            bits = self._getbin()[key]
            return self._create(int(bits or "0", 2), len(bits))
        i = operator.index(key)
        if i < 0:
            i += self._len
        if not 0 <= i < self._len:
            raise IndexError("bitarray index out of range")
        return self._getbit(i)

    def __eq__(self, other: object) -> bool:
        # An int, float or None compares unequal, as in upstream. Bytes or a list,
        # which upstream converts and compares, raise TypeError in _convert.
        if not isinstance(other, (Bits, str, Iterable)):
            return False
        bs = self._convert(other)
        return self._len == bs._len and self._value == bs._value

    def __contains__(self, item: object) -> bool:
        # Without this, "in" would compare item with each bit and return False
        # where upstream searches for a sub-bitstring
        raise TypeError("Searching a bitstring is not supported.")

    def __add__(self, other: "Bits | str") -> "Bits":
        bs = self._convert(other)
        # As in upstream, a longer right operand of a subclass type decides the class
        if isinstance(bs, type(self)) and bs._len > self._len:
            cls = type(bs)
        else:
            cls = type(self)
        return cls._create((self._value << bs._len) | bs._value, self._len + bs._len)

    def __mul__(self: _T, n: int) -> _T:
        if n < 0:
            raise ValueError("Cannot multiply by a negative integer.")
        value = 0
        for _ in range(n):
            value = (value << self._len) | self._value
        return self._create(value, self._len * n)

    def __and__(self: _T, other: "Bits | str") -> _T:
        return self._create(self._value & self._same_length(other)._value, self._len)

    def __or__(self: _T, other: "Bits | str") -> _T:
        return self._create(self._value | self._same_length(other)._value, self._len)

    def __str__(self) -> str:
        length = self._len
        if not length:
            return ""
        if length > MAX_CHARS * 4:
            # Too long for hex. Truncate...
            return "".join(("0x", self[0 : MAX_CHARS * 4]._gethex(), "..."))
        # If it's quite short and we can't do hex then use bin
        if length < 32 and length % 4 != 0:
            return "0b" + self._getbin()
        # If we can use hex then do so
        if not length % 4:
            return "0x" + self._gethex()
        # Otherwise first we do as much as we can in hex
        # then add on 1, 2 or 3 bits on at the end
        bits_at_end = length % 4
        return "".join(
            (
                "0x",
                self[0 : length - bits_at_end]._gethex(),
                ", ",
                "0b",
                self[length - bits_at_end :]._getbin(),
            )
        )

    def _repr(self, classname: str, length: int, pos: int) -> str:
        pos_string = f", pos={pos}" if pos else ""
        s = self.__str__()
        lengthstring = ""
        if s.endswith("..."):
            lengthstring = f"  # length={length}"
        return f"{classname}('{s}'{pos_string}){lengthstring}"

    def __repr__(self) -> str:
        return self._repr(self.__class__.__name__, len(self), 0)


class BitArray(Bits):
    """A mutable sequence of bits."""

    __slots__ = ()

    def _replace(self, start: int, end: int, bs: Bits) -> None:
        """Replace bits [start, end) with bs. An end past the length extends."""
        end = min(end, self._len)
        tail = self._len - end
        head = self._value >> (self._len - start)
        tail_value = self._value & ((1 << tail) - 1)
        new_value = (((head << bs._len) | bs._value) << tail) | tail_value
        self._len = start + bs._len + tail
        self._value = new_value

    def set(self, value: object, pos: int | Iterable[int] | None = None) -> None:
        """Set all bits, or the bits at pos, to bool(value)."""
        if pos is None:
            self._value = (1 << self._len) - 1 if value else 0
            return
        if not isinstance(pos, Iterable):
            pos = (pos,)
        for p in pos:
            i = operator.index(p)
            if i < 0:
                i += self._len
            if not 0 <= i < self._len:
                raise IndexError("bitarray assignment index out of range")
            mask = 1 << (self._len - 1 - i)
            self._value = self._value | mask if value else self._value & ~mask

    def append(self, bs: "Bits | str") -> None:
        self._replace(self._len, self._len, self._convert(bs))

    def reverse(self) -> None:
        self._value = int(self._getbin()[::-1] or "0", 2)

    def invert(self) -> None:
        self._value ^= (1 << self._len) - 1

    def byteswap(self) -> int:
        """Reverse the order of all whole bytes. Trailing bits stay in place.

        Return the number of swaps made (0 or 1).
        """
        nbytes, tail = divmod(self._len, 8)
        if not nbytes:
            return 0
        swapped = (self._value >> tail).to_bytes(nbytes, "big")
        tail_value = self._value & ((1 << tail) - 1)
        self._value = (int.from_bytes(swapped, "little") << tail) | tail_value
        return 1

    def copy(self: _T) -> _T:
        return self._create(self._value, self._len)

    def __ior__(self: _T, other: "Bits | str") -> _T:
        self._value |= self._same_length(other)._value
        return self


class BitStream(BitArray):
    """A mutable sequence of bits with a bit position (pos) for reads and writes.

    New objects, including slices, copies and operator results, start at pos 0.
    """

    __slots__ = ("_pos",)

    def __init__(
        self,
        auto: t.Any = None,
        /,
        length: int | None = None,
        bytes: "builtins.bytes | bytearray | None" = None,
    ) -> None:
        super().__init__(auto, length, bytes=bytes)
        self._pos = 0

    @property
    def pos(self) -> int:
        return self._pos

    @pos.setter
    def pos(self, pos: int) -> None:
        if pos < 0:
            raise ValueError("Bit position cannot be negative.")
        if pos > self._len:
            raise ValueError("Cannot seek past the end of the data.")
        self._pos = pos

    def __repr__(self) -> str:
        return self._repr(self.__class__.__name__, len(self), self._pos)

    def _read_token(self, token: str, pos: int) -> tuple[t.Any, int]:
        """Interpret one 'name[:]length' token at pos. Return value and bit length."""
        m = NAME_INT_RE.match(token)
        if not m:
            raise ValueError(f"Can't parse 'name[:]length' token '{token}'.")
        name = m.group(1)
        length = int(m.group(2)) if m.group(2) else None
        available = self._len - pos
        if name == "bool":
            if length not in (None, 1):
                raise ValueError(
                    f"A length of {length} was supplied for the 'bool' dtype, but "
                    "its only allowed length is 1."
                )
            if not available:
                raise InterpretError(
                    "'bool' dtypes must have a length of 1, but received a length of 0."
                )
            return self._getbit(pos), 1
        if name not in ("uint", "bytes"):
            raise ValueError(
                f"Unknown Dtype name '{name}'. Names available: "
                "['bool', 'bytes', 'uint']."
            )
        if length is None:
            # Upstream would read up to the end of the data; nothing here does that
            raise ValueError(f"The '{name}' dtype needs a length.")
        bitlength = length * 8 if name == "bytes" else length
        if bitlength > available:
            raise ReadError(
                f"Needed a length of at least {bitlength} bits, but only "
                f"{available} bits were available."
            )
        value = self._slice_value(pos, pos + bitlength)
        if name == "bytes":
            return value.to_bytes(length, "big"), bitlength
        if not bitlength:
            raise InterpretError(
                "Cannot interpret a zero length bitstring as an integer."
            )
        return value, bitlength

    @t.overload
    def read(self, fmt: int) -> "BitStream": ...

    @t.overload
    def read(self, fmt: str) -> t.Any: ...

    def read(self, fmt: int | str) -> t.Any:
        """Read fmt bits as a new BitStream, or one 'bool', 'uint:N' or 'bytes:N'
        value as a Python bool, int or bytes, and advance pos past them.
        """
        if isinstance(fmt, int):
            if fmt < 0:
                raise ValueError("Cannot read negative amount.")
            available = self._len - self._pos
            if fmt > available:
                raise ReadError(f"Cannot read {fmt} bits, only {available} available.")
            bs = self[self._pos : self._pos + fmt]
            self._pos += fmt
            return bs
        value, bitlength = self._read_token("".join(fmt.split()), self._pos)
        self._pos += bitlength
        return value

    def readlist(self, fmt: str) -> list[t.Any]:
        """Read comma-separated tokens such as '8*uint:32' and return a list.

        pos advances only if every token could be read.
        """
        pos = self._pos
        values = []
        for token in _preprocess_tokens(fmt):
            value, bitlength = self._read_token(token, pos)
            values.append(value)
            pos += bitlength
        self._pos = pos
        return values

    def overwrite(self, bs: "Bits | str", /, pos: int | None = None) -> None:
        """Overwrite with bs at pos (default: the current pos) and move pos past it.

        Writing past the end extends the bitstring.
        """
        bs = self._convert(bs)
        if len(bs) == 0:
            return
        if pos is None:
            pos = self._pos
        if pos < 0:
            pos += len(self)
        if pos < 0 or pos > len(self):
            raise ValueError("Overwrite starts outside boundary of bitstring.")
        # Taken before _replace, which changes len(bs) when bs is self
        n = len(bs)
        self._replace(pos, pos + n, bs)
        self._pos = pos + n

    def insert(self, bs: "Bits | str", /, pos: int | None = None) -> None:
        """Insert bs before bit pos (default: the current pos) and move pos past it."""
        bs = self._convert(bs)
        if len(bs) == 0:
            return
        if pos is None:
            pos = self._pos
        if pos < 0:
            pos += len(self)
        if not 0 <= pos <= len(self):
            raise ValueError("Invalid insert position.")
        n = len(bs)
        self._replace(pos, pos, bs)
        self._pos = pos + n

    def append(self, bs: "Bits | str") -> None:
        super().append(bs)
        self._pos = self._len

    def __delitem__(self, key: slice) -> None:
        if not isinstance(key, slice) or key.step not in (None, 1):
            raise TypeError("Only contiguous slices can be deleted from a bitstring.")
        start, stop, _ = key.indices(self._len)
        if stop > start:
            self._replace(start, stop, Bits())
            self._pos = 0
