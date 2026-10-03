# Tests for the chunked, retrying stub flash read

import pytest

from esptool import cmds
from esptool.cmds import _read_flash_stub_with_retries, read_flash
from esptool.util import FatalError

SECTOR = 0x1000


class FakeStubLoader:
    """Serves bytes from a buffer, failing the calls listed in ``failures``."""

    IS_STUB = True
    FLASH_SECTOR_SIZE = SECTOR

    def __init__(self, flash: bytes, failures: dict[int, str] | None = None):
        self.flash = flash
        # Maps the (1-based) number of a read_flash() call to the error to raise
        self.failures = failures or {}
        self.calls: list[tuple[int, int]] = []
        self.resyncs = 0

    def read_flash(self, offset, length, progress_fn=None):
        self.calls.append((offset, length))
        failure = self.failures.get(len(self.calls))
        if failure:
            raise FatalError(failure)
        if progress_fn:
            progress_fn(length, length, offset)
        return self.flash[offset : offset + length]

    def flush_input(self):
        pass

    def sync(self):
        self.resyncs += 1


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(cmds.time, "sleep", lambda _seconds: None)


@pytest.fixture
def flash():
    return bytes(i % 251 for i in range(5 * SECTOR + 123))


@pytest.mark.host_test
def test_read_is_split_into_chunks(flash):
    esp = FakeStubLoader(flash)
    data = _read_flash_stub_with_retries(esp, 0, len(flash), None, 2 * SECTOR, 3)
    assert data == flash
    assert esp.calls == [
        (0, 2 * SECTOR),
        (2 * SECTOR, 2 * SECTOR),
        (4 * SECTOR, 1 * SECTOR + 123),
    ]
    assert esp.resyncs == 0


@pytest.mark.host_test
def test_failed_chunk_is_retried_and_stream_resynced(flash):
    esp = FakeStubLoader(
        flash,
        {
            2: "Corrupt data, expected 0x1000 bytes but received 0xfff bytes.",
            3: "Digest mismatch: expected A, got B",
        },
    )
    progress = []
    data = _read_flash_stub_with_retries(
        esp, 0, len(flash), lambda done, total, addr: progress.append(done), SECTOR, 3
    )
    assert data == flash
    # The second chunk fails twice and succeeds on its third attempt
    assert esp.calls[:4] == [
        (0, SECTOR),
        (SECTOR, SECTOR),
        (SECTOR, SECTOR),
        (SECTOR, SECTOR),
    ]
    assert esp.resyncs == 2
    assert progress[-1] == len(flash)


@pytest.mark.host_test
def test_read_with_nonzero_address(flash):
    esp = FakeStubLoader(flash)
    data = _read_flash_stub_with_retries(esp, 0x100, 3 * SECTOR, None, 2 * SECTOR, 1)
    assert data == flash[0x100 : 0x100 + 3 * SECTOR]


@pytest.mark.host_test
def test_gives_up_after_all_attempts(flash):
    esp = FakeStubLoader(
        flash, {n: "Digest mismatch: expected A, got B" for n in (1, 2, 3)}
    )
    with pytest.raises(FatalError, match="after 3 attempts.*Digest mismatch"):
        _read_flash_stub_with_retries(esp, 0, len(flash), None, SECTOR, 3)
    assert len(esp.calls) == 3
    assert esp.resyncs == 2


@pytest.mark.host_test
def test_failed_resync_is_fatal(flash):
    esp = FakeStubLoader(flash, {1: "Corrupt data"})

    def broken_sync():
        raise FatalError("no response")

    esp.sync = broken_sync
    with pytest.raises(FatalError, match="resynchronize"):
        _read_flash_stub_with_retries(esp, 0, len(flash), None, SECTOR, 3)


@pytest.mark.host_test
@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"read_attempts": 0}, "at least 1"),
        ({"read_chunk_size": 0}, "multiple of"),
        ({"read_chunk_size": SECTOR + 1}, "multiple of"),
    ],
)
def test_read_flash_rejects_bad_options(monkeypatch, flash, kwargs, message):
    monkeypatch.setattr(cmds, "_set_flash_parameters", lambda *_args: None)
    with pytest.raises(FatalError, match=message):
        read_flash(FakeStubLoader(flash), 0, SECTOR, **kwargs)


@pytest.mark.host_test
def test_read_flash_uses_chunk_options(monkeypatch, flash):
    monkeypatch.setattr(cmds, "_set_flash_parameters", lambda *_args: None)
    esp = FakeStubLoader(flash, {1: "Corrupt data"})
    data = read_flash(esp, 0, 3 * SECTOR, read_attempts=2, read_chunk_size=SECTOR)
    assert data == flash[: 3 * SECTOR]
    assert esp.calls == [
        (0, SECTOR),
        (0, SECTOR),
        (SECTOR, SECTOR),
        (2 * SECTOR, SECTOR),
    ]
