"""Follow the DNS-collector JSON-lines log from a byte offset (see ``readjson()``)."""
import json
import os
import time


def log_end_offset(log_file) -> int:
    """Return the current size of the log file in bytes (0 if it is missing).

    Phases call this before starting traffic and read only from this offset on,
    instead of truncating a file the collector keeps open.
    """
    try:
        return os.path.getsize(log_file)
    except OSError:
        return 0


class LogReader:
    """Follow a JSON-lines log file and yield one parsed event per line.

    Created by ``readjson()``; iterate it like a generator. ``offset`` is the
    byte position right after the last line read (yielded or skipped), so a
    caller can tell whether it has caught up with a given point in the log.
    """

    def __init__(self, log_file, start_offset=0, poll_interval=0.05, max_idle_seconds=None):
        self.path = log_file
        self.offset = start_offset
        self._lines = self._follow(start_offset, poll_interval, max_idle_seconds)

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._lines)

    def close(self):
        self._lines.close()

    def _follow(self, start_offset, poll_interval, max_idle_seconds):
        f = open(self.path, 'rb')
        try:
            inode = os.fstat(f.fileno()).st_ino
            skip_partial = False
            if start_offset > 0:
                f.seek(start_offset - 1)
                skip_partial = f.read(1) != b"\n"
            f.seek(start_offset)
            pending = b""
            last_data_time = time.monotonic()

            while True:
                chunk = f.readline()
                if chunk:
                    pending += chunk
                    if not pending.endswith(b"\n"):
                        continue  # incomplete line: wait for the rest
                    line, pending = pending, b""
                    self.offset = f.tell()
                    last_data_time = time.monotonic()
                    if skip_partial:
                        skip_partial = False
                        continue
                    line = line.strip(b"\x00 \t\r\n")
                    if not line:
                        continue
                    try:
                        dns_event = json.loads(line.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        continue  # skip invalid JSON lines
                    yield dns_event
                    continue

                # Idle: detect truncation or replacement of the file.
                try:
                    st = os.stat(self.path)
                except OSError:
                    st = None
                if st is not None and (st.st_ino != inode or st.st_size < f.tell()):
                    f.close()
                    f = open(self.path, 'rb')
                    inode = os.fstat(f.fileno()).st_ino
                    pending, skip_partial = b"", False
                    self.offset = 0
                    continue

                if max_idle_seconds is not None and time.monotonic() - last_data_time > max_idle_seconds:
                    return
                time.sleep(poll_interval)
                yield None
        finally:
            f.close()


def readjson(log_file, start_offset=0, poll_interval=0.05, max_idle_seconds=None) -> LogReader:
    """Follow a JSON-lines log file and yield one parsed event per line.

    The log is never truncated while the collector writes to it. Each phase
    records the end of the file with ``log_end_offset()`` and reads from there.

    * Buffered lines are yielded back to back.
    * When no new line is available the reader sleeps ``poll_interval``
      seconds and yields ``None``, so a caller looping over it can check its
      stop event at least every ``poll_interval`` seconds.
    * A line without its trailing newline is kept until the rest has been
      written; partial lines are never parsed or dropped.
    * If ``start_offset`` falls inside a line, that partial line is skipped.
    * Leading NUL bytes (left by earlier truncations of an open file) are
      stripped. Lines that are not valid JSON are skipped.
    * If the file is truncated or replaced (rotation), it is reopened from
      the beginning.

    Args:
        log_file: Path to the log file.
        start_offset: Byte offset to start reading from.
        poll_interval: Sleep between polls while the log is idle, in seconds.
        max_idle_seconds: If set, the reader ends after this many seconds
            without new data. By default it never ends on its own; phases end
            through their stop event.

    Returns:
        LogReader: Iterator of parsed events (``None`` after an idle poll),
        with ``offset`` and ``path`` attributes.
    """
    return LogReader(log_file, start_offset, poll_interval, max_idle_seconds)
