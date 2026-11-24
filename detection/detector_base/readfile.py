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


def readjson(log_file, start_offset=0, poll_interval=0.05, max_idle_seconds=None):
    """Follow a JSON-lines log file and yield one parsed event per line.

    The log is never truncated while the collector writes to it. Each phase
    records the end of the file with ``log_end_offset()`` and reads from there.

    * Buffered lines are yielded back to back.
    * When no new line is available the generator sleeps ``poll_interval``
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
        max_idle_seconds: If set, the generator ends after this many seconds
            without new data. By default it never ends on its own; phases end
            through their stop event.

    Yields:
        dict | None: A parsed event, or None after an idle poll.
    """
    f = open(log_file, 'rb')
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
                st = os.stat(log_file)
            except OSError:
                st = None
            if st is not None and (st.st_ino != inode or st.st_size < f.tell()):
                f.close()
                f = open(log_file, 'rb')
                inode = os.fstat(f.fileno()).st_ino
                pending, skip_partial = b"", False
                continue

            if max_idle_seconds is not None and time.monotonic() - last_data_time > max_idle_seconds:
                return
            time.sleep(poll_interval)
            yield None
    finally:
        f.close()
