import json
import time


def readjson(log_file, poll_interval=0.05, max_idle_seconds=None):
    """Follow a JSON-lines log file and yield one parsed event per line.

    Buffered lines are yielded back to back. When no new line is available the
    generator sleeps ``poll_interval`` seconds and yields ``None``, so a caller
    looping over it can check its stop event at least every ``poll_interval``
    seconds, also on an idle log. Lines that are not valid JSON are skipped.

    Args:
        log_file: Path to the log file.
        poll_interval: Sleep between polls while the log is idle, in seconds.
        max_idle_seconds: If set, the generator ends after this many seconds
            without new data. By default it never ends on its own; phases end
            through their stop event.

    Yields:
        dict | None: A parsed event, or None after an idle poll.
    """
    with open(log_file, 'r') as f:
        last_data_time = time.monotonic()
        while True:
            line = f.readline()
            if not line:
                if max_idle_seconds is not None and time.monotonic() - last_data_time > max_idle_seconds:
                    return
                time.sleep(poll_interval)
                yield None
                continue

            last_data_time = time.monotonic()
            try:
                dns_event = json.loads(line)
            except json.JSONDecodeError:
                # Skip invalid JSON lines
                continue
            yield dns_event
