import json
import time
import sys

def readjson(log_file, timeout_seconds=5, max_timeouts=3):
    """
    Read JSON lines from a log file, yielding each parsed event.
    
    Args:
        log_file: Path to the log file
        timeout_seconds: How long to wait for new data before yielding None (default: 5 seconds)
        max_timeouts: Maximum consecutive timeouts before stopping (default: 3)
    
    Yields:
        Parsed JSON objects or None if timeout is reached
    """
    with open(log_file, 'r') as f:
        f.seek(0, 0)  # Start at the beginning
        last_data_time = time.time()
        consecutive_timeouts = 0
        
        while True:
            line = f.readline()
            if not line:
                # Check if we've been waiting too long for new data
                if time.time() - last_data_time > timeout_seconds:
                    consecutive_timeouts += 1
                    if consecutive_timeouts >= max_timeouts:
                        # No data for too long, file is likely complete
                        return
                    yield None  # Signal timeout to caller
                    last_data_time = time.time()  # Reset timer
                time.sleep(0.01)
                continue
            
            consecutive_timeouts = 0  # Reset on successful read
            last_data_time = time.time()  # Reset timer when data is read
                
            try:
                dns_event = json.loads(line)
                yield dns_event
            except json.JSONDecodeError:
                continue