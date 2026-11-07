import json
import time
import os

def readjson(log_file, timeout_seconds=5, max_timeouts=3):
    """
    Read JSON lines from a log file, yielding each parsed event.
    Uses a simple timeout-based approach with small sleeps to allow checking
    stop events in the main thread. Works cross-platform.
    
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
            # Check if we've waited long enough since last data
            if time.time() - last_data_time > timeout_seconds:
                consecutive_timeouts += 1
                if consecutive_timeouts >= max_timeouts:
                    # No data for too long, file is likely complete
                    return
                yield None  # Signal timeout to caller
                last_data_time = time.time()
            
            # Try to read a line
            line = f.readline()
            if line:
                # Successfully read a line
                consecutive_timeouts = 0
                last_data_time = time.time()
                
                try:
                    dns_event = json.loads(line)
                    yield dns_event
                except json.JSONDecodeError:
                    # Skip invalid JSON lines
                    continue
            
            # Small sleep to prevent busy waiting and allow file to be written
            time.sleep(0.01)