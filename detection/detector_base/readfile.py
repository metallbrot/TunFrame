import json
import time
import sys

def readjson(log_file):
    with open(log_file, 'r') as f:
        f.seek(0, 2)  # Start am Ende
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.01)
                continue
                
            try:
                dns_event = json.loads(line)
                yield dns_event
            except json.JSONDecodeError:
                continue