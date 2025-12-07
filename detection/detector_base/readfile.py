import json
import time
import sys

def readjson(log_file):
    with open(log_file, 'r') as f:
        f.seek(0, 2)  # Start am Ende
        while True:
            line = f.readline()
            if not line:
                continue
                
            try:
                dns_event = json.loads(line)
                yield dns_event
            except json.JSONDecodeError:
                continue

'''
if __name__ == '__main__':
    if len(sys.argv) == 2:
        filepath = sys.argv[1]
    while True:
        line = next(readjson(filepath))
        print(line)
        print()
        print(feature_extraction.get_registered_domain(line))
        print()
'''