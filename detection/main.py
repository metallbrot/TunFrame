import os
import sys
import importlib
import inspect

sys.path.append(os.getcwd())
from detector_base.readfile import readjson
from detector_base.feature_extraction import get_registered_domain

# Dynamically import all detector classes
DETECTORS = []
detectors_path = "detectors"
FILEPATH = "../dns-collector/logs/dnslogs.json"
TUNNEL_DOMAINS = {"tunnel.com"}

for folder in os.listdir(detectors_path):
    folder_path = os.path.join(detectors_path, folder)
    if os.path.isdir(folder_path) and not folder.startswith("__"):
        try:
            module = importlib.import_module(f"detectors.{folder}.detector")
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and obj.__module__ == module.__name__:
                    DETECTORS.append(obj)
        except ImportError:
            pass

alldomains = set()

detectors = [detector_class() for detector_class in DETECTORS]

for i in range(10):
    logline = next(readjson(FILEPATH))
    print(i)
    domain = get_registered_domain(logline)
    if domain not in alldomains and domain != "":
        alldomains.add(domain)
    for detector in detectors:
        detector.detect([logline])

for detector in detectors:
    print(f"Evaluation of {type(detector).__name__}:")
    print()
    detector.evaluate(TUNNEL_DOMAINS, {}, alldomains)
    print()