import os
import sys
import importlib
import inspect
from functools import lru_cache
import threading

from detection.detector_base.readfile import readjson
from detection.detector_base.feature_extraction import get_registered_domain

detector_ready = threading.Event()
stop_event = threading.Event()

def load_detectors(detectors_path):
    """Load all detector classes dynamically."""
    detectors = []
    
    for folder in os.listdir(detectors_path):
        folder_path = os.path.join(detectors_path, folder)
        
        # Skip non-directories and __pycache__
        if not os.path.isdir(folder_path) or folder.startswith("__"):
            continue
        
        detector_py_path = os.path.join(folder_path, "detector.py")
        if not os.path.isfile(detector_py_path):
            print(f"⚠ Skipping {folder} (no detector.py)")
            continue
        
        print(f"✓ Loading: {folder}")
        
        try:
            module = importlib.import_module(f"detection.detectors.{folder}.detector")
            
            # Find all classes defined in this module
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if obj.__module__ == module.__name__:
                    detectors.append(obj)
                    
        except ImportError as e:
            print(f"✗ Import error in {folder}: {e}")
    
    return detectors

def evaluate(detector_path: str, logfile: str, tunneling_domains: list[str]) -> dict:
    tunneling_domains = set(tunneling_domains)
    detector_classes = load_detectors(detector_path)
    detectors = [cls() for cls in detector_classes]
    print(f"\n{len(detectors)} detectors loaded: {[type(d).__name__ for d in detectors]}\n")

    alldomains = set()
    log_generator = readjson(logfile)

    detector_ready.set() 

    logcount = 0
    tunnel_count = 0
    while not stop_event.is_set():
        try:
            logline = next(log_generator)
        except StopIteration:
            print(f"\n⚠ Log ended after {logcount} lines")
            break

        print(f"Processing line {logcount}", end="\r")
        istunnel = False
        logcount += 1

        domain = get_registered_domain(logline)
        if domain and domain not in alldomains:
            alldomains.add(domain)
        if domain in tunneling_domains:
            istunnel = True
            tunnel_count += 1

        for detector in detectors:
            detector.process_line(logline, istunnel)

    # Evaluation
    for detector in detectors:
        print(f"\n=== Evaluation of {type(detector).__name__} ===")
        detector.evaluate(tunneling_domains, {}, alldomains, logcount, tunnel_count)
        print()