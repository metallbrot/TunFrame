import os
import importlib
import inspect
import threading
import logging
from detection.detector_base.readfile import readjson
from detection.detector_base.feature_extraction import get_registered_domain, is_response, extract_record_type, extract_subdomain_string, json_safe_get, get_fqdn, validate_fqdn
import json
from datetime import datetime
import time

# Get the logger configured in main.py
logger = logging.getLogger('dns_detector')

def cfg_safe_get(cfg: dict, path: list[str], default: any = None) -> any:
    """safe get values from yaml with default values"""
    cur = cfg
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur

detector_ready = threading.Event()
wartime_stop_event = threading.Event()
peacetime_stop_event = threading.Event()
peacetime_done = threading.Event()

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
            logger.warning(f"⚠ Skipping {folder} (no detector.py)")
            continue
        logger.info(f"✓ Loading: {folder}")
        try:
            module = importlib.import_module(f"detection.detectors.{folder}.detector")
            # Find all classes defined in this module
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if obj.__module__ == module.__name__:
                    detectors.append(obj)
        except ImportError as e:
            logger.error(f"✗ Import error in {folder}: {e}")
    return detectors

def evaluate(detector_path: str, logfile: str, tunneling_domains: list[str], allowlist_path: str, results_file: str, cfg: dict) -> dict:

    ### INITILIZATION ###
    
    detector_classes = load_detectors(detector_path)
    detectors = [cls() for cls in detector_classes]
    logger.info(f"\n{len(detectors)} detectors loaded: {[type(d).__name__ for d in detectors]}\n")

    alldomains = set()
    # Use longer timeout (10s) and more retries (6) to handle chunked writes
    # This allows up to 60 seconds of no data before considering file complete
    log_generator = readjson(logfile, timeout_seconds=10, max_timeouts=6)

    tunneling_domains = set(tunneling_domains)

    global_allowlist = set()
    with open(allowlist_path, 'r') as file:
        global_allowlist.update(file.read().splitlines())


    ### PEACETIME ###
    duration = int(cfg_safe_get(cfg, ["timing", "duration"], 60))
    peacetime_duration = cfg_safe_get(cfg, ["timing", "peacetime_duration"], duration // 3)
    if not peacetime_duration:
        peacetime_duration = 0

    detector_ready.set()

    start_timestamp = datetime.now()

    if peacetime_duration != 0:

        logger.info("\n" + "="*60)
        logger.info("PEACETIME PHASE - Building Allowlist")
        logger.info("="*60)

        peace_logcount = 0

        while not peacetime_stop_event.is_set():
            try:
                logline = next(log_generator)
            except StopIteration:
                logger.warning(f"\n⚠ Log ended after {peace_logcount} lines")
                break
            
            # Handle timeout from generator
            if logline is None:
                continue

            domain = get_registered_domain(logline)
            if domain in tunneling_domains:
                logger.warning(f"[!] WARNING! Tunneling domain {domain} seen during peacetime!")

            if not validate_fqdn(logline) or not domain:
                logger.debug(f"[!] Invalid FQDN detected: {get_fqdn(logline)}")
                continue
            
            # Only update progress every 500 lines
            if peace_logcount % 100 == 0:
                logger.info(f"[PEACETIME] Processing line {peace_logcount} ({domain})", extra={'progress': True})
            
            peace_logcount += 1

            for detector in detectors:
                detector.process_line(logline, False)



    for detector in detectors:
            local_allowlist = detector.alarms
            detector.reset()
            detector.allowlist = local_allowlist.union(global_allowlist)
            logger.info(f"[+] {detector.__class__.__name__} added {len(detector.allowlist)} domains to allowlist")

    peacetime_done.set()
    
    ### WARTIME ###

    logger.info("\n" + "="*60)
    logger.info("WARTIME PHASE - Detection Active")
    logger.info("="*60)

    tunneling_domains_seen = {domain: False for domain in tunneling_domains}
    
    logcount = 0
    tunnel_count = 0

    while not wartime_stop_event.is_set():
        try:
            logline = next(log_generator)
        except StopIteration:
            logger.warning(f"\n⚠ Log ended after {logcount} lines")
            break

        # Handle timeout from generator
        if logline is None or get_fqdn(logline) is None:
            continue

        domain = get_registered_domain(logline)
        
        if not validate_fqdn(logline) or domain == "":
            logger.debug(f"[!] Invalid FQDN detected: {get_fqdn(logline)}")
            continue

        if domain and domain not in alldomains:
            alldomains.add(domain)

        # Only update progress every 500 lines
        if logcount % 100 == 0:
            logger.info(f"[WARTIME] Processing line {logcount} ({domain})", extra={'progress': True})
        
        istunnel = False
        logcount += 1
        
        if domain in tunneling_domains:
            tunneling_domains_seen[domain] = True
            istunnel = True
            tunnel_count += 1
            logger.debug(f"[!] Tunneling seen...({domain})")
        
        for detector in detectors:
            detector.process_line(logline, istunnel)
    
    end_timestamp = datetime.now()
    
    # Clear the progress line
    logger.info("")  
    
    logger.info("\n" + "="*60)
    logger.info("EVALUATION PHASE - Computing Metrics")
    logger.info("="*60)
    
    seen_tunnels = set([domain for domain, seen in tunneling_domains_seen.items() if seen])
    
    results = []
    for detector in detectors:
        logger.info(f"\n=== Evaluation of {type(detector).__name__} ===")
        results.append(detector.evaluate(seen_tunnels, alldomains, logcount, tunnel_count))
        logger.info("")
    
    # Build comprehensive metadata
    metadata = {
        "experiment": {
            "name": cfg_safe_get(cfg, ['global', 'name'], 'unknown'),
            "description": cfg_safe_get(cfg, ['global', 'description']),
            "start_timestamp": start_timestamp.isoformat(),
            "end_timestamp": end_timestamp.isoformat(),
            "duration_seconds": cfg_safe_get(cfg, ['timing', 'duration'], 0),
            "actual_runtime_seconds": (end_timestamp - start_timestamp).total_seconds(),
        },
        "traffic_config": {
            "benign": {
                "enabled": cfg_safe_get(cfg, ['traffic', 'benign', 'enabled'], False),
                "pcap": cfg_safe_get(cfg, ['traffic', 'benign', 'pcap'], ''),
                "pps": cfg_safe_get(cfg, ['traffic', 'benign', 'pps'], 0),
                "loop": cfg_safe_get(cfg, ['traffic', 'benign', 'loop'], False)
            },
            "wildcard": {
                "enabled": cfg_safe_get(cfg, ['traffic', 'wildcard', 'enabled'], False),
                "pcap": cfg_safe_get(cfg, ['traffic', 'wildcard', 'pcap'], ''),
                "pps": cfg_safe_get(cfg, ['traffic', 'wildcard', 'pps'], 0),
                "loop": cfg_safe_get(cfg, ['traffic', 'wildcard', 'loop'], False)
            },
            "tunnel": {
                "replay_enabled": cfg_safe_get(cfg, ['traffic', 'tunnel', 'replay'], False),
                "pcap": cfg_safe_get(cfg, ['traffic', 'tunnel', 'pcap'], ''),
                "pps": cfg_safe_get(cfg, ['traffic', 'tunnel', 'pps'], 0),
                "loop": cfg_safe_get(cfg, ['traffic', 'tunnel', 'loop'], False),
                "tunneling_domains": list(tunneling_domains),
                "tunneling_domains_seen": list(seen_tunnels),
                "tunnel_server_ip": cfg_safe_get(cfg, ['traffic', 'tunnel', 'tunnel_server_ip'], ''),
                "expansion_factor": cfg_safe_get(cfg, ['traffic', 'tunnel', 'expansion_factor'], 1)
            },
            "pcap_path": cfg_safe_get(cfg, ['traffic', 'pcap_path'], ''),
            "allowlist_path": str(allowlist_path)
        },
        "dataset_statistics": {
            "total_loglines": logcount,
            "tunnel_loglines": tunnel_count,
            "tunnel_percentage": (tunnel_count / logcount * 100) if logcount > 0 else 0,
            "unique_domains": len(alldomains),
            "logfile": logfile
        },
        "global_config": {
            "public_resolver": cfg_safe_get(cfg, ['global', 'public_resolver'], ''),
            "detector_path": str(detector_path)
        },
        "complete_config": cfg
    }
    
    # Comprehensive output structure
    output = {
        "metadata": metadata,
        "detectors": results
    }
    
    # Save results to file
    with open(results_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    logger.info(f"[+] Results saved to {results_file}")
    
    return output
