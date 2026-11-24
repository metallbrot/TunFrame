import os
import importlib
import inspect
import threading
import logging
import time
from detection.detector_base.readfile import readjson
from detection.detector_base.feature_extraction import get_registered_domain, is_response, extract_record_type, extract_subdomain_string, json_safe_get, get_fqdn, validate_fqdn
import json

# Get the logger configured in main.py
logger = logging.getLogger('dns_detector')


def load_global_allowlist(allowlist_path: str) -> set:
    """Load global allowlist from file."""
    global_allowlist = set()
    if allowlist_path:
        with open(allowlist_path, 'r') as file:
            global_allowlist.update(file.read().splitlines())
    return global_allowlist


def save_results(results_file: str, results: dict, metadata: dict) -> None:
    """Save results to JSON file."""
    output = {
        "metadata": metadata,
        "detectors": results
    }
    with open(results_file, 'w') as f:
        json.dump(output, f, indent=2)
    logger.info(f"[+] Results saved to {results_file}")


def generate_allowlists(detectors: list, global_allowlist: set, peace_logcount: int) -> None:
    """Generate and assign allowlists to detectors after peacetime."""
    for detector in detectors:
        detector_name = type(detector).__name__
        # Get allowlist from detector's alarms (from peacetime)
        local_allowlist = detector.alarms
        detector.full_reset()
        detector.allowlist = local_allowlist.union(global_allowlist)
        logger.info(f"[+] {detector_name} allowlist size: {len(detector.allowlist)}")


def run_peacetime(detectors: list, log_generator, tunneling_domains: set) -> tuple:
    """Run peacetime phase to build allowlists.

    Sets ``peacetime_done`` when the phase has finished.

    Returns:
        tuple: (peace_logcount, alldomains)
    """
    try:
        return _run_peacetime(detectors, log_generator, tunneling_domains)
    finally:
        peacetime_done.set()


def _run_peacetime(detectors: list, log_generator, tunneling_domains: set) -> tuple:
    """Peacetime loop; see ``run_peacetime()``."""
    alldomains = set()
    peace_logcount = 0
    
    # The caller clears peacetime_stop_event before arming the phase timer;
    # clearing it here would swallow a stop that was already signalled.
    while not peacetime_stop_event.is_set():
        try:
            logline = next(log_generator)
        except StopIteration:
            logger.warning(f"\n⚠ Log ended after {peace_logcount} lines")
            break
        
        # Idle poll: the reader yields None so the stop event is re-checked.
        if logline is None:
            continue

        domain = get_registered_domain(logline)
        if domain in tunneling_domains:
            logger.warning(f"[!] WARNING! Tunneling domain {domain} seen during peacetime!")

        if not validate_fqdn(logline) or not domain:
            logger.debug(f"[!] Invalid FQDN detected: {get_fqdn(logline)}")
            continue
        
        # Only update progress every 100 lines
        if peace_logcount % 100 == 0:
            logger.info(f"[PEACETIME] Processing line {peace_logcount} ({domain})", extra={'progress': True})
        
        peace_logcount += 1
        
        domain = domain.lower()
        if domain and domain not in alldomains:
            alldomains.add(domain)

        for detector in detectors:
            detector.process_line(logline, False)
    
    return peace_logcount, alldomains


def run_wartime(detectors: list, log_generator, tunneling_domains: set, global_allowlist: set) -> tuple:
    """Run one wartime window and evaluate all detectors on it.

    The domain universe used for TN and FPR contains only the registered
    domains seen in this wartime window. Domains seen during peacetime or in
    other DNSExfiltrator configurations are never part of it.

    Args:
        detectors: Detector instances to feed.
        log_generator: Generator yielding parsed log events (or None when idle).
        tunneling_domains: Ground-truth tunneling domains for this window.
        global_allowlist: Global allowlist (reported per detector).

    Returns:
        tuple: (results, logcount, tunnel_count, seen_tunnels, alldomains, counts).
        ``logcount`` and ``tunnel_count`` count log lines (queries and
        responses). ``alldomains`` is the set of registered domains seen in
        this window. ``counts`` splits lines into ``total_queries``,
        ``total_responses``, ``tunnel_queries`` and ``tunnel_responses``.
    """
    alldomains = set()
    tunneling_domains_seen = {domain: False for domain in tunneling_domains}
    
    logcount = 0
    tunnel_count = 0
    counts = {"total_queries": 0, "total_responses": 0, "tunnel_queries": 0, "tunnel_responses": 0}
    
    # The caller clears wartime_stop_event before arming the phase timer;
    # clearing it here would swallow a stop that was already signalled.
    while not wartime_stop_event.is_set():
        try:
            logline = next(log_generator)
        except StopIteration:
            logger.warning(f"\n⚠ Log ended after {logcount} lines")
            break

        # Idle poll: the reader yields None so the stop event is re-checked.
        if logline is None:
            continue
        if get_fqdn(logline) is None:
            continue

        domain = get_registered_domain(logline)
        
        if not validate_fqdn(logline) or domain == "":
            logger.debug(f"[!] Invalid FQDN detected: {get_fqdn(logline)}")
            continue

        domain = domain.lower()

        if domain and domain not in alldomains:
            alldomains.add(domain)

        # Only update progress every 100 lines
        if logcount % 100 == 0:
            logger.info(f"[WARTIME] Processing line {logcount} ({domain})", extra={'progress': True})
        
        istunnel = False
        logcount += 1
        response = is_response(logline)
        counts["total_responses" if response else "total_queries"] += 1
        
        if domain in tunneling_domains:
            tunneling_domains_seen[domain] = True
            istunnel = True
            tunnel_count += 1
            counts["tunnel_responses" if response else "tunnel_queries"] += 1
            logger.debug(f"[!] Tunneling seen...({domain})")
        
        for detector in detectors:
            detector.process_line(logline, istunnel)

        done = True

        for detector in detectors:
            if detector.alarms.intersection(tunneling_domains) != tunneling_domains or len(tunneling_domains) == 0:
                done = False
                break

        if done:
            logger.info("[+] All tunneling domains detected. Stopping Wartime...")
            wartime_stop_event.set()
    
    seen_tunnels = set([domain for domain, seen in tunneling_domains_seen.items() if seen])
    
    results = []
    for detector in detectors:
        logger.info(f"\n=== Evaluation of {type(detector).__name__} ===")
        results.append(detector.evaluate(
            seen_tunnels, alldomains, logcount, counts["tunnel_queries"], global_allowlist,
            tunneling_responses=counts["tunnel_responses"],
        ))
        logger.info("")
    
    return results, logcount, tunnel_count, seen_tunnels, alldomains, counts


def cfg_safe_get(cfg: dict, path: list[str], default: any = None) -> any:
    """safe get values from yaml with default values"""
    cur = cfg
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur

def format_duration(seconds: int) -> str:
    """Convert seconds to human-readable format (e.g., '1h20m' or '5m30s')"""
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    
    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 and hours == 0:  # Only show seconds if no hours
        parts.append(f"{secs}s")
    
    return "".join(parts) or "0s"

detector_ready = threading.Event()
wartime_stop_event = threading.Event()
peacetime_stop_event = threading.Event()
peacetime_done = threading.Event()
tunnel_started_event = threading.Event()
tunnel_phase_start_event = threading.Event()
tunnel_phase_complete_event = threading.Event()

def load_detectors(detectors_path, active_detectors=None):
    """Load detector classes dynamically, filtered by active_detectors list."""
    detectors = []
    for folder in os.listdir(detectors_path):
        folder_path = os.path.join(detectors_path, folder)
        if not os.path.isdir(folder_path) or folder.startswith("__"):
            continue
        # Filter by active_detectors if provided
        if active_detectors is not None and folder not in active_detectors:
            logger.info(f"⊘ Skipping {folder} (not in active detectors)")
            continue
        detector_py_path = os.path.join(folder_path, "detector.py")
        if not os.path.isfile(detector_py_path):
            logger.warning(f"⚠ Skipping {folder} (no detector.py)")
            continue
        logger.info(f"✓ Loading: {folder}")
        try:
            module = importlib.import_module(f"detection.detectors.{folder}.detector")
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if obj.__module__ == module.__name__:
                    detectors.append(obj)
        except ImportError as e:
            logger.error(f"✗ Import error in {folder}: {e}")
    return detectors
