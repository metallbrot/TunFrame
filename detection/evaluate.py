import os
import re
import importlib
import inspect
import threading
import logging
from detection.detector_base.readfile import log_end_offset
from detection.detector_base.feature_extraction import get_registered_domain, registered_domain_of, is_response, get_fqdn, validate_fqdn
import json

# Get the logger configured in main.py
logger = logging.getLogger('dns_detector')


def parse_allowlist_line(line: str) -> str:
    """Extract the domain from one allowlist line, or return '' if there is none.

    Supported formats: one domain per line, CSV such as Tranco's
    ``rank,domain``, tab- or space-separated columns (hosts-file style), and
    ``#`` comments. The last column that looks like a domain is used and
    reduced to its registered domain, the granularity detectors alarm on.
    """
    line = line.split('#', 1)[0].strip()
    if not line:
        return ''
    fields = [f.strip().strip('"\'') for f in re.split(r'[,;\t ]+', line) if f.strip()]
    for field in reversed(fields):
        if '.' in field and not field.replace('.', '').isdigit():
            return registered_domain_of(field)
    return ''


def load_global_allowlist(allowlist_path: str, base_dir=None) -> set:
    """Load the global allowlist.

    Args:
        allowlist_path: Path to the allowlist file. Empty means no allowlist.
            A relative path is resolved against ``base_dir``.
        base_dir: Directory of the configuration file; relative paths are
            resolved against it instead of the working directory.

    Returns:
        set: Lowercased registered domains.

    Raises:
        FileNotFoundError: If the configured file does not exist.
    """
    global_allowlist = set()
    if not allowlist_path:
        return global_allowlist
    path = allowlist_path
    if base_dir is not None and not os.path.isabs(path):
        path = os.path.join(str(base_dir), path)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Global allowlist not found: {path}")
    with open(path, 'r', encoding='utf-8', errors='replace') as file:
        for line in file:
            domain = parse_allowlist_line(line)
            if domain:
                global_allowlist.add(domain)
    logger.info(f"[+] Global allowlist: {len(global_allowlist)} domains from {path}")
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


def generate_allowlists(detectors: list, global_allowlist: set) -> None:
    """Generate and assign allowlists to detectors after peacetime."""
    for detector in detectors:
        detector_name = type(detector).__name__
        # Get allowlist from detector's alarms (from peacetime)
        local_allowlist = detector.alarms
        detector.reset(clear_allowlist=True, reset_state=False)
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
        # Same guard as run_wartime(): events without a query name are skipped.
        if get_fqdn(logline) is None:
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
        
        if domain:
            alldomains.add(domain)

        for detector in detectors:
            detector.process_line(logline, False)
    
    return peace_logcount, alldomains


def run_wartime(detectors: list, log_generator, tunneling_domains: set, global_allowlist: set,
                expansion_factor: float = 1.0, transfer_event: threading.Event = None) -> tuple:
    """Run one wartime window and evaluate all detectors on it.

    The domain universe used for TN and FPR contains only the registered
    domains seen in this wartime window. Domains seen during peacetime or in
    other DNSExfiltrator configurations are never part of it.

    Args:
        detectors: Detector instances to feed.
        log_generator: Generator yielding parsed log events (or None when idle).
        tunneling_domains: Ground-truth tunneling domains for this window.
        global_allowlist: Global allowlist (reported per detector).
        expansion_factor: Encoding expansion factor of the tunnel traffic in
            this window, used to estimate the real uplink data volume.
        transfer_event: Set when the exfiltrated file has arrived. The window
            then keeps reading until it has caught up with the log as it was at
            that moment (or the log is idle), and ends with stop reason
            ``transfer_complete``. ``None`` disables this.

    Returns:
        tuple: (results, logcount, tunnel_count, seen_tunnels, alldomains, counts).
        ``logcount`` and ``tunnel_count`` count log lines (queries and
        responses). ``alldomains`` is the set of registered domains seen in
        this window. ``counts`` splits lines into ``total_queries``,
        ``total_responses``, ``tunnel_queries`` and ``tunnel_responses``, plus
        ``interrupted`` (True if Ctrl+C ended the window early) and
        ``stop_reason``: ``transfer_complete``, ``all_detected``, ``timer``,
        ``log_ended``, ``interrupted``, or a reason passed to
        ``request_wartime_stop`` (``user_skip``, ``user_stop``).
    """
    alldomains = set()
    tunneling_domains_seen = {domain: False for domain in tunneling_domains}
    
    logcount = 0
    tunnel_count = 0
    counts = {"total_queries": 0, "total_responses": 0, "tunnel_queries": 0, "tunnel_responses": 0}
    
    # The caller clears wartime_stop_event before arming the phase timer;
    # clearing it here would swallow a stop that was already signalled.
    interrupted = False
    stop_reason = None
    drain_target = None
    try:
        while not wartime_stop_event.is_set():
            if transfer_event is not None and transfer_event.is_set():
                if drain_target is None:
                    path = getattr(log_generator, "path", None)
                    drain_target = log_end_offset(path) if path else 0
                    logger.info("[+] Transfer complete - finishing the window after catching up with the log")
                if getattr(log_generator, "offset", drain_target) >= drain_target:
                    stop_reason = "transfer_complete"
                    break
            try:
                logline = next(log_generator)
            except StopIteration:
                logger.warning(f"\n⚠ Log ended after {logcount} lines")
                stop_reason = "log_ended"
                break

            # Idle poll: the reader yields None so the stop events are re-checked.
            # Idle after the transfer finished means the log has been caught up.
            if logline is None:
                if drain_target is not None:
                    stop_reason = "transfer_complete"
                    break
                continue
            if get_fqdn(logline) is None:
                continue

            domain = get_registered_domain(logline)
        
            if not validate_fqdn(logline) or domain == "":
                logger.debug(f"[!] Invalid FQDN detected: {get_fqdn(logline)}")
                continue


            if domain:
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
                stop_reason = "all_detected"
                wartime_stop_event.set()
    
    except KeyboardInterrupt:
        # Ctrl+C: stop reading and evaluate the partial window so its
        # results can still be written (status 'interrupted').
        interrupted = True
        logger.warning("\n[!] Interrupted: evaluating the partial wartime window")
    counts["interrupted"] = interrupted
    external, _external_stop["reason"] = _external_stop["reason"], None
    counts["stop_reason"] = "interrupted" if interrupted else (stop_reason or external or "timer")
    
    seen_tunnels = set([domain for domain, seen in tunneling_domains_seen.items() if seen])
    
    results = []
    for detector in detectors:
        logger.debug(f"\n=== Evaluation of {type(detector).__name__} ===")
        results.append(detector.evaluate(
            seen_tunnels, alldomains, logcount, counts["tunnel_queries"], global_allowlist,
            tunneling_responses=counts["tunnel_responses"],
            expansion_factor=expansion_factor,
        ))
    
    return results, logcount, tunnel_count, seen_tunnels, alldomains, counts


def cfg_safe_get(cfg: dict, path: list[str], default: any = None) -> any:
    """safe get values from yaml with default values"""
    cur = cfg
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur

def format_duration(seconds: float) -> str:
    """Convert seconds to a human-readable duration.

    The value is rounded to whole seconds. Seconds are omitted once the
    duration reaches an hour.

    Args:
        seconds: Duration in seconds (int or float).

    Returns:
        str: For example ``'1h20m'``, ``'5m30s'`` or ``'0s'``.
    """
    seconds = int(round(seconds or 0))
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

# Phase stop events shared with main.py (set by PhaseTimer or by early stop).
wartime_stop_event = threading.Event()
# Set when the exfiltrated file has arrived at the server (see main.TransferWatcher).
transfer_complete_event = threading.Event()
# Reason for a stop requested from outside the timer (dashboard controls).
_external_stop = {"reason": None}


def reset_wartime_stop() -> None:
    """Clear the stop event and any pending external stop reason (new window)."""
    _external_stop["reason"] = None
    wartime_stop_event.clear()


def request_wartime_stop(reason: str) -> None:
    """End the running wartime window now and record ``reason`` as its stop reason."""
    _external_stop["reason"] = reason
    wartime_stop_event.set()
peacetime_stop_event = threading.Event()
peacetime_done = threading.Event()

def load_detectors(detectors_path, active_detectors=None):
    """Load and instantiate detectors from ``detectors_path``.

    Every subdirectory with a ``detector.py`` is a detector package. Only
    concrete ``Detector`` subclasses defined in that ``detector.py`` are used;
    imported helper classes and other classes are ignored.

    Error policy: a detector listed in ``active_detectors`` that is missing or
    fails to import or instantiate aborts the run. Without an active list,
    a failing detector is logged with its traceback and skipped.

    Args:
        detectors_path: Directory containing one subdirectory per detector.
        active_detectors: Directory names to load, or None for all.

    Returns:
        list: Detector instances.

    Raises:
        RuntimeError: If an explicitly requested detector cannot be loaded.
    """
    from detection.detector_base.detector_base import Detector

    requested = set(active_detectors) if active_detectors is not None else None
    detectors = []
    failures = []
    found = set()
    for folder in sorted(os.listdir(detectors_path)):
        folder_path = os.path.join(detectors_path, folder)
        if not os.path.isdir(folder_path) or folder.startswith("__"):
            continue
        if requested is not None and folder not in requested:
            logger.info(f"⊘ Skipping {folder} (not in active detectors)")
            continue
        if not os.path.isfile(os.path.join(folder_path, "detector.py")):
            logger.warning(f"⚠ Skipping {folder} (no detector.py)")
            continue
        found.add(folder)
        logger.info(f"✓ Loading: {folder}")
        try:
            module = importlib.import_module(f"detection.detectors.{folder}.detector")
            classes = [obj for _, obj in inspect.getmembers(module, inspect.isclass)
                       if obj.__module__ == module.__name__ and issubclass(obj, Detector)
                       and not inspect.isabstract(obj)]
            if not classes:
                raise ImportError(f"no concrete Detector subclass in {folder}/detector.py")
            for cls in classes:
                detectors.append(cls())
        except Exception as e:
            logger.error(f"✗ Failed to load {folder}: {e}", exc_info=True)
            failures.append(folder)

    missing = sorted(requested - found) if requested is not None else []
    if missing:
        raise RuntimeError(f"Requested detectors not found in {detectors_path}: {missing}")
    if requested is not None and failures:
        raise RuntimeError(f"Requested detectors failed to load: {failures}")
    return detectors
