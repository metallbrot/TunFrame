import subprocess
import time
import yaml
from pathlib import Path
import sys
import threading
import logging
import warnings
from datetime import datetime
import shutil
import copy

# Suppress sklearn version warnings
warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')


PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from detection.evaluate import load_detectors, run_peacetime, run_wartime, generate_allowlists, save_results, load_global_allowlist, wartime_stop_event, peacetime_stop_event, peacetime_done, cfg_safe_get, format_duration
from detection.detector_base.readfile import readjson, log_end_offset
from detection.detector_base.feature_extraction import normalize_domain
from config.dns_config_generator import generate_all_configs

CONFIG_PATH = PROJECT_ROOT / "config.yaml"
DOCKER_PATH = PROJECT_ROOT / "docker"
DOCKER_COMPOSE_FILE = DOCKER_PATH / "docker-compose.yml"
DOCKER_ENV_FILE = DOCKER_PATH / ".env"
CONFIG_TEMPLATE_DIR = PROJECT_ROOT / "config" / "templates"
RESULTS_DIR = PROJECT_ROOT / "results"
DETECTOR_PATH = PROJECT_ROOT / "detection" / "detectors"
LOGFILE = DOCKER_PATH / "dns-collector" / "logs" / "dnslogs.json"

class UnifiedOutputHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.last_progress_length = 0
        self._lock = threading.Lock()
        self.setFormatter(logging.Formatter('%(message)s'))

    def emit(self, record):
        try:
            msg = self.format(record)
            is_progress = getattr(record, 'progress', False)

            with self._lock:
                if is_progress:
                    padded_msg = msg.ljust(self.last_progress_length)
                    sys.stdout.write(f"\r{padded_msg}")
                    sys.stdout.flush()
                    self.last_progress_length = len(msg)
                else:
                    if self.last_progress_length > 0:
                        sys.stdout.write("\r" + " " * self.last_progress_length + "\r")
                        self.last_progress_length = 0
                    sys.stdout.write(msg + "\n")
                    sys.stdout.flush()
        except Exception:
            self.handleError(record)

logger = logging.getLogger('dns_detector')
logger.setLevel(logging.INFO)
logger.handlers.clear()

console_handler = UnifiedOutputHandler()
console_handler.setLevel(logging.INFO)
logger.addHandler(console_handler)

logger.propagate = False


def load_config(path=CONFIG_PATH):
    with open(path) as f:
        return yaml.safe_load(f)


def write_docker_env(pcap_dir):
    DOCKER_ENV_FILE.write_text(f"PCAP_PATH={pcap_dir}\n")


def compose_up(profile):
    cmd = [
        "docker",
        "compose",
        "-f", str(DOCKER_COMPOSE_FILE),
        "--profile", profile,
        "up",
        "-d",
    ]
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f"[!] Docker compose up failed for profile {profile}")
        logger.error(f"[!] stdout: {result.stdout}")
        logger.error(f"[!] stderr: {result.stderr}")
        raise RuntimeError(f"Docker compose up failed for profile {profile}")
    return result


def compose_down():
    cmd = [
        "docker",
        "compose",
        "-f", str(DOCKER_COMPOSE_FILE),
        "--profile", "*",
        "down"
    ]
    try:
        result = subprocess.run(cmd, check=False)
        if result.returncode != 0:
            logger.warning(f"[!] Docker compose down returned code {result.returncode}")
            if result.stderr:
                logger.warning(f"[!] Error: {result.stderr.strip()}")
        else:
            logger.info("[+] Docker containers stopped successfully")
    except Exception as e:
        logger.error(f"[!] Failed to run docker compose down: {e}")


def docker_exec(container: str, *docker_cmd: str, check: bool = True):
    cmd = ["docker", "exec", container] + list(docker_cmd)
    subprocess.run(cmd, check=check)


def check_process_running(container: str, process_name: str, expect_running: bool = True) -> bool:
    """Check if a process is running in a Docker container.
    
    Args:
        container: Docker container name
        process_name: Process name or pattern to search for
        expect_running: If True, logs error when not running; if False, logs info
    
    Returns:
        True if process is running, False otherwise
    """
    try:
        cmd = ["docker", "exec", container, "ps", "aux"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        is_running = process_name in result.stdout
        
        if not is_running and expect_running:
            # Get container logs for debugging
            try:
                logs_cmd = ["docker", "logs", container]
                logs_result = subprocess.run(logs_cmd, capture_output=True, text=True, check=False)
                if logs_result.stdout:
                    logger.error(f"[!] Container {container} logs (last 500 chars):\n{logs_result.stdout[-500:]}")
            except Exception:
                pass
            
            # Also show what processes ARE running
            if result.stdout:
                logger.error(f"[!] Processes in {container}: {result.stdout.strip()}")
        
        return is_running
    except Exception as e:
        logger.debug(f"[!] Error checking process {process_name} in {container}: {e}")
        return False


def get_dnsexfiltrator_status() -> dict:
    """Get detailed status of DNSExfiltrator server and client processes.
    
    Returns:
        dict: Status information with keys 'server_running', 'client_running',
              'server_pid', 'client_pid', 'server_processes', 'client_processes'
    """
    status = {
        'server_running': False,
        'client_running': False,
        'server_pid': None,
        'client_pid': None,
        'server_processes': [],
        'client_processes': []
    }
    
    try:
        # Check server
        cmd = ["docker", "exec", "dnsexfiltrator-server", "ps", "aux"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                if 'dnsExfiltrator' in line:
                    status['server_processes'].append(line)
                    status['server_running'] = True
    except Exception:
        pass
    
    try:
        # Check client
        cmd = ["docker", "exec", "dnsexfiltrator-client", "ps", "aux"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                if 'DNSExfiltrator' in line:
                    status['client_processes'].append(line)
                    status['client_running'] = True
    except Exception:
        pass
    
    return status


def start_dnsexfiltrator_server(
    domains: list[str],
    password: str = "tunframe",
):
    """Start DNSExfiltrator server with configurable domains."""
    volume_dir = PROJECT_ROOT / "docker/dnsexfiltrator-server/volume"
    volume_dir.mkdir(parents=True, exist_ok=True)
    
    domains_file = volume_dir / "domains.txt"
    domains_file.write_text("\n".join(domains))

    cmd = [
        "docker", "exec", "-d", "dnsexfiltrator-server",
        "python3", "-u", "/app/dnsExfiltrator.py",
        "-f", "/app/domains.txt",
        "-p", password,
        "-o", "/app/outputfile",
    ]
    logger.info(f"[+] Starting DNSExfiltrator server: {len(domains)} domains")
    subprocess.run(cmd, check=True)


def start_dnsexfiltrator_client(
    filepath: str,
    domains: list[str],
    password: str,
    throttle: int = None,
    throttle_random: int = None,
    label_size: int = None,
    encoding: str = None,
    dil: int = None,
):
    """Start DNSExfiltrator client with configurable parameters."""
    data_dir = PROJECT_ROOT / "docker/dnsexfiltrator-client/data"
    data_dir.mkdir(parents=True, exist_ok=True)
    
    domains_file = data_dir / "domains.txt"
    domains_file.write_text("\n".join(domains))

    # Handle filepath - strip /data/ prefix if present (container path)
    if filepath.startswith('/data/'):
        # Container path - look for file in data_dir
        relative_filepath = filepath[6:]  # Remove '/data/' prefix
        file_path = data_dir / relative_filepath
        container_filepath = f"/data/{relative_filepath}"
    else:
        file_path = data_dir / filepath
        container_filepath = f"/data/{filepath}"
    
    if not file_path.exists():
        # Also check if it's an absolute host path
        if filepath.startswith('/') and Path(filepath).exists():
            file_path = Path(filepath)
            container_filepath = f"/data/{Path(filepath).name}"
        else:
            raise FileNotFoundError(f"File not found: {file_path}")

    cmd = [
        "docker", "exec", "-d", "dnsexfiltrator-client",
        "mono", "/app/DNSExfiltrator.exe",
        container_filepath,
        "/data/domains.txt",
        password,
        "s=172.16.0.2",
    ]

    if throttle is not None:
        cmd.append(f"t={throttle}")
    if throttle_random is not None:
        cmd.append(f"tr={throttle_random}")
    if label_size is not None:
        cmd.append(f"l={label_size}")
    if encoding is not None:
        cmd.append(f"e={encoding}")
    if dil is not None:
        cmd.append(f"dil={dil}")

    logger.info(f"[+] Starting DNSExfiltrator client: {filepath}, {len(domains)} domains")
    subprocess.run(cmd, check=True)


def replay_fire_and_forget(pcap: str, pps: int, label: str):
    """Fire and forget: startet tcpreplay ohne zu warten"""
    if not pcap:
        logger.warning(f"[-] Skipping {label} replay (disabled)")
        return
    
    cmd = ["tcpreplay"]
    if pps is None or pps <= 0:
        logger.info(f"[+] Firing {label} replay at original speed from {pcap}")
        cmd.extend(["-i", "replay0", pcap])
    else:
        logger.info(f"[+] Firing {label} replay: {pps} PPS from {pcap}")
        cmd.extend([f"--pps={pps}", "-i", "replay0", pcap])
    
    docker_exec("pcap-replayer", *cmd, check=False)


# Traffic sources whose replay has been started in this run. tcpreplay keeps
# running until it reaches the end of the pcap or the containers stop.
_started_replays = set()


def start_replay(label: str, pcap: str, pps) -> bool:
    """Start a fire-and-forget tcpreplay at most once per run and traffic source.

    A replay started during peacetime keeps running into wartime, so wartime
    sees the continuation of the capture instead of a restart from packet 0.

    Args:
        label: Traffic source name (``benign``, ``wildcard``, ``tunnel``).
        pcap: Pcap file name inside the pcap directory.
        pps: Replay rate in packets per second; None or <= 0 for original timing.

    Returns:
        bool: True if a new replay was started, False if it was already running.
    """
    if label in _started_replays:
        logger.info(f"[+] {label} replay already running since an earlier phase, continuing it")
        return False
    _started_replays.add(label)
    threading.Thread(target=replay_fire_and_forget, args=(pcap, pps, label), daemon=True).start()
    return True


# Ratio of encoded query characters to raw payload bytes per encoding
# (thesis section 2.3.1). Used to estimate the real data volume from ULV.
ENCODING_EXPANSION_FACTORS = {
    'base32': 8 / 5,       # 1.6
    'base32map': 3 * 8 / 5,  # 4.8: each Base32 character becomes a 3-letter word
    'base64': 4 / 3,
    'hex': 2.0,
}


def config_expansion_factor(config: dict) -> float:
    """Return the expansion factor for one DNSExfiltrator configuration.

    An explicit ``expansion_factor`` in the configuration wins; otherwise the
    factor is derived from its ``encoding``.

    Args:
        config: Filled DNSExfiltrator configuration.

    Returns:
        float: Expansion factor (1.0 for an unknown encoding, with a warning).
    """
    if config.get('expansion_factor') is not None:
        return float(config['expansion_factor'])
    encoding = str(config.get('encoding', '')).lower()
    if encoding not in ENCODING_EXPANSION_FACTORS:
        logger.warning(f"[!] Unknown encoding '{encoding}', using expansion factor 1.0")
        return 1.0
    return ENCODING_EXPANSION_FACTORS[encoding]


class PhaseTimer:
    """Cancellable timer that sets a phase stop event after a duration.

    Every phase must cancel its timer when it ends, also when it ends early
    (all tunnels detected, log ended, error). A cancelled timer can no longer
    set the event, so it cannot cut a later phase short.

    Args:
        event: Stop event to set when the duration has elapsed.
        duration: Phase duration in seconds.
    """

    def __init__(self, event: threading.Event, duration: float):
        self._timer = threading.Timer(duration, event.set)
        self._timer.daemon = True

    def start(self) -> "PhaseTimer":
        """Start the timer and return self."""
        self._timer.start()
        return self

    def cancel(self) -> None:
        """Cancel the timer; a no-op if it already fired."""
        self._timer.cancel()


def build_and_save_metadata(
    results_file: Path,
    results: list,
    logcount: int,
    tunnel_count: int,
    seen_tunnels: set,
    alldomains: set,
    start_timestamp: datetime,
    end_timestamp: datetime,
    wartime_duration: float,
    peacetime_duration: float,
    tunneling_domains_set: set,
    tunneling_enabled: bool,
    tunneling_pcap: str,
    tunneling_pps,
    server_ip: str,
    public_resolver: str,
    cfg: dict,
    counts: dict = None,
    status: str = "completed",
    status_reason: str = "",
    dnsexfil_config: dict = None
):
    """Build metadata and save results to file.

    ``tunnel_percentage`` is the share of tunneling queries among all queries;
    responses are counted separately in ``counts``.
    """
    counts = counts or {}
    total_queries = counts.get("total_queries", 0)
    tunnel_queries = counts.get("tunnel_queries", 0)
    tunnel_percentage = (tunnel_queries / total_queries * 100) if total_queries > 0 else 0
    
    benign_enabled = bool(cfg_safe_get(cfg, ["traffic", "benign", "enabled"], False))
    benign_pcap = cfg_safe_get(cfg, ["traffic", "benign", "pcap"], "")
    benign_pps = cfg_safe_get(cfg, ["traffic", "benign", "pps"])
    
    wildcard_enabled = bool(cfg_safe_get(cfg, ["traffic", "wildcard", "enabled"], False))
    wildcard_pcap = cfg_safe_get(cfg, ["traffic", "wildcard", "pcap"], "")
    wildcard_pps = cfg_safe_get(cfg, ["traffic", "wildcard", "pps"])
    
    metadata = {
        "experiment": {
            "name": cfg_safe_get(cfg, ['global', 'name'], 'unknown'),
            "description": cfg_safe_get(cfg, ['global', 'description']),
            "start_timestamp": start_timestamp.isoformat(),
            "end_timestamp": end_timestamp.isoformat(),
            "wartime_duration": format_duration(wartime_duration),
            "peacetime_duration": format_duration(peacetime_duration),
            "actual_runtime": format_duration((end_timestamp - start_timestamp).total_seconds()),
        },
        "traffic_config": {
            "benign": {
                "enabled": benign_enabled,
                "pcap": benign_pcap,
                "pps": benign_pps,
            },
            "wildcard": {
                "enabled": wildcard_enabled,
                "pcap": wildcard_pcap,
                "pps": wildcard_pps,
            },
            "tunnel": {
                "replay_enabled": tunneling_enabled,
                "pcap": tunneling_pcap,
                "pps": tunneling_pps,
                "tunneling_domains": list(tunneling_domains_set),
                "tunneling_domains_seen": list(seen_tunnels),
                "tunnel_server_ip": server_ip,
            },
            "pcap_path": cfg_safe_get(cfg, ['traffic', 'pcap_path'], ''),
        },
        "dataset_statistics": {
            "total_loglines": logcount,
            "tunnel_loglines": tunnel_count,
            "total_queries": total_queries,
            "total_responses": counts.get("total_responses", 0),
            "tunnel_queries": tunnel_queries,
            "tunnel_responses": counts.get("tunnel_responses", 0),
            "tunnel_percentage": tunnel_percentage,
            "unique_domains": len(alldomains),
            "logfile": str(LOGFILE)
        },
        "global_config": {
            "public_resolver": public_resolver,
            "detector_path": str(DETECTOR_PATH)
        },
        "complete_config": cfg,
        "dnsexfiltrator_config": dnsexfil_config,
        "run_info": get_run_info(),
        "run_status": {"status": status, "reason": status_reason},
    }
    save_results(str(results_file), results, metadata)


_RUN_INFO = None


def _command_output(cmd: list) -> str:
    """Return the stripped stdout of a command, or an empty string on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, cwd=PROJECT_ROOT)
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def get_run_info() -> dict:
    """Collect code and tool versions for reproducibility (cached per run).

    Returns:
        dict: git commit and dirty flag, Python version, versions of the Python
        libraries the harness depends on, and Docker / Docker Compose versions.
        Unavailable values are empty strings.
    """
    global _RUN_INFO
    if _RUN_INFO is None:
        try:
            from importlib.metadata import version as _pkg_version
        except ImportError:  # pragma: no cover
            _pkg_version = None
        libraries = {}
        for package in ("tldextract", "fqdn", "PyYAML"):
            try:
                libraries[package] = _pkg_version(package) if _pkg_version else ""
            except Exception:
                libraries[package] = ""
        _RUN_INFO = {
            "git_commit": _command_output(["git", "rev-parse", "HEAD"]),
            "git_dirty": bool(_command_output(["git", "status", "--porcelain", "--untracked-files=no"])),
            "python_version": sys.version.split()[0],
            "libraries": libraries,
            "docker_version": _command_output(["docker", "--version"]),
            "docker_compose_version": _command_output(["docker", "compose", "version", "--short"]),
        }
    return _RUN_INFO


def save_status_result(cfg: dict, config_name: str, status: str, reason: str, dnsexfil_config: dict = None) -> Path:
    """Write a results file for a configuration that produced no measurements.

    Every requested configuration leaves a results file, so gaps in a sweep
    are visible in the data and not only in the console log.

    Args:
        cfg: Complete experiment configuration.
        config_name: Name of the DNSExfiltrator configuration (or "wartime").
        status: "skipped" (never started) or "failed" (error while starting).
        reason: Human-readable reason.
        dnsexfil_config: The DNSExfiltrator configuration, if any.

    Returns:
        Path: The written results file.
    """
    name = cfg_safe_get(cfg, ['global', 'name'], 'experiment')
    results_file = RESULTS_DIR / f"results_{name}_{config_name}_{status}_{int(time.time())}.json"
    metadata = {
        "experiment": {
            "name": name,
            "description": cfg_safe_get(cfg, ['global', 'description']),
            "config_name": config_name,
            "timestamp": datetime.now().isoformat(),
        },
        "complete_config": cfg,
        "dnsexfiltrator_config": dnsexfil_config,
        "run_info": get_run_info(),
        "run_status": {"status": status, "reason": reason},
    }
    logger.warning(f"[!] Configuration {config_name} {status}: {reason}")
    save_results(str(results_file), [], metadata)
    return results_file


# Default values for every DNSExfiltrator configuration.
DNSEXFIL_DEFAULTS = {
    'file': '/data/synthetic_cc_data_100.csv',
    'password': 'tunframe',
    'throttle': 10,
    'throttle_random': 0,
    'label_max_size': 63,
    'encoding': 'base32',
    'dilution': 0,
    'domains': [],
    'expansion_factor': None,  # None: derive from 'encoding'
}


def _check_dnsexfil_keys(where: str, keys) -> None:
    """Raise ValueError if a DNSExfiltrator config block uses unknown parameters."""
    unknown = sorted(set(keys) - set(DNSEXFIL_DEFAULTS) - {'name'})
    if unknown:
        raise ValueError(
            f"Unknown DNSExfiltrator parameter(s) in {where}: {unknown}. "
            f"Valid parameters: {sorted(DNSEXFIL_DEFAULTS)}"
        )


# Keys that older docs or configs used but the code does not read.
# Renamed keys abort the run because ignoring them would silently change it.
RENAMED_CONFIG_KEYS = {
    ('timing', 'duration'): "use timing.wartime_duration (minutes)",
    ('detector', 'names'): "use detectors.active (list of detector directory names)",
}
IGNORED_CONFIG_KEYS = {
    ('traffic', 'tunnel', 'docker'): "live tunneling is configured in the dnsexfiltrator section",
    ('traffic', 'tunnel', 'toolname'): "not used",
    ('allowlist', 'local_allowlist_dir'): "saved per-detector allowlists are not supported; use a peacetime phase",
}


def check_config_keys(cfg: dict) -> None:
    """Reject renamed configuration keys and warn about ignored ones.

    Args:
        cfg: Configuration dictionary.

    Raises:
        ValueError: If a renamed key (for example ``timing.duration``) is set.
    """
    _missing = object()
    errors = []
    for path, hint in RENAMED_CONFIG_KEYS.items():
        if cfg_safe_get(cfg, list(path), _missing) is not _missing:
            errors.append(f"'{'.'.join(path)}' is not supported: {hint}")
    if errors:
        raise ValueError("Invalid configuration:\n  " + "\n  ".join(errors))
    for path, hint in IGNORED_CONFIG_KEYS.items():
        if cfg_safe_get(cfg, list(path), _missing) is not _missing:
            logger.warning(f"[!] Config key '{'.'.join(path)}' is ignored: {hint}")


def resolve_results_dir(cfg: dict) -> Path:
    """Return the results directory from ``output.logdir`` (default ``results``).

    Relative paths are resolved against the directory of ``config.yaml``.
    """
    logdir = Path(cfg_safe_get(cfg, ['output', 'logdir'], 'results') or 'results')
    return logdir if logdir.is_absolute() else (CONFIG_PATH.parent / logdir).resolve()


def validate_dnsexfil_domains(configs: list, tunneling_domains: list) -> None:
    """Check that every DNSExfiltrator config only uses BIND-routed tunnel domains.

    The BIND configs for resolver, root and TLD are generated once from
    ``traffic.tunnel.tunneling_domains``. A domain outside that list would be
    forwarded to the public resolver instead of the simulated hierarchy, while
    the evaluation would still treat it as ground truth.

    Args:
        configs: Filled DNSExfiltrator configurations.
        tunneling_domains: ``traffic.tunnel.tunneling_domains`` from the config.

    Raises:
        ValueError: If a config has no domains or uses a domain that is not in
            ``traffic.tunnel.tunneling_domains``.
    """
    routed = {str(d).strip().rstrip('.').lower() for d in (tunneling_domains or [])}
    problems = []
    for config in configs:
        name = config.get('name', 'config')
        domains = [str(d).strip().rstrip('.').lower() for d in config.get('domains') or []]
        if not domains:
            problems.append(f"{name}: no domains configured")
            continue
        missing = sorted(set(domains) - routed)
        if missing:
            problems.append(f"{name}: {missing} not in traffic.tunnel.tunneling_domains")
    if problems:
        raise ValueError(
            "DNSExfiltrator domains must be listed in traffic.tunnel.tunneling_domains "
            f"(routed domains: {sorted(routed)}):\n  " + "\n  ".join(problems)
        )


def get_dnsexfiltrator_configs(cfg: dict):
    """Get DNSExfiltrator configurations from config file.

    Builds the baseline, one config per sweep value and the predefined
    profiles. Sweeps and profiles inherit every value they do not set from the
    filled baseline; the baseline inherits from ``DNSEXFIL_DEFAULTS``.
    Unknown parameter names in the baseline, a sweep or a profile raise
    ValueError at startup.

    Args:
        cfg: Configuration dictionary

    Returns:
        list: List of dnsexfiltrator configurations

    Raises:
        ValueError: If a block uses an unknown parameter name.
    """
    dnsexfil_enabled = cfg_safe_get(cfg, ['dnsexfiltrator', 'enabled'], False)
    if not dnsexfil_enabled:
        logger.info("[+] DNSExfiltrator disabled")
        return []

    logger.info("\n" + "="*60)
    logger.info("DNSExfiltrator Configurations")
    logger.info("="*60)

    def with_base(base: dict, overrides: dict) -> dict:
        """Deep-copy ``base`` and apply ``overrides`` on top."""
        filled = copy.deepcopy(base)
        filled.update(copy.deepcopy(overrides or {}))
        return filled

    configs = []

    # 1. Baseline (inherits DNSEXFIL_DEFAULTS)
    baseline_cfg = cfg_safe_get(cfg, ['dnsexfiltrator', 'baseline'], None) or {}
    _check_dnsexfil_keys("baseline", baseline_cfg)
    base_cfg = with_base(DNSEXFIL_DEFAULTS, baseline_cfg)
    base_cfg.pop('name', None)
    if baseline_cfg:
        logger.info(f"[+] Processing baseline configuration")
        configs.append(with_base(base_cfg, {'name': 'baseline'}))

    # 2. Sweeps (inherit the filled baseline)
    sweeps = cfg_safe_get(cfg, ['dnsexfiltrator', 'sweeps'], []) or []
    for sweep in sweeps:
        sweep_name = sweep.get('name', 'unnamed_sweep')
        parameter = sweep.get('parameter', '')
        if parameter not in DNSEXFIL_DEFAULTS:
            raise ValueError(
                f"Unknown sweep parameter '{parameter}' in sweep '{sweep_name}'. "
                f"Valid parameters: {sorted(DNSEXFIL_DEFAULTS)}"
            )
        for value in sweep.get('values', []):
            sweep_config = with_base(base_cfg, {parameter: value})
            sweep_config['name'] = f"{sweep_name}_{parameter}_{value}"
            configs.append(sweep_config)
            logger.info(f"[+] Added sweep config: {sweep_config['name']} ({parameter}={value})")

    # 3. Profiles (inherit the filled baseline)
    profiles = cfg_safe_get(cfg, ['dnsexfiltrator', 'profiles'], []) or []
    for profile in profiles:
        profile_name = profile.get('name', 'unnamed_profile')
        _check_dnsexfil_keys(f"profile '{profile_name}'", profile)
        filled_profile = with_base(base_cfg, profile)
        filled_profile['name'] = profile_name
        configs.append(filled_profile)
        logger.info(f"[+] Added profile: {profile_name}")

    # If no configurations were found, run the baseline values once
    if not configs:
        configs.append(with_base(base_cfg, {'name': 'default'}))
        logger.info("[+] Created default configuration")

    logger.info(f"[+] Total DNSExfiltrator configurations: {len(configs)}")
    logger.info("="*60)

    return configs


def run_setup(cfg: dict):
    """Setup phase: Load config, clean state, start docker containers.
    
    Returns:
        tuple: (wartime_duration, peacetime_duration, tunneling_domains, server_ip,
                public_resolver, global_allowlist_path, active_detectors_list, results_file,
                dnsexfil_configs)
    """
    global RESULTS_DIR
    check_config_keys(cfg)
    RESULTS_DIR = resolve_results_dir(cfg)

    # Load timing configuration (minutes)
    wartime_duration_config = cfg_safe_get(cfg, ["timing", "wartime_duration"], 60)
    peacetime_duration_config = cfg_safe_get(cfg, ["timing", "peacetime_duration"], None)
    
    # Convert from minutes to seconds
    wartime_duration = float(wartime_duration_config) * 60
    
    if peacetime_duration_config is None:
        # Default to wartime_duration / 3
        peacetime_duration = (float(wartime_duration_config) / 3) * 60
    else:
        peacetime_duration = float(peacetime_duration_config) * 60
    
    if not peacetime_duration:
        peacetime_duration = 0

    tunneling_domains = cfg_safe_get(cfg, ["traffic", "tunnel", "tunneling_domains"], [])
    server_ip = cfg_safe_get(cfg, ['traffic', 'tunnel', 'tunnel_server_ip'], '192.168.4.4')
    public_resolver = cfg_safe_get(cfg, ['global', 'public_resolver'], '1.1.1.1')
    global_allowlist_path = cfg_safe_get(cfg, ['allowlist', 'global_allowlist_path'])
    active_detectors_list = cfg_safe_get(cfg, ['detectors', 'active'], None)
    
    if global_allowlist_path is None:
        global_allowlist_path = ""
    
    # Get DNSExfiltrator configurations to calculate total duration, and make
    # sure every config domain is routed to the simulated DNS hierarchy.
    dnsexfil_configs = get_dnsexfiltrator_configs(cfg)
    validate_dnsexfil_domains(dnsexfil_configs, tunneling_domains)
    
    # Calculate total estimated duration
    if dnsexfil_configs:
        total_estimated_duration = peacetime_duration + (wartime_duration * len(dnsexfil_configs))
    else:
        total_estimated_duration = peacetime_duration + wartime_duration
    
    logger.info("\n" + "="*60)
    logger.info("EXPERIMENT SETUP")
    logger.info("="*60)
    logger.info(f"[+] Experiment: {cfg_safe_get(cfg, ['global', 'name'], '')}")
    logger.info(f"[+] Peacetime Duration: {format_duration(peacetime_duration)}")
    
    if dnsexfil_configs:
        logger.info(f"[+] Wartime Duration (per config): {format_duration(wartime_duration)}")
        logger.info(f"[+] Number of DNSExfiltrator configs: {len(dnsexfil_configs)}")
    else:
        logger.info(f"[+] Wartime Duration: {format_duration(wartime_duration)}")
    
    logger.info(f"[+] Total Estimated Duration: {format_duration(total_estimated_duration)}")
    logger.info("="*60)

    results_file = RESULTS_DIR / f"results_{cfg_safe_get(cfg, ['global', 'name'], 'experiment')}_{int(time.time())}.json"
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Ensure docker is stopped before cleaning up
    logger.info("[+] Ensuring clean state...")
    try:
        compose_down()
    except:
        pass
    
    # Clear old logfile. This is the only truncation: the collector container
    # is stopped at this point. During a run, phases read from byte offsets.
    LOGFILE.parent.mkdir(parents=True, exist_ok=True)
    if LOGFILE.exists():
        file_size = LOGFILE.stat().st_size / (1024*1024)
        logger.info(f"[+] Clearing old logfile ({file_size:.1f} MB)")
        LOGFILE.write_text("")
    else:
        LOGFILE.touch()

    write_docker_env(PROJECT_ROOT / cfg_safe_get(cfg, ['traffic', 'pcap_path']))
    generate_all_configs(tunneling_domains, server_ip, public_resolver, CONFIG_TEMPLATE_DIR, DOCKER_PATH)
    
    logger.info("[+] Starting docker compose")
    compose_up("essential")
    time.sleep(5)

    return (
        wartime_duration, peacetime_duration, tunneling_domains, server_ip,
        public_resolver, global_allowlist_path, active_detectors_list, results_file,
        dnsexfil_configs
    )


def run_peacetime_phase(
    peacetime_duration: float,
    tunneling_domains_set: set,
    global_allowlist_path: str,
    active_detectors_list: list,
    log_generator
):
    """Peacetime phase: Load detectors, run peacetime, generate allowlists.
    
    Returns:
        tuple: (active_detectors, global_allowlist, tunneling_domains_set, 
                alldomains, peace_logcount, start_timestamp)
    """
    # Load detectors and setup
    logger.info("[+] Loading detectors...")
    active_detectors = load_detectors(DETECTOR_PATH, active_detectors_list)
    logger.info(f"\n{len(active_detectors)} detectors loaded: {[type(d).__name__ for d in active_detectors]}\n")
    global_allowlist = load_global_allowlist(global_allowlist_path, base_dir=CONFIG_PATH.parent)
    
    log_generator_iter = log_generator
    start_timestamp = datetime.now()

    # Start benign traffic
    cfg = load_config()
    benign_enabled = bool(cfg_safe_get(cfg, ["traffic", "benign", "enabled"], False))
    benign_pcap = cfg_safe_get(cfg, ["traffic", "benign", "pcap"], "")
    benign_pps = cfg_safe_get(cfg, ["traffic", "benign", "pps"])

    wildcard_enabled = bool(cfg_safe_get(cfg, ["traffic", "wildcard", "enabled"], False))
    wildcard_pcap = cfg_safe_get(cfg, ["traffic", "wildcard", "pcap"], "")
    wildcard_pps = cfg_safe_get(cfg, ["traffic", "wildcard", "pps"])

    # Background replays start here only if there is a peacetime phase; with
    # peacetime disabled they are started by the wartime phase.
    if peacetime_duration:
        if benign_enabled:
            start_replay("benign", benign_pcap, benign_pps)
        if wildcard_enabled:
            start_replay("wildcard", wildcard_pcap, wildcard_pps)

        if wildcard_enabled or benign_enabled:
            logger.info(f"[+] Benign traffic started - running for {format_duration(peacetime_duration)}...")
        else:
            logger.info(f"[+] No benign traffic - waiting for external DNS traffic or wartime...")

    alldomains = set()
    peace_logcount = 0

    # PEACETIME
    if peacetime_duration and peacetime_duration != 0:
        logger.info("\n" + "="*60)
        logger.info("PEACETIME PHASE - Building Allowlist")
        logger.info("="*60)
        logger.info(f"[+] Peacetime started: Running for {format_duration(peacetime_duration)}...")
        
        peacetime_stop_event.clear()
        peacetime_done.clear()
        
        # Start timer that will signal peacetime to stop
        peace_timer = PhaseTimer(peacetime_stop_event, peacetime_duration).start()
        try:
            # Run peacetime (will block until stop event is set)
            peace_logcount, alldomains = run_peacetime(active_detectors, log_generator_iter, tunneling_domains_set)
        finally:
            peace_timer.cancel()
        
        # run_peacetime() sets peacetime_done itself when it returns.
        if peacetime_done.is_set():
            logger.info(f"[+] Peacetime done!")
        
        logger.info("[+] Generating allowlists...")

    return (
        active_detectors, global_allowlist, tunneling_domains_set, 
        alldomains, peace_logcount, start_timestamp
    )


def show_results(results, config_name=None, peacetime_logcount=0, wartime_duration=None):
    """Display experiment results in a formatted summary table.
    
    Args:
        results: List of detector evaluation result dictionaries
        config_name: Optional configuration name (for DNSExfiltrator multi-config runs)
        peacetime_logcount: Number of log lines processed during peacetime
        wartime_duration: Duration of wartime in seconds
    """
    if not results:
        logger.info("\n[!] No results to display")
        return
    
    header = "EXPERIMENT RESULTS"
    if config_name:
        header += f" - Configuration: {config_name}"
    
    logger.info("\n" + "="*80)
    logger.info(header)
    logger.info("="*80)
    
    # Summary statistics
    if peacetime_logcount > 0:
        logger.info(f"Peacetime log lines: {peacetime_logcount}")
    if wartime_duration:
        logger.info(f"Wartime duration: {format_duration(wartime_duration)}")
    logger.info("")
    
    # Table header
    logger.info(f"{'Detector':<20} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'TPR':>10} {'FPR':>12} {'TP':>6} {'FP':>6} {'FN':>6} {'Runtime(s)':>12}")
    logger.info("-"*80)
    
    # Sort results by F1 score (descending)
    sorted_results = sorted(results, key=lambda x: x.get('f1', 0), reverse=True)
    
    for result in sorted_results:
        detector_name = result.get('detector_name', 'Unknown')
        accuracy = result.get('accuracy', 0)
        precision = result.get('precision', 0)
        recall = result.get('recall', 0)
        f1 = result.get('f1', 0)
        tpr = result.get('tpr', 0)
        fpr = result.get('fpr', 0)
        tp = result.get('tp', 0)
        fp = result.get('fp', 0)
        fn = result.get('fn', 0)
        runtime = result.get('runtime', 0)
        
        logger.info(f"{detector_name:<20} {accuracy:>10.4f} {precision:>10.4f} {recall:>10.4f} {f1:>10.4f} {tpr:>10.4f} {fpr:>12.6f} {tp:>6} {fp:>6} {fn:>6} {runtime:>12.3f}")
    
    logger.info("-"*80)
    
    # Show alarms for each detector
    for result in sorted_results:
        detector_name = result.get('detector_name', 'Unknown')
        alarms = result.get('alarms_raised', [])
        tp_list = result.get('true_positives_list', [])
        fp_list = result.get('false_positives_list', [])
        fn_list = result.get('false_negatives_list', [])
        tunneling_domains = result.get('tunneling_domains', [])
        
        logger.info(f"\n{detector_name}:")
        logger.info(f"  Tunneling domains: {tunneling_domains}")
        logger.info(f"  Alarms raised: {alarms}")
        logger.info(f"  True Positives: {tp_list}")
        if fp_list:
            logger.info(f"  False Positives: {fp_list}")
        if fn_list:
            logger.info(f"  False Negatives: {fn_list}")
    
    logger.info("")


def run_wartime_phase(
    wartime_duration: float,
    peacetime_duration: float,
    tunneling_domains_set: set,
    global_allowlist: set,
    active_detectors: list,
    log_generator,
    alldomains: set,
    start_timestamp: datetime,
    server_ip: str,
    public_resolver: str,
    cfg: dict,
    results_file: Path,
    dnsexfil_configs: list = None,
    results_sink: list = None
):
    """Wartime phase: Start tunnel traffic, run wartime, build and save results.

    Completed windows are appended to ``results_sink`` as soon as they finish,
    so the caller still has them after an interrupt. A window ended by Ctrl+C
    is evaluated, saved with status ``interrupted``, and the interrupt is then
    re-raised.
    """
    logger.info("\n" + "="*60)
    logger.info("WARTIME PHASE")
    logger.info("="*60)

    tunneling_enabled = bool(cfg_safe_get(cfg, ["traffic", "tunnel", "replay"], False))
    tunneling_pcap = cfg_safe_get(cfg, ["traffic", "tunnel", "pcap"], "")
    tunneling_pps = cfg_safe_get(cfg, ["traffic", "tunnel", "pps"])
    dnsexfil_enabled = cfg_safe_get(cfg, ['dnsexfiltrator', 'enabled'], False)

    all_results = results_sink if results_sink is not None else []

    # Never truncate the log while the collector writes to it: record where
    # wartime starts and read only from this offset.
    wartime_offset = log_end_offset(LOGFILE)


    # Start benign traffic if enabled (regardless of DNSExfiltrator)
    benign_enabled = bool(cfg_safe_get(cfg, ["traffic", "benign", "enabled"], False))
    benign_pcap = cfg_safe_get(cfg, ["traffic", "benign", "pcap"], "")
    benign_pps = cfg_safe_get(cfg, ["traffic", "benign", "pps"])
    
    if benign_enabled:
        # Continues the peacetime replay if one is running; never restarts it.
        if start_replay("benign", benign_pcap, benign_pps):
            logger.info(f"[+] Benign traffic replay started - running for {format_duration(wartime_duration)}...")

    # Wildcard traffic runs alongside benign and tunnel traffic in wartime too
    # (README: all three sources run together). A peacetime replay continues.
    wildcard_enabled = bool(cfg_safe_get(cfg, ["traffic", "wildcard", "enabled"], False))
    if wildcard_enabled:
        if start_replay("wildcard", cfg_safe_get(cfg, ["traffic", "wildcard", "pcap"], ""),
                        cfg_safe_get(cfg, ["traffic", "wildcard", "pps"])):
            logger.info(f"[+] Wildcard traffic replay started - running for {format_duration(wartime_duration)}...")
        # Note: tcpreplay runs in background, no direct verification possible

    # Start tunnel traffic if enabled and DNSExfiltrator is not
    if tunneling_enabled and not dnsexfil_enabled:
        if start_replay("tunnel", tunneling_pcap, tunneling_pps):
            logger.info(f"[+] Tunnel replay started - running for {format_duration(wartime_duration)}...")
        # Note: tcpreplay runs in background, no direct verification possible
    
    # Configurations requested by the user; each one gets a results file,
    # also when it is skipped.
    requested_configs = list(dnsexfil_configs or [])

    # Handle DNSExfiltrator configurations sequentially
    if dnsexfil_enabled and dnsexfil_configs:
        # Verify resolver is running and accessible before starting DNSExfiltrator
        # DNSExfiltrator client needs to connect to resolver at 172.16.0.2
        def container_exists(container_name: str) -> bool:
            """Check if a container exists (regardless of running state)."""
            try:
                subprocess.run(
                    ["docker", "inspect", container_name],
                    capture_output=True, text=True, check=True
                )
                return True
            except Exception:
                return False
        
        def container_is_running(container_name: str) -> bool:
            """Check if a container is running."""
            try:
                result = subprocess.run(
                    ["docker", "inspect", "--format", "{{.State.Running}}", container_name],
                    capture_output=True, text=True, check=True
                )
                return result.stdout.strip() == "true"
            except Exception as e:
                logger.debug(f"[!] Error checking container {container_name}: {e}")
                return False
        
        # Check resolver container
        if not container_is_running("resolver"):
            logger.error(f"[!] Resolver container is not running!")
            logger.error(f"[!] DNSExfiltrator needs the resolver at 172.16.0.2")
            logger.error(f"[!] Try running: docker compose -f docker-compose.yml --profile essential up -d")
            dnsexfil_configs = []
        else:
            # Check if resolver is listening on port 53 or if BIND9 is running
            # Use ps aux to check for BIND9 process (more reliable than netstat/ss which may not be installed)
            port_ok = True
            try:
                check_cmd = ["docker", "exec", "resolver", "ps", "aux"]
                check_result = subprocess.run(check_cmd, capture_output=True, text=True, check=False)
                if check_result.returncode == 0:
                    if "named" not in check_result.stdout and "bind9" not in check_result.stdout.lower():
                        logger.warning(f"[!] BIND9 process not found in resolver, but continuing anyway")
                        # Don't fail here, the connectivity test will catch it
                else:
                    logger.warning(f"[!] Could not check resolver processes")
            except Exception as e:
                logger.warning(f"[!] Could not check resolver: {e}. Continuing with connectivity test.")
            
            if port_ok:
                # Start the dnsexfiltrator containers once
                logger.info(f"[+] Starting DNSExfiltrator containers...")
                try:
                    logger.info(f"[+] Running: docker compose -f {DOCKER_COMPOSE_FILE} --profile dnsexfiltrator up -d")
                    compose_up("dnsexfiltrator")
                    time.sleep(5)  # Increased from 3 to 5 seconds
                    
                    # List containers to verify they were created
                    try:
                        list_cmd = ["docker", "ps", "-a", "--format", "table {{.Names}}\t{{.Status}}"]
                        list_result = subprocess.run(list_cmd, capture_output=True, text=True, check=False)
                        logger.info(f"[+] Containers after compose up:\n{list_result.stdout}")
                    except Exception:
                        pass
                    
                    # Wait for containers to be fully ready
                    logger.info(f"[+] Waiting for DNSExfiltrator containers to be ready...")
                    for i in range(10):  # Try for 10 seconds
                        if container_exists("dnsexfiltrator-server") and container_exists("dnsexfiltrator-client"):
                            logger.info(f"[+] DNSExfiltrator containers are ready after {i+1}s")
                            break
                        time.sleep(1)
                    else:
                        logger.error(f"[!] DNSExfiltrator containers did not start within 10 seconds")
                        dnsexfil_configs = []
                except Exception as e:
                    logger.error(f"[!] Failed to start DNSExfiltrator containers: {e}")
                    dnsexfil_configs = []
                
                # Verify containers exist and are running
                server_exists = container_exists("dnsexfiltrator-server")
                client_exists = container_exists("dnsexfiltrator-client")
                server_running = container_is_running("dnsexfiltrator-server") if server_exists else False
                client_running = container_is_running("dnsexfiltrator-client") if client_exists else False
                
                # If containers don't exist, try to list all containers for debugging
                if not server_exists or not client_exists:
                    try:
                        list_cmd = ["docker", "ps", "-a", "--format", "table {{.Names}}\t{{.Status}}"]
                        list_result = subprocess.run(list_cmd, capture_output=True, text=True, check=False)
                        logger.error(f"[!] Current containers:\n{list_result.stdout}")
                    except Exception:
                        pass
                
                if not server_exists or not client_exists:
                    logger.error(f"[!] DNSExfiltrator containers do not exist!")
                    logger.error(f"[!] Server exists: {server_exists}, Client exists: {client_exists}")
                    dnsexfil_configs = []
                elif not server_running or not client_running:
                    logger.error(f"[!] DNSExfiltrator containers not running!")
                    logger.error(f"[!] Server running: {server_running}, Client running: {client_running}")
                    dnsexfil_configs = []
                else:
                    logger.info(f"[+] DNSExfiltrator containers are running")
                    
                    # Check if client can reach resolver
                    connectivity_ok = True
                    try:
                        # Try to resolve via the resolver from the client container
                        test_cmd = ["docker", "exec", "dnsexfiltrator-client", "dig", "@172.16.0.2", "example.com", "+timeout=2", "+tries=1"]
                        test_result = subprocess.run(test_cmd, capture_output=True, text=True, check=False, timeout=5)
                        if "connection timed out" in test_result.stdout or "no servers could be reached" in test_result.stdout:
                            logger.error(f"[!] DNSExfiltrator client cannot reach resolver at 172.16.0.2!")
                            logger.error(f"[!] Dig output: {test_result.stdout[-200:]}")
                            connectivity_ok = False
                        else:
                            logger.info(f"[+] Connectivity check: DNSExfiltrator client can reach resolver")
                    except Exception as e:
                        logger.warning(f"[!] Could not verify connectivity: {e}")
                        connectivity_ok = True  # Assume ok if we can't check
                    
                    if not connectivity_ok:
                        dnsexfil_configs = []
        # Track domains seen across all configs (initialized before conditional to avoid UnboundLocalError)
        all_seen_domains = set()

        if not dnsexfil_configs:
            logger.warning(f"[!] No DNSExfiltrator configurations will be run")
            for skipped in requested_configs:
                save_status_result(cfg, skipped.get('name', 'config'), "skipped",
                                   "DNSExfiltrator readiness checks failed (resolver, containers or connectivity); see console log",
                                   dnsexfil_config=skipped)
        else:
            logger.info(f"[+] Running {len(dnsexfil_configs)} DNSExfiltrator configurations sequentially")
            
            # Prepare directories
            server_volume_dir = PROJECT_ROOT / "docker/dnsexfiltrator-server/volume"
            server_volume_dir.mkdir(parents=True, exist_ok=True)
            client_data_dir = PROJECT_ROOT / "docker/dnsexfiltrator-client/data"
            client_data_dir.mkdir(parents=True, exist_ok=True)
            
            
            # Run each configuration sequentially
        for config_idx, config in enumerate(dnsexfil_configs):
            config_name = config.get('name', f'config_{config_idx}')
            
            # Check if containers still exist at the start of each config
            server_exists_at_start = container_exists("dnsexfiltrator-server")
            client_exists_at_start = container_exists("dnsexfiltrator-client")
            if not server_exists_at_start or not client_exists_at_start:
                logger.warning(f"[!] WARNING: Containers missing at start of config {config_name}!")
                logger.warning(f"[!] Server exists: {server_exists_at_start}, Client exists: {client_exists_at_start}")
                # Try to recreate containers
                try:
                    logger.info(f"[+] Attempting to recreate DNSExfiltrator containers...")
                    compose_up("dnsexfiltrator")
                    time.sleep(5)
                except Exception as e:
                    logger.error(f"[!] Failed to recreate containers: {e}")
                    save_status_result(cfg, config_name, "failed", f"could not recreate DNSExfiltrator containers: {e}", dnsexfil_config=config)
                    continue
            
            domains = config.get('domains', [])
            password = config.get('password', 'tunframe')
            filepath = config.get('file', '/data/synthetic_cc_data_100.csv')
            
            logger.info(f"\n[+] --- Running DNSExfiltrator configuration: {config_name} ({config_idx + 1}/{len(dnsexfil_configs)}) ---")
            
            # Use config domains as tunneling domains for this run
            config_tunneling_domains_set = {normalize_domain(d) for d in domains} if domains else tunneling_domains_set
            
            # Update domain file for this configuration (single file)
            domains_file = server_volume_dir / "domains.txt"
            domains_file.write_text("\n".join(domains))
            
            # Update client domains file
            client_domains_file = client_data_dir / "domains.txt"
            client_domains_file.write_text("\n".join(domains))
            
            # Stop any existing server and client processes (if containers exist)
            if container_exists("dnsexfiltrator-server"):
                docker_exec("dnsexfiltrator-server", "pkill", "-f", "dnsExfiltrator.py", check=False)
            else:
                logger.warning(f"[!] dnsexfiltrator-server container does not exist, skipping pkill")
            
            if container_exists("dnsexfiltrator-client"):
                docker_exec("dnsexfiltrator-client", "pkill", "-f", "DNSExfiltrator.exe", check=False)
            else:
                logger.warning(f"[!] dnsexfiltrator-client container does not exist, skipping pkill")
            
            time.sleep(1)
            
            # Record where this configuration starts in the log BEFORE starting
            # DNSExfiltrator; the log is never truncated while the collector runs.
            config_offset = log_end_offset(LOGFILE)
            
            # Reset state for this configuration - create fresh log generator
            config_alldomains = set()
            config_start_timestamp = datetime.now()
            config_log_generator = readjson(str(LOGFILE), start_offset=config_offset)
            
            # Start server for this configuration
            logger.info(f"[+] Starting DNSExfiltrator server with {len(domains)} domains")
            server_cmd = [
                "docker", "exec", "-d", "dnsexfiltrator-server",
                "python3", "-u", "/app/dnsExfiltrator.py",
                "-f", "/app/domains.txt",
                "-p", password,
                "-o", "/app/outputfile",
            ]
            result = subprocess.run(server_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"[!] Failed to start server: {result.stderr}")
                if result.stdout:
                    logger.error(f"[!] Stdout: {result.stdout}")
                # Try running without -d to see the error
                try:
                    test_cmd = [
                        "docker", "exec", "dnsexfiltrator-server",
                        "python3", "-u", "/app/dnsExfiltrator.py",
                        "-f", "/app/domains.txt",
                        "-p", password,
                        "-o", "/app/outputfile",
                    ]
                    test_result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=5)
                    logger.error(f"[!] Server test output: {test_result.stdout}")
                    logger.error(f"[!] Server test error: {test_result.stderr}")
                except Exception as e:
                    logger.error(f"[!] Server test failed: {e}")
            else:
                # Get the actual process PID from the container
                try:
                    pid_check = subprocess.run(
                        ["docker", "exec", "dnsexfiltrator-server", "pgrep", "-f", "dnsExfiltrator.py"],
                        capture_output=True, text=True, check=False
                    )
                    pid = pid_check.stdout.strip() if pid_check.stdout.strip() else "unknown"
                except:
                    pid = "unknown"
                logger.info(f"  Server started (PID: {pid})")
            
            # Verify server is running
            time.sleep(1)
            if not check_process_running("dnsexfiltrator-server", "dnsExfiltrator.py"):
                logger.error(f"[!] DNSExfiltrator server failed to start or crashed!")
                logger.error(f"[!] Skipping configuration: {config_name}")
                save_status_result(cfg, config_name, "skipped", "DNSExfiltrator server failed to start or crashed", dnsexfil_config=config)
                continue
            
            # Start client for this configuration
            logger.info(f"[+] Starting DNSExfiltrator client: {filepath}")
            
            throttle = config.get('throttle')
            throttle_random = config.get('throttle_random')
            label_size = config.get('label_max_size')
            encoding = config.get('encoding')
            dil = config.get('dilution')
            
            # Ensure the data file is in the client data directory
            # filepath can be absolute or just a filename
            if filepath.startswith('/data/'):
                # Absolute path in container's /data directory - use as-is
                client_filepath = filepath[6:]  # Remove '/data/' prefix for relative path in container
            elif filepath.startswith('/'):
                # Absolute path on host - copy to client data dir
                src_path = Path(filepath)
                if src_path.exists():
                    dest_path = client_data_dir / src_path.name
                    if not dest_path.exists():
                        shutil.copy2(src_path, dest_path)
                        logger.info(f"[+] Copied {src_path.name} to client data directory")
                    client_filepath = src_path.name
                else:
                    logger.warning(f"[!] File not found on host: {filepath}")
                    client_filepath = Path(filepath).name
            else:
                # Relative path - assume it's already in data directory or will be handled
                client_filepath = filepath
            
            # Use absolute paths in container
            # DNSExfiltrator.exe is built in /app by Dockerfile
            cmd = [
                "docker", "exec", "-d", "dnsexfiltrator-client",
                "mono", "/app/DNSExfiltrator.exe",
                f"/data/{client_filepath}",
                "/data/domains.txt",
                password,
                "s=172.16.0.2",
            ]
            
            if throttle is not None:
                cmd.append(f"t={throttle}")
            if throttle_random is not None:
                cmd.append(f"tr={throttle_random}")
            if label_size is not None:
                cmd.append(f"l={label_size}")
            if encoding is not None:
                cmd.append(f"e={encoding}")
            if dil is not None:
                cmd.append(f"dil={dil}")
            

            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"[!] Failed to start client: {result.stderr}")
                if result.stdout:
                    logger.error(f"[!] Stdout: {result.stdout}")
                
                # Check if executable exists
                try:
                    exe_check = subprocess.run(
                        ["docker", "exec", "dnsexfiltrator-client", "ls", "-la", "/app/DNSExfiltrator.exe"],
                        capture_output=True, text=True, check=False
                    )
                    if exe_check.returncode != 0:
                        logger.error(f"[!] DNSExfiltrator.exe not found at /app/DNSExfiltrator.exe")
                        logger.error(f"[!] Executable check: {exe_check.stderr}")
                    else:
                        logger.info(f"[+] DNSExfiltrator.exe exists: {exe_check.stdout.strip()}")
                except Exception:
                    pass
                
                # Check if file exists in container
                try:
                    file_check = subprocess.run(
                        ["docker", "exec", "dnsexfiltrator-client", "ls", "-la", f"/data/{client_filepath}"],
                        capture_output=True, text=True, check=False
                    )
                    if file_check.returncode != 0:
                        logger.error(f"[!] File /data/{client_filepath} not found in container!")
                        logger.error(f"[!] Container file check: {file_check.stderr}")
                        # List what IS in /data
                        try:
                            ls_result = subprocess.run(
                                ["docker", "exec", "dnsexfiltrator-client", "ls", "-la", "/data/"],
                                capture_output=True, text=True, check=False
                            )
                            if ls_result.returncode == 0:
                                logger.error(f"[!] Files in /data/: {ls_result.stdout}")
                        except Exception:
                            pass
                except Exception:
                    pass
                
                # Try running without -d to see the error
                try:
                    test_cmd = [
                        "docker", "exec", "dnsexfiltrator-client",
                        "mono", "/app/DNSExfiltrator.exe",
                        f"/data/{client_filepath}",
                        "/data/domains.txt",
                        password,
                        "s=172.16.0.2",
                    ]
                    test_result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=5)
                    logger.error(f"[!] Client test output: {test_result.stdout[:500]}")
                    logger.error(f"[!] Client test error: {test_result.stderr[:500]}")
                except Exception as e:
                    logger.error(f"[!] Client test failed: {e}")
            else:
                # Get the actual process PID from the container
                try:
                    pid_check = subprocess.run(
                        ["docker", "exec", "dnsexfiltrator-client", "pgrep", "-f", "DNSExfiltrator.exe"],
                        capture_output=True, text=True, check=False
                    )
                    pid = pid_check.stdout.strip() if pid_check.stdout.strip() else "unknown"
                except:
                    pid = "unknown"
                logger.info(f"  Client started (PID: {pid})")
            
            # Verify client is running
            time.sleep(1)
            if not check_process_running("dnsexfiltrator-client", "DNSExfiltrator.exe"):
                logger.error(f"[!] DNSExfiltrator client failed to start or crashed!")
                logger.error(f"[!] Skipping configuration: {config_name}")
                save_status_result(cfg, config_name, "skipped", "DNSExfiltrator client failed to start or crashed", dnsexfil_config=config)
                continue
            
            # Give some time for the client to start generating traffic
            time.sleep(2)
            
            # Final verification that both processes are running before starting detection
            if not check_process_running("dnsexfiltrator-server", "dnsExfiltrator.py"):
                logger.error(f"[!] DNSExfiltrator server is not running! Skipping config: {config_name}")
                save_status_result(cfg, config_name, "skipped", "DNSExfiltrator server stopped before wartime", dnsexfil_config=config)
                continue
            if not check_process_running("dnsexfiltrator-client", "DNSExfiltrator.exe"):
                logger.error(f"[!] DNSExfiltrator client is not running! Skipping config: {config_name}")
                save_status_result(cfg, config_name, "skipped", "DNSExfiltrator client stopped before wartime", dnsexfil_config=config)
                continue
            
            logger.info(f"[+] Both DNSExfiltrator server and client are confirmed running")
            
            # Start every configuration from a clean detector state: alarms,
            # counters, runtime and leakage of earlier configs must not carry
            # over (the allowlist from peacetime is kept).
            for detector in active_detectors:
                detector.reset()

            # Reset wartime event and run detection for this configuration
            wartime_stop_event.clear()
            war_timer = PhaseTimer(wartime_stop_event, wartime_duration).start()
            
            logger.info(f"[+] Wartime started for config {config_name}: Running for {format_duration(wartime_duration)}...")
            
            # Run wartime detection for this specific configuration with clean state
            try:
                results, logcount, tunnel_count, seen_tunnels, config_alldomains, counts = run_wartime(
                    active_detectors, config_log_generator, config_tunneling_domains_set, global_allowlist,
                    expansion_factor=config_expansion_factor(config),
                )
            finally:
                war_timer.cancel()
            
            # Store results for this configuration
            all_results.append({
                'config_name': config_name,
                'results': results,
                'logcount': logcount,
                'tunnel_count': tunnel_count
            })
            
            # Update all seen domains
            all_seen_domains.update(config_alldomains)
            
            # Show results for this configuration
            show_results(results, config_name=config_name, wartime_duration=wartime_duration)
            
            # Build metadata and save results for this configuration
            config_end_timestamp = datetime.now()
            
            # Save per-config results
            config_results_file = RESULTS_DIR / f"results_{cfg_safe_get(cfg, ['global', 'name'], 'experiment')}_{config_name}_{int(time.time())}.json"
            build_and_save_metadata(
                results_file=config_results_file,
                results=results,
                logcount=logcount,
                tunnel_count=tunnel_count,
                seen_tunnels=seen_tunnels,
                alldomains=config_alldomains,
                start_timestamp=config_start_timestamp,
                end_timestamp=config_end_timestamp,
                wartime_duration=wartime_duration,
                peacetime_duration=peacetime_duration,
                tunneling_domains_set=config_tunneling_domains_set,
                tunneling_enabled=tunneling_enabled,
                tunneling_pcap=tunneling_pcap,
                tunneling_pps=tunneling_pps,
                server_ip=server_ip,
                public_resolver=public_resolver,
                cfg=cfg,
                counts=counts,
                dnsexfil_config=dict(config, expansion_factor_used=config_expansion_factor(config)),
                status="interrupted" if counts.get("interrupted") else "completed",
                status_reason="Ctrl+C during wartime; partial window" if counts.get("interrupted") else ""
            )
            if counts.get("interrupted"):
                raise KeyboardInterrupt
            
            logger.info(f"[+] Completed configuration: {config_name}")
            
            # Check if traffic was detected
            if logcount == 0:
                logger.warning(f"[!] WARNING: No DNS traffic detected for config {config_name}!")
                logger.warning(f"[!] This likely means DNSExfiltrator failed to generate traffic")
                logger.warning(f"[!] Check: DNSExfiltrator processes, network connectivity, DNS resolver")
            elif tunnel_count == 0:
                logger.warning(f"[!] WARNING: No tunneling traffic detected for config {config_name}!")
                logger.warning(f"[!] DNS traffic was seen ({logcount} lines) but no tunneling domains were detected")
                logger.warning(f"[!] Expected tunneling domains: {config_tunneling_domains_set}")
                logger.warning(f"[!] Detected domains: {seen_tunnels}")
            
            # Stop client and server for this configuration
            docker_exec("dnsexfiltrator-server", "pkill", "-f", "dnsExfiltrator.py", check=False)
            docker_exec("dnsexfiltrator-client", "pkill", "-f", "DNSExfiltrator.exe", check=False)
            time.sleep(1)
        
        # Update the alldomains with all domains seen across all configs
        alldomains.update(all_seen_domains)
        
        logger.info(f"[+] Completed all {len(dnsexfil_configs)} DNSExfiltrator configurations")
    else:
        # Standard wartime without DNSExfiltrator
        logger.info(f"[+] Wartime started: Running for {format_duration(wartime_duration)}...")
        
        # Fresh generator for wartime, starting where wartime began in the log
        wartime_log_generator = readjson(str(LOGFILE), start_offset=wartime_offset)
        
        wartime_stop_event.clear()
        war_timer = PhaseTimer(wartime_stop_event, wartime_duration).start()
        
        # Run wartime (will block until stop event is set or all tunnels detected).
        # The TN/FPR universe is the set of domains seen in this wartime only.
        try:
            results, logcount, tunnel_count, seen_tunnels, alldomains, counts = run_wartime(
                active_detectors, wartime_log_generator, tunneling_domains_set, global_allowlist,
                expansion_factor=float(cfg_safe_get(cfg, ['traffic', 'tunnel', 'expansion_factor'], 1) or 1),
            )
        finally:
            war_timer.cancel()
        
        end_timestamp = datetime.now()
        
        # Store results
        all_results.append({
            'config_name': None,
            'results': results,
            'logcount': logcount,
            'tunnel_count': tunnel_count
        })
        
        # Show results
        show_results(results, wartime_duration=wartime_duration)
        
        # Build metadata and save results
        build_and_save_metadata(
            results_file=results_file,
            results=results,
            logcount=logcount,
            tunnel_count=tunnel_count,
            seen_tunnels=seen_tunnels,
            alldomains=alldomains,
            start_timestamp=start_timestamp,
            end_timestamp=end_timestamp,
            wartime_duration=wartime_duration,
            peacetime_duration=peacetime_duration,
            tunneling_domains_set=tunneling_domains_set,
            tunneling_enabled=tunneling_enabled,
            tunneling_pcap=tunneling_pcap,
            tunneling_pps=tunneling_pps,
            server_ip=server_ip,
            public_resolver=public_resolver,
            cfg=cfg,
            counts=counts,
            status="interrupted" if counts.get("interrupted") else "completed",
            status_reason="Ctrl+C during wartime; partial window" if counts.get("interrupted") else ""
        )
        if counts.get("interrupted"):
            raise KeyboardInterrupt
    
    return alldomains, all_results


def main():
    cfg = load_config(CONFIG_PATH)
    
    # Reset events
    peacetime_stop_event.clear()
    peacetime_done.clear()
    wartime_stop_event.clear()
    
    all_experiment_results = []
    peace_logcount = 0
    
    try:
        # Run setup phase
        (
            wartime_duration, peacetime_duration, tunneling_domains, server_ip,
            public_resolver, global_allowlist_path, active_detectors_list, results_file,
            dnsexfil_configs
        ) = run_setup(cfg)
        
        tunneling_domains_set = {normalize_domain(d) for d in tunneling_domains}
        
        # Create log generator
        log_generator = readjson(str(LOGFILE), start_offset=log_end_offset(LOGFILE))
        
        # Run peacetime phase
        (
            active_detectors, global_allowlist, tunneling_domains_set,
            alldomains, peace_logcount, start_timestamp
        ) = run_peacetime_phase(
            peacetime_duration, tunneling_domains_set, global_allowlist_path,
            active_detectors_list, log_generator
        )
        
        generate_allowlists(active_detectors, global_allowlist, peace_logcount)
        

        # Run wartime phase(s)
        alldomains, _ = run_wartime_phase(
            wartime_duration, peacetime_duration, tunneling_domains_set, global_allowlist,
            active_detectors, log_generator, alldomains, start_timestamp,
            server_ip, public_resolver, cfg, results_file, dnsexfil_configs,
            results_sink=all_experiment_results
        )

        compose_down()

    except KeyboardInterrupt:
        logger.info("\n[!] Interrupted by user - shutting down...")
        peacetime_stop_event.set()
        wartime_stop_event.set()
        compose_down()
        # Show results if any were collected
        if all_experiment_results:
            logger.info("\n[+] Showing partial results before exit:")
            for result_entry in all_experiment_results:
                show_results(
                    result_entry['results'],
                    config_name=result_entry.get('config_name'),
                    peacetime_logcount=peace_logcount,
                    wartime_duration=wartime_duration
                )

    except Exception as e:
        logger.error(f"[!] Error: {e}", exc_info=True)
        peacetime_stop_event.set()
        wartime_stop_event.set()
        compose_down()
        # Show results if any were collected
        if all_experiment_results:
            logger.info("\n[+] Showing partial results before exit:")
            for result_entry in all_experiment_results:
                show_results(
                    result_entry['results'],
                    config_name=result_entry.get('config_name'),
                    peacetime_logcount=peace_logcount,
                    wartime_duration=wartime_duration
                )

    finally:
        try:
            compose_down()
        except:
            pass


if __name__ == "__main__":
    main()
