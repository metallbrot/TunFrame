import subprocess
import time
import yaml
from pathlib import Path
from typing import Any, List
import sys
import threading

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from detection.evaluate import evaluate, detector_ready, stop_event

CONFIG_PATH = PROJECT_ROOT / "config.yaml"
DOCKER_COMPOSE_FILE = PROJECT_ROOT / "docker" / "docker-compose.yml"
DOCKER_ENV_FILE = PROJECT_ROOT / "docker" / ".env"
PCAP_DIR = PROJECT_ROOT / "pcaps"
RESULTS_DIR = PROJECT_ROOT / "results"
DETECTOR_PATH = PROJECT_ROOT / "detection" / "detectors"
LOGFILE = PROJECT_ROOT / "docker" / "dns-collector" / "logs" / "dnslogs.json"

def generate_dns_entries_from_config(tunneling_domains: list[str], server_ip: str) -> None:
    pass


def safe_get(cfg: dict, path: List[str], default: Any = None) -> Any:
    """safe get values from yaml with default values"""
    cur = cfg
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def load_config(path=CONFIG_PATH):
    with open(path) as f:
        return yaml.safe_load(f)


def write_docker_env():
    DOCKER_ENV_FILE.write_text(f"PCAP_PATH={PCAP_DIR}\n")


def compose_up():
    cmd = [
        "docker",
        "compose",
        "-f", str(DOCKER_COMPOSE_FILE),
        "up",
        "-d",
    ]
    subprocess.run(cmd, check=True)


def compose_down():
    cmd = [
        "docker",
        "compose",
        "-f", str(DOCKER_COMPOSE_FILE),
        "down",
    ]
    subprocess.run(cmd, check=True)


def docker_exec(container: str, *docker_cmd: str, check: bool = True):
    cmd = ["docker", "exec", container] + list(docker_cmd)
    subprocess.run(cmd, check=check)


def replay_fire_and_forget(pcap: str, pps: int, label: str):
    """Fire and forget: startet tcpreplay ohne zu warten"""
    if not pcap or pps <= 0:
        print(f"[-] Skipping {label} replay (disabled)")
        return
    print(f"[+] Firing {label} replay: {pps} PPS from {pcap}")
    docker_exec(
        "pcap-replayer",
        "tcpreplay",
        f"--pps={pps}",
        "-i", "replay0",
        pcap,
        check=False
    )


def main():
    cfg = load_config(CONFIG_PATH)
    duration = int(safe_get(cfg, ["timing", "duration"], 10))
    tunneling_domains = safe_get(cfg, ["traffic", "tunnel", "tunneling_domains"], [])

    print(f"[+] Experiment: {safe_get(cfg, ['global', 'name'], '')}")
    print(f"[+] Duration: {duration}s")
    print("[+] Starting docker compose")

    try:
        write_docker_env()
        compose_up()
        time.sleep(5)

    
        t_detect = threading.Thread(
            target=evaluate,
            args=(DETECTOR_PATH, str(LOGFILE), tunneling_domains),
        )
        t_detect.start()

        detector_ready.wait()
        print("[+] Detection ready")

        #fire-and-forget
        benign_enabled = bool(safe_get(cfg, ["traffic", "benign", "enabled"], False))
        benign_pcap = safe_get(cfg, ["traffic", "benign", "pcap"], "")
        benign_pps = int(safe_get(cfg, ["traffic", "benign", "pps"], 0))

        wildcard_enabled = bool(safe_get(cfg, ["traffic", "wildcard", "enabled"], False))
        wildcard_pcap = safe_get(cfg, ["traffic", "wildcard", "pcap"], "")
        wildcard_pps = int(safe_get(cfg, ["traffic", "wildcard", "pps"], 0))

        if benign_enabled:
            threading.Thread(
                target=replay_fire_and_forget,
                args=(benign_pcap, benign_pps, "benign"),
                daemon=True, 
            ).start()

        if wildcard_enabled:
            threading.Thread(
                target=replay_fire_and_forget,
                args=(wildcard_pcap, wildcard_pps, "wildcard"),
                daemon=True,  
            ).start()

        print(f"[+] Replays started - running for {duration}s...")

        time.sleep(duration)

        print("[+] Duration reached - signaling stop")
        stop_event.set()
        t_detect.join()
        compose_down()


    except KeyboardInterrupt:
        stop_event.set()
        compose_down()
    except Exception as e:
        print(f"[!] Error: {e}")
        stop_event.set()
        compose_down()
    finally:
        compose_down()


if __name__ == "__main__":
    main()
