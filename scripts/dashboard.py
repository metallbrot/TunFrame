"""Local operations dashboard for TunFrame runs.

Serves the run directories written by ``main.py`` (see ``detection/reporting.py``
and ``detection/monitoring.py``) on http://127.0.0.1:8050 and polls them, so a
running experiment updates live: status, elapsed and estimated end time, DNS
traffic, resource usage, DNSExfiltrator progress and logs, detection results.

The only write is ``control.json`` in a running run's directory (skip the
running configuration, stop the run). Control requests need the token that is
embedded in the page, and the server only listens on 127.0.0.1.

Usage:
    python3 scripts/dashboard.py [--results DIR] [--port 8050]

Without ``--results`` the directory comes from ``output.logdir`` in
``config.yaml`` (default ``results``), as in ``main.py``.
"""
import argparse
import json
import os
import re
import secrets
import sys
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "dashboard_static"
TOOL_LOGS = {
    "server": PROJECT_ROOT / "docker" / "dnsexfiltrator-server" / "volume" / "logs" / "server.log",
    "client": PROJECT_ROOT / "docker" / "dnsexfiltrator-client" / "data" / "logs" / "client.log",
}
LOG_CHUNK = 64 * 1024
METRICS_CHUNK = 2 * 1024 * 1024
CONTROL_ACTIONS = ("skip_config", "stop_run")
STATIC_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
                ".js": "text/javascript; charset=utf-8"}
RUN_FILE_TYPES = {".html": "text/html; charset=utf-8", ".json": "application/json",
                  ".png": "image/png", ".log": "text/plain; charset=utf-8"}
# Keep SGR colour codes (CSI ending in "m") so the browser can render them; drop the
# other CSI control sequences (cursor moves, erase) a PTY inserts, which end in any
# other letter. The client runs under ``script``, so these appear in its log.
_OTHER_ESC = re.compile(r"\x1b\[[0-9;?]*[A-Za-ln-z]")


def default_results_dir() -> Path:
    """Resolve ``output.logdir`` from config.yaml the same way main.py does."""
    config_path = PROJECT_ROOT / "config.yaml"
    logdir = "results"
    if config_path.exists():
        try:
            import yaml
            cfg = yaml.safe_load(config_path.read_text()) or {}
            logdir = (cfg.get("output") or {}).get("logdir") or "results"
        except Exception:
            pass
    path = Path(logdir)
    return path if path.is_absolute() else (config_path.parent / path).resolve()


def read_run(run_dir: Path):
    try:
        return json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def list_runs(results_dir: Path) -> list:
    runs = []
    if not results_dir.is_dir():
        return runs
    for run_dir in results_dir.iterdir():
        state = read_run(run_dir) if run_dir.is_dir() else None
        if state is None:
            continue
        runs.append({
            "id": run_dir.name,
            "name": state.get("name"),
            "status": state.get("status"),
            "mode": state.get("mode"),
            "phase": state.get("phase"),
            "started": state.get("started"),
            "updated": state.get("updated"),
            "configs": len(state.get("configs", [])),
            "planned": len(state.get("planned_configs", [])),
        })
    runs.sort(key=lambda r: r.get("started") or "", reverse=True)
    return runs


def read_chunk(path: Path, offset: int, limit: int, align_lines: bool = False) -> dict:
    """Read up to ``limit`` bytes from ``offset``; ``offset < 0`` reads the tail."""
    size = path.stat().st_size if path.exists() else 0
    if offset < 0 or offset > size:
        offset = max(0, size - limit)
        if align_lines and offset > 0:
            with open(path, "rb") as f:
                f.seek(offset)
                offset += len(f.readline())  # start at a complete line
    end = min(size, offset + limit)
    data = b""
    if end > offset:
        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read(end - offset)
    if align_lines:
        cut = data.rfind(b"\n") + 1  # never hand out a partial line
        data, end = data[:cut], offset + cut
    return {"offset": end, "size": size, "data": data}


def clean_tool_log(text: str) -> str:
    """Keep SGR colours, drop other escapes, collapse \\r progress bars to their last state."""
    text = _OTHER_ESC.sub("", text)
    return "\n".join(line.rstrip("\r").split("\r")[-1] for line in text.split("\n"))


class DashboardHandler(BaseHTTPRequestHandler):
    results_dir: Path = None
    token: str = ""
    port: int = 8050

    def log_message(self, fmt, *args):  # keep the terminal quiet
        pass

    # -- responses ----------------------------------------------------------

    def _send(self, status, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, status=HTTPStatus.OK):
        self._send(status, json.dumps(data, default=str).encode(), "application/json")

    def _error(self, status, message):
        self._json({"error": message}, status)

    def _run_dir(self, run_id: str):
        run_dir = (self.results_dir / run_id).resolve()
        if run_dir.parent != self.results_dir.resolve() or not (run_dir / "run.json").exists():
            return None
        return run_dir

    # -- GET ----------------------------------------------------------------

    def do_GET(self):
        url = urlparse(self.path)
        parts = [unquote(p) for p in url.path.split("/") if p]
        query = parse_qs(url.query)
        if not parts:
            page = (STATIC_DIR / "index.html").read_text(encoding="utf-8").replace("{{TOKEN}}", self.token)
            return self._send(HTTPStatus.OK, page.encode(), "text/html; charset=utf-8")
        if parts[0] == "static" and len(parts) == 2:
            return self._static(parts[1])
        if parts == ["api", "runs"]:
            return self._json(list_runs(self.results_dir))
        if len(parts) >= 3 and parts[:2] == ["api", "run"]:
            run_dir = self._run_dir(parts[2])
            if run_dir is None:
                return self._error(HTTPStatus.NOT_FOUND, "run not found")
            if len(parts) == 3:
                state = read_run(run_dir) or {}
                state["has_report"] = (run_dir / "report.html").exists()
                state["server_time"] = datetime.now().isoformat(timespec="seconds")
                return self._json(state)
            if len(parts) == 4 and parts[3] == "log":
                return self._text_chunk(run_dir / "run.log", self._offset(query), LOG_CHUNK)
            if len(parts) == 4 and parts[3] == "metrics":
                return self._metrics(run_dir, query)
            if len(parts) == 4 and parts[3] == "toollog":
                return self._tool_log(run_dir, query)
            return self._error(HTTPStatus.NOT_FOUND, "not found")
        if len(parts) >= 3 and parts[0] == "runs":
            return self._run_file(parts[1], parts[2:])
        return self._error(HTTPStatus.NOT_FOUND, "not found")

    @staticmethod
    def _offset(query) -> int:
        try:
            return int(query.get("offset", ["-1"])[0])
        except ValueError:
            return -1

    def _text_chunk(self, path: Path, offset: int, limit: int, clean=False):
        chunk = read_chunk(path, offset, limit)
        text = chunk["data"].decode("utf-8", errors="replace")
        return self._json({"offset": chunk["offset"], "size": chunk["size"],
                           "text": clean_tool_log(text) if clean else text})

    def _metrics(self, run_dir: Path, query):
        chunk = read_chunk(run_dir / "metrics.jsonl", self._offset(query), METRICS_CHUNK, align_lines=True)
        samples = []
        for line in chunk["data"].splitlines():
            try:
                samples.append(json.loads(line))
            except ValueError:
                continue
        return self._json({"offset": chunk["offset"], "size": chunk["size"], "samples": samples})

    def _tool_log(self, run_dir: Path, query):
        which = query.get("which", [""])[0]
        if which not in TOOL_LOGS:
            return self._error(HTTPStatus.BAD_REQUEST, "which must be server or client")
        # The shared tool logs (cleared at every run start) belong to the run
        # that is going; a finished run reads the copy main.py put into its
        # directory, and shows nothing without one. A fresh read of a running
        # configuration starts at its own offset, otherwise at the tail.
        state = read_run(run_dir) or {}
        offset = self._offset(query)
        if state.get("status") != "running":
            return self._text_chunk(run_dir / f"exfil-{which}.log", offset, LOG_CHUNK, clean=True)
        start = (state.get("current") or {}).get(f"{which}_log_offset")
        path = TOOL_LOGS[which]
        if offset < 0 and start is not None:
            size = path.stat().st_size if path.exists() else 0
            offset = max(int(start), size - LOG_CHUNK)
        return self._text_chunk(path, offset, LOG_CHUNK, clean=True)

    def _static(self, name: str):
        path = (STATIC_DIR / name).resolve()
        if path.parent != STATIC_DIR or path.suffix not in STATIC_TYPES or not path.is_file():
            return self._error(HTTPStatus.NOT_FOUND, "not found")
        return self._send(HTTPStatus.OK, path.read_bytes(), STATIC_TYPES[path.suffix])

    def _run_file(self, run_id: str, rel_parts: list):
        run_dir = self._run_dir(run_id)
        if run_dir is None:
            return self._error(HTTPStatus.NOT_FOUND, "not found")
        path = run_dir.joinpath(*rel_parts).resolve()
        if run_dir not in path.parents or not path.is_file() or path.suffix not in RUN_FILE_TYPES:
            return self._error(HTTPStatus.NOT_FOUND, "not found")
        return self._send(HTTPStatus.OK, path.read_bytes(), RUN_FILE_TYPES[path.suffix])

    # -- POST (run control) -------------------------------------------------

    def _origin_ok(self) -> bool:
        hosts = {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}
        origin = self.headers.get("Origin")
        return self.headers.get("Host", "") in hosts and (origin is None or origin in {f"http://{h}" for h in hosts})

    def do_POST(self):
        parts = [unquote(p) for p in urlparse(self.path).path.split("/") if p]
        if len(parts) != 4 or parts[:2] != ["api", "run"] or parts[3] != "control":
            return self._error(HTTPStatus.NOT_FOUND, "not found")
        if not self._origin_ok() or not secrets.compare_digest(self.headers.get("X-TunFrame-Token", ""), self.token):
            return self._error(HTTPStatus.FORBIDDEN, "forbidden")
        run_dir = self._run_dir(parts[2])
        if run_dir is None:
            return self._error(HTTPStatus.NOT_FOUND, "run not found")
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 4096)
            action = json.loads(self.rfile.read(length) or b"{}").get("action")
        except (ValueError, AttributeError):
            return self._error(HTTPStatus.BAD_REQUEST, "invalid body")
        if action not in CONTROL_ACTIONS:
            return self._error(HTTPStatus.BAD_REQUEST, "unknown action")
        if (read_run(run_dir) or {}).get("status") != "running":
            return self._error(HTTPStatus.CONFLICT, "run is not running")
        control_path = run_dir / "control.json"
        try:
            last_id = int(json.loads(control_path.read_text(encoding="utf-8")).get("id", 0))
        except (OSError, ValueError, TypeError):
            last_id = 0
        request = {"id": last_id + 1, "action": action, "requested": datetime.now().isoformat(timespec="seconds")}
        tmp = control_path.with_name("control.json.tmp")
        tmp.write_text(json.dumps(request), encoding="utf-8")
        os.replace(tmp, control_path)
        return self._json({"ok": True, "request": request})


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the TunFrame dashboard on localhost.")
    parser.add_argument("--results", type=Path, default=None, help="results directory (default: output.logdir)")
    parser.add_argument("--port", type=int, default=8050)
    args = parser.parse_args()
    DashboardHandler.results_dir = (args.results or default_results_dir()).resolve()
    DashboardHandler.token = secrets.token_urlsafe(24)
    DashboardHandler.port = args.port
    server = ThreadingHTTPServer(("127.0.0.1", args.port), DashboardHandler)
    print(f"TunFrame dashboard: http://127.0.0.1:{args.port}  (results: {DashboardHandler.results_dir})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())
