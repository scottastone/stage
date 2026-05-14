import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import request as urllib_request
from urllib.error import URLError
from urllib.parse import quote, unquote

STAGE_DIR = Path.home() / ".stage"
CONFIG_PATH = Path.home() / ".config" / "stage" / "config.toml"
PID_FILE = STAGE_DIR / "daemon.pid"
MANIFEST_FILE = STAGE_DIR / "manifest.json"
UPDATE_FILE = STAGE_DIR / "update.json"
DEFAULT_PORT = 47200
PROBE_TIMEOUT = 3
UPDATE_INTERVAL = 86400  # seconds between remote checks


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        _usage()
        return

    cmd = args[0]

    # Internal subcommands — skip everything else
    if cmd == "_serve":
        _run_daemon(int(args[1]), int(args[2]))
        return
    if cmd == "_check":
        if len(args) > 1:
            _do_update_check(args[1])
        return

    _maybe_check_updates()

    if cmd == "pull":
        _pull(args[1] if len(args) > 1 else None)
    elif cmd == "status":
        _status(args[1] if len(args) > 1 else None)
    elif cmd == "clear":
        _clear()
    elif cmd == "update":
        _update()
    elif cmd == "setup":
        _setup(args[1:])
    else:
        n = 1
        paths = []
        i = 0
        while i < len(args):
            if args[i] == "-n" and i + 1 < len(args):
                try:
                    n = int(args[i + 1])
                    if n < 1:
                        raise ValueError
                except ValueError:
                    _die(f"Invalid value for -n: {args[i + 1]}")
                i += 2
            else:
                paths.append(args[i])
                i += 1
        if not paths:
            _usage()
            return
        _stage(paths, n)


def _stage(paths, n=1):
    files = []
    for p in paths:
        path = Path(p).resolve()
        if not path.exists():
            _die(f"Not found: {p}")
        if path.is_dir():
            print(f"Archiving {path.name}/...", end=" ", flush=True)
            STAGE_DIR.mkdir(parents=True, exist_ok=True)
            tmp = STAGE_DIR / f"_dir_{secrets.token_hex(4)}_{path.name}.tar.gz"
            with tarfile.open(tmp, "w:gz") as tar:
                tar.add(path, arcname=path.name)
            size = tmp.stat().st_size
            print(f"done ({_human_size(size)})")
            files.append(
                {
                    "name": path.name,
                    "path": str(tmp),
                    "size": size,
                    "type": "dir",
                    "temp": True,
                }
            )
        elif path.is_file():
            files.append(
                {
                    "name": path.name,
                    "path": str(path),
                    "size": path.stat().st_size,
                    "type": "file",
                    "temp": False,
                }
            )
        else:
            _die(f"Not a file or directory: {p}")

    if _is_daemon_running():
        _die("A staging session is already active. Run 'stage clear' first.")

    config = _load_config()
    port = int(config["stage"].get("port", DEFAULT_PORT))

    STAGE_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_FILE.write_text(json.dumps({"files": files}, indent=2))

    proc = subprocess.Popen(
        [sys.executable, "-m", "stage", "_serve", str(port), str(n)],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    PID_FILE.write_text(str(proc.pid))

    for _ in range(20):
        time.sleep(0.25)
        try:
            urllib_request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)
            break
        except Exception:
            pass
    else:
        if not _is_daemon_running():
            MANIFEST_FILE.unlink(missing_ok=True)
            PID_FILE.unlink(missing_ok=True)
            _die(f"Failed to start staging server. Is port {port} already in use?")

    total = sum(f["size"] for f in files)
    names = ", ".join(f["name"] for f in files)
    pull_s = "pull" if n == 1 else "pulls"
    print(f"Staged: {names} ({_human_size(total)}, {n} {pull_s} allowed)")
    print()

    ts_ip = _tailscale_ip()
    local_ips = [ip for ip in _local_ips() if ip != ts_ip]

    if ts_ip:
        print(f"  Via Tailscale:  stage pull")
    for ip in local_ips:
        print(f"  Direct:         stage pull {ip}:{port}")
    if not ts_ip and not local_ips:
        print(f"  stage pull <this-machine-ip>:{port}")


def _run_daemon(port, n):
    config = _load_config()
    token = config["stage"]["token"]
    manifest = json.loads(MANIFEST_FILE.read_text())
    entries = {f["name"]: f for f in manifest["files"]}
    pulls_remaining = [n]
    done_event = threading.Event()

    def _shutdown(sig, frame):
        done_event.set()

    signal.signal(signal.SIGTERM, _shutdown)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == "/health":
                self._respond(200, "text/plain", b"ok")
                return
            if not self._auth():
                return
            path = unquote(self.path.lstrip("/"))
            if path in ("manifest", "status"):
                body = json.dumps(
                    {
                        "files": [
                            {
                                "name": e["name"],
                                "type": e.get("type", "file"),
                                "size": e["size"],
                            }
                            for e in entries.values()
                        ],
                        "pulls_remaining": pulls_remaining[0],
                    }
                ).encode()
                self._respond(200, "application/json", body)
            elif path.startswith("files/"):
                name = path[6:]
                if name not in entries:
                    self.send_error(404)
                    return
                fp = Path(entries[name]["path"])
                if not fp.exists():
                    self.send_error(410)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(fp.stat().st_size))
                self.end_headers()
                try:
                    with open(fp, "rb") as f:
                        while chunk := f.read(65536):
                            self.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            else:
                self.send_error(404)

        def do_POST(self):
            if not self._auth():
                return
            if self.path == "/done":
                pulls_remaining[0] -= 1
                remaining = pulls_remaining[0]
                self._respond(
                    200,
                    "application/json",
                    json.dumps({"pulls_remaining": remaining}).encode(),
                )
                if remaining <= 0:
                    done_event.set()
            elif self.path == "/cancel":
                self._respond(200, "text/plain", b"cancelled")
                done_event.set()
            else:
                self.send_error(404)

        def _auth(self):
            if self.headers.get("Authorization") != f"Bearer {token}":
                self.send_error(401)
                return False
            return True

        def _respond(self, code, ctype, body):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    try:
        done_event.wait()
    finally:
        server.shutdown()
        for entry in entries.values():
            if entry.get("temp"):
                Path(entry["path"]).unlink(missing_ok=True)
        MANIFEST_FILE.unlink(missing_ok=True)
        PID_FILE.unlink(missing_ok=True)


def _find_session(host_arg, config, *, quiet=False):
    """Return (base_url, headers, manifest_data) or None."""
    token = config["stage"]["token"]
    port = int(config["stage"].get("port", DEFAULT_PORT))
    headers = {"Authorization": f"Bearer {token}"}

    if host_arg:
        base = _base_url(host_arg, port)
        try:
            req = urllib_request.Request(f"{base}/manifest", headers=headers)
            resp = urllib_request.urlopen(req, timeout=PROBE_TIMEOUT)
            return base, headers, json.loads(resp.read())
        except Exception:
            if not quiet:
                _die(f"No active session reachable at {host_arg}")
            return None

    peers = _tailscale_peers()
    if not peers:
        if not quiet:
            _die(
                "No Tailscale peers found.\n"
                "For a direct connection: stage pull <host>[:<port>]"
            )
        return None

    result = [None]
    lock = threading.Lock()

    def probe(ip):
        base = f"http://{ip}:{port}"
        try:
            req = urllib_request.Request(f"{base}/manifest", headers=headers)
            resp = urllib_request.urlopen(req, timeout=PROBE_TIMEOUT)
            data = json.loads(resp.read())
            with lock:
                if result[0] is None:
                    result[0] = (base, headers, data)
        except Exception:
            pass

    threads = [threading.Thread(target=probe, args=(ip,), daemon=True) for ip in peers]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=PROBE_TIMEOUT + 1)

    if result[0] is None:
        if not quiet:
            _die(
                "No active staging session found on any Tailscale peer.\n"
                "For a direct connection: stage pull <host>[:<port>]"
            )
        return None
    return result[0]


def _pull(host_arg=None):
    config = _load_config()
    session = _find_session(host_arg, config)
    if session is None:
        return
    base, headers, data = session

    raw = data["files"]
    # Support both old format (list of strings) and new format (list of dicts)
    file_entries = [
        f if isinstance(f, dict) else {"name": f, "type": "file"} for f in raw
    ]
    if not file_entries:
        print("Nothing staged.")
        _post(f"{base}/done", headers)
        return

    cwd = Path.cwd()
    success = True
    for entry in file_entries:
        name = entry["name"]
        entry_type = entry.get("type", "file")
        encoded = quote(name, safe="")
        try:
            req = urllib_request.Request(f"{base}/files/{encoded}", headers=headers)
            resp = urllib_request.urlopen(req, timeout=300)
            if entry_type == "dir":
                with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
                    tmp_path = Path(tmp.name)
                try:
                    _download(resp, tmp_path, name, suffix="")
                    target = _unique_path(cwd / name)
                    _extract_archive(tmp_path, target)
                    rename = f" -> {target.name}/" if target.name != name else ""
                    print(f"  extracted {name}/{rename}")
                finally:
                    tmp_path.unlink(missing_ok=True)
            else:
                dest = _unique_path(cwd / name)
                _download(resp, dest, name)
        except (URLError, OSError) as e:
            print(f"\n{name}: failed: {e}", file=sys.stderr)
            success = False

    if success:
        resp = _post(f"{base}/done", headers)
        remaining = json.loads(resp.read()).get("pulls_remaining", 0)
        n = len(file_entries)
        suffix = (
            f" ({remaining} pull{'s' if remaining != 1 else ''} remaining)"
            if remaining > 0
            else " Session closed."
        )
        print(f"Pulled {n} item{'s' if n != 1 else ''}.{suffix}")
    else:
        print("Some items failed. Session remains open for retry.", file=sys.stderr)
        sys.exit(1)


def _status(host_arg=None):
    config = _load_config()
    session = _find_session(host_arg, config, quiet=True)
    if session is None:
        print("No active staging session found.")
        return
    _, _, data = session
    pulls = data.get("pulls_remaining", "?")
    entries = data["files"]
    print(f"Active: {len(entries)} item(s), {pulls} pull(s) remaining")
    for e in entries:
        if isinstance(e, dict):
            indicator = "/" if e.get("type") == "dir" else ""
            print(f"  {e['name']}{indicator}  ({_human_size(e['size'])})")
        else:
            print(f"  {e}")


def _clear():
    if not _is_daemon_running():
        print("No active staging session.")
        return
    pid = int(PID_FILE.read_text().strip())
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    PID_FILE.unlink(missing_ok=True)
    MANIFEST_FILE.unlink(missing_ok=True)
    print("Staging session cleared.")


def _setup(extra_args=None):
    provided_token = None
    provided_port = None
    provided_repo = None
    args = list(extra_args or [])
    i = 0
    while i < len(args):
        if args[i] == "--token" and i + 1 < len(args):
            provided_token = args[i + 1]
            i += 2
        elif args[i] == "--port" and i + 1 < len(args):
            try:
                provided_port = int(args[i + 1])
            except ValueError:
                _die(f"Invalid port: {args[i + 1]}")
            i += 2
        elif args[i] == "--repo" and i + 1 < len(args):
            provided_repo = args[i + 1]
            i += 2
        else:
            _die(f"Unknown argument: {args[i]}")

    non_interactive = provided_token is not None and provided_port is not None

    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)

    existing_cfg = {}
    if CONFIG_PATH.exists():
        if not non_interactive:
            print(f"Config exists at {CONFIG_PATH}")
            if input("Reconfigure? [y/N] ").strip().lower() != "y":
                return
        with open(CONFIG_PATH, "rb") as f:
            existing_cfg = tomllib.load(f).get("stage", {})

    if provided_port is not None:
        port = provided_port
    else:
        default_port = existing_cfg.get("port", DEFAULT_PORT)
        port_input = input(f"Port [{default_port}]: ").strip()
        port = int(port_input) if port_input else default_port

    if provided_token is not None:
        token = provided_token
    else:
        existing_token = existing_cfg.get("token", "")
        if existing_token:
            print(f"Existing token: {existing_token}")
            if input("Keep existing token? [Y/n] ").strip().lower() == "n":
                existing_token = ""
        if not existing_token:
            existing_token = secrets.token_hex(16)
            print(f"Generated token: {existing_token}")
            print("Copy this token when configuring other machines.")
        token = existing_token

    if provided_repo is not None:
        repo = provided_repo
    elif not non_interactive:
        existing_repo = existing_cfg.get("repo", "")
        prompt = (
            f"Repo URL for update checks [{existing_repo}]: "
            if existing_repo
            else "Repo URL for update checks (leave blank to skip): "
        )
        repo_input = input(prompt).strip()
        repo = repo_input or existing_repo
    else:
        repo = existing_cfg.get("repo", "")

    repo_line = f'\nrepo = "{repo}"' if repo else ""
    CONFIG_PATH.write_text(f'[stage]\nport = {port}\ntoken = "{token}"{repo_line}\n')
    CONFIG_PATH.chmod(0o600)
    print(f"Config saved to {CONFIG_PATH}")

    if not non_interactive:
        repo_flag = f" --repo {repo}" if repo else ""
        print(f"\nTo configure another machine:")
        print(f"  stage setup --token {token} --port {port}{repo_flag}")


def _update():
    result = subprocess.run(["uv", "tool", "upgrade", "stage"])
    if result.returncode != 0:
        _die("Update failed. Is 'uv' in your PATH?")
    # Record installed SHA so the update notice clears
    try:
        with open(CONFIG_PATH, "rb") as f:
            repo = tomllib.load(f).get("stage", {}).get("repo")
        if repo:
            sha = _remote_sha(repo)
            if sha:
                state = _load_update_state()
                state.update(
                    installed_sha=sha, latest_sha=sha, last_checked=time.time()
                )
                _save_update_state(state)
    except Exception:
        pass


def _maybe_check_updates():
    if not CONFIG_PATH.exists():
        return
    try:
        with open(CONFIG_PATH, "rb") as f:
            repo = tomllib.load(f).get("stage", {}).get("repo")
        if not repo:
            return
        state = _load_update_state()
        if (
            state.get("latest_sha")
            and state.get("installed_sha")
            and state["latest_sha"] != state["installed_sha"]
        ):
            print(
                "A new version of stage is available. Run 'stage update'.",
                file=sys.stderr,
            )
        if time.time() - state.get("last_checked", 0) > UPDATE_INTERVAL:
            subprocess.Popen(
                [sys.executable, "-m", "stage", "_check", repo],
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except Exception:
        pass


def _do_update_check(repo):
    sha = _remote_sha(repo)
    if sha is None:
        return
    state = _load_update_state()
    state["latest_sha"] = sha
    state["last_checked"] = time.time()
    if "installed_sha" not in state:
        state["installed_sha"] = sha  # first check: baseline, no notice yet
    _save_update_state(state)


def _remote_sha(repo):
    try:
        r = subprocess.run(
            ["git", "ls-remote", repo, "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode == 0 and r.stdout:
            return r.stdout.split()[0]
    except (FileNotFoundError, subprocess.TimeoutExpired, IndexError):
        pass
    return None


def _load_update_state():
    try:
        if UPDATE_FILE.exists():
            return json.loads(UPDATE_FILE.read_text())
    except Exception:
        pass
    return {}


def _save_update_state(state):
    STAGE_DIR.mkdir(parents=True, exist_ok=True)
    UPDATE_FILE.write_text(json.dumps(state))


def _base_url(host_str, default_port):
    if ":" in host_str:
        h, p = host_str.rsplit(":", 1)
        return f"http://{h}:{p}"
    return f"http://{host_str}:{default_port}"


def _download(resp, dest, name, suffix=None):
    total = int(resp.headers.get("Content-Length", 0))
    downloaded = 0
    start = time.monotonic()
    tty = sys.stdout.isatty()

    with open(dest, "wb") as f:
        while chunk := resp.read(65536):
            f.write(chunk)
            downloaded += len(chunk)
            if tty:
                elapsed = max(time.monotonic() - start, 1e-9)
                _render_bar(name, downloaded, total, downloaded / elapsed, end="")

    elapsed = max(time.monotonic() - start, 1e-9)
    speed = downloaded / elapsed
    if suffix is None:
        suffix = f" -> {dest.name}" if dest.name != name else ""

    if tty:
        _render_bar(name, downloaded, total or downloaded, speed, suffix=suffix, end="\n")
    else:
        print(f"{name}: {_human_size(downloaded)} at {_human_size(speed)}/s{suffix}")


def _extract_archive(archive_path, target):
    """Extract a tar.gz so its root directory lands at target."""
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(tmp, filter="data")
        items = list(Path(tmp).iterdir())
        if len(items) == 1 and items[0].is_dir():
            shutil.move(str(items[0]), str(target))
        else:
            target.mkdir(parents=True, exist_ok=True)
            for item in items:
                shutil.move(str(item), str(target / item.name))


def _render_bar(name, done, total, speed, suffix="", end=""):
    BAR = 22
    if total:
        pct = min(done / total, 1.0)
        filled = int(BAR * pct)
        arrow = "" if filled >= BAR else ">"
        bar = "=" * filled + arrow + " " * (BAR - filled - len(arrow))
        line = (
            f"\r{name}  [{bar}]  {pct:3.0%}"
            f"  {_human_size(done)}/{_human_size(total)}"
            f"  {_human_size(speed)}/s{suffix}"
        )
    else:
        line = f"\r{name}  {_human_size(done)}  {_human_size(speed)}/s{suffix}"
    print(line, end=end, flush=True)


def _post(url, headers):
    req = urllib_request.Request(url, method="POST", headers=headers, data=b"")
    return urllib_request.urlopen(req, timeout=10)


def _tailscale_ip():
    try:
        r = subprocess.run(
            ["tailscale", "ip", "-4"], capture_output=True, text=True, timeout=3
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _tailscale_peers():
    try:
        r = subprocess.run(
            ["tailscale", "status", "--json"], capture_output=True, text=True, timeout=5
        )
        if r.returncode != 0:
            return []
        data = json.loads(r.stdout)
        ips = []
        for peer in data.get("Peer", {}).values():
            if not peer.get("Online", False):
                continue
            for ip in peer.get("TailscaleIPs", []):
                if ":" not in ip:  # IPv4 only
                    ips.append(ip)
                    break
        return ips
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []


def _local_ips():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return [s.getsockname()[0]]
    except Exception:
        return []


def _load_config():
    if not CONFIG_PATH.exists():
        _die("No config found. Run 'stage setup' first.")
    with open(CONFIG_PATH, "rb") as f:
        return tomllib.load(f)


def _is_daemon_running():
    if not PID_FILE.exists():
        return False
    try:
        pid = int(PID_FILE.read_text().strip())
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, OSError, ValueError):
        return False


def _unique_path(path):
    if not path.exists():
        return path
    stem, suffix, parent = path.stem, path.suffix, path.parent
    for i in range(1, 1000):
        candidate = parent / f"{stem}_{i}{suffix}"
        if not candidate.exists():
            return candidate
    return path


def _human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _die(msg):
    print(f"stage: {msg}", file=sys.stderr)
    sys.exit(1)


def _usage():
    print("Usage:")
    print("  stage [-n N] <file> [files...]    Stage files (default: 1 pull allowed)")
    print("  stage pull [<host>[:<port>]]       Pull staged files to current directory")
    print("  stage status [<host>[:<port>]]     Show active staging session info")
    print("  stage clear                        Cancel active staging session")
    print("  stage update                       Upgrade to the latest version")
    print("  stage setup                        Configure port, token, and repo")
