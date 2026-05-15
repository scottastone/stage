import json
import os
import re
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import request as urllib_request
from urllib.error import URLError
from urllib.parse import quote, unquote

import tomllib
from rich.console import Console
from rich.panel import Panel
from rich.status import Status
from rich.table import Table
from tqdm import tqdm

STAGE_DIR = Path.home() / ".stage"
CONFIG_PATH = Path.home() / ".config" / "stage" / "config.toml"
PID_FILE = STAGE_DIR / "daemon.pid"
MANIFEST_FILE = STAGE_DIR / "manifest.json"
UPDATE_FILE = STAGE_DIR / "update.json"
DEFAULT_PORT = 47200
PROBE_TIMEOUT = 3
UPDATE_INTERVAL = 86400


class StageApp:
    def __init__(self):
        self.console = Console()
        self.err_console = Console(stderr=True)
        self._config_cache = None
        self._print_lock = threading.Lock()

    @property
    def config(self):
        if self._config_cache is None:
            if not CONFIG_PATH.exists():
                self.die("No config found. Run 'stage setup' first.")
            with open(CONFIG_PATH, "rb") as f:
                self._config_cache = tomllib.load(f)
        return self._config_cache

    def die(self, msg):
        self.err_console.print(f"[red]stage: {msg}[/red]")
        sys.exit(1)

    def run(self, args=None):
        args = sys.argv[1:] if args is None else args
        if not args or args[0] in ("-h", "--help"):
            self._usage()
            return

        cmd = args[0]

        if cmd == "_serve":
            self._run_daemon(int(args[1]), int(args[2]))
            return
        if cmd == "_check":
            if len(args) > 1:
                self._do_update_check(args[1])
            return

        self._maybe_check_updates()

        if cmd == "pull":
            self.pull(args[1] if len(args) > 1 else None)
        elif cmd == "status":
            self.status(args[1] if len(args) > 1 else None)
        elif cmd == "clear":
            self.clear()
        elif cmd == "update":
            self.update()
        elif cmd == "setup":
            self.setup(args[1:])
        elif cmd == "provision":
            self.provision()
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
                        self.die(f"Invalid value for -n: {args[i + 1]}")
                    i += 2
                else:
                    paths.append(args[i])
                    i += 1
            if not paths:
                self._usage()
                return
            self.stage(paths, n)

    # -------------------------------------------------------------------------
    # Staging
    # -------------------------------------------------------------------------

    def stage(self, paths, n=1):
        files = []
        for p in paths:
            path = Path(p).resolve()
            if not path.exists():
                self.die(f"Not found: {p}")
            if path.is_dir():
                with Status(
                    f"Sizing [bold]{path.name}/[/bold]...", console=self.console
                ):
                    size, file_count = _dir_stats(path)
                self.console.print(
                    f"Staged [bold]{path.name}/[/bold]"
                    f" ([cyan]{_human_size(size)}[/cyan], {file_count} files)"
                )
                files.append(
                    {
                        "name": path.name,
                        "path": str(path),
                        "size": size,
                        "file_count": file_count,
                        "type": "dir",
                    }
                )
            elif path.is_file():
                files.append(
                    {
                        "name": path.name,
                        "path": str(path),
                        "size": path.stat().st_size,
                        "type": "file",
                    }
                )
            else:
                self.die(f"Not a file or directory: {p}")

        if _is_daemon_running():
            self.die("A staging session is already active. Run 'stage clear' first.")

        port = int(self.config["stage"].get("port", DEFAULT_PORT))

        STAGE_DIR.mkdir(parents=True, exist_ok=True)
        MANIFEST_FILE.write_text(json.dumps({"files": files}, indent=2))

        proc = subprocess.Popen(
            [sys.executable, "-m", "stage", "_serve", str(port), str(n)],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        PID_FILE.write_text(str(proc.pid))

        try:
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
                    self.die(
                        f"Failed to start staging server. Is port {port} already in use?"
                    )

            pub_ip = [None]
            if self.config["stage"].get("public_ip_check"):
                t = threading.Thread(
                    target=lambda: pub_ip.__setitem__(0, _public_ip()), daemon=True
                )
                t.start()
                t.join(timeout=4)

            total = sum(f["size"] for f in files)
            names = ", ".join(
                f["name"] + ("/" if f.get("type") == "dir" else "") for f in files
            )
            pull_s = "pull" if n == 1 else "pulls"
            self.console.print(
                f"\nStaged: [bold]{names}[/bold] ([cyan]{_human_size(total)}[/cyan], {n} {pull_s} allowed)\n"
            )

            ts_ip, _peers = _tailscale_info()
            local_ips = [ip for ip in _local_ips() if ip != ts_ip]

            if ts_ip:
                self.console.print("  Via Tailscale:  [bold]stage pull[/bold]")
            for ip in local_ips:
                self.console.print(f"  Direct:         [bold]stage pull {ip}:{port}[/bold]")
            if pub_ip[0]:
                self.console.print(
                    f"  Public IP:      [bold]stage pull {pub_ip[0]}:{port}[/bold]"
                )
            if not ts_ip and not local_ips and not pub_ip[0]:
                self.console.print(f"  [bold]stage pull <this-machine-ip>:{port}[/bold]")

        except KeyboardInterrupt:
            try:
                proc.terminate()
            except Exception:
                pass
            MANIFEST_FILE.unlink(missing_ok=True)
            PID_FILE.unlink(missing_ok=True)
            print()
            sys.exit(130)

    # -------------------------------------------------------------------------
    # Daemon
    # -------------------------------------------------------------------------

    def _run_daemon(self, port, n):
        token = self.config["stage"]["token"]
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
                    def _entry_meta(e):
                        m = {"name": e["name"], "type": e.get("type", "file"), "size": e["size"]}
                        if "file_count" in e:
                            m["file_count"] = e["file_count"]
                        return m
                    body = json.dumps(
                        {
                            "files": [_entry_meta(e) for e in entries.values()],
                            "pulls_remaining": pulls_remaining[0],
                        }
                    ).encode()
                    self._respond(200, "application/json", body)
                elif path.startswith("files/"):
                    name = path[6:]
                    if name not in entries:
                        self.send_error(404)
                        return
                    entry = entries[name]
                    fp = Path(entry["path"])
                    if not fp.exists():
                        self.send_error(410)
                        return
                    if entry.get("type") == "dir":
                        # Stream directory as uncompressed tar on demand. Gzip saves
                        # bandwidth but costs more CPU than it saves on fast LAN/Tailscale
                        # links, especially for directories with many small files.
                        # Connection: close is required because we don't know Content-Length.
                        self.send_response(200)
                        self.send_header("Content-Type", "application/x-tar")
                        self.send_header("Connection", "close")
                        self.close_connection = True
                        self.end_headers()
                        try:
                            with tarfile.open(fileobj=self.wfile, mode="w|") as tar:
                                tar.add(fp, arcname=fp.name)
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                    else:
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
            MANIFEST_FILE.unlink(missing_ok=True)
            PID_FILE.unlink(missing_ok=True)

    # -------------------------------------------------------------------------
    # Session discovery
    # -------------------------------------------------------------------------

    def _find_session(self, host_arg, *, quiet=False):
        """Return (base_url, headers, manifest_data) or None."""
        token = self.config["stage"]["token"]
        port = int(self.config["stage"].get("port", DEFAULT_PORT))
        headers = {"Authorization": f"Bearer {token}"}

        if host_arg:
            base = _base_url(host_arg, port)
            try:
                req = urllib_request.Request(f"{base}/manifest", headers=headers)
                resp = urllib_request.urlopen(req, timeout=PROBE_TIMEOUT)
                return base, headers, json.loads(resp.read())
            except Exception:
                if not quiet:
                    self.die(f"No active session reachable at {host_arg}")
                return None

        _local_ip, peers = _tailscale_info()
        if not peers:
            if not quiet:
                self.die(
                    "No Tailscale peers found.\n"
                    "For a direct connection: stage pull <host>[:<port>]"
                )
            return None

        result = [None]
        lock = threading.Lock()
        found = threading.Event()

        def probe(ip):
            if found.is_set():
                return
            base = f"http://{ip}:{port}"
            try:
                req = urllib_request.Request(f"{base}/manifest", headers=headers)
                resp = urllib_request.urlopen(req, timeout=PROBE_TIMEOUT)
                data = json.loads(resp.read())
                with lock:
                    if result[0] is None:
                        result[0] = (base, headers, data)
                        found.set()
            except Exception:
                pass

        threads = [
            threading.Thread(target=probe, args=(ip,), daemon=True) for ip in peers
        ]
        for t in threads:
            t.start()
        found.wait(timeout=PROBE_TIMEOUT + 1)

        if result[0] is None:
            if not quiet:
                self.die(
                    "No active staging session found on any Tailscale peer.\n"
                    "For a direct connection: stage pull <host>[:<port>]"
                )
            return None
        return result[0]

    # -------------------------------------------------------------------------
    # Pull
    # -------------------------------------------------------------------------

    def pull(self, host_arg=None):
        session = self._find_session(host_arg)
        if session is None:
            return
        base, headers, data = session

        raw = data["files"]
        file_entries = [
            f if isinstance(f, dict) else {"name": f, "type": "file"} for f in raw
        ]
        if not file_entries:
            self.console.print("Nothing staged.")
            _post(f"{base}/done", headers)
            return

        from_host = base.removeprefix("http://")
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column()
        table.add_column(justify="right", style="cyan")
        for entry in file_entries:
            indicator = "/" if entry.get("type") == "dir" else ""
            size_str = _human_size(entry["size"]) if "size" in entry else ""
            table.add_row(f"{entry['name']}{indicator}", size_str)
        self.console.print(f"From [bold]{from_host}[/bold]:")
        self.console.print(table)

        cwd = Path.cwd()

        # Pre-assign destination paths sequentially to avoid name-collision races
        # between concurrent downloads.
        assignments = [
            (entry, _unique_path(cwd / entry["name"])) for entry in file_entries
        ]

        parallel = len(assignments) > 1
        errors = []

        def fetch(entry, dest):
            name = entry["name"]
            entry_type = entry.get("type", "file")
            encoded = quote(name, safe="")
            show_progress = not parallel
            try:
                req = urllib_request.Request(f"{base}/files/{encoded}", headers=headers)
                resp = urllib_request.urlopen(req, timeout=300)
                if entry_type == "dir":
                    total_bytes = entry.get("size") or None
                    total_files = entry.get("file_count")
                    files_done = 0
                    with tqdm(
                        total=total_bytes,
                        unit="B",
                        unit_scale=True,
                        unit_divisor=1024,
                        desc=name,
                        ncols=80,
                        leave=False,
                        file=sys.stderr,
                        disable=not show_progress,
                    ) as bar:
                        class _Reader:
                            def read(self, n=-1):
                                chunk = resp.read(n)
                                if chunk:
                                    bar.update(len(chunk))
                                return chunk

                        with tempfile.TemporaryDirectory() as tmp_dir:
                            with tarfile.open(fileobj=_Reader(), mode="r|") as tar:
                                for member in tar:
                                    tar.extract(member, tmp_dir, filter=_tar_filter)
                                    if member.isfile():
                                        files_done += 1
                                        if total_files and show_progress:
                                            bar.set_postfix_str(
                                                f"{files_done}/{total_files} files",
                                                refresh=False,
                                            )
                            items = list(Path(tmp_dir).iterdir())
                            if len(items) == 1 and items[0].is_dir():
                                shutil.move(str(items[0]), str(dest))
                            else:
                                dest.mkdir(parents=True, exist_ok=True)
                                for item in items:
                                    shutil.move(str(item), str(dest / item.name))

                    rename = f" -> {dest.name}/" if dest.name != name else ""
                    with self._print_lock:
                        self.console.print(f"  extracted [bold]{name}/[/bold]{rename}")
                else:
                    self._download(resp, dest, name, show_progress=show_progress)
                return None
            except (URLError, OSError, tarfile.TarError) as e:
                return (name, e)

        n_workers = min(4, len(assignments))
        executor = ThreadPoolExecutor(max_workers=n_workers)
        futures = {executor.submit(fetch, entry, dest): entry for entry, dest in assignments}
        try:
            for fut in as_completed(futures):
                err = fut.result()
                if err:
                    name, exc = err
                    with self._print_lock:
                        self.err_console.print(f"\n[red]{name}: failed: {exc}[/red]")
                    errors.append(name)
        except KeyboardInterrupt:
            for fut in futures:
                fut.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
            try:
                _post(f"{base}/cancel", headers)
            except Exception:
                pass
            self.console.print("\n[yellow]Pull interrupted.[/yellow]")
            os._exit(130)
        else:
            executor.shutdown(wait=True)

        if not errors:
            resp = _post(f"{base}/done", headers)
            remaining = json.loads(resp.read()).get("pulls_remaining", 0)
            n = len(file_entries)
            suffix = (
                f" ([dim]{remaining} pull{'s' if remaining != 1 else ''} remaining[/dim])"
                if remaining > 0
                else " [dim]Session closed.[/dim]"
            )
            self.console.print(
                f"\nPulled [bold]{n}[/bold] item{'s' if n != 1 else ''}.{suffix}"
            )
        else:
            self.err_console.print(
                "[red]Some items failed. Session remains open for retry.[/red]"
            )
            sys.exit(1)

    def _download(self, resp, dest, name, suffix=None, show_progress=True):
        total = int(resp.headers.get("Content-Length", 0)) or None
        downloaded = 0
        start = time.monotonic()

        with tqdm(
            total=total,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            desc=name,
            ncols=80,
            leave=False,
            file=sys.stderr,
            disable=not show_progress,
        ) as bar:
            with open(dest, "wb") as f:
                while chunk := resp.read(65536):
                    f.write(chunk)
                    bar.update(len(chunk))
                    downloaded += len(chunk)

        elapsed = max(time.monotonic() - start, 1e-9)
        speed = downloaded / elapsed
        if suffix is None:
            suffix = f" -> {dest.name}" if dest.name != name else ""
        with self._print_lock:
            self.console.print(
                f"  {name}{suffix}  [cyan]{_human_size(downloaded)}[/cyan]"
                f" at [cyan]{_human_size(speed)}/s[/cyan]"
            )

    # -------------------------------------------------------------------------
    # Status / Clear
    # -------------------------------------------------------------------------

    def status(self, host_arg=None):
        session = self._find_session(host_arg, quiet=True)
        if session is None:
            self.console.print("No active staging session found.")
            return
        _, _, data = session
        pulls = data.get("pulls_remaining", "?")
        entries = data["files"]
        self.console.print(
            f"[bold]Active:[/bold] {len(entries)} item(s), {pulls} pull(s) remaining"
        )
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column()
        table.add_column(justify="right", style="cyan")
        for e in entries:
            if isinstance(e, dict):
                indicator = "/" if e.get("type") == "dir" else ""
                table.add_row(f"{e['name']}{indicator}", _human_size(e["size"]))
            else:
                table.add_row(str(e), "")
        self.console.print(table)

    def clear(self):
        if not _is_daemon_running():
            self.console.print("No active staging session.")
            return
        pid = int(PID_FILE.read_text().strip())
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        PID_FILE.unlink(missing_ok=True)
        MANIFEST_FILE.unlink(missing_ok=True)
        self.console.print("Staging session cleared.")

    # -------------------------------------------------------------------------
    # Setup / Update / Provision
    # -------------------------------------------------------------------------

    def setup(self, extra_args=None):
        provided_token = None
        provided_port = None
        provided_repo = None
        provided_public_ip = None
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
                    self.die(f"Invalid port: {args[i + 1]}")
                i += 2
            elif args[i] == "--repo" and i + 1 < len(args):
                provided_repo = args[i + 1]
                i += 2
            elif args[i] == "--public-ip":
                provided_public_ip = True
                i += 1
            else:
                self.die(f"Unknown argument: {args[i]}")

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

        if provided_public_ip is not None:
            public_ip_check = provided_public_ip
        elif not non_interactive:
            current = existing_cfg.get("public_ip_check", False)
            default = "Y/n" if current else "y/N"
            ans = (
                input(f"Show public IP for internet connections? [{default}]: ")
                .strip()
                .lower()
            )
            public_ip_check = (ans == "y") if ans else current
        else:
            public_ip_check = existing_cfg.get("public_ip_check", False)

        repo_line = f'\nrepo = "{repo}"' if repo else ""
        pub_line = "\npublic_ip_check = true" if public_ip_check else ""
        CONFIG_PATH.write_text(
            f'[stage]\nport = {port}\ntoken = "{token}"{repo_line}{pub_line}\n'
        )
        CONFIG_PATH.chmod(0o600)
        print(f"Config saved to {CONFIG_PATH}")

        if not non_interactive:
            repo_flag = f" --repo {repo}" if repo else ""
            pub_flag = " --public-ip" if public_ip_check else ""
            print("\nTo configure another machine:")
            print(f"  stage setup --token {token} --port {port}{repo_flag}{pub_flag}")

    def update(self):
        state = _load_update_state()
        old_sha = state.get("installed_sha")

        self.console.print("Upgrading [bold]stage[/bold]...")
        result = subprocess.run(["uv", "tool", "upgrade", "stage"])
        if result.returncode != 0:
            self.die("Update failed. Is 'uv' in your PATH?")

        try:
            with open(CONFIG_PATH, "rb") as f:
                repo = tomllib.load(f).get("stage", {}).get("repo")
            if repo:
                new_sha = _remote_sha(repo)
                if new_sha:
                    state = _load_update_state()
                    state.update(
                        installed_sha=new_sha,
                        latest_sha=new_sha,
                        last_checked=time.time(),
                    )
                    _save_update_state(state)
                    if old_sha and old_sha != new_sha:
                        changes = _github_changelog(repo, old_sha, new_sha)
                        if changes:
                            self.console.print(
                                Panel(
                                    changes,
                                    title="[bold green]What's new[/bold green]",
                                    border_style="green",
                                )
                            )
        except Exception:
            pass

    def provision(self):
        cfg = self.config["stage"]
        token = cfg["token"]
        port = cfg.get("port", DEFAULT_PORT)
        repo = cfg.get("repo", "")
        public_ip = cfg.get("public_ip_check", False)

        if not repo:
            self.die("No repo configured. Run 'stage setup' and set a repo URL first.")

        url = _install_url(repo)
        pub_flag = " --public-ip" if public_ip else ""
        cmd = (
            f"uv tool install {url} && "
            f"stage setup --token {token} --port {port} --repo {repo}{pub_flag}"
        )
        print(cmd)

    # -------------------------------------------------------------------------
    # Update checks
    # -------------------------------------------------------------------------

    def _maybe_check_updates(self):
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
                self.err_console.print(
                    "[yellow]A new version of stage is available. Run 'stage update'.[/yellow]"
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

    def _do_update_check(self, repo):
        sha = _remote_sha(repo)
        if sha is None:
            return
        state = _load_update_state()
        state["latest_sha"] = sha
        state["last_checked"] = time.time()
        if "installed_sha" not in state:
            state["installed_sha"] = sha
        _save_update_state(state)

    # -------------------------------------------------------------------------
    # Help
    # -------------------------------------------------------------------------

    def _usage(self):
        self.console.print("Usage:")
        self.console.print(
            "  stage [-n N] <file> [files...]     Stage files (default: 1 pull allowed)"
        )
        self.console.print(
            "  stage pull [<host>[:<port>]]       Pull staged files to current directory"
        )
        self.console.print(
            "  stage status [<host>[:<port>]]     Show active staging session info"
        )
        self.console.print(
            "  stage clear                        Cancel active staging session"
        )
        self.console.print(
            "  stage update                       Upgrade to the latest version"
        )
        self.console.print(
            "  stage provision                    Print one-liner to configure a new machine"
        )
        self.console.print(
            "  stage setup                        Configure port, token, and repo"
        )


# =============================================================================
# Module-level pure helpers (no app state)
# =============================================================================


def _dir_stats(path: Path) -> tuple[int, int]:
    """Return (total_bytes, file_count) via stat-only walk (no file reads)."""
    size = count = 0
    for f in path.rglob("*"):
        if f.is_file():
            size += f.stat().st_size
            count += 1
    return size, count


def _tailscale_info():
    """Return (local_ipv4, peer_ipv4s) from a single tailscale status --json call."""
    try:
        r = subprocess.run(
            ["tailscale", "status", "--json"], capture_output=True, text=True, timeout=5
        )
        if r.returncode != 0:
            return None, []
        data = json.loads(r.stdout)
        local_ip = None
        for ip in data.get("Self", {}).get("TailscaleIPs", []):
            if ":" not in ip:
                local_ip = ip
                break
        peers = []
        for peer in data.get("Peer", {}).values():
            if not peer.get("Online", False):
                continue
            for ip in peer.get("TailscaleIPs", []):
                if ":" not in ip:
                    peers.append(ip)
                    break
        return local_ip, peers
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None, []


def _tar_filter(member, dest_path):
    # Use data_filter for path traversal / special file protection, but skip
    # symlinks that point to absolute or out-of-destination paths -- these are
    # system-specific (e.g. .venv/bin/python -> /usr/bin/python3.14) and would
    # be broken on a different machine anyway.
    try:
        return tarfile.data_filter(member, dest_path)
    except (tarfile.AbsoluteLinkError, tarfile.LinkOutsideDestinationError):
        return None



def _post(url, headers):
    req = urllib_request.Request(url, method="POST", headers=headers, data=b"")
    return urllib_request.urlopen(req, timeout=10)


def _local_ips():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return [s.getsockname()[0]]
    except Exception:
        return []


def _public_ip():
    try:
        resp = urllib_request.urlopen("https://api4.ipify.org", timeout=3)
        return resp.read().decode().strip()
    except Exception:
        return None


def _is_daemon_running():
    if not PID_FILE.exists():
        return False
    try:
        pid = int(PID_FILE.read_text().strip())
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, OSError, ValueError):
        return False


def _base_url(host_str, default_port):
    if ":" in host_str:
        h, p = host_str.rsplit(":", 1)
        return f"http://{h}:{p}"
    return f"http://{host_str}:{default_port}"


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


def _install_url(repo_url):
    m = re.match(r"git@github\.com:([^/]+)/([^.]+?)(?:\.git)?$", repo_url)
    if m:
        return f"git+ssh://git@github.com/{m.group(1)}/{m.group(2)}"
    return repo_url


def _github_api_base(repo_url):
    for pat in (
        r"git@github\.com:([^/]+)/([^.]+?)(?:\.git)?$",
        r"git\+ssh://git@github\.com/([^/]+)/([^.]+?)(?:\.git)?$",
        r"https://github\.com/([^/]+)/([^.]+?)(?:\.git)?$",
    ):
        m = re.match(pat, repo_url)
        if m:
            return f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}"
    return None


def _github_changelog(repo_url, old_sha, new_sha):
    api_base = _github_api_base(repo_url)
    if not api_base:
        return None
    try:
        url = f"{api_base}/compare/{old_sha[:7]}...{new_sha[:7]}"
        req = urllib_request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "stage-cli",
            },
        )
        resp = urllib_request.urlopen(req, timeout=5)
        data = json.loads(resp.read())
        commits = data.get("commits", [])
        if not commits:
            return None
        lines = []
        for c in reversed(commits):
            msg = c["commit"]["message"].splitlines()[0]
            sha = c["sha"][:7]
            lines.append(f"[dim]{sha}[/dim] {msg}")
        return "\n".join(lines)
    except Exception:
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


def main():
    StageApp().run()
