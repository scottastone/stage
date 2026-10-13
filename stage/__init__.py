import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from compression import zstd
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
PEERS_FILE = STAGE_DIR / "peers.json"
UPNP_FILE = STAGE_DIR / "upnp.json"
DEFAULT_PORT = 47200
PROBE_TIMEOUT = 3
UPDATE_INTERVAL = 86400

# I/O chunk size for file streaming and tar stream buffering.
CHUNK_SIZE = 1 << 20
# Single files at least this large are fetched as parallel byte ranges.
RANGED_MIN_SIZE = 64 << 20
RANGED_PART_SIZE = 32 << 20
RANGED_MAX_PARTS = 4

_ENABLE_PUBLIC_HINT = "enable them with 'stage setup' (or --allow-public)"

_PSK_IDENTITY = "stage"
_ZSTD_OPTIONS = {
    zstd.CompressionParameter.compression_level: 3,
    zstd.CompressionParameter.nb_workers: min(
        os.cpu_count() or 1, zstd.CompressionParameter.nb_workers.bounds()[1]
    ),
}

# Networks considered "private" for the purpose of default access control.
# Connections from outside these ranges are rejected unless --public is given.
# Covers: loopback, RFC 1918, CGNAT/Tailscale (100.64.0.0/10, RFC 6598),
# link-local, and IPv6 equivalents.
_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class StageApp:
    def __init__(self):
        self.console = Console()
        self.err_console = Console(stderr=True)
        self._config_cache = None
        self._ssl_ctx_cache = None
        self._print_lock = threading.Lock()

    @property
    def config(self):
        if self._config_cache is None:
            if not CONFIG_PATH.exists():
                self.die("No config found. Run 'stage setup' first.")
            with open(CONFIG_PATH, "rb") as f:
                self._config_cache = tomllib.load(f)
        return self._config_cache

    @property
    def allow_public(self) -> bool:
        """Master switch for anything that touches public addresses. Off unless
        explicitly enabled in setup."""
        return self.config["stage"].get("allow_public", False) is True

    @property
    def ssl_ctx(self):
        if self._ssl_ctx_cache is None:
            if not ssl.HAS_PSK:
                self.die(
                    "This Python's ssl module lacks TLS-PSK support,"
                    " which stage needs for encrypted transfers."
                )
            self._ssl_ctx_cache = _client_ssl_ctx(self.config["stage"]["token"])
        return self._ssl_ctx_cache

    def _open(self, url, headers=None, data=None, method=None, timeout=10):
        req = urllib_request.Request(
            url, headers=headers or {}, data=data, method=method
        )
        return urllib_request.urlopen(req, timeout=timeout, context=self.ssl_ctx)

    def _post(self, url, headers):
        return self._open(url, headers=headers, data=b"", method="POST")

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
            public = len(args) > 3 and args[3] == "1"
            self._run_daemon(int(args[1]), int(args[2]), public=public)
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
        elif cmd == "peers":
            self.peers(args[1:])
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
            public = False
            compress = False
            quiet = False
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
                elif args[i] == "--public":
                    public = True
                    i += 1
                elif args[i] in ("-z", "--compress"):
                    compress = True
                    i += 1
                elif args[i] in ("-q", "--quiet"):
                    quiet = True
                    i += 1
                else:
                    paths.append(args[i])
                    i += 1
            if not paths:
                self._usage()
                return
            self.stage(paths, n, public=public, compress=compress, quiet=quiet)

    # -------------------------------------------------------------------------
    # Staging
    # -------------------------------------------------------------------------

    def stage(self, paths, n=1, public=False, compress=False, quiet=False):
        if public and not self.allow_public:
            self.die(f"--public is disabled; {_ENABLE_PUBLIC_HINT}.")
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
                if not quiet:
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

        # If a session is already running, amend it rather than error out.
        daemon_pid = _daemon_pid()
        if daemon_pid is not None:
            port = int(self.config["stage"].get("port", DEFAULT_PORT))
            token = self.config["stage"]["token"]
            amend_headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            body = json.dumps({"files": files}).encode()
            try:
                self._open(
                    f"https://127.0.0.1:{port}/amend",
                    headers=amend_headers,
                    data=body,
                    method="POST",
                )
            except Exception as e:
                # The session may have just ended (last pull done) and be
                # shutting down. Wait for the process itself to exit so its
                # cleanup cannot delete the new session's files or UPnP mapping.
                if not _wait_for_exit(daemon_pid, timeout=5):
                    self.die(f"Failed to amend active session: {e}")
                daemon_pid = None
            if daemon_pid is not None:
                if not quiet:
                    for f in files:
                        indicator = "/" if f.get("type") == "dir" else ""
                        self.console.print(
                            f"Amended: [bold]{f['name']}{indicator}[/bold]"
                            f"  [cyan]{_human_size(f['size'])}[/cyan]"
                        )
                return

        port = int(self.config["stage"].get("port", DEFAULT_PORT))
        ssl_ctx = self.ssl_ctx  # fail early if TLS-PSK is unavailable

        STAGE_DIR.mkdir(parents=True, exist_ok=True)
        MANIFEST_FILE.write_text(
            json.dumps({"files": files, "compress": "zstd" if compress else False}, indent=2)
        )

        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "stage",
                "_serve",
                str(port),
                str(n),
                "1" if public else "0",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            **_daemon_popen_kwargs(),
        )
        PID_FILE.write_text(str(proc.pid))

        try:
            for _ in range(100):
                time.sleep(0.05)
                try:
                    urllib_request.urlopen(
                        f"https://127.0.0.1:{port}/health", timeout=1, context=ssl_ctx
                    )
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

            # Run UPnP forwarding and public-IP lookup concurrently so neither
            # blocks the other. UPnP discovery typically takes ~500 ms.
            upnp_info = [None]
            pub_ip = [None]
            ts_info = [(None, [])]
            bg = []
            if not quiet:
                t = threading.Thread(
                    target=lambda: ts_info.__setitem__(0, _tailscale_info()),
                    daemon=True,
                )
                t.start()
                bg.append(t)
            if public:
                t = threading.Thread(
                    target=lambda: upnp_info.__setitem__(0, _try_upnp_forward(port)),
                    daemon=True,
                )
                t.start()
                bg.append(t)
            if self.allow_public and self.config["stage"].get("public_ip_check"):
                t = threading.Thread(
                    target=lambda: pub_ip.__setitem__(0, _public_ip()), daemon=True
                )
                t.start()
                bg.append(t)
            for t in bg:
                t.join(timeout=5)

            if upnp_info[0]:
                UPNP_FILE.write_text(json.dumps(upnp_info[0]))

            if not quiet:
                total = sum(f["size"] for f in files)
                names = ", ".join(
                    f["name"] + ("/" if f.get("type") == "dir" else "") for f in files
                )
                pull_s = "pull" if n == 1 else "pulls"
                compress_note = " [dim](compressed)[/dim]" if compress else ""
                self.console.print(
                    f"\nStaged: [bold]{names}[/bold]"
                    f" ([cyan]{_human_size(total)}[/cyan], {n} {pull_s} allowed){compress_note}\n"
                )

                if public:
                    self.console.print(
                        "[yellow]Warning: --public is set. Connections from any IP address"
                        " will be accepted. Only use this on networks you trust.[/yellow]\n"
                    )

                ts_ip, _ts_peers = ts_info[0]
                local_ips = [ip for ip in _local_ips() if ip != ts_ip]

                if ts_ip:
                    self.console.print("  Via Tailscale:  [bold]stage pull[/bold]")
                for ip in local_ips:
                    self.console.print(
                        f"  Direct:         [bold]stage pull {ip}:{port}[/bold]"
                    )

                if upnp_info[0]:
                    u = upnp_info[0]
                    self.console.print(
                        f"  Internet:       [bold]stage pull {u['external_ip']}:{u['external_port']}[/bold]"
                        f"  [green](UPnP port forwarded)[/green]"
                    )
                elif pub_ip[0]:
                    if public:
                        self.console.print(
                            f"  Public IP:      [bold]stage pull {pub_ip[0]}:{port}[/bold]"
                            f"  [dim](check firewall / NAT)[/dim]"
                        )
                    else:
                        self.console.print(
                            f"  Public IP:      [dim]{pub_ip[0]}:{port}"
                            f" (add --public to accept)[/dim]"
                        )

                if public and not upnp_info[0]:
                    if not _upnp_available():
                        self.console.print(
                            "  UPnP:           [dim]not enabled --"
                            " run [bold]uv tool inject stage miniupnpc[/bold] to enable[/dim]"
                        )
                    else:
                        self.console.print(
                            "  UPnP:           [dim]no compatible router found[/dim]"
                        )

                if not ts_ip and not local_ips and not pub_ip[0] and not upnp_info[0]:
                    self.console.print(
                        f"  [bold]stage pull <this-machine-ip>:{port}[/bold]"
                    )

        except KeyboardInterrupt:
            try:
                proc.terminate()
            except Exception:
                pass
            if upnp_info[0]:
                _remove_upnp_forward(upnp_info[0])
            MANIFEST_FILE.unlink(missing_ok=True)
            PID_FILE.unlink(missing_ok=True)
            UPNP_FILE.unlink(missing_ok=True)
            print()
            sys.exit(130)

    # -------------------------------------------------------------------------
    # Daemon
    # -------------------------------------------------------------------------

    def _run_daemon(self, port, n, public=False):
        token = self.config["stage"]["token"]
        # Enforce the setting here too, in case _serve is invoked directly.
        public = public and self.allow_public
        manifest = json.loads(MANIFEST_FILE.read_text())
        compress = manifest.get("compress", False)
        entries = {f["name"]: f for f in manifest["files"]}
        entries_lock = threading.Lock()
        pulls_remaining = [n]
        done_event = threading.Event()

        def _shutdown(sig, frame):
            done_event.set()

        signal.signal(signal.SIGTERM, _shutdown)
        # SIGBREAK is the closest Windows equivalent to SIGTERM for interactive shutdown.
        if hasattr(signal, "SIGBREAK"):
            signal.signal(signal.SIGBREAK, _shutdown)

        server = _StagingServer(
            ("0.0.0.0", port),
            _StagingHandler,
            token=token,
            ssl_ctx=_server_ssl_ctx(token),
            entries=entries,
            entries_lock=entries_lock,
            compress=compress,
            pulls_remaining=pulls_remaining,
            done_event=done_event,
            public=public,
        )
        threading.Thread(target=server.serve_forever, daemon=True).start()

        try:
            done_event.wait()
        finally:
            server.shutdown()
            # Close the listener so new connections are refused immediately
            # instead of queueing until the process exits.
            server.server_close()
            MANIFEST_FILE.unlink(missing_ok=True)
            PID_FILE.unlink(missing_ok=True)
            if UPNP_FILE.exists():
                try:
                    _remove_upnp_forward(json.loads(UPNP_FILE.read_text()))
                except Exception:
                    pass
                UPNP_FILE.unlink(missing_ok=True)

    # -------------------------------------------------------------------------
    # Session discovery
    # -------------------------------------------------------------------------

    def _find_session(self, host_arg, *, quiet=False):
        """Return (base_url, headers, manifest_data, source_label) or None."""
        token = self.config["stage"]["token"]
        port = int(self.config["stage"].get("port", DEFAULT_PORT))
        headers = {"Authorization": f"Bearer {token}"}

        if host_arg:
            try:
                host, host_port = _split_host_port(host_arg, port)
            except ValueError:
                self.die(f"Invalid host: {host_arg}")
            try:
                ip = _resolve_allowed(host, host_port, self.allow_public)
            except _PublicNotAllowed as e:
                self.die(
                    f"{host_arg} is a public address ({e}). Public connections"
                    f" are disabled; {_ENABLE_PUBLIC_HINT}"
                )
            except OSError:
                if not quiet:
                    self.die(f"Could not resolve {host}")
                return None
            base = f"https://{_url_host(ip)}:{host_port}"
            if ip != host:
                host_arg = f"{host_arg} ({ip})"
            try:
                resp = self._open(
                    f"{base}/manifest", headers=headers, timeout=PROBE_TIMEOUT
                )
                return base, headers, json.loads(resp.read()), host_arg
            except Exception as e:
                if not quiet:
                    if isinstance(getattr(e, "reason", e), ssl.SSLError):
                        self.die(
                            f"TLS handshake with {host_arg} failed. The tokens may"
                            " differ, or the other machine runs an older stage"
                            " (run 'stage update' on both)."
                        )
                    self.die(f"No active session reachable at {host_arg}")
                return None

        _local_ip, ts_peers = _tailscale_info()
        hostname_map = {ip: hostname for ip, hostname in ts_peers}
        extra_peers = _load_peers()
        all_peers = [ip for ip, _ in ts_peers] + extra_peers

        if not all_peers:
            if not quiet:
                self.die(
                    "No Tailscale peers found and no extra peers configured.\n"
                    "For a direct connection: stage pull <host>[:<port>]"
                )
            return None

        result = [None]
        blocked = []
        lock = threading.Lock()
        found = threading.Event()

        def probe(peer):
            if found.is_set():
                return
            try:
                host, host_port = _split_host_port(peer, port)
                ip = _resolve_allowed(host, host_port, self.allow_public)
            except _PublicNotAllowed:
                with lock:
                    blocked.append(peer)
                return
            except (OSError, ValueError):
                return
            base = f"https://{_url_host(ip)}:{host_port}"
            try:
                resp = self._open(
                    f"{base}/manifest", headers=headers, timeout=PROBE_TIMEOUT
                )
                data = json.loads(resp.read())
                with lock:
                    if result[0] is None:
                        hostname = hostname_map.get(ip) or (
                            host if host != ip else ""
                        )
                        label = f"{hostname} ({ip})" if hostname else ip
                        result[0] = (base, headers, data, label)
                        found.set()
            except Exception:
                pass

        threads = [
            threading.Thread(target=probe, args=(ip,), daemon=True) for ip in all_peers
        ]
        for t in threads:
            t.start()
        found.wait(timeout=PROBE_TIMEOUT + 1)

        if result[0] is None:
            if not quiet:
                skipped = (
                    f"\nSkipped public peers: {', '.join(blocked)} ({_ENABLE_PUBLIC_HINT})"
                    if blocked
                    else ""
                )
                self.die(
                    "No active staging session found on any reachable peer.\n"
                    "For a direct connection: stage pull <host>[:<port>]" + skipped
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
        base, headers, data, source_label = session

        raw = data["files"]
        compress = data.get("compress", False)
        file_entries = [
            f if isinstance(f, dict) else {"name": f, "type": "file"} for f in raw
        ]
        if not file_entries:
            self.console.print("Nothing staged.")
            self._post(f"{base}/done", headers)
            return

        from_label = source_label or base.removeprefix("https://")
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column()
        table.add_column(justify="right", style="cyan")
        for entry in file_entries:
            indicator = "/" if entry.get("type") == "dir" else ""
            size_str = _human_size(entry["size"]) if "size" in entry else ""
            table.add_row(f"{entry['name']}{indicator}", size_str)
        self.console.print(f"From [bold]{from_label}[/bold]:")
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
            url = f"{base}/files/{encoded}"
            try:
                size = entry.get("size") or 0
                if entry_type != "dir" and not compress and size >= RANGED_MIN_SIZE:
                    self._download_ranged(
                        url, headers, size, dest, name, show_progress=show_progress
                    )
                    return None
                resp = self._open(url, headers=headers, timeout=300)
                if entry_type == "dir":
                    # When compressed, we don't know the compressed size ahead of time,
                    # so suppress the total to avoid a misleading progress bar.
                    total_bytes = None if compress else (entry.get("size") or None)
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

                        src = _Reader()
                        if compress:
                            src = zstd.ZstdFile(src, "rb")
                        # Extract beside the destination so the final move is a
                        # rename rather than a cross-filesystem copy out of /tmp.
                        with tempfile.TemporaryDirectory(
                            dir=dest.parent, prefix=".stage-"
                        ) as tmp_dir:
                            with tarfile.open(fileobj=src, mode="r|") as tar:
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
                    file_resp = zstd.ZstdFile(resp, "rb") if compress else resp
                    self._download(file_resp, dest, name, show_progress=show_progress)
                return None
            except (URLError, OSError, tarfile.TarError, zstd.ZstdError) as e:
                return (name, e)

        n_workers = min(4, len(assignments))
        executor = ThreadPoolExecutor(max_workers=n_workers)
        futures = {
            executor.submit(fetch, entry, dest): entry for entry, dest in assignments
        }
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
                self._post(f"{base}/cancel", headers)
            except Exception:
                pass
            self.console.print("\n[yellow]Pull interrupted.[/yellow]")
            os._exit(130)
        else:
            executor.shutdown(wait=True)

        if not errors:
            resp = self._post(f"{base}/done", headers)
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
        hdrs = getattr(resp, "headers", None)
        total = (int(hdrs.get("Content-Length", 0)) or None) if hdrs else None
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
            buf = memoryview(bytearray(CHUNK_SIZE))
            with open(dest, "wb") as f:
                while n := resp.readinto(buf):
                    f.write(buf[:n])
                    bar.update(n)
                    downloaded += n

        self._report_download(name, dest, downloaded, start, suffix)

    def _download_ranged(self, url, headers, size, dest, name, show_progress=True):
        """Fetch a large file as parallel byte ranges over separate connections.

        Each connection has its own TLS session, so decryption spreads across
        cores and high-latency links get several TCP windows in flight.
        """
        n_parts = max(2, min(RANGED_MAX_PARTS, size // RANGED_PART_SIZE))
        step = -(-size // n_parts)
        spans = [(lo, min(lo + step, size) - 1) for lo in range(0, size, step)]
        bar_lock = threading.Lock()
        start = time.monotonic()

        with open(dest, "wb") as f:
            f.truncate(size)

        with tqdm(
            total=size,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            desc=name,
            ncols=80,
            leave=False,
            file=sys.stderr,
            disable=not show_progress,
        ) as bar:

            def fetch_span(lo, hi):
                resp = self._open(
                    url, headers={**headers, "Range": f"bytes={lo}-{hi}"}, timeout=300
                )
                if resp.status != 206:
                    resp.close()
                    raise _RangeNotSupported
                buf = memoryview(bytearray(CHUNK_SIZE))
                remaining = hi - lo + 1
                with open(dest, "r+b") as f:
                    f.seek(lo)
                    while remaining:
                        n = resp.readinto(buf[: min(CHUNK_SIZE, remaining)])
                        if not n:
                            raise OSError(f"connection closed with {remaining} bytes left")
                        f.write(buf[:n])
                        remaining -= n
                        with bar_lock:
                            bar.update(n)

            with ThreadPoolExecutor(max_workers=len(spans)) as ex:
                futures = [ex.submit(fetch_span, lo, hi) for lo, hi in spans]
                try:
                    for fut in futures:
                        fut.result()
                except _RangeNotSupported:
                    for fut in futures:
                        fut.cancel()
                    ex.shutdown(wait=True)
                    bar.reset()
                    resp = self._open(url, headers=headers, timeout=300)
                    self._download(resp, dest, name, show_progress=show_progress)
                    return

        self._report_download(name, dest, size, start)

    def _report_download(self, name, dest, downloaded, start, suffix=None):
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
        _, _, data, source_label = session
        pulls = data.get("pulls_remaining", "?")
        entries = data["files"]
        from_str = f" from [bold]{source_label}[/bold]" if source_label else ""
        self.console.print(
            f"[bold]Active:[/bold] {len(entries)} item(s), {pulls} pull(s) remaining{from_str}"
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
            _proc_terminate(pid)
        except OSError:
            pass
        # Wait so the port and UPnP mapping are released before we return;
        # otherwise an immediate re-stage can fail to bind.
        _wait_for_exit(pid, timeout=5)
        PID_FILE.unlink(missing_ok=True)
        MANIFEST_FILE.unlink(missing_ok=True)
        self.console.print("Staging session cleared.")

    # -------------------------------------------------------------------------
    # Peers
    # -------------------------------------------------------------------------

    def peers(self, args=None):
        args = list(args or [])
        if not args or args[0] == "list":
            self._peers_list()
        elif args[0] == "add" and len(args) > 1:
            self._peers_add(args[1])
        elif args[0] == "remove" and len(args) > 1:
            self._peers_remove(args[1])
        else:
            self.console.print(
                "Usage: stage peers [add <host> | remove <host>]", markup=False
            )

    def _peers_list(self):
        _, ts_peers = _tailscale_info()
        extra = _load_peers()

        if ts_peers:
            table = Table(show_header=True, box=None, padding=(0, 2))
            table.add_column("Hostname", style="bold")
            table.add_column("IP")
            for ip, hostname in ts_peers:
                table.add_row(hostname or "[dim]unknown[/dim]", ip)
            self.console.print("Tailscale peers:")
            self.console.print(table)
        else:
            self.console.print("[dim]No Tailscale peers found.[/dim]")

        if extra:
            self.console.print("\nConfigured extra peers:")
            for peer in extra:
                self.console.print(f"  {peer}{self._peer_tag(peer)}")
        elif not ts_peers:
            self.console.print(
                "\nNo extra peers configured. Use 'stage peers add <ip>' to add one."
            )

    def _peer_tag(self, peer: str) -> str:
        port = int(self.config["stage"].get("port", DEFAULT_PORT))
        try:
            host, host_port = _split_host_port(peer, port)
            ip = _resolve_allowed(host, host_port, allow_public=True)
        except (OSError, ValueError):
            return " [dim](does not resolve right now)[/dim]"
        resolved = f" [dim]-> {ip}[/dim]" if ip != host else ""
        if _is_private_ip(ip):
            return resolved
        if self.allow_public:
            return f"{resolved} [yellow](public)[/yellow]"
        return f"{resolved} [red](public, blocked)[/red]"

    def _peers_add(self, peer: str):
        existing = _load_peers()
        if peer in existing:
            self.console.print(f"{peer} is already in the peer list.")
            return
        port = int(self.config["stage"].get("port", DEFAULT_PORT))
        try:
            host, host_port = _split_host_port(peer, port)
        except ValueError:
            self.die(f"Invalid peer: {peer}")
        try:
            ip = _resolve_allowed(host, host_port, self.allow_public)
        except _PublicNotAllowed as e:
            self.die(
                f"{peer} is a public address ({e}). Public connections are"
                f" disabled; {_ENABLE_PUBLIC_HINT}."
            )
        except OSError:
            # Common for VPN hostnames while disconnected; checked at each pull.
            self.console.print(
                f"[dim]{host} does not resolve right now; it will be checked"
                " on each pull.[/dim]"
            )
        else:
            if not _is_private_ip(ip):
                self.console.print(
                    f"[yellow]Warning: {peer} is a public address ({ip}).[/yellow]\n"
                    "Make sure you trust this host and its network."
                )
        existing.append(peer)
        _save_peers(existing)
        self.console.print(f"Added {peer} to peer list.")

    def _peers_remove(self, ip: str):
        existing = _load_peers()
        if ip not in existing:
            self.console.print(f"{ip} is not in the peer list.")
            return
        existing.remove(ip)
        _save_peers(existing)
        self.console.print(f"Removed {ip} from peer list.")

    # -------------------------------------------------------------------------
    # Setup / Update / Provision
    # -------------------------------------------------------------------------

    def setup(self, extra_args=None):
        provided_token = None
        provided_port = None
        provided_repo = None
        provided_public_ip = None
        provided_allow_public = None
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
            elif args[i] == "--allow-public":
                provided_allow_public = True
                i += 1
            elif args[i] == "--no-allow-public":
                provided_allow_public = False
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

        if provided_allow_public is not None:
            allow_public = provided_allow_public
        elif not non_interactive:
            current = existing_cfg.get("allow_public", False) is True
            default = "Y/n" if current else "y/N"
            ans = (
                input(
                    "Allow connections over the public internet"
                    f" (--public, UPnP, public peers)? [{default}]: "
                )
                .strip()
                .lower()
            )
            allow_public = (ans == "y") if ans else current
        else:
            allow_public = existing_cfg.get("allow_public", False) is True

        if provided_public_ip is not None:
            public_ip_check = provided_public_ip
        elif not allow_public:
            public_ip_check = existing_cfg.get("public_ip_check", False)
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
        allow_line = "\nallow_public = true" if allow_public else ""
        CONFIG_PATH.write_text(
            f'[stage]\nport = {port}\ntoken = "{token}"'
            f"{repo_line}{pub_line}{allow_line}\n"
        )
        CONFIG_PATH.chmod(0o600)
        print(f"Config saved to {CONFIG_PATH}")

        if not non_interactive:
            repo_flag = f" --repo {repo}" if repo else ""
            pub_flag = " --public-ip" if public_ip_check else ""
            print("\nTo configure another machine:")
            print(f"  stage setup --token {token} --port {port}{repo_flag}{pub_flag}")
            if allow_public:
                print("  (public connections are enabled per machine: add --allow-public)")

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
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    **_daemon_popen_kwargs(),
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
            "  stage [-n N] [-z] [-q] [--public] <file> [files...]"
        )
        self.console.print(
            "      Stage files. Appends to an active session if one exists."
        )
        self.console.print(
            "      -n N       Allow N pulls (default 1)"
        )
        self.console.print(
            "      -z         Compress transfer with zstd (more CPU, less bandwidth)"
        )
        self.console.print(
            "      -q         Quiet: suppress output unless there is an error"
        )
        self.console.print(
            "      --public   Accept connections from any IP (default: private/Tailscale"
            " only). Requires public connections to be enabled in setup"
        )
        self.console.print("")
        self.console.print(
            "  stage pull [<host>[:<port>]]       Pull staged files to current directory"
        )
        self.console.print(
            "  stage status [<host>[:<port>]]     Show what is staged and where"
        )
        self.console.print(
            "  stage peers [add|remove <host>]    List or manage discoverable peers",
            markup=False,
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
            "  stage setup                        Configure port, token, repo, and"
            " public access (off by default)"
        )


# =============================================================================
# Module-level pure helpers (no app state)
# =============================================================================


def _dir_stats(path: Path) -> tuple[int, int]:
    """Return (total_bytes, file_count) via stat-only walk (no file reads).

    Uses scandir's cached entry types, and does not follow symlinks, matching
    what tarfile.add sends.
    """
    size = count = 0
    stack = [str(path)]
    while stack:
        try:
            it = os.scandir(stack.pop())
        except OSError:
            continue
        with it:
            for entry in it:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        size += entry.stat(follow_symlinks=False).st_size
                        count += 1
                except OSError:
                    pass
    return size, count


def _tailscale_info():
    """Return (local_ipv4, peers) where peers is a list of (ipv4, hostname) tuples."""
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
            hostname = peer.get("HostName", "")
            for ip in peer.get("TailscaleIPs", []):
                if ":" not in ip:
                    peers.append((ip, hostname))
                    break
        return local_ip, peers
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None, []


def _load_peers() -> list[str]:
    try:
        if PEERS_FILE.exists():
            return json.loads(PEERS_FILE.read_text())
    except Exception:
        pass
    return []


def _save_peers(peers: list[str]) -> None:
    STAGE_DIR.mkdir(parents=True, exist_ok=True)
    PEERS_FILE.write_text(json.dumps(peers))


# Windows reserved device names that cannot be used as filenames.
_WIN_RESERVED = re.compile(
    r"^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\..*)?$", re.IGNORECASE
)


def _tar_filter(member, dest_path):
    # Use data_filter for path traversal / special file protection, but skip
    # symlinks that point to absolute or out-of-destination paths -- these are
    # system-specific (e.g. .venv/bin/python -> /usr/bin/python3.14) and would
    # be broken on a different machine anyway.
    try:
        result = tarfile.data_filter(member, dest_path)
    except (tarfile.AbsoluteLinkError, tarfile.LinkOutsideDestinationError):
        return None
    if result is None:
        return None
    if sys.platform == "win32":
        # Symlink creation on Windows requires Developer Mode or elevation.
        if result.issym() or result.islnk():
            return None
        # Skip entries whose name components match Windows reserved device names.
        for part in Path(result.name).parts:
            if _WIN_RESERVED.match(part):
                return None
    return result


def _proc_alive(pid: int) -> bool:
    """Check whether a process is running without sending it a signal."""
    if sys.platform == "win32":
        import ctypes
        import ctypes.wintypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        h = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        if not h:
            return False
        try:
            code = ctypes.wintypes.DWORD()
            ctypes.windll.kernel32.GetExitCodeProcess(h, ctypes.byref(code))
            return code.value == STILL_ACTIVE
        finally:
            ctypes.windll.kernel32.CloseHandle(h)
    else:
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, OSError):
            return False


def _proc_terminate(pid: int) -> None:
    """Terminate a process by PID, cross-platform."""
    if sys.platform == "win32":
        import ctypes

        PROCESS_TERMINATE = 0x0001
        h = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if h:
            try:
                ctypes.windll.kernel32.TerminateProcess(h, 0)
            finally:
                ctypes.windll.kernel32.CloseHandle(h)
    else:
        os.kill(pid, signal.SIGTERM)


def _daemon_popen_kwargs() -> dict:
    """Return platform-appropriate Popen kwargs for background daemon spawning."""
    if sys.platform == "win32":
        # start_new_session and creationflags are mutually exclusive in Python.
        # CREATE_NEW_PROCESS_GROUP prevents Ctrl+C propagation from the parent.
        # CREATE_NO_WINDOW suppresses a spurious console window on Windows.
        return {
            "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP
            | subprocess.CREATE_NO_WINDOW,
        }
    return {"start_new_session": True}


def _is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


class _RangeNotSupported(Exception):
    pass


def _psk_key(token: str) -> bytes:
    # Derive the TLS pre-shared key from the token rather than using it raw.
    return hmac.new(token.encode(), b"stage-tls-psk-v1", hashlib.sha256).digest()


# TLS 1.2 fallback cipher: PSK with ECDHE and an AEAD, so sessions keep forward
# secrecy. TLS 1.3 PSK uses (EC)DHE key exchange by default.
_PSK_CIPHERS = "ECDHE-PSK-CHACHA20-POLY1305"


def _server_ssl_ctx(token: str) -> ssl.SSLContext:
    key = _psk_key(token)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(_PSK_CIPHERS)
    # An empty key for an unknown identity makes the handshake fail.
    ctx.set_psk_server_callback(lambda ident: key if ident == _PSK_IDENTITY else b"")
    return ctx


def _client_ssl_ctx(token: str) -> ssl.SSLContext:
    key = _psk_key(token)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # The shared key authenticates both sides; there are no certificates.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(_PSK_CIPHERS)
    ctx.set_psk_client_callback(lambda hint: (_PSK_IDENTITY, key))
    return ctx


def _parse_range(header: str, size: int) -> tuple[int, int] | None:
    """Parse a single 'bytes=lo-hi' range. Returns (lo, hi) inclusive or None."""
    m = re.fullmatch(r"bytes=(\d+)-(\d*)", header.strip())
    if not m:
        return None
    lo = int(m.group(1))
    hi = min(int(m.group(2)), size - 1) if m.group(2) else size - 1
    if lo > hi:
        return None
    return lo, hi


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


def _daemon_pid() -> int | None:
    """Return the PID of the running daemon, or None."""
    try:
        pid = int(PID_FILE.read_text().strip())
    except (OSError, ValueError):
        return None
    return pid if _proc_alive(pid) else None


def _is_daemon_running():
    return _daemon_pid() is not None


def _wait_for_exit(pid: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while _proc_alive(pid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)
    return True


def _split_host_port(host_str: str, default_port: int) -> tuple[str, int]:
    """Parse 'host', 'host:port', '[v6]', '[v6]:port', or a bare IPv6 address."""
    if host_str.startswith("["):
        host, _, rest = host_str[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default_port
    if host_str.count(":") == 1:
        host, port = host_str.split(":")
        return host, int(port)
    return host_str, default_port


class _PublicNotAllowed(Exception):
    pass


def _resolve_allowed(host: str, port: int, allow_public: bool) -> str:
    """Resolve host to one IP address that policy permits connecting to.

    Without allow_public, only private addresses qualify. The caller connects
    to the returned IP, so a DNS answer cannot change between check and use.
    Raises OSError if the name does not resolve and _PublicNotAllowed if it
    resolves only to public addresses.
    """
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    # The daemon listens on IPv4 only, so try IPv4 first.
    addrs = sorted(
        dict.fromkeys(info[4][0] for info in infos), key=lambda a: ":" in a
    )
    allowed = [a for a in addrs if allow_public or _is_private_ip(a)]
    if not allowed:
        raise _PublicNotAllowed(addrs[0] if addrs else host)
    return allowed[0]


def _url_host(ip: str) -> str:
    return f"[{ip}]" if ":" in ip else ip


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


# =============================================================================
# UPnP helpers
# =============================================================================


def _upnp_available() -> bool:
    """Return True if miniupnpc is importable."""
    try:
        import miniupnpc  # noqa: F401
        return True
    except ImportError:
        return False


def _try_upnp_forward(port: int) -> dict | None:
    """Attempt to open a UPnP port mapping. Returns mapping info or None.
    Callers should check _upnp_available() first to distinguish 'not installed'
    from 'installed but no compatible router found'."""
    try:
        import miniupnpc  # optional dependency
    except ImportError:
        return None
    try:
        u = miniupnpc.UPnP()
        u.discoverdelay = 500
        if u.discover() == 0:
            return None
        u.selectigd()
        external_ip = u.externalipaddress()
        internal_ip = u.lanaddr
        u.addportmapping(port, "TCP", internal_ip, port, "stage", "")
        return {
            "external_ip": external_ip,
            "external_port": port,
            "internal_ip": internal_ip,
            "internal_port": port,
        }
    except Exception:
        return None


def _remove_upnp_forward(info: dict) -> None:
    """Remove a UPnP port mapping previously created by _try_upnp_forward."""
    try:
        import miniupnpc  # optional dependency
    except ImportError:
        return
    try:
        u = miniupnpc.UPnP()
        u.discoverdelay = 500
        if u.discover() == 0:
            return
        u.selectigd()
        u.deleteportmapping(info["external_port"], "TCP")
    except Exception:
        pass


# =============================================================================
# HTTP server (extracted from _run_daemon to reduce cyclomatic complexity)
# =============================================================================


class _StagingServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that carries shared session state for _StagingHandler."""

    def __init__(
        self,
        server_address,
        RequestHandlerClass,
        *,
        token: str,
        ssl_ctx: ssl.SSLContext,
        entries: dict,
        entries_lock: threading.Lock,
        compress: str | bool,
        pulls_remaining: list,
        done_event: threading.Event,
        public: bool,
    ):
        super().__init__(server_address, RequestHandlerClass)
        self.token = token
        self.ssl_ctx = ssl_ctx
        self.entries = entries
        self.entries_lock = entries_lock
        self.compress = compress
        self.pulls_remaining = pulls_remaining
        self.done_event = done_event
        self.public = public

    def finish_request(self, request, client_address):
        # Runs in the per-connection thread, so a slow handshake cannot stall
        # accept(). A client with the wrong token fails here and is dropped.
        request.settimeout(10)
        try:
            tls = self.ssl_ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            tls.settimeout(300)
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            tls.close()


class _StagingHandler(BaseHTTPRequestHandler):
    # Buffer writes so tar's small blocks coalesce into large TLS records.
    # (A large tarfile bufsize is slower: its stream buffer re-slices on
    # every read.) StreamRequestHandler.finish() flushes this.
    wbufsize = 256 << 10

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass

    def _allowed_client(self) -> bool:
        if self.server.public:
            return True
        if _is_private_ip(self.client_address[0]):
            return True
        self.send_error(403)
        return False

    def _auth(self) -> bool:
        if self.headers.get("Authorization") != f"Bearer {self.server.token}":
            self.send_error(401)
            return False
        return True

    def _respond(self, code: int, ctype: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _entry_meta(e: dict) -> dict:
        m = {"name": e["name"], "type": e.get("type", "file"), "size": e["size"]}
        if "file_count" in e:
            m["file_count"] = e["file_count"]
        return m

    def do_GET(self) -> None:
        if self.path == "/health":
            # Only respond to localhost; external probing reveals the daemon
            # is running without any authentication.
            if self.client_address[0] == "127.0.0.1":
                self._respond(200, "text/plain", b"ok")
            else:
                self.send_error(404)
            return
        if not self._allowed_client():
            return
        if not self._auth():
            return
        path = unquote(self.path.lstrip("/"))
        if path in ("manifest", "status"):
            with self.server.entries_lock:
                file_list = [self._entry_meta(e) for e in self.server.entries.values()]
            body = json.dumps(
                {
                    "files": file_list,
                    "pulls_remaining": self.server.pulls_remaining[0],
                    "compress": self.server.compress,
                }
            ).encode()
            self._respond(200, "application/json", body)
        elif path.startswith("files/"):
            self._serve_file(path[6:])
        else:
            self.send_error(404)

    def _serve_file(self, name: str) -> None:
        with self.server.entries_lock:
            entry = self.server.entries.get(name)
        if entry is None:
            self.send_error(404)
            return
        fp = Path(entry["path"])
        if not fp.exists():
            self.send_error(410)
            return
        if entry.get("type") == "dir":
            self._serve_dir(fp)
        else:
            self._serve_regular_file(fp)

    def _serve_dir(self, fp: Path) -> None:
        # Connection: close is required because Content-Length is unknown.
        # Default is uncompressed (fast LAN/VPN).
        # compress uses multithreaded zstd; tarfile's own "w|zst" mode cannot
        # take compressor options, so the zstd layer wraps the socket instead.
        self.send_response(200)
        self.send_header("Content-Type", "application/x-tar")
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()
        try:
            if self.server.compress:
                out = zstd.ZstdFile(self.wfile, "wb", options=_ZSTD_OPTIONS)
            else:
                out = self.wfile
            with tarfile.open(fileobj=out, mode="w|") as tar:
                tar.add(fp, arcname=fp.name)
            if out is not self.wfile:
                out.close()
        except OSError:
            # Covers client disconnect (BrokenPipeError, ConnectionResetError)
            # on both POSIX and Windows.
            pass

    def _serve_regular_file(self, fp: Path) -> None:
        size = fp.stat().st_size
        lo, hi = 0, size - 1
        range_header = self.headers.get("Range")
        if range_header and not self.server.compress:
            span = _parse_range(range_header, size)
            if span is None:
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{size}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            lo, hi = span
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {lo}-{hi}/{size}")
        else:
            self.send_response(200)
            self.send_header("Accept-Ranges", "none" if self.server.compress else "bytes")
        self.send_header("Content-Type", "application/octet-stream")
        if self.server.compress:
            self.send_header("Connection", "close")
            self.close_connection = True
        else:
            self.send_header("Content-Length", str(hi - lo + 1))
        self.end_headers()
        try:
            with open(fp, "rb") as f:
                if self.server.compress:
                    with zstd.ZstdFile(self.wfile, "wb", options=_ZSTD_OPTIONS) as zf:
                        shutil.copyfileobj(f, zf, CHUNK_SIZE)
                else:
                    f.seek(lo)
                    buf = memoryview(bytearray(CHUNK_SIZE))
                    remaining = hi - lo + 1
                    while remaining:
                        n = f.readinto(buf[: min(CHUNK_SIZE, remaining)])
                        if not n:
                            break
                        self.wfile.write(buf[:n])
                        remaining -= n
        except OSError:
            # Same as above; also covers TOCTOU FileNotFoundError.
            pass

    def do_POST(self) -> None:
        if not self._allowed_client():
            return
        if not self._auth():
            return
        if self.path == "/done":
            self.server.pulls_remaining[0] -= 1
            remaining = self.server.pulls_remaining[0]
            self._respond(
                200,
                "application/json",
                json.dumps({"pulls_remaining": remaining}).encode(),
            )
            if remaining <= 0:
                self.server.done_event.set()
        elif self.path == "/cancel":
            self._respond(200, "text/plain", b"cancelled")
            self.server.done_event.set()
        elif self.path == "/amend":
            length = int(self.headers.get("Content-Length", 0))
            new_files = json.loads(self.rfile.read(length)).get("files", [])
            with self.server.entries_lock:
                for f in new_files:
                    self.server.entries[f["name"]] = f
                all_files = list(self.server.entries.values())
            MANIFEST_FILE.write_text(
                json.dumps(
                    {"files": all_files, "compress": self.server.compress}, indent=2
                )
            )
            self._respond(
                200,
                "application/json",
                json.dumps({"files": list(self.server.entries.keys())}).encode(),
            )
        else:
            self.send_error(404)


def main():
    StageApp().run()
