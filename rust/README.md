# stage (Rust port)

A Rust reimplementation of `stage`, the pull-based CLI file transfer tool for
Tailscale networks and trusted LANs. It is a drop-in, faster replacement for the
Python version: same commands, same config, same on-the-wire protocol.

See the [top-level README](../README.md) for the full description of what
`stage` does and why. This document covers what is specific to the Rust build.

## Why a Rust port

The transfer path is CPU-bound in a few places the Python version cannot avoid:
per-chunk work in the download loop, tar streaming, and gzip. The Rust build
compiles to a single static-ish binary with no interpreter startup, streams
files with a hand-written HTTP/1.1 path, and does gzip/tar in native code.
Startup is instant (no `python -m` import cost), which matters because every
invocation pays that cost.

## Feature parity

Everything the Python CLI does is implemented:

- `stage [-n N] [-z] [-q] [--public] <files...>` including amend-into-running-session
- `stage pull [<host>[:<port>]]` with Tailscale + extra-peer discovery, parallel
  downloads (up to 4), collision-safe renaming, and tar extraction
- `stage status`, `stage clear`, `stage peers [add|remove <ip>]`
- `stage setup` (interactive and `--token/--port/--repo/--public-ip` flags),
  `stage provision`, `stage update`
- Private-network access control (403 before auth), Bearer-token auth (401),
  localhost-only `/health`
- gzip (`-z`) compressed transfers, uncompressed by default
- Update-check notifications via `git ls-remote` and the GitHub compare API
- UPnP port forwarding (`--public`) behind the default `upnp` feature

Config (`~/.config/stage/config.toml`), state (`~/.stage/`), the HTTP endpoints,
JSON manifest shape, and tar/gzip streaming all match the Python version, so a
Rust and a Python machine interoperate on the same network with the same token.

## Build

```
cd rust
cargo build --release
# binary at target/release/stage
```

Install it on your PATH, e.g.:

```
cargo install --path .
```

### Features

- `upnp` (default): compile in UPnP/IGD port forwarding. Disable with
  `cargo build --release --no-default-features` if you do not want it; the
  `--public` output then reports UPnP as not enabled, matching the Python
  behavior when `miniupnpc` is not installed.

## Notes and differences

- `stage update` still shells out to `uv tool upgrade stage`, mirroring the
  Python packaging flow. If you distribute the Rust binary some other way,
  adjust that step to your installer; the update-*check* notifications work
  regardless.
- Graceful UPnP teardown on `stage clear` is handled via `SIGTERM` on Unix. On
  Windows the process is terminated abruptly (as in the Python version), so a
  UPnP mapping may need to age out on its own.
- Progress bars use `indicatif` instead of `tqdm`; output text otherwise matches.
