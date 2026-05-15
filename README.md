# stage

A pull-based CLI file transfer tool for Tailscale networks and trusted LANs.

## The problem

You have a file on machine A. You want it on machine B. The standard options:

- **scp / rsync**: You have to know the source path from the receiver's perspective, have SSH configured, and type out both sides of the connection. If you're the one receiving, you can't initiate -- you wait for the sender to push.
- **croc / magic-wormhole**: Both sides have to be present at the same time to exchange a one-time code. You can't stage something and walk away.
- **Tailscale Taildrop** (`tailscale file cp file.txt machine:`): Works well, but it's push-based. If you're on machine B and you know machine A has something for you, you cannot pull it. You have to go to machine A and push.

`stage` inverts the model. The sender stages files once and walks away. The receiver pulls whenever they're ready, from wherever they are.

## How it works

On the machine with the files:

```
stage report.pdf video.mp4
```

On any other machine on the same Tailscale network:

```
stage pull
```

That's it. `stage` probes all online Tailscale peers, finds the active session, and downloads to the current directory. No codes. No hostnames. No path specification.

## Installation

```
uv tool install git+ssh://git@github.com/scottastone/stage
stage setup
```

`setup` prompts for a port (default 47200), generates a shared token, and optionally configures update checks. Run the same command on each machine that will send or receive -- use `stage provision` to print a one-liner that configures a new machine with the same token.

## Usage

### Stage files

```
stage report.pdf
stage ~/Downloads/archive.zip ~/Documents/notes/
stage -n 3 dataset.tar          # allow up to 3 pulls
stage --public large-file.iso   # accept connections from any IP (see Security)
```

After staging, `stage` prints the available pull addresses:

```
Staged: report.pdf (2.3 MB, 1 pull allowed)

  Via Tailscale:  stage pull
  Direct:         stage pull 192.168.1.42:47200
  Public IP:      203.0.113.5:47200 (add --public to accept)
```

### Pull files

```
stage pull                          # auto-discover via Tailscale peers
stage pull 192.168.1.42             # direct IP
stage pull 192.168.1.42:8000        # direct IP with custom port
```

Files are saved to the current directory. If a file already exists, it is renamed (e.g., `report_1.pdf`) rather than overwritten. Directories are streamed as uncompressed tar and extracted in place.

### Other commands

```
stage status                        # show what's currently staged and pulls remaining
stage status 192.168.1.42           # check a specific host
stage clear                         # cancel the active staging session
stage update                        # upgrade to the latest version
stage provision                     # print a one-liner to configure a new machine
```

## Security

### Default behavior: private networks only

By default, `stage` only accepts connections from private IP ranges:

- RFC 1918 (10.x, 172.16.x, 192.168.x)
- Tailscale / CGNAT (100.64.0.0/10)
- Loopback and link-local

A connection from a public IP is rejected with 403 before authentication is even attempted. This means the token is never tested against requests from the internet unless you explicitly opt in with `--public`.

### Token authentication

Every request requires a `Bearer` token in the `Authorization` header. The token is a 32-character random hex string generated at setup and shared across your machines. Without it, the server returns 401. The token is stored in `~/.config/stage/config.toml`, which is written with `0600` permissions.

### What happens if someone gets your token?

If an attacker obtains the token and can reach the daemon on the network, they can:

- List staged files and their sizes
- Download staged files
- Post to `/cancel` and end the session early

They cannot: execute code, write files, browse the filesystem beyond what is explicitly staged, or do anything persistent -- the daemon exits as soon as all pulls are consumed or the session is cancelled.

The blast radius is limited to whatever you have staged at that moment. Nothing is exposed between sessions.

If you are on a Tailscale network and your Tailscale credentials are not compromised, this is not a practical attack -- the daemon is unreachable from the internet by default. The token matters most if you use `--public` on an untrusted network, in which case it is the only layer of authentication.

### `--public` flag

By default, `stage` binds to all interfaces (`0.0.0.0`) but rejects connections from public IPs at the application layer. If you want to stage for someone outside your private network:

```
stage --public largefile.zip
```

This prints a warning and enables connections from any source IP. Only use this on networks where you are comfortable with the token being the sole protection. On a home or office network with a properly configured NAT firewall, the risk is low. On open public Wi-Fi, it is not recommended.

### Archive extraction safety

Directories are transferred as tar streams. Extraction uses `tarfile.data_filter` (Python 3.12+), which blocks path traversal attacks (e.g., `../../etc/passwd`). Absolute symlinks and symlinks pointing outside the destination are silently skipped. On Windows, entries matching reserved device names (CON, NUL, COM1-COM9, LPT1-LPT9) are also skipped.

## Compared to alternatives

| Tool               | Model        | Peer discovery | Relay required | Per-transfer setup       |
| ------------------ | ------------ | -------------- | -------------- | ------------------------ |
| scp / rsync        | push         | none           | no             | SSH config + target path |
| croc               | push + relay | none           | yes (default)  | exchange one-time code   |
| magic-wormhole     | push + relay | none           | yes            | exchange one-time code   |
| Tailscale Taildrop | push         | Tailscale      | no             | specify target machine   |
| **stage**          | **pull**     | **Tailscale**  | **no**         | **none after setup**     |

The pull model is the key difference. The sender stages once; receivers pull at their own pace, from any machine with the shared token. Sessions persist until the pull limit is reached or the session is cleared.

## Requirements

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) (for installation)
- Tailscale (optional, but required for zero-config peer discovery)
