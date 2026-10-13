# stage

A pull-based CLI file transfer tool for Tailscale networks and trusted LANs. Every transfer is encrypted, with or without Tailscale.

## The problem

You have a file on machine A. You want it on machine B. The standard options:

- **scp / rsync**: You have to know the source path from the receiver's perspective, have SSH configured, and type out both sides of the connection. If you're the one receiving, you can't initiate -- you wait for the sender to push.
- **croc / magic-wormhole**: Both sides have to be present at the same time to exchange a one-time code. You can't stage something and walk away.
- **Tailscale's Taildrop** (`tailscale file cp file.txt machine:`): Works well, but it's push-based. If you're on machine B and you know machine A has something for you, you cannot pull it. You have to go to machine A and push.

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

`setup` prompts for a port (default 47200), generates a shared token, optionally configures update checks, and asks whether to allow public internet connections (off by default; see Security). Run the same command on each machine that will send or receive -- use `stage provision` to print a one-liner that configures a new machine with the same token.

An example provision output might look like:

```
stage provision
uv tool install git+ssh://git@github.com/scottastone/stage && stage setup --token <32 character bearer token> --port 47200 --repo git@github.com:scottastone/stage.git --public-ip
```

## Usage

### Stage files

```
stage report.pdf
stage ~/Downloads/archive.zip ~/Documents/notes/
stage -n 3 dataset.tar          # allow up to 3 pulls
stage -z large-dir/             # compress transfer with zstd (less bandwidth, more CPU)
stage -q build-output/          # quiet: no output unless an error occurs
stage --public large-file.iso   # accept connections from any IP (must be enabled in setup; see Security)
```

After staging, `stage` prints the available pull addresses:

```
Staged: report.pdf (2.3 MB, 1 pull allowed)

  Via Tailscale:  stage pull
  Direct:         stage pull 192.168.1.42:47200
  Public IP:      203.0.113.5:47200 (add --public to accept)
```

If a session is already running, staging additional files amends it rather than erroring:

```
stage report.pdf               # starts a session
stage notes.txt                # adds notes.txt to the same session
```

### Pull files

```
stage pull                          # auto-discover via Tailscale peers
stage pull 192.168.1.42             # direct IP
stage pull 192.168.1.42:8000        # direct IP with custom port
```

Files are saved to the current directory. If a file already exists, it is renamed (e.g., `report_1.pdf`) rather than overwritten. Directories are streamed as tar and extracted in place. Files of 64 MB or more are downloaded as up to four parallel byte ranges, which spreads decryption across CPU cores and helps on high-latency links.

By default, only one pull is allowed per session, after which the session is automatically terminated and the files are no longer available. This can be overridden with the `-n <number>` flag to allow multiple pulls per session.

### Manage peers

By default, `stage pull` probes all online Tailscale peers. You can also add peers by IP or hostname for machines not on Tailscale. Hostnames are looked up on every pull, which suits networks such as corporate VPNs where a machine's name stays fixed but its IP changes:

```
stage peers                     # list Tailscale peers and any configured extras
stage peers add 192.168.1.50    # add a peer by IP
stage peers add build-box.corp.example.com   # add a peer by hostname
stage peers add 203.0.113.5     # public address: refused unless public connections are enabled
stage peers remove 192.168.1.50 # remove a peer
```

Extra peers are stored in `~/.stage/peers.json` and probed alongside Tailscale peers on every `stage pull`. `stage pull <hostname>` also works for a one-off pull.

### Other commands

```
stage status                        # show what's staged, pulls remaining, and source host
stage status 192.168.1.42           # check a specific host
stage clear                         # cancel the active staging session
stage update                        # upgrade to the latest version
stage provision                     # print a one-liner to configure a new machine
```

## Security

### Encryption

All traffic, including over Tailscale and on loopback, is carried over TLS 1.3 using a pre-shared key (TLS-PSK) derived from your shared token. This needs no certificates and no extra dependencies; it uses Python's built-in `ssl` module.

- Files and the token are never sent in cleartext, so a plain LAN or an internet connection (`--public`, UPnP) is as private as Tailscale.
- Both sides prove they know the token during the handshake. A machine with the wrong token, or a port scanner, fails the handshake and never reaches the HTTP layer.
- The key exchange uses ephemeral (EC)DHE, so recorded traffic cannot be decrypted later even if the token leaks.

Machines running a version of `stage` from before encryption was added cannot talk to newer ones. Run `stage update` on every machine.

### Default behavior: private networks only

By default, `stage` only accepts connections from private IP ranges:

- RFC 1918 (10.x, 172.16.x, 192.168.x)
- Tailscale / CGNAT (100.64.0.0/10)
- Loopback and link-local

A connection from a public IP is rejected with 403 before authentication is even attempted. This means the token is never tested against requests from the internet unless you explicitly opt in with `--public`. **If you decide to opt in, ensure you know what you are doing.**

### Token authentication

The token is a 32-character random hex string generated at setup and shared across your machines. It is the source of the TLS key (see Encryption), and every request also carries it as a `Bearer` token in the `Authorization` header, inside the encrypted channel. The token is stored in `~/.config/stage/config.toml`, which is written with `0600` permissions.

### What happens if someone gets your token?

If an attacker obtains the token and can reach the daemon on the network, they can:

- List staged files and their sizes
- Download staged files
- Post to `/cancel` and end the session early

They cannot: execute code, write files, browse the filesystem beyond what is explicitly staged, or do anything persistent -- the daemon exits as soon as all pulls are consumed or the session is cancelled.

The blast radius is limited to whatever you have staged at that moment. Nothing is exposed between sessions.

If you are on a Tailscale network and your Tailscale credentials are not compromised, this is not a practical attack -- the daemon is unreachable from the internet by default. The token matters most if you use `--public` on an untrusted network, in which case it is the only layer of authentication. Because the token never crosses the network, it cannot be sniffed; it can only leak from a machine's config file.

### Public connections (off by default)

Everything that involves the public internet is disabled until you enable it on that machine, either by answering yes in `stage setup` or with `stage setup ... --allow-public`. This sets `allow_public = true` in the config. While it is off:

- `stage --public` is refused, so the daemon never accepts public connections and UPnP never opens a port. The daemon also re-checks the setting itself.
- Your public IP is never looked up or displayed.
- `stage pull` and `stage peers add` refuse hosts that resolve only to public addresses. Hostnames are resolved first, and the pull connects to the address that passed the check.

`stage provision` deliberately does not copy this setting to new machines; each machine opts in on its own. Use `--no-allow-public` to turn it off again.

### `--public` flag

By default, `stage` binds to all interfaces (`0.0.0.0`) but rejects connections from public IPs at the application layer. If public connections are enabled and you want to stage for someone outside your private network:

```
stage --public largefile.zip
```

This prints a warning and enables connections from any source IP. Traffic is still encrypted, but only use this on networks where you are comfortable with the token being the sole protection. On a home or office network with a properly configured NAT firewall, the risk is low. On open public Wi-Fi, it is not recommended.

### Archive extraction safety

Directories are transferred as tar streams (uncompressed by default, multithreaded zstd with `-z`). Extraction uses `tarfile.data_filter` (Python 3.12+), which blocks path traversal attacks (e.g., `../../etc/passwd`). Absolute symlinks and symlinks pointing outside the destination are silently skipped. On Windows, entries matching reserved device names (CON, NUL, COM1-COM9, LPT1-LPT9) are also skipped.

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

- Python 3.14+ (with the standard OpenSSL-backed `ssl` module, which provides TLS-PSK)
- [uv](https://github.com/astral-sh/uv) (for installation)
- Tailscale (optional, but required for zero-config peer discovery; not required for encryption)
