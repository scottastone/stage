// Platform / network glue: private-IP classification, local & public IP
// discovery, Tailscale peer enumeration, process liveness, and daemon spawn.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::config;

/// Networks considered "private" for default access control. Mirrors the Python
/// list: loopback, RFC 1918, CGNAT/Tailscale, link-local, and IPv6 equivalents.
pub fn is_private_ip(addr: &str) -> bool {
    let ip: IpAddr = match addr.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // 127.0.0.0/8
    if o[0] == 127 {
        return true;
    }
    // 10.0.0.0/8
    if o[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if o[0] == 172 && (16..=31).contains(&o[1]) {
        return true;
    }
    // 192.168.0.0/16
    if o[0] == 192 && o[1] == 168 {
        return true;
    }
    // 100.64.0.0/10 (CGNAT / Tailscale)
    if o[0] == 100 && (o[1] & 0xC0) == 0x40 {
        return true;
    }
    // 169.254.0.0/16 (link-local)
    if o[0] == 169 && o[1] == 254 {
        return true;
    }
    false
}

fn is_private_v6(ip: Ipv6Addr) -> bool {
    if ip == Ipv6Addr::LOCALHOST {
        return true; // ::1/128
    }
    let s = ip.segments();
    // fc00::/7 -> first 7 bits are 1111110
    if (s[0] & 0xFE00) == 0xFC00 {
        return true;
    }
    // fe80::/10 -> first 10 bits 1111111010
    if (s[0] & 0xFFC0) == 0xFE80 {
        return true;
    }
    false
}

/// Best-effort single local IPv4 address (the one used to reach the internet).
pub fn local_ips() -> Vec<String> {
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => {
            if sock.connect("8.8.8.8:80").is_ok() {
                if let Ok(addr) = sock.local_addr() {
                    return vec![addr.ip().to_string()];
                }
            }
            Vec::new()
        }
        Err(_) => Vec::new(),
    }
}

/// Public IPv4 via ipify. Returns None on any failure.
pub fn public_ip() -> Option<String> {
    let resp = ureq::get("https://api4.ipify.org")
        .config()
        .timeout_global(Some(Duration::from_secs(3)))
        .build()
        .call()
        .ok()?;
    let body = resp.into_body().read_to_string().ok()?;
    let trimmed = body.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// (local_ipv4, peers) where peers is a list of (ipv4, hostname).
pub fn tailscale_info() -> (Option<String>, Vec<(String, String)>) {
    let output = Command::new("tailscale")
        .args(["status", "--json"])
        .output();
    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return (None, Vec::new()),
    };
    let data: serde_json::Value = match serde_json::from_slice(&output.stdout) {
        Ok(v) => v,
        Err(_) => return (None, Vec::new()),
    };

    let mut local_ip = None;
    if let Some(ips) = data
        .get("Self")
        .and_then(|s| s.get("TailscaleIPs"))
        .and_then(|v| v.as_array())
    {
        for ip in ips {
            if let Some(s) = ip.as_str() {
                if !s.contains(':') {
                    local_ip = Some(s.to_string());
                    break;
                }
            }
        }
    }

    let mut peers = Vec::new();
    if let Some(peer_map) = data.get("Peer").and_then(|v| v.as_object()) {
        for peer in peer_map.values() {
            if !peer.get("Online").and_then(|v| v.as_bool()).unwrap_or(false) {
                continue;
            }
            let hostname = peer
                .get("HostName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if let Some(ips) = peer.get("TailscaleIPs").and_then(|v| v.as_array()) {
                for ip in ips {
                    if let Some(s) = ip.as_str() {
                        if !s.contains(':') {
                            peers.push((s.to_string(), hostname.clone()));
                            break;
                        }
                    }
                }
            }
        }
    }
    (local_ip, peers)
}

// --- Process management ------------------------------------------------------

#[cfg(unix)]
pub fn proc_alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

#[cfg(unix)]
pub fn proc_terminate(pid: i32) {
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
}

#[cfg(windows)]
pub fn proc_alive(pid: i32) -> bool {
    let out = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid), "/NH"])
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()),
        Err(_) => false,
    }
}

#[cfg(windows)]
pub fn proc_terminate(pid: i32) {
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .output();
}

pub fn is_daemon_running() -> bool {
    let path = config::pid_file();
    if !path.exists() {
        return false;
    }
    match std::fs::read_to_string(&path) {
        Ok(text) => match text.trim().parse::<i32>() {
            Ok(pid) => proc_alive(pid),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

// --- Daemon spawn ------------------------------------------------------------

/// Spawn the background staging daemon (`stage _serve <port> <n> <public>`)
/// detached from the current session. Returns the child PID.
pub fn spawn_daemon(port: u16, n: u32, public: bool) -> std::io::Result<u32> {
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.arg("_serve")
        .arg(port.to_string())
        .arg(n.to_string())
        .arg(if public { "1" } else { "0" })
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                // Detach from the controlling terminal / session so Ctrl+C in
                // the parent shell does not reach the daemon.
                libc::setsid();
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }

    let child = cmd.spawn()?;
    Ok(child.id())
}

/// Spawn a detached `stage _check <repo>` background update probe.
pub fn spawn_update_check(repo: &str) {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut cmd = Command::new(exe);
    cmd.arg("_check")
        .arg(repo)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
    let _ = cmd.spawn();
}

/// Parse a `host[:port]` argument into (host, port), mirroring _base_url.
pub fn parse_host(host_str: &str, default_port: u16) -> (String, u16) {
    if let Some(idx) = host_str.rfind(':') {
        let (h, p) = host_str.split_at(idx);
        let p = &p[1..];
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (host_str.to_string(), default_port)
}

/// Restrict a file to owner read/write (0600) on unix; no-op elsewhere.
pub fn chmod_600(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}
