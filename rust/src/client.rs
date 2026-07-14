// User-facing commands: stage, pull, status, and peer management, plus session
// discovery over Tailscale peers and direct hosts.

use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use flate2::read::GzDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;

use crate::config::{self, Entry, Manifest, PROBE_TIMEOUT_SECS};
use crate::http;
use crate::platform::{self, parse_host};
use crate::upnp;
use crate::util::{self, human_size, pct_encode, unique_path};

fn die(msg: &str) -> ! {
    let err = util::err();
    eprintln!("{}", err.red(&format!("stage: {}", msg)));
    std::process::exit(1);
}

fn auth(token: &str) -> String {
    format!("Bearer {}", token)
}

#[derive(Deserialize, Default)]
struct ManifestResp {
    #[serde(default)]
    files: Vec<Entry>,
    #[serde(default)]
    compress: bool,
    #[serde(default)]
    pulls_remaining: Option<i64>,
}

struct Session {
    host: String,
    port: u16,
    label: String,
    resp: ManifestResp,
}

// --- Session discovery -------------------------------------------------------

fn probe_manifest(
    host: &str,
    port: u16,
    token: &str,
    timeout: Duration,
) -> Option<ManifestResp> {
    let hdr = auth(token);
    let resp = http::request(
        "GET",
        host,
        port,
        "/manifest",
        &[("Authorization", &hdr)],
        None,
        timeout,
        Some(timeout),
    )
    .ok()?;
    if resp.status != 200 {
        return None;
    }
    let bytes = resp.read_to_vec().ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn find_session(host_arg: Option<&str>, quiet: bool) -> Option<Session> {
    let cfg = config::load_config().unwrap_or_else(|e| die(&e));
    let port = cfg.port;
    let token = cfg.token;
    let probe_to = Duration::from_secs(PROBE_TIMEOUT_SECS);

    if let Some(arg) = host_arg {
        let (host, hport) = parse_host(arg, port);
        match probe_manifest(&host, hport, &token, probe_to) {
            Some(resp) => {
                return Some(Session {
                    host,
                    port: hport,
                    label: arg.to_string(),
                    resp,
                })
            }
            None => {
                if !quiet {
                    die(&format!("No active session reachable at {}", arg));
                }
                return None;
            }
        }
    }

    let (_local, ts_peers) = platform::tailscale_info();
    let hostname_map: std::collections::HashMap<String, String> =
        ts_peers.iter().cloned().map(|(ip, h)| (ip, h)).collect();
    let extra = config::load_peers();
    let mut all_peers: Vec<String> = ts_peers.iter().map(|(ip, _)| ip.clone()).collect();
    all_peers.extend(extra);

    if all_peers.is_empty() {
        if !quiet {
            die("No Tailscale peers found and no extra peers configured.\nFor a direct connection: stage pull <host>[:<port>]");
        }
        return None;
    }

    let (tx, rx) = mpsc::channel();
    for ip in all_peers {
        let tx = tx.clone();
        let token = token.clone();
        thread::spawn(move || {
            if let Some(resp) = probe_manifest(&ip, port, &token, probe_to) {
                let _ = tx.send((ip, resp));
            }
        });
    }
    drop(tx);

    match rx.recv_timeout(Duration::from_secs(PROBE_TIMEOUT_SECS + 1)) {
        Ok((ip, resp)) => {
            let hostname = hostname_map.get(&ip).cloned().unwrap_or_default();
            let label = if hostname.is_empty() {
                ip.clone()
            } else {
                format!("{} ({})", hostname, ip)
            };
            Some(Session {
                host: ip,
                port,
                label,
                resp,
            })
        }
        Err(_) => {
            if !quiet {
                die("No active staging session found on any reachable peer.\nFor a direct connection: stage pull <host>[:<port>]");
            }
            None
        }
    }
}

// --- Table printing ----------------------------------------------------------

fn print_file_table(rows: &[(String, String)]) {
    let out = util::out();
    let name_w = rows.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
    for (name, size) in rows {
        if size.is_empty() {
            println!("  {}", name);
        } else {
            println!("  {:<width$}  {}", name, out.cyan(size), width = name_w);
        }
    }
}

// --- stage -------------------------------------------------------------------

pub fn stage(paths: &[String], n: u32, public: bool, compress: bool, quiet: bool) {
    let out = util::out();
    let mut files: Vec<Entry> = Vec::new();

    for p in paths {
        let path = Path::new(p);
        if !path.exists() {
            die(&format!("Not found: {}", p));
        }
        let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let name = abs
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        if abs.is_dir() {
            if !quiet {
                eprint!("Sizing {}/...\r", name);
                let _ = std::io::stderr().flush();
            }
            let (size, file_count) = util::dir_stats(&abs);
            if !quiet {
                eprint!("\x1b[2K");
                println!(
                    "Staged {} ({}, {} files)",
                    out.bold(&format!("{}/", name)),
                    out.cyan(&human_size(size as f64)),
                    file_count
                );
            }
            files.push(Entry {
                name,
                entry_type: "dir".into(),
                size,
                file_count: Some(file_count),
                path: Some(abs.to_string_lossy().into_owned()),
            });
        } else if abs.is_file() {
            let size = abs.metadata().map(|m| m.len()).unwrap_or(0);
            files.push(Entry {
                name,
                entry_type: "file".into(),
                size,
                file_count: None,
                path: Some(abs.to_string_lossy().into_owned()),
            });
        } else {
            die(&format!("Not a file or directory: {}", p));
        }
    }

    let cfg = config::load_config().unwrap_or_else(|e| die(&e));
    let port = cfg.port;

    // Amend an already-running session instead of erroring.
    if platform::is_daemon_running() {
        let body = serde_json::to_vec(&serde_json::json!({ "files": files })).unwrap();
        let hdr = auth(&cfg.token);
        let res = http::request(
            "POST",
            "127.0.0.1",
            port,
            "/amend",
            &[
                ("Authorization", &hdr),
                ("Content-Type", "application/json"),
            ],
            Some(&body),
            Duration::from_secs(10),
            Some(Duration::from_secs(10)),
        );
        match res {
            Ok(r) if r.status == 200 => {}
            Ok(r) => die(&format!("Failed to amend active session: HTTP {}", r.status)),
            Err(e) => die(&format!("Failed to amend active session: {}", e)),
        }
        if !quiet {
            for f in &files {
                let indicator = if f.is_dir() { "/" } else { "" };
                println!(
                    "Amended: {}  {}",
                    out.bold(&format!("{}{}", f.name, indicator)),
                    out.cyan(&human_size(f.size as f64))
                );
            }
        }
        return;
    }

    let _ = std::fs::create_dir_all(config::stage_dir());
    config::write_manifest(&Manifest {
        files: files.clone(),
        compress,
    });

    let pid = match platform::spawn_daemon(port, n, public) {
        Ok(pid) => pid,
        Err(e) => die(&format!("Failed to start staging server: {}", e)),
    };
    let _ = std::fs::write(config::pid_file(), pid.to_string());

    // Wait for the daemon to come up.
    let mut up = false;
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(250));
        if http::request(
            "GET",
            "127.0.0.1",
            port,
            "/health",
            &[],
            None,
            Duration::from_secs(1),
            Some(Duration::from_secs(1)),
        )
        .map(|r| r.status == 200)
        .unwrap_or(false)
        {
            up = true;
            break;
        }
    }
    if !up && !platform::is_daemon_running() {
        let _ = std::fs::remove_file(config::manifest_file());
        let _ = std::fs::remove_file(config::pid_file());
        die(&format!(
            "Failed to start staging server. Is port {} already in use?",
            port
        ));
    }

    // Run UPnP forwarding and public-IP lookup concurrently.
    let upnp_rx = if public {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(upnp::try_forward(port));
        });
        Some(rx)
    } else {
        None
    };
    let pubip_rx = if cfg.public_ip_check {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(platform::public_ip());
        });
        Some(rx)
    } else {
        None
    };
    let upnp_info = upnp_rx
        .and_then(|rx| rx.recv_timeout(Duration::from_secs(5)).ok())
        .flatten();
    let pub_ip = pubip_rx
        .and_then(|rx| rx.recv_timeout(Duration::from_secs(5)).ok())
        .flatten();

    if let Some(info) = &upnp_info {
        if let Ok(text) = serde_json::to_string(info) {
            let _ = std::fs::write(config::upnp_file(), text);
        }
    }

    if quiet {
        return;
    }

    let total: u64 = files.iter().map(|f| f.size).sum();
    let names = files
        .iter()
        .map(|f| format!("{}{}", f.name, if f.is_dir() { "/" } else { "" }))
        .collect::<Vec<_>>()
        .join(", ");
    let pull_s = if n == 1 { "pull" } else { "pulls" };
    let compress_note = if compress {
        format!(" {}", out.dim("(compressed)"))
    } else {
        String::new()
    };
    println!(
        "\nStaged: {} ({}, {} {} allowed){}\n",
        out.bold(&names),
        out.cyan(&human_size(total as f64)),
        n,
        pull_s,
        compress_note
    );

    if public {
        println!(
            "{}\n",
            out.yellow("Warning: --public is set. Connections from any IP address will be accepted. Only use this on networks you trust.")
        );
    }

    let (ts_ip, _ts_peers) = platform::tailscale_info();
    let local_ips: Vec<String> = platform::local_ips()
        .into_iter()
        .filter(|ip| Some(ip) != ts_ip.as_ref())
        .collect();

    if ts_ip.is_some() {
        println!("  Via Tailscale:  {}", out.bold("stage pull"));
    }
    for ip in &local_ips {
        println!(
            "  Direct:         {}",
            out.bold(&format!("stage pull {}:{}", ip, port))
        );
    }

    if let Some(u) = &upnp_info {
        println!(
            "  Internet:       {}  {}",
            out.bold(&format!("stage pull {}:{}", u.external_ip, u.external_port)),
            out.green("(UPnP port forwarded)")
        );
    } else if let Some(ip) = &pub_ip {
        if public {
            println!(
                "  Public IP:      {}  {}",
                out.bold(&format!("stage pull {}:{}", ip, port)),
                out.dim("(check firewall / NAT)")
            );
        } else {
            println!(
                "  Public IP:      {}",
                out.dim(&format!("{}:{} (add --public to accept)", ip, port))
            );
        }
    }

    if public && upnp_info.is_none() {
        if !upnp::available() {
            println!(
                "  UPnP:           {}",
                out.dim("not enabled -- rebuild with the upnp feature to enable")
            );
        } else {
            println!(
                "  UPnP:           {}",
                out.dim("no compatible router found")
            );
        }
    }

    if ts_ip.is_none() && local_ips.is_empty() && pub_ip.is_none() && upnp_info.is_none() {
        println!(
            "  {}",
            out.bold(&format!("stage pull <this-machine-ip>:{}", port))
        );
    }
}

// --- pull --------------------------------------------------------------------

pub fn pull(host_arg: Option<&str>) {
    let out = util::out();
    let err = util::err();
    let session = match find_session(host_arg, false) {
        Some(s) => s,
        None => return,
    };
    let cfg = config::load_config().unwrap_or_else(|e| die(&e));
    let token = cfg.token;
    let compress = session.resp.compress;
    let file_entries = &session.resp.files;

    if file_entries.is_empty() {
        println!("Nothing staged.");
        let _ = post(&session, &token, "/done");
        return;
    }

    println!("From {}:", out.bold(&session.label));
    let rows: Vec<(String, String)> = file_entries
        .iter()
        .map(|e| {
            let indicator = if e.is_dir() { "/" } else { "" };
            (format!("{}{}", e.name, indicator), human_size(e.size as f64))
        })
        .collect();
    print_file_table(&rows);

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    // Pre-assign destinations sequentially to avoid name-collision races.
    let assignments: Vec<(Entry, PathBuf)> = file_entries
        .iter()
        .map(|e| (e.clone(), unique_path(&cwd.join(&e.name))))
        .collect();

    let parallel = assignments.len() > 1;
    let print_lock = Arc::new(Mutex::new(()));
    let errors = Arc::new(Mutex::new(Vec::<String>::new()));
    let queue = Arc::new(Mutex::new(assignments.into_iter().collect::<Vec<_>>()));
    let host = session.host.clone();
    let port = session.port;

    let n_workers = 4.min(file_entries.len()).max(1);
    let mut handles = Vec::new();
    for _ in 0..n_workers {
        let queue = Arc::clone(&queue);
        let errors = Arc::clone(&errors);
        let print_lock = Arc::clone(&print_lock);
        let token = token.clone();
        let host = host.clone();
        handles.push(thread::spawn(move || loop {
            let task = {
                let mut q = queue.lock().unwrap();
                q.pop()
            };
            let (entry, dest) = match task {
                Some(t) => t,
                None => break,
            };
            if let Err(name) = fetch(
                &host,
                port,
                &token,
                &entry,
                &dest,
                compress,
                !parallel,
                &print_lock,
            ) {
                errors.lock().unwrap().push(name);
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }

    let errors = Arc::try_unwrap(errors).unwrap().into_inner().unwrap();
    if errors.is_empty() {
        let remaining = post(&session, &token, "/done")
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|v| v.get("pulls_remaining").and_then(|r| r.as_i64()))
            .unwrap_or(0);
        let n = file_entries.len();
        let suffix = if remaining > 0 {
            format!(
                " {}",
                out.dim(&format!(
                    "({} pull{} remaining)",
                    remaining,
                    if remaining != 1 { "s" } else { "" }
                ))
            )
        } else {
            format!(" {}", out.dim("Session closed."))
        };
        println!(
            "\nPulled {} item{}.{}",
            out.bold(&n.to_string()),
            if n != 1 { "s" } else { "" },
            suffix
        );
    } else {
        eprintln!(
            "{}",
            err.red("Some items failed. Session remains open for retry.")
        );
        std::process::exit(1);
    }
}

fn post(session: &Session, token: &str, path: &str) -> std::io::Result<Vec<u8>> {
    let hdr = auth(token);
    let resp = http::request(
        "POST",
        &session.host,
        session.port,
        path,
        &[("Authorization", &hdr)],
        Some(b""),
        Duration::from_secs(10),
        Some(Duration::from_secs(10)),
    )?;
    resp.read_to_vec()
}

#[allow(clippy::too_many_arguments)]
fn fetch(
    host: &str,
    port: u16,
    token: &str,
    entry: &Entry,
    dest: &Path,
    compress: bool,
    show_progress: bool,
    print_lock: &Mutex<()>,
) -> Result<(), String> {
    let name = &entry.name;
    let hdr = auth(token);
    let encoded = pct_encode(name);
    let resp = http::request(
        "GET",
        host,
        port,
        &format!("/files/{}", encoded),
        &[("Authorization", &hdr)],
        None,
        Duration::from_secs(30),
        Some(Duration::from_secs(300)),
    )
    .map_err(|_| name.clone())?;
    if resp.status != 200 {
        return Err(name.clone());
    }
    let content_length = resp.content_length();
    let body = resp.into_body();

    if entry.is_dir() {
        extract_dir(
            body,
            dest,
            name,
            compress,
            entry,
            show_progress,
            print_lock,
        )
        .map_err(|_| name.clone())?;
        let out = util::out();
        let rename = if dest.file_name().map(|s| s.to_string_lossy().into_owned())
            != Some(name.clone())
        {
            format!(" -> {}/", dest.file_name().unwrap_or_default().to_string_lossy())
        } else {
            String::new()
        };
        let _g = print_lock.lock().unwrap();
        println!("  extracted {}{}", out.bold(&format!("{}/", name)), rename);
        Ok(())
    } else {
        let total = if compress { None } else { content_length };
        if compress {
            let reader = GzDecoder::new(body);
            download_file(reader, dest, name, None, show_progress, print_lock)
                .map_err(|_| name.clone())
        } else {
            download_file(body, dest, name, total, show_progress, print_lock)
                .map_err(|_| name.clone())
        }
    }
}

fn make_bar(total: Option<u64>, name: &str, show: bool) -> ProgressBar {
    if !show {
        return ProgressBar::hidden();
    }
    match total {
        Some(t) => {
            let bar = ProgressBar::new(t);
            bar.set_style(
                ProgressStyle::with_template(
                    "{msg} {bytes}/{total_bytes} [{bar:20}] {bytes_per_sec}",
                )
                .unwrap()
                .progress_chars("=> "),
            );
            bar.set_message(name.to_string());
            bar
        }
        None => {
            let bar = ProgressBar::new_spinner();
            bar.set_style(
                ProgressStyle::with_template("{msg} {bytes} {bytes_per_sec}").unwrap(),
            );
            bar.set_message(name.to_string());
            bar
        }
    }
}

fn download_file<R: Read>(
    mut reader: R,
    dest: &Path,
    name: &str,
    total: Option<u64>,
    show_progress: bool,
    print_lock: &Mutex<()>,
) -> std::io::Result<()> {
    let out = util::out();
    let bar = make_bar(total, name, show_progress);
    let start = Instant::now();
    let mut downloaded: u64 = 0;
    let mut file = std::fs::File::create(dest)?;
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])?;
        downloaded += n as u64;
        bar.inc(n as u64);
    }
    bar.finish_and_clear();

    let elapsed = start.elapsed().as_secs_f64().max(1e-9);
    let speed = downloaded as f64 / elapsed;
    let suffix = if dest.file_name().map(|s| s.to_string_lossy().into_owned())
        != Some(name.to_string())
    {
        format!(" -> {}", dest.file_name().unwrap_or_default().to_string_lossy())
    } else {
        String::new()
    };
    let _g = print_lock.lock().unwrap();
    println!(
        "  {}{}  {} at {}",
        name,
        suffix,
        out.cyan(&human_size(downloaded as f64)),
        out.cyan(&format!("{}/s", human_size(speed)))
    );
    Ok(())
}

struct ProgressReader<R> {
    inner: R,
    bar: ProgressBar,
}

impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bar.inc(n as u64);
        Ok(n)
    }
}

#[allow(clippy::too_many_arguments)]
fn extract_dir<R: Read>(
    body: R,
    dest: &Path,
    name: &str,
    compress: bool,
    entry: &Entry,
    show_progress: bool,
    _print_lock: &Mutex<()>,
) -> std::io::Result<()> {
    // Compressed streams have no known total, so suppress a misleading bar.
    let total = if compress { None } else { entry.size.checked_add(0) };
    let bar = make_bar(if compress { None } else { total }, name, show_progress);
    let counted = ProgressReader {
        inner: body,
        bar: bar.clone(),
    };

    let tmp = make_temp_dir(dest);
    std::fs::create_dir_all(&tmp)?;

    let result = (|| -> std::io::Result<()> {
        if compress {
            let dec = GzDecoder::new(counted);
            extract_tar(dec, &tmp)?;
        } else {
            extract_tar(counted, &tmp)?;
        }
        Ok(())
    })();

    bar.finish_and_clear();

    if let Err(e) = result {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e);
    }

    // Move extracted content into place.
    let items: Vec<PathBuf> = std::fs::read_dir(&tmp)?
        .flatten()
        .map(|e| e.path())
        .collect();
    if items.len() == 1 && items[0].is_dir() {
        move_path(&items[0], dest)?;
    } else {
        std::fs::create_dir_all(dest)?;
        for item in items {
            if let Some(fname) = item.file_name() {
                move_path(&item, &dest.join(fname))?;
            }
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

fn extract_tar<R: Read>(reader: R, dst: &Path) -> std::io::Result<u64> {
    let mut archive = tar::Archive::new(reader);
    let mut files = 0u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let et = entry.header().entry_type();

        // Skip absolute/parent-escaping links (broken across machines, unsafe).
        if et.is_symlink() || et.is_hard_link() {
            if let Ok(Some(link)) = entry.link_name() {
                let lp = link.as_ref();
                if lp.is_absolute()
                    || lp.components().any(|c| matches!(c, Component::ParentDir))
                {
                    continue;
                }
            }
            #[cfg(windows)]
            {
                continue; // symlink creation needs elevation on Windows
            }
        }

        #[cfg(windows)]
        {
            if let Ok(path) = entry.path() {
                if path.components().any(|c| is_win_reserved(c.as_os_str())) {
                    continue;
                }
            }
        }

        let is_file = et.is_file();
        // unpack_in refuses path traversal / absolute paths (returns Ok(false)).
        if entry.unpack_in(dst)? && is_file {
            files += 1;
        }
    }
    Ok(files)
}

#[cfg(windows)]
fn is_win_reserved(part: &std::ffi::OsStr) -> bool {
    let s = part.to_string_lossy().to_uppercase();
    let base = s.split('.').next().unwrap_or(&s);
    matches!(base, "CON" | "PRN" | "AUX" | "NUL")
        || (base.len() == 4
            && (base.starts_with("COM") || base.starts_with("LPT"))
            && base.as_bytes()[3].is_ascii_digit())
}

/// Move src to dst, falling back to copy+remove across filesystems.
fn move_path(src: &Path, dst: &Path) -> std::io::Result<()> {
    if std::fs::rename(src, dst).is_ok() {
        return Ok(());
    }
    if src.is_dir() {
        copy_dir_all(src, dst)?;
        std::fs::remove_dir_all(src)?;
    } else {
        std::fs::copy(src, dst)?;
        std::fs::remove_file(src)?;
    }
    Ok(())
}

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)?.flatten() {
        let path = entry.path();
        let target = dst.join(entry.file_name());
        if path.is_dir() {
            copy_dir_all(&path, &target)?;
        } else {
            std::fs::copy(&path, &target)?;
        }
    }
    Ok(())
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn make_temp_dir(near: &Path) -> PathBuf {
    let parent = near.parent().unwrap_or_else(|| Path::new("."));
    let c = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    parent.join(format!(".stage-tmp-{}-{}", pid, c))
}

// --- status ------------------------------------------------------------------

pub fn status(host_arg: Option<&str>) {
    let out = util::out();
    let session = match find_session(host_arg, true) {
        Some(s) => s,
        None => {
            println!("No active staging session found.");
            return;
        }
    };
    let pulls = session
        .resp
        .pulls_remaining
        .map(|p| p.to_string())
        .unwrap_or_else(|| "?".into());
    let entries = &session.resp.files;
    let from_str = format!(" from {}", out.bold(&session.label));
    println!(
        "{} {} item(s), {} pull(s) remaining{}",
        out.bold("Active:"),
        entries.len(),
        pulls,
        from_str
    );
    let rows: Vec<(String, String)> = entries
        .iter()
        .map(|e| {
            let indicator = if e.is_dir() { "/" } else { "" };
            (format!("{}{}", e.name, indicator), human_size(e.size as f64))
        })
        .collect();
    print_file_table(&rows);
}

// --- clear -------------------------------------------------------------------

pub fn clear() {
    if !platform::is_daemon_running() {
        println!("No active staging session.");
        return;
    }
    if let Ok(text) = std::fs::read_to_string(config::pid_file()) {
        if let Ok(pid) = text.trim().parse::<i32>() {
            platform::proc_terminate(pid);
        }
    }
    let _ = std::fs::remove_file(config::pid_file());
    let _ = std::fs::remove_file(config::manifest_file());
    println!("Staging session cleared.");
}

// --- peers -------------------------------------------------------------------

pub fn peers(args: &[String]) {
    match args.first().map(|s| s.as_str()) {
        None | Some("list") => peers_list(),
        Some("add") if args.len() > 1 => peers_add(&args[1]),
        Some("remove") if args.len() > 1 => peers_remove(&args[1]),
        _ => println!("Usage: stage peers [add <ip> | remove <ip>]"),
    }
}

fn peers_list() {
    let out = util::out();
    let (_local, ts_peers) = platform::tailscale_info();
    let extra = config::load_peers();

    if !ts_peers.is_empty() {
        println!("Tailscale peers:");
        let name_w = ts_peers
            .iter()
            .map(|(_, h)| if h.is_empty() { 7 } else { h.len() })
            .max()
            .unwrap_or(0);
        for (ip, hostname) in &ts_peers {
            let host = if hostname.is_empty() {
                out.dim("unknown")
            } else {
                out.bold(hostname)
            };
            let raw = if hostname.is_empty() { "unknown" } else { hostname };
            let pad = name_w.saturating_sub(raw.len());
            println!("  {}{}  {}", host, " ".repeat(pad), ip);
        }
    } else {
        println!("{}", out.dim("No Tailscale peers found."));
    }

    if !extra.is_empty() {
        println!("\nConfigured extra peers:");
        for ip in &extra {
            let tag = if !platform::is_private_ip(ip) {
                format!(" {}", out.yellow("(public)"))
            } else {
                String::new()
            };
            println!("  {}{}", ip, tag);
        }
    } else if ts_peers.is_empty() {
        println!("\nNo extra peers configured. Use 'stage peers add <ip>' to add one.");
    }
}

fn peers_add(ip: &str) {
    let out = util::out();
    let mut existing = config::load_peers();
    if existing.iter().any(|e| e == ip) {
        println!("{} is already in the peer list.", ip);
        return;
    }
    if !platform::is_private_ip(ip) {
        println!(
            "{}\nConnections to this peer will bypass private-network restrictions.\nMake sure you trust this host and its network.",
            out.yellow(&format!("Warning: {} appears to be a public IP address.", ip))
        );
    }
    existing.push(ip.to_string());
    config::save_peers(&existing);
    println!("Added {} to peer list.", ip);
}

fn peers_remove(ip: &str) {
    let mut existing = config::load_peers();
    if !existing.iter().any(|e| e == ip) {
        println!("{} is not in the peer list.", ip);
        return;
    }
    existing.retain(|e| e != ip);
    config::save_peers(&existing);
    println!("Removed {} from peer list.", ip);
}
