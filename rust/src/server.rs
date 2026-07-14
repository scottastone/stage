// The background staging daemon: a small threaded HTTP/1.1 server that streams
// staged files to authenticated peers. Every response sets `Connection: close`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, Once};
use std::thread;

use flate2::write::GzEncoder;
use flate2::Compression;

use crate::config::{self, Entry, Manifest};
use crate::platform;
use crate::upnp;
use crate::util::pct_decode;

struct State {
    token: String,
    entries: Mutex<Vec<Entry>>,
    compress: bool,
    pulls_remaining: Mutex<i64>,
    public: bool,
}

static SHUTDOWN: Once = Once::new();

/// Remove the UPnP mapping (if any), clean up state files, and exit.
fn shutdown() -> ! {
    SHUTDOWN.call_once(|| {
        if config::upnp_file().exists() {
            if let Ok(text) = std::fs::read_to_string(config::upnp_file()) {
                if let Ok(info) = serde_json::from_str::<upnp::UpnpInfo>(&text) {
                    upnp::remove_forward(&info);
                }
            }
            let _ = std::fs::remove_file(config::upnp_file());
        }
        let _ = std::fs::remove_file(config::manifest_file());
        let _ = std::fs::remove_file(config::pid_file());
    });
    std::process::exit(0);
}

pub fn run_daemon(port: u16, n: u32, public: bool) {
    let cfg = match config::load_config() {
        Ok(c) => c,
        Err(_) => std::process::exit(1),
    };
    let manifest = match config::read_manifest() {
        Ok(m) => m,
        Err(_) => std::process::exit(1),
    };

    let state = Arc::new(State {
        token: cfg.token,
        entries: Mutex::new(manifest.files),
        compress: manifest.compress,
        pulls_remaining: Mutex::new(n as i64),
        public,
    });

    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(_) => std::process::exit(1),
    };

    install_signal_handler();

    for conn in listener.incoming() {
        if let Ok(stream) = conn {
            let st = Arc::clone(&state);
            thread::spawn(move || {
                let _ = handle(stream, st);
            });
        }
    }
}

#[cfg(unix)]
fn install_signal_handler() {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
    thread::spawn(|| unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        let mut sig: libc::c_int = 0;
        libc::sigwait(&set, &mut sig);
        shutdown();
    });
}

#[cfg(not(unix))]
fn install_signal_handler() {}

// --- Request handling --------------------------------------------------------

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn parse_request(stream: &TcpStream) -> std::io::Result<Request> {
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse().unwrap_or(0);
            }
            headers.push((key, val));
        }
    }

    let mut body = Vec::new();
    if content_length > 0 {
        body.resize(content_length, 0);
        reader.read_exact(&mut body)?;
    }

    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        410 => "Gone",
        _ => "OK",
    }
}

fn send_simple(stream: &mut TcpStream, code: u16, ctype: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        code,
        status_text(code),
        ctype,
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn send_error(stream: &mut TcpStream, code: u16) {
    send_simple(stream, code, "text/plain", status_text(code).as_bytes());
}

fn client_ip(stream: &TcpStream) -> String {
    stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default()
}

fn allowed_client(stream: &mut TcpStream, state: &State) -> bool {
    if state.public {
        return true;
    }
    if platform::is_private_ip(&client_ip(stream)) {
        return true;
    }
    send_error(stream, 403);
    false
}

fn authed(stream: &mut TcpStream, req: &Request, state: &State) -> bool {
    let expected = format!("Bearer {}", state.token);
    if req.header("Authorization") != Some(expected.as_str()) {
        send_error(stream, 401);
        return false;
    }
    true
}

fn handle(mut stream: TcpStream, state: Arc<State>) -> std::io::Result<()> {
    let req = parse_request(&stream)?;
    if req.method == "GET" {
        handle_get(&mut stream, &req, &state);
    } else if req.method == "POST" {
        handle_post(&mut stream, &req, &state);
    } else {
        send_error(&mut stream, 404);
    }
    Ok(())
}

fn manifest_json(state: &State) -> Vec<u8> {
    let entries = state.entries.lock().unwrap();
    let files: Vec<Entry> = entries.iter().map(|e| e.meta()).collect();
    let remaining = *state.pulls_remaining.lock().unwrap();
    let body = serde_json::json!({
        "files": files,
        "pulls_remaining": remaining,
        "compress": state.compress,
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

fn handle_get(stream: &mut TcpStream, req: &Request, state: &State) {
    if req.path == "/health" {
        // Only localhost may probe; external probing would reveal the daemon.
        if client_ip(stream) == "127.0.0.1" {
            send_simple(stream, 200, "text/plain", b"ok");
        } else {
            send_error(stream, 404);
        }
        return;
    }
    if !allowed_client(stream, state) {
        return;
    }
    if !authed(stream, req, state) {
        return;
    }

    let path = pct_decode(req.path.trim_start_matches('/'));
    if path == "manifest" || path == "status" {
        let body = manifest_json(state);
        send_simple(stream, 200, "application/json", &body);
    } else if let Some(name) = path.strip_prefix("files/") {
        serve_file(stream, name, state);
    } else {
        send_error(stream, 404);
    }
}

fn serve_file(stream: &mut TcpStream, name: &str, state: &State) {
    let entry = {
        let entries = state.entries.lock().unwrap();
        entries.iter().find(|e| e.name == name).cloned()
    };
    let entry = match entry {
        Some(e) => e,
        None => {
            send_error(stream, 404);
            return;
        }
    };
    let fp = std::path::PathBuf::from(entry.path.clone().unwrap_or_default());
    if !fp.exists() {
        send_error(stream, 410);
        return;
    }
    if entry.is_dir() {
        serve_dir(stream, &fp, state.compress);
    } else {
        serve_regular_file(stream, &fp, state.compress);
    }
}

fn serve_dir(stream: &mut TcpStream, fp: &std::path::Path, compress: bool) {
    let head =
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-tar\r\nConnection: close\r\n\r\n";
    if stream.write_all(head.as_bytes()).is_err() {
        return;
    }
    let arcname = fp
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Errors here are typically client disconnects; ignore them.
    if compress {
        let gz = GzEncoder::new(&mut *stream, Compression::default());
        let mut builder = tar::Builder::new(gz);
        let _ = builder.append_dir_all(&arcname, fp);
        let _ = builder.into_inner().and_then(|gz| gz.finish());
    } else {
        let mut builder = tar::Builder::new(&mut *stream);
        let _ = builder.append_dir_all(&arcname, fp);
        let _ = builder.finish();
    }
    let _ = stream.flush();
}

fn serve_regular_file(stream: &mut TcpStream, fp: &std::path::Path, compress: bool) {
    let mut file = match std::fs::File::open(fp) {
        Ok(f) => f,
        Err(_) => {
            send_error(stream, 410);
            return;
        }
    };

    if compress {
        let head = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n";
        if stream.write_all(head.as_bytes()).is_err() {
            return;
        }
        let mut gz = GzEncoder::new(&mut *stream, Compression::default());
        let _ = std::io::copy(&mut file, &mut gz);
        let _ = gz.finish();
        let _ = stream.flush();
    } else {
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            size
        );
        if stream.write_all(head.as_bytes()).is_err() {
            return;
        }
        let mut buf = [0u8; 65536];
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if stream.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = stream.flush();
    }
}

fn handle_post(stream: &mut TcpStream, req: &Request, state: &State) {
    if !allowed_client(stream, state) {
        return;
    }
    if !authed(stream, req, state) {
        return;
    }

    if req.path == "/done" {
        let remaining = {
            let mut pr = state.pulls_remaining.lock().unwrap();
            *pr -= 1;
            *pr
        };
        let body = serde_json::json!({ "pulls_remaining": remaining });
        send_simple(
            stream,
            200,
            "application/json",
            &serde_json::to_vec(&body).unwrap_or_default(),
        );
        if remaining <= 0 {
            shutdown();
        }
    } else if req.path == "/cancel" {
        send_simple(stream, 200, "text/plain", b"cancelled");
        shutdown();
    } else if req.path == "/amend" {
        let parsed: serde_json::Value =
            serde_json::from_slice(&req.body).unwrap_or(serde_json::Value::Null);
        let new_files: Vec<Entry> = parsed
            .get("files")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let (names, snapshot) = {
            let mut entries = state.entries.lock().unwrap();
            for nf in new_files {
                if let Some(existing) = entries.iter_mut().find(|e| e.name == nf.name) {
                    *existing = nf;
                } else {
                    entries.push(nf);
                }
            }
            let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
            (names, entries.clone())
        };
        config::write_manifest(&Manifest {
            files: snapshot,
            compress: state.compress,
        });
        let body = serde_json::json!({ "files": names });
        send_simple(
            stream,
            200,
            "application/json",
            &serde_json::to_vec(&body).unwrap_or_default(),
        );
    } else {
        send_error(stream, 404);
    }
}
