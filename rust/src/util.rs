// Small pure helpers: human sizes, unique paths, directory stats, percent
// encoding, and terminal styling.

use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

pub fn human_size(n: f64) -> String {
    let mut n = n;
    for unit in ["B", "KB", "MB", "GB"] {
        if n < 1024.0 {
            return format!("{:.1} {}", n, unit);
        }
        n /= 1024.0;
    }
    format!("{:.1} TB", n)
}

/// Return (total_bytes, file_count) via a stat-only walk (no file reads).
pub fn dir_stats(path: &Path) -> (u64, u64) {
    let mut size = 0u64;
    let mut count = 0u64;
    fn walk(p: &Path, size: &mut u64, count: &mut u64) {
        let rd = match fs::read_dir(p) {
            Ok(rd) => rd,
            Err(_) => return,
        };
        for entry in rd.flatten() {
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_dir() {
                walk(&entry.path(), size, count);
            } else if ft.is_file() {
                if let Ok(m) = entry.metadata() {
                    *size += m.len();
                    *count += 1;
                }
            }
        }
    }
    walk(path, &mut size, &mut count);
    (size, count)
}

/// If `path` is free, return it; otherwise append _1, _2, ... before the suffix.
pub fn unique_path(path: &Path) -> PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let suffix = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    for i in 1..1000 {
        let candidate = parent.join(format!("{}_{}{}", stem, i, suffix));
        if !candidate.exists() {
            return candidate;
        }
    }
    path.to_path_buf()
}

// --- Percent encoding (matches urllib.parse.quote(safe="") / unquote) --------

pub fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}

pub fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// --- Terminal styling --------------------------------------------------------

fn wrap(s: &str, code: &str, on: bool) -> String {
    if on {
        format!("\x1b[{}m{}\x1b[0m", code, s)
    } else {
        s.to_string()
    }
}

/// A styler bound to whether its target stream is a terminal.
pub struct Styler {
    pub on: bool,
}

impl Styler {
    pub fn bold(&self, s: &str) -> String {
        wrap(s, "1", self.on)
    }
    pub fn dim(&self, s: &str) -> String {
        wrap(s, "2", self.on)
    }
    pub fn red(&self, s: &str) -> String {
        wrap(s, "31", self.on)
    }
    pub fn green(&self, s: &str) -> String {
        wrap(s, "32", self.on)
    }
    pub fn yellow(&self, s: &str) -> String {
        wrap(s, "33", self.on)
    }
    pub fn cyan(&self, s: &str) -> String {
        wrap(s, "36", self.on)
    }
}

pub fn out() -> Styler {
    Styler {
        on: std::io::stdout().is_terminal(),
    }
}

/// Print an error to stderr and exit with status 1.
pub fn die(msg: &str) -> ! {
    let e = err();
    eprintln!("{}", e.red(&format!("stage: {}", msg)));
    std::process::exit(1);
}

pub fn err() -> Styler {
    Styler {
        on: std::io::stderr().is_terminal(),
    }
}
