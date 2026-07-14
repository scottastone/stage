// Paths, on-disk config, peers list, update state, and the file/manifest model.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DEFAULT_PORT: u16 = 47200;
pub const PROBE_TIMEOUT_SECS: u64 = 3;
pub const UPDATE_INTERVAL: f64 = 86400.0;

fn home() -> PathBuf {
    #[allow(deprecated)]
    std::env::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

pub fn stage_dir() -> PathBuf {
    home().join(".stage")
}
pub fn config_path() -> PathBuf {
    home().join(".config").join("stage").join("config.toml")
}
pub fn pid_file() -> PathBuf {
    stage_dir().join("daemon.pid")
}
pub fn manifest_file() -> PathBuf {
    stage_dir().join("manifest.json")
}
pub fn update_file() -> PathBuf {
    stage_dir().join("update.json")
}
pub fn peers_file() -> PathBuf {
    stage_dir().join("peers.json")
}
pub fn upnp_file() -> PathBuf {
    stage_dir().join("upnp.json")
}

// --- Config ------------------------------------------------------------------

#[derive(Deserialize)]
struct ConfigFile {
    stage: StageConfig,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

#[derive(Deserialize, Clone)]
pub struct StageConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub repo: String,
    #[serde(default)]
    pub public_ip_check: bool,
}

/// Load the [stage] config, or an error message suitable for `die`.
pub fn load_config() -> Result<StageConfig, String> {
    let path = config_path();
    if !path.exists() {
        return Err("No config found. Run 'stage setup' first.".into());
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read config: {}", e))?;
    let cfg: ConfigFile =
        toml::from_str(&text).map_err(|e| format!("Failed to parse config: {}", e))?;
    Ok(cfg.stage)
}

/// Load only the configured repo, ignoring any error (used for update checks).
pub fn load_repo() -> Option<String> {
    load_config().ok().and_then(|c| {
        if c.repo.is_empty() {
            None
        } else {
            Some(c.repo)
        }
    })
}

// --- Peers -------------------------------------------------------------------

pub fn load_peers() -> Vec<String> {
    let path = peers_file();
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(v) = serde_json::from_str::<Vec<String>>(&text) {
            return v;
        }
    }
    Vec::new()
}

pub fn save_peers(peers: &[String]) {
    let _ = std::fs::create_dir_all(stage_dir());
    if let Ok(text) = serde_json::to_string(peers) {
        let _ = std::fs::write(peers_file(), text);
    }
}

// --- Update state ------------------------------------------------------------

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct UpdateState {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub installed_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub latest_sha: Option<String>,
    #[serde(default)]
    pub last_checked: f64,
}

pub fn load_update_state() -> UpdateState {
    if let Ok(text) = std::fs::read_to_string(update_file()) {
        if let Ok(v) = serde_json::from_str::<UpdateState>(&text) {
            return v;
        }
    }
    UpdateState::default()
}

pub fn save_update_state(state: &UpdateState) {
    let _ = std::fs::create_dir_all(stage_dir());
    if let Ok(text) = serde_json::to_string(state) {
        let _ = std::fs::write(update_file(), text);
    }
}

// --- File entries / manifest -------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct Entry {
    pub name: String,
    #[serde(rename = "type", default = "default_type")]
    pub entry_type: String,
    #[serde(default)]
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub file_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub path: Option<String>,
}

fn default_type() -> String {
    "file".into()
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        self.entry_type == "dir"
    }

    /// The manifest/status view: name, type, size, and file_count (no path).
    pub fn meta(&self) -> Entry {
        Entry {
            name: self.name.clone(),
            entry_type: self.entry_type.clone(),
            size: self.size,
            file_count: self.file_count,
            path: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Manifest {
    pub files: Vec<Entry>,
    #[serde(default)]
    pub compress: bool,
}

pub fn read_manifest() -> Result<Manifest, String> {
    let text = std::fs::read_to_string(manifest_file())
        .map_err(|e| format!("Failed to read manifest: {}", e))?;
    serde_json::from_str(&text).map_err(|e| format!("Failed to parse manifest: {}", e))
}

pub fn write_manifest(m: &Manifest) {
    let _ = std::fs::create_dir_all(stage_dir());
    if let Ok(text) = serde_json::to_string_pretty(m) {
        let _ = std::fs::write(manifest_file(), text);
    }
}
