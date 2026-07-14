// setup / update / provision commands plus the background update-check logic.

use std::io::Write;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{self, DEFAULT_PORT, UPDATE_INTERVAL};
use crate::platform;
use crate::util;

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn prompt(msg: &str) -> String {
    print!("{}", msg);
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    line.trim().to_string()
}

fn gen_token() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("system randomness unavailable");
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

// --- setup -------------------------------------------------------------------

pub fn setup(args: &[String]) {
    let die = util::die;
    let mut provided_token: Option<String> = None;
    let mut provided_port: Option<u16> = None;
    let mut provided_repo: Option<String> = None;
    let mut provided_public_ip: Option<bool> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--token" if i + 1 < args.len() => {
                provided_token = Some(args[i + 1].clone());
                i += 2;
            }
            "--port" if i + 1 < args.len() => {
                match args[i + 1].parse::<u16>() {
                    Ok(p) => provided_port = Some(p),
                    Err(_) => die(&format!("Invalid port: {}", args[i + 1])),
                }
                i += 2;
            }
            "--repo" if i + 1 < args.len() => {
                provided_repo = Some(args[i + 1].clone());
                i += 2;
            }
            "--public-ip" => {
                provided_public_ip = Some(true);
                i += 1;
            }
            other => die(&format!("Unknown argument: {}", other)),
        }
    }

    let non_interactive = provided_token.is_some() && provided_port.is_some();
    let config_path = config::config_path();
    if let Some(parent) = config_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let existing_cfg = config::load_config().ok();
    if config_path.exists() && !non_interactive {
        println!("Config exists at {}", config_path.display());
        if prompt("Reconfigure? [y/N] ").to_lowercase() != "y" {
            return;
        }
    }

    // Port.
    let port = if let Some(p) = provided_port {
        p
    } else {
        let default_port = existing_cfg.as_ref().map(|c| c.port).unwrap_or(DEFAULT_PORT);
        let input = prompt(&format!("Port [{}]: ", default_port));
        if input.is_empty() {
            default_port
        } else {
            input.parse().unwrap_or(default_port)
        }
    };

    // Token.
    let token = if let Some(t) = provided_token {
        t
    } else {
        let mut existing_token = existing_cfg
            .as_ref()
            .map(|c| c.token.clone())
            .unwrap_or_default();
        if !existing_token.is_empty() {
            println!("Existing token: {}", existing_token);
            if prompt("Keep existing token? [Y/n] ").to_lowercase() == "n" {
                existing_token.clear();
            }
        }
        if existing_token.is_empty() {
            existing_token = gen_token();
            println!("Generated token: {}", existing_token);
            println!("Copy this token when configuring other machines.");
        }
        existing_token
    };

    // Repo.
    let repo = if let Some(r) = provided_repo {
        r
    } else if !non_interactive {
        let existing_repo = existing_cfg
            .as_ref()
            .map(|c| c.repo.clone())
            .unwrap_or_default();
        let p = if !existing_repo.is_empty() {
            format!("Repo URL for update checks [{}]: ", existing_repo)
        } else {
            "Repo URL for update checks (leave blank to skip): ".to_string()
        };
        let input = prompt(&p);
        if input.is_empty() {
            existing_repo
        } else {
            input
        }
    } else {
        existing_cfg.as_ref().map(|c| c.repo.clone()).unwrap_or_default()
    };

    // public_ip_check.
    let public_ip_check = if let Some(v) = provided_public_ip {
        v
    } else if !non_interactive {
        let current = existing_cfg
            .as_ref()
            .map(|c| c.public_ip_check)
            .unwrap_or(false);
        let default = if current { "Y/n" } else { "y/N" };
        let ans = prompt(&format!(
            "Show public IP for internet connections? [{}]: ",
            default
        ))
        .to_lowercase();
        if ans.is_empty() {
            current
        } else {
            ans == "y"
        }
    } else {
        existing_cfg
            .as_ref()
            .map(|c| c.public_ip_check)
            .unwrap_or(false)
    };

    let repo_line = if !repo.is_empty() {
        format!("\nrepo = \"{}\"", repo)
    } else {
        String::new()
    };
    let pub_line = if public_ip_check {
        "\npublic_ip_check = true"
    } else {
        ""
    };
    let contents = format!(
        "[stage]\nport = {}\ntoken = \"{}\"{}{}\n",
        port, token, repo_line, pub_line
    );
    if std::fs::write(&config_path, contents).is_err() {
        die("Failed to write config");
    }
    platform::chmod_600(&config_path);
    println!("Config saved to {}", config_path.display());

    if !non_interactive {
        let repo_flag = if !repo.is_empty() {
            format!(" --repo {}", repo)
        } else {
            String::new()
        };
        let pub_flag = if public_ip_check { " --public-ip" } else { "" };
        println!("\nTo configure another machine:");
        println!(
            "  stage setup --token {} --port {}{}{}",
            token, port, repo_flag, pub_flag
        );
    }
}

// --- update ------------------------------------------------------------------

pub fn update() {
    let die = util::die;
    let out = util::out();
    let state = config::load_update_state();
    let old_sha = state.installed_sha.clone();

    println!("Upgrading {}...", out.bold("stage"));
    let status = Command::new("uv").args(["tool", "upgrade", "stage"]).status();
    match status {
        Ok(s) if s.success() => {}
        _ => die("Update failed. Is 'uv' in your PATH?"),
    }

    if let Some(repo) = config::load_repo() {
        if let Some(new_sha) = remote_sha(&repo) {
            let mut state = config::load_update_state();
            state.installed_sha = Some(new_sha.clone());
            state.latest_sha = Some(new_sha.clone());
            state.last_checked = now_secs();
            config::save_update_state(&state);
            if let Some(old) = old_sha {
                if old != new_sha {
                    if let Some(changes) = github_changelog(&repo, &old, &new_sha) {
                        print_panel("What's new", &changes);
                    }
                }
            }
        }
    }
}

fn print_panel(title: &str, body: &str) {
    let out = util::out();
    let width = body
        .lines()
        .map(|l| visible_len(l))
        .chain(std::iter::once(title.len() + 2))
        .max()
        .unwrap_or(0)
        + 2;
    let top = format!("╭─ {} {}╮", out.green(title), "─".repeat(width.saturating_sub(title.len() + 3)));
    println!("{}", top);
    for line in body.lines() {
        let pad = width.saturating_sub(visible_len(line) + 1);
        println!("│ {}{}│", line, " ".repeat(pad));
    }
    println!("╰{}╯", "─".repeat(width + 1));
}

/// Length of a string ignoring ANSI escape sequences.
fn visible_len(s: &str) -> usize {
    let mut len = 0;
    let mut in_escape = false;
    for c in s.chars() {
        if in_escape {
            if c == 'm' {
                in_escape = false;
            }
        } else if c == '\x1b' {
            in_escape = true;
        } else {
            len += 1;
        }
    }
    len
}

// --- provision ---------------------------------------------------------------

pub fn provision() {
    let die = util::die;
    let cfg = match config::load_config() {
        Ok(c) => c,
        Err(e) => die(&e),
    };
    if cfg.repo.is_empty() {
        die("No repo configured. Run 'stage setup' and set a repo URL first.");
    }
    let url = install_url(&cfg.repo);
    let pub_flag = if cfg.public_ip_check {
        " --public-ip"
    } else {
        ""
    };
    println!(
        "uv tool install {} && stage setup --token {} --port {} --repo {}{}",
        url, cfg.token, cfg.port, cfg.repo, pub_flag
    );
}

// --- update checks -----------------------------------------------------------

pub fn maybe_check_updates() {
    if !config::config_path().exists() {
        return;
    }
    let repo = match config::load_repo() {
        Some(r) => r,
        None => return,
    };
    let state = config::load_update_state();
    if let (Some(latest), Some(installed)) = (&state.latest_sha, &state.installed_sha) {
        if latest != installed {
            let err = util::err();
            eprintln!(
                "{}",
                err.yellow("A new version of stage is available. Run 'stage update'.")
            );
        }
    }
    if now_secs() - state.last_checked > UPDATE_INTERVAL {
        platform::spawn_update_check(&repo);
    }
}

pub fn do_update_check(repo: &str) {
    let sha = match remote_sha(repo) {
        Some(s) => s,
        None => return,
    };
    let mut state = config::load_update_state();
    state.latest_sha = Some(sha.clone());
    state.last_checked = now_secs();
    if state.installed_sha.is_none() {
        state.installed_sha = Some(sha);
    }
    config::save_update_state(&state);
}

pub fn remote_sha(repo: &str) -> Option<String> {
    let out = Command::new("git")
        .args(["ls-remote", repo, "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.split_whitespace().next().map(|s| s.to_string())
}

fn parse_github(url: &str) -> Option<(String, String)> {
    let rest = url
        .strip_prefix("git@github.com:")
        .or_else(|| url.strip_prefix("git+ssh://git@github.com/"))
        .or_else(|| url.strip_prefix("https://github.com/"))?;
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    let mut it = rest.splitn(2, '/');
    let owner = it.next()?;
    let repo = it.next()?;
    let repo = repo.split('/').next().unwrap_or(repo);
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner.to_string(), repo.to_string()))
}

fn install_url(repo_url: &str) -> String {
    if let Some(rest) = repo_url.strip_prefix("git@github.com:") {
        let rest = rest.strip_suffix(".git").unwrap_or(rest);
        return format!("git+ssh://git@github.com/{}", rest);
    }
    repo_url.to_string()
}

fn github_api_base(repo_url: &str) -> Option<String> {
    let (owner, repo) = parse_github(repo_url)?;
    Some(format!("https://api.github.com/repos/{}/{}", owner, repo))
}

fn github_changelog(repo_url: &str, old_sha: &str, new_sha: &str) -> Option<String> {
    let api_base = github_api_base(repo_url)?;
    let old7 = &old_sha[..old_sha.len().min(7)];
    let new7 = &new_sha[..new_sha.len().min(7)];
    let url = format!("{}/compare/{}...{}", api_base, old7, new7);
    let resp = ureq::get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "stage-cli")
        .config()
        .timeout_global(Some(std::time::Duration::from_secs(5)))
        .build()
        .call()
        .ok()?;
    let text = resp.into_body().read_to_string().ok()?;
    let data: serde_json::Value = serde_json::from_str(&text).ok()?;
    let commits = data.get("commits")?.as_array()?;
    if commits.is_empty() {
        return None;
    }
    let out = util::out();
    let mut lines = Vec::new();
    for c in commits.iter().rev() {
        let msg = c
            .get("commit")
            .and_then(|c| c.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .lines()
            .next()
            .unwrap_or("");
        let sha = c.get("sha").and_then(|s| s.as_str()).unwrap_or("");
        let sha7 = &sha[..sha.len().min(7)];
        lines.push(format!("{} {}", out.dim(sha7), msg));
    }
    Some(lines.join("\n"))
}
