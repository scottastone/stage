mod client;
mod config;
mod http;
mod platform;
mod server;
mod update;
mod upnp;
mod util;

use util as u;

fn die(msg: &str) -> ! {
    let err = u::err();
    eprintln!("{}", err.red(&format!("stage: {}", msg)));
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help") {
        usage();
        return;
    }

    let cmd = args[0].as_str();

    // Internal subcommands (spawned by the tool itself).
    if cmd == "_serve" {
        let port = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(config::DEFAULT_PORT);
        let n = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
        let public = args.get(3).map(|s| s == "1").unwrap_or(false);
        server::run_daemon(port, n, public);
        return;
    }
    if cmd == "_check" {
        if let Some(repo) = args.get(1) {
            update::do_update_check(repo);
        }
        return;
    }

    update::maybe_check_updates();

    match cmd {
        "pull" => client::pull(args.get(1).map(|s| s.as_str())),
        "status" => client::status(args.get(1).map(|s| s.as_str())),
        "peers" => client::peers(&args[1..]),
        "clear" => client::clear(),
        "update" => update::update(),
        "setup" => update::setup(&args[1..]),
        "provision" => update::provision(),
        _ => stage_command(&args),
    }
}

fn stage_command(args: &[String]) {
    let mut n: u32 = 1;
    let mut public = false;
    let mut compress = false;
    let mut quiet = false;
    let mut paths: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-n" if i + 1 < args.len() => {
                match args[i + 1].parse::<u32>() {
                    Ok(v) if v >= 1 => n = v,
                    _ => die(&format!("Invalid value for -n: {}", args[i + 1])),
                }
                i += 2;
            }
            "--public" => {
                public = true;
                i += 1;
            }
            "-z" | "--compress" => {
                compress = true;
                i += 1;
            }
            "-q" | "--quiet" => {
                quiet = true;
                i += 1;
            }
            other => {
                paths.push(other.to_string());
                i += 1;
            }
        }
    }

    if paths.is_empty() {
        usage();
        return;
    }
    client::stage(&paths, n, public, compress, quiet);
}

fn usage() {
    println!("Usage:");
    println!("  stage [-n N] [-z] [-q] [--public] <file> [files...]");
    println!("      Stage files. Appends to an active session if one exists.");
    println!("      -n N       Allow N pulls (default 1)");
    println!("      -z         Compress transfer with gzip (slower CPU, less bandwidth)");
    println!("      -q         Quiet: suppress output unless there is an error");
    println!("      --public   Accept connections from any IP (default: private/Tailscale only)");
    println!();
    println!("  stage pull [<host>[:<port>]]       Pull staged files to current directory");
    println!("  stage status [<host>[:<port>]]     Show what is staged and where");
    println!("  stage peers [add|remove <ip>]      List or manage discoverable peers");
    println!("  stage clear                        Cancel active staging session");
    println!("  stage update                       Upgrade to the latest version");
    println!("  stage provision                    Print one-liner to configure a new machine");
    println!("  stage setup                        Configure port, token, and repo");
}
