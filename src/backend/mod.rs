// ─── Firewalld Backend ──────────────────────────────────────────────────────
//
// Communicates with firewalld through `firewall-cmd`. The process must already
// be running as root — the app does not escalate via sudo.
//
// Notes:
// - firewall-cmd only accepts `--opt=value` (value glued to the option),
//   never `--opt value`.
// - Zone details are fetched with a single `--list-all` per zone, in
//   parallel, to keep refreshes fast.
// - Service details (ports + description) are loaded in the background by
//   `ServiceLoader` because there are hundreds of services.

pub mod error;

pub use error::*;

use crate::types::{ConfigMode, ForwardPort, PortEntry, Service, Zone};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// How long a single `firewall-cmd` may run before we treat it as hung and
/// kill it. Without this, a firewalld/D-Bus stall freezes the whole TUI.
const CMD_TIMEOUT: Duration = Duration::from_secs(4);

/// Check if firewalld is running
pub fn is_firewalld_running() -> bool {
    Command::new("pgrep")
        .arg("-x")
        .arg("firewalld")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ─── Command runner ─────────────────────────────────────────────────────────

// The most recent `firewall-cmd …` command line run by this thread.
// The TUI reads this right after a mutation to echo the exact command.
thread_local! {
    static LAST_COMMAND: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Return the command line of the last `run_firewall_cmd` call (if any).
pub fn last_command() -> Option<String> {
    LAST_COMMAND.with(|c| c.borrow().clone())
}

/// Run `firewall-cmd <args>` and return trimmed stdout.
///
/// `mode` is prepended as `--permanent` when set; `None` (or runtime mode)
/// means a plain runtime call.
fn run_firewall_cmd(mode: Option<ConfigMode>, args: &[&str]) -> Result<String> {
    let mut full: Vec<&str> = Vec::new();
    if let Some(m) = mode {
        if let Some(flag) = m.flag() {
            full.push(flag);
        }
    }
    full.extend_from_slice(args);

    LAST_COMMAND.with(|c| *c.borrow_mut() = Some(format!("firewall-cmd {}", full.join(" "))));

    let mut child = Command::new("firewall-cmd")
        .args(&full)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FirewalldError::FirewalldNotInstalled
            } else {
                FirewalldError::CommandFailed(format!("failed to run firewall-cmd: {e}"))
            }
        })?;

    let pid = child.id() as i32;
    // Put the child in its own process group so a timeout can kill the whole
    // group (firewall-cmd), not just the parent.
    unsafe {
        libc::setpgid(pid, pid);
    }
    let mut stdout_pipe = child.stdout.take().expect("stdout is piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr is piped");

    // Drain both pipes in a worker thread (avoids a deadlock on a full pipe
    // buffer) and report the result over a channel so the main thread can
    // time it out instead of blocking forever.
    let (tx, rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut out = Vec::new();
        let mut err = Vec::new();
        stdout_pipe.read_to_end(&mut out).ok();
        drop(stdout_pipe);
        stderr_pipe.read_to_end(&mut err).ok();
        drop(stderr_pipe);
        let success = child.wait().map(|s| s.success()).unwrap_or(false);
        let _ = tx.send((success, out, err));
    });

    let (success, out, err) = match rx.recv_timeout(CMD_TIMEOUT) {
        Ok(v) => v,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Hung: kill the whole process group and report a clean timeout.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            return Err(FirewalldError::Timeout(CMD_TIMEOUT.as_secs()));
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = worker.join();
            return Err(FirewalldError::CommandFailed(
                "firewall-cmd worker thread failed".into(),
            ));
        }
    };

    if !success {
        let stdout = String::from_utf8_lossy(&out);
        let stderr = String::from_utf8_lossy(&err);
        let msg = format!("{stdout}{stderr}").trim().to_string();
        return Err(FirewalldError::CommandFailed(if msg.is_empty() {
            "firewall-cmd exited with a non-zero status".to_string()
        } else {
            msg
        }));
    }

    Ok(String::from_utf8_lossy(&out).trim().to_string())
}

// ─── Parsing helpers ────────────────────────────────────────────────────────

fn split_ws(s: &str) -> Vec<String> {
    s.split_whitespace().map(|x| x.to_string()).collect()
}

/// Parse `80/tcp 443/tcp 53/udp` style output
pub fn parse_ports(output: &str) -> Vec<PortEntry> {
    output
        .split_whitespace()
        .filter_map(|p| {
            let mut it = p.splitn(2, '/');
            let port = it.next()?.to_string();
            let protocol = it.next().unwrap_or("tcp").to_string();
            (!port.is_empty()).then_some(PortEntry { port, protocol })
        })
        .collect()
}

/// Parse `port=8080:proto=tcp:toport=80:toaddr=127.0.0.1`
fn parse_forward_port(s: &str) -> Option<ForwardPort> {
    let mut port = None;
    let mut proto = None;
    let mut to_port = None;
    let mut to_addr = None;
    for part in s.split(':') {
        if let Some(v) = part.strip_prefix("port=") {
            port = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("proto=") {
            proto = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("toport=") {
            to_port = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("toaddr=") {
            to_addr = Some(v.to_string());
        }
    }
    match (port, proto) {
        (Some(p), Some(pr)) => Some(ForwardPort {
            port: p,
            protocol: pr,
            to_port,
            to_addr,
        }),
        _ => None,
    }
}

/// Parse the output of `firewall-cmd --zone=X --list-all`
fn parse_list_all(zone_name: &str, output: &str) -> Zone {
    let mut zone = Zone {
        name: zone_name.to_string(),
        is_default: false,
        is_active: false,
        target: "default".to_string(),
        interfaces: Vec::new(),
        sources: Vec::new(),
        icmp_services: Vec::new(),
        icmp_blocks: Vec::new(),
        ports: Vec::new(),
        services: Vec::new(),
        masquerade: false,
        forward: false,
        forward_port: Vec::new(),
        source_ports: Vec::new(),
        protocols: Vec::new(),
        rich_rules: Vec::new(),
    };

    // Header line: "public (default, active)"
    if let Some(first) = output.lines().next() {
        zone.is_default = first.contains("default");
        zone.is_active = first.contains("active");
    }

    let mut section: Option<&'static str> = None;
    for line in output.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Continuation lines (forward-ports, rich rules) are tab-indented.
        if line.starts_with('\t') {
            match section {
                Some("forward-ports") => {
                    if let Some(fp) = parse_forward_port(trimmed) {
                        zone.forward_port.push(fp);
                    }
                }
                Some("rich rules") => zone.rich_rules.push(trimmed.to_string()),
                _ => {}
            }
            continue;
        }
        let Some(pos) = trimmed.find(':') else {
            continue;
        };
        let key = trimmed[..pos].trim();
        let value = trimmed[pos + 1..].trim();
        section = match key {
            "target" => {
                zone.target = value.to_string();
                None
            }
            "interfaces" => {
                zone.interfaces = split_ws(value);
                None
            }
            "sources" => {
                zone.sources = split_ws(value);
                None
            }
            "services" => {
                zone.services = split_ws(value);
                None
            }
            "ports" => {
                zone.ports = parse_ports(value);
                None
            }
            "source-ports" => {
                zone.source_ports = parse_ports(value);
                None
            }
            "protocols" => {
                zone.protocols = split_ws(value);
                None
            }
            "forward" => {
                zone.forward = value == "yes";
                None
            }
            "masquerade" => {
                zone.masquerade = value == "yes";
                None
            }
            "icmp-blocks" => {
                zone.icmp_blocks = split_ws(value);
                None
            }
            "icmp-services" => {
                zone.icmp_services = split_ws(value);
                None
            }
            "forward-ports" => Some("forward-ports"),
            "rich rules" => Some("rich rules"),
            _ => None,
        };
    }

    zone
}

// ─── Zones ──────────────────────────────────────────────────────────────────

/// List all zone names for the given mode (`None` = runtime)
pub fn zone_names(mode: Option<ConfigMode>) -> Result<Vec<String>> {
    let output = run_firewall_cmd(mode, &["--get-zones"])?;
    Ok(split_ws(&output))
}

/// Load all zones for the given mode (one parallel `--list-all` per zone)
pub fn load_zones(mode: Option<ConfigMode>) -> Result<Vec<Zone>> {
    let names = Arc::new(zone_names(mode)?);
    let mut handles = Vec::with_capacity(names.len());
    for name in names.iter() {
        let name = Arc::new(name.clone());
        handles.push(thread::spawn(move || {
            let out = run_firewall_cmd(mode, &[&format!("--zone={name}"), "--list-all"]);
            out.map(|o| parse_list_all(&name, &o))
        }));
    }
    let mut zones = Vec::with_capacity(handles.len());
    for h in handles {
        let res = h
            .join()
            .map_err(|_| FirewalldError::CommandFailed("zone loader thread panicked".into()))?;
        zones.push(res?);
    }
    Ok(zones)
}

/// Get the default zone name
pub fn get_default_zone() -> Result<String> {
    run_firewall_cmd(None, &["--get-default-zone"])
}

/// Set the default zone.
///
/// `--set-default-zone` is a firewalld **stand-alone** option: it cannot be
/// combined with `--permanent` (firewall-cmd rejects it with
/// "Can't use stand-alone options with other options"), and it inherently
/// writes the permanent config (`firewalld.conf` `DefaultZone`) and reloads,
/// so the mode flag has no effect here. Run it bare regardless of mode.
pub fn set_default_zone(zone: &str, _mode: ConfigMode) -> Result<()> {
    run_firewall_cmd(None, &[&format!("--set-default-zone={zone}")])?;
    Ok(())
}

/// Extract the first `<tag>…</tag>` body from a firewalld XML document.
fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

/// Map each zone name to its human-readable short description, read directly
/// from firewalld's zone XML files (built-in and user-defined). Prefers the
/// `<short>` caption and falls back to `<description>` when it is absent.
///
/// Reading the files on disk (rather than calling `firewall-cmd --get-description`
/// per zone) keeps the cost at a few small file reads and avoids one subprocess
/// per zone. Files that are unreadable or malformed are simply skipped.
pub fn load_zone_descriptions() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for dir in ["/usr/lib/firewalld/zones", "/etc/firewalld/zones"] {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("xml") {
                continue;
            }
            let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };
            let desc = xml_tag(&contents, "short")
                .or_else(|| xml_tag(&contents, "description"))
                .map(|d| d.split_whitespace().collect::<Vec<_>>().join(" "))
                .unwrap_or_default();
            if !desc.is_empty() {
                map.insert(name.to_string(), desc);
            }
        }
    }
    map
}

fn validate_zone_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !ok {
        return Err(FirewalldError::InvalidInput(format!(
            "invalid zone name '{name}' (use lowercase letters, digits, '-' or '_')"
        )));
    }
    Ok(())
}

/// Create a new zone (permanent configuration)
pub fn new_zone(name: &str) -> Result<()> {
    validate_zone_name(name)?;
    run_firewall_cmd(
        Some(ConfigMode::Permanent),
        &[&format!("--new-zone={name}")],
    )?;
    Ok(())
}

/// Delete a zone (permanent configuration)
pub fn delete_zone(name: &str) -> Result<()> {
    run_firewall_cmd(
        Some(ConfigMode::Permanent),
        &[&format!("--delete-zone={name}")],
    )?;
    Ok(())
}

// ─── Ports / Services / Rules / Forwarding / Masquerade ────────────────────

fn validate_port(port: &str) -> Result<()> {
    let ok = !port.is_empty()
        && port
            .split('-')
            .all(|p| !p.is_empty() && p.len() <= 5 && p.chars().all(|c| c.is_ascii_digit()));
    if !ok {
        return Err(FirewalldError::InvalidInput(format!(
            "invalid port '{port}' (use digits or a range like 8000-8010)"
        )));
    }
    Ok(())
}

fn validate_protocol(protocol: &str) -> Result<()> {
    if protocol != "tcp" && protocol != "udp" {
        return Err(FirewalldError::InvalidInput(format!(
            "invalid protocol '{protocol}' (use tcp or udp)"
        )));
    }
    Ok(())
}

/// Add a port to a zone
pub fn add_port(zone: &str, port: &str, protocol: &str, mode: ConfigMode) -> Result<()> {
    validate_port(port)?;
    validate_protocol(protocol)?;
    run_firewall_cmd(
        Some(mode),
        &[
            &format!("--zone={zone}"),
            &format!("--add-port={port}/{protocol}"),
        ],
    )?;
    Ok(())
}

/// Remove a port from a zone
pub fn remove_port(zone: &str, port: &str, protocol: &str, mode: ConfigMode) -> Result<()> {
    run_firewall_cmd(
        Some(mode),
        &[
            &format!("--zone={zone}"),
            &format!("--remove-port={port}/{protocol}"),
        ],
    )?;
    Ok(())
}

/// Add a service to a zone
pub fn add_service(zone: &str, service: &str, mode: ConfigMode) -> Result<()> {
    run_firewall_cmd(
        Some(mode),
        &[
            &format!("--zone={zone}"),
            &format!("--add-service={service}"),
        ],
    )?;
    Ok(())
}

/// Remove a service from a zone
pub fn remove_service(zone: &str, service: &str, mode: ConfigMode) -> Result<()> {
    run_firewall_cmd(
        Some(mode),
        &[
            &format!("--zone={zone}"),
            &format!("--remove-service={service}"),
        ],
    )?;
    Ok(())
}

/// Add a rich rule to a zone
pub fn add_rich_rule(zone: &str, rule: &str, mode: ConfigMode) -> Result<()> {
    if !rule.starts_with("rule") {
        return Err(FirewalldError::InvalidInput(
            "rich rule must start with 'rule'".to_string(),
        ));
    }
    run_firewall_cmd(
        Some(mode),
        &[
            &format!("--zone={zone}"),
            &format!("--add-rich-rule={rule}"),
        ],
    )?;
    Ok(())
}

/// Remove a rich rule from a zone
pub fn remove_rich_rule(zone: &str, rule: &str, mode: ConfigMode) -> Result<()> {
    run_firewall_cmd(
        Some(mode),
        &[
            &format!("--zone={zone}"),
            &format!("--remove-rich-rule={rule}"),
        ],
    )?;
    Ok(())
}

fn forward_port_spec(port: &str, protocol: &str, to_port: &str, to_addr: &str) -> Result<String> {
    validate_port(port)?;
    validate_protocol(protocol)?;
    if !to_port.is_empty() {
        validate_port(to_port)?;
    }
    let mut spec = format!("port={port}:proto={protocol}");
    if !to_port.is_empty() {
        spec.push_str(&format!(":toport={to_port}"));
    }
    if !to_addr.is_empty() {
        spec.push_str(&format!(":toaddr={to_addr}"));
    }
    Ok(spec)
}

/// Add a port forwarding rule to a zone
pub fn add_forward_port(
    zone: &str,
    port: &str,
    protocol: &str,
    to_port: &str,
    to_addr: &str,
    mode: ConfigMode,
) -> Result<()> {
    let spec = forward_port_spec(port, protocol, to_port, to_addr)?;
    run_firewall_cmd(
        Some(mode),
        &[
            &format!("--zone={zone}"),
            &format!("--add-forward-port={spec}"),
        ],
    )?;
    Ok(())
}

/// Remove a port forwarding rule from a zone
pub fn remove_forward_port(
    zone: &str,
    port: &str,
    protocol: &str,
    to_port: &str,
    to_addr: &str,
    mode: ConfigMode,
) -> Result<()> {
    let spec = forward_port_spec(port, protocol, to_port, to_addr)?;
    run_firewall_cmd(
        Some(mode),
        &[
            &format!("--zone={zone}"),
            &format!("--remove-forward-port={spec}"),
        ],
    )?;
    Ok(())
}

/// Enable or disable masquerading on a zone
pub fn set_masquerade(zone: &str, enabled: bool, mode: ConfigMode) -> Result<()> {
    let op = if enabled {
        "--add-masquerade"
    } else {
        "--remove-masquerade"
    };
    run_firewall_cmd(Some(mode), &[&format!("--zone={zone}"), op])?;
    Ok(())
}

/// Reload firewalld (applies permanent configuration to runtime)
pub fn reload() -> Result<()> {
    run_firewall_cmd(None, &["--reload"])?;
    Ok(())
}

/// Query firewalld's panic mode (runtime). `--query-panic` signals the answer
/// through the exit status (0 = on, 1 = off) rather than stdout, so this reads
/// the status directly instead of treating a non-zero exit as an error.
pub fn get_panic_state() -> bool {
    Command::new("firewall-cmd")
        .arg("--query-panic")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Enable or disable panic mode (runtime only). While enabled, firewalld drops
/// ALL traffic — including established SSH sessions — so callers should always
/// confirm with the user first.
pub fn set_panic(on: bool) -> Result<()> {
    run_firewall_cmd(None, &[if on { "--panic-on" } else { "--panic-off" }])?;
    Ok(())
}

/// The interface carrying the default route, per `ip route show default`
/// (best-effort; `None` when the `ip` tool is unavailable or there is no
/// default route). Used by the lockout guard to tell which zone the current
/// remote session's traffic actually traverses.
pub fn default_route_interface() -> Option<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // e.g. "default via 10.0.0.1 dev eth0 proto dhcp metric 100"
    for line in stdout.lines() {
        let mut it = line.split_whitespace();
        while let Some(tok) = it.next() {
            if tok == "dev" {
                if let Some(iface) = it.next() {
                    return Some(iface.to_string());
                }
            }
        }
    }
    None
}

/// Load a single zone's full config in the given mode (`None` = runtime).
pub fn load_zone(name: &str, mode: Option<ConfigMode>) -> Result<Zone> {
    let out = run_firewall_cmd(mode, &[&format!("--zone={name}"), "--list-all"])?;
    Ok(parse_list_all(name, &out))
}

// ─── ICMP blocks / Sources / Target / Forward policy ───────────────────────

fn validate_icmp(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !ok {
        return Err(FirewalldError::InvalidInput(format!(
            "invalid icmp-block name '{name}' (use lowercase letters, digits, '-')"
        )));
    }
    Ok(())
}

/// Add an icmp-block to a zone
pub fn add_icmp_block(zone: &str, icmp: &str, mode: ConfigMode) -> Result<()> {
    validate_icmp(icmp)?;
    run_firewall_cmd(
        Some(mode),
        &[
            &format!("--zone={zone}"),
            &format!("--add-icmp-block={icmp}"),
        ],
    )?;
    Ok(())
}

/// Remove an icmp-block from a zone
pub fn remove_icmp_block(zone: &str, icmp: &str, mode: ConfigMode) -> Result<()> {
    run_firewall_cmd(
        Some(mode),
        &[
            &format!("--zone={zone}"),
            &format!("--remove-icmp-block={icmp}"),
        ],
    )?;
    Ok(())
}

/// Add a source (IP or CIDR) to a zone
pub fn add_source(zone: &str, source: &str, mode: ConfigMode) -> Result<()> {
    if source.trim().is_empty() {
        return Err(FirewalldError::InvalidInput("source is required".into()));
    }
    run_firewall_cmd(
        Some(mode),
        &[&format!("--zone={zone}"), &format!("--add-source={source}")],
    )?;
    Ok(())
}

/// Remove a source (IP or CIDR) from a zone
pub fn remove_source(zone: &str, source: &str, mode: ConfigMode) -> Result<()> {
    run_firewall_cmd(
        Some(mode),
        &[
            &format!("--zone={zone}"),
            &format!("--remove-source={source}"),
        ],
    )?;
    Ok(())
}

/// Add a source port to a zone (traffic originating from this port)
pub fn add_source_port(zone: &str, port: &str, protocol: &str, mode: ConfigMode) -> Result<()> {
    if port.trim().is_empty() {
        return Err(FirewalldError::InvalidInput("port is required".into()));
    }
    run_firewall_cmd(
        Some(mode),
        &[
            &format!("--zone={zone}"),
            &format!("--add-source-port={port}/{protocol}"),
        ],
    )?;
    Ok(())
}

/// Remove a source port from a zone
pub fn remove_source_port(zone: &str, port: &str, protocol: &str, mode: ConfigMode) -> Result<()> {
    run_firewall_cmd(
        Some(mode),
        &[
            &format!("--zone={zone}"),
            &format!("--remove-source-port={port}/{protocol}"),
        ],
    )?;
    Ok(())
}

fn validate_protocol_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !ok {
        return Err(FirewalldError::InvalidInput(format!(
            "invalid protocol name '{name}' (use lowercase letters, digits, '-' or '_')"
        )));
    }
    Ok(())
}

/// Add a zone-level protocol to a zone (e.g. ah, esp, sctp, ipip)
pub fn add_protocol(zone: &str, protocol: &str, mode: ConfigMode) -> Result<()> {
    validate_protocol_name(protocol)?;
    run_firewall_cmd(
        Some(mode),
        &[
            &format!("--zone={zone}"),
            &format!("--add-protocol={protocol}"),
        ],
    )?;
    Ok(())
}

/// Remove a zone-level protocol from a zone
pub fn remove_protocol(zone: &str, protocol: &str, mode: ConfigMode) -> Result<()> {
    validate_protocol_name(protocol)?;
    run_firewall_cmd(
        Some(mode),
        &[
            &format!("--zone={zone}"),
            &format!("--remove-protocol={protocol}"),
        ],
    )?;
    Ok(())
}

fn validate_target(target: &str) -> Result<()> {
    if !matches!(target, "default" | "reject" | "drop") {
        return Err(FirewalldError::InvalidInput(format!(
            "invalid target '{target}' (use default, reject, or drop)"
        )));
    }
    Ok(())
}

/// Set a zone's target (default / reject / drop)
pub fn set_zone_target(zone: &str, target: &str, mode: ConfigMode) -> Result<()> {
    validate_target(target)?;
    run_firewall_cmd(
        Some(mode),
        &[&format!("--zone={zone}"), &format!("--set-target={target}")],
    )?;
    Ok(())
}

/// Set a zone's forward policy (yes / no)
pub fn set_zone_forward(zone: &str, enabled: bool, mode: ConfigMode) -> Result<()> {
    // firewalld has no `--set-forward`; forwarding is toggled with
    // `--add-forward` / `--remove-forward`.
    let op = if enabled {
        "--add-forward"
    } else {
        "--remove-forward"
    };
    run_firewall_cmd(Some(mode), &[&format!("--zone={zone}"), op])?;
    Ok(())
}

// ─── Interface bindings ─────────────────────────────────────────────────────

/// Validate an interface name (alphanumeric, dot, dash, underscore; max 15 chars).
fn validate_interface(iface: &str) -> Result<()> {
    let ok = !iface.is_empty()
        && iface.len() <= 15
        && iface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
    if !ok {
        return Err(FirewalldError::InvalidInput(format!(
            "invalid interface name '{iface}'"
        )));
    }
    Ok(())
}

/// List the system's network interfaces (from `/sys/class/net`), sorted.
pub fn list_system_interfaces() -> Result<Vec<String>> {
    let entries = std::fs::read_dir("/sys/class/net").map_err(|e| {
        FirewalldError::CommandFailed(format!("failed to read /sys/class/net: {e}"))
    })?;
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().to_string()))
        .collect();
    names.sort();
    Ok(names)
}

/// Map each interface to its primary IPv4 address, using `ip -4 -o addr show`.
///
/// The `-o` (oneline) format puts one address per line:
///   `2: enp1s0f0    inet 192.168.1.10/24 brd ... scope global enp1s0f0`
/// Interfaces without an IPv4 address are omitted. Reading addresses does not
/// require root.
pub fn get_interface_ips() -> Result<HashMap<String, String>> {
    let output = Command::new("ip")
        .args(["-4", "-o", "addr", "show"])
        .output()
        .map_err(FirewalldError::from)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ips: HashMap<String, String> = HashMap::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // parts: [ "2:", "enp1s0f0", "inet", "192.168.1.10/24", ... ]
        if parts.len() >= 4 && parts[2] == "inet" {
            let iface = parts[1];
            let ip = parts[3].split('/').next().unwrap_or("");
            if !ip.is_empty() {
                // Keep only the first IPv4 address per interface.
                ips.entry(iface.to_string())
                    .or_insert_with(|| ip.to_string());
            }
        }
    }
    Ok(ips)
}

/// Return the zone an interface is bound to, or `None` if unbound.
///
/// `firewall-cmd --get-zone-of-interface` exits non-zero when the interface is
/// unbound (while still printing "no zone"), so we read stdout directly instead
/// of treating a non-zero exit as an error.
pub fn get_zone_of_interface(iface: &str) -> Result<Option<String>> {
    let output = Command::new("firewall-cmd")
        .args([&format!("--get-zone-of-interface={iface}")])
        .output()
        .map_err(FirewalldError::from)?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() || stdout == "no zone" {
        Ok(None)
    } else {
        Ok(Some(stdout))
    }
}

/// Assign an interface to a zone.
///
/// Uses `--change-interface`, which works whether the interface is currently
/// unbound or bound to a different zone (it moves it).
pub fn assign_interface(zone: &str, iface: &str, mode: ConfigMode) -> Result<()> {
    validate_interface(iface)?;
    run_firewall_cmd(
        Some(mode),
        &[
            &format!("--zone={zone}"),
            &format!("--change-interface={iface}"),
        ],
    )?;
    Ok(())
}

/// Remove an interface's binding from a zone.
pub fn remove_interface(zone: &str, iface: &str, mode: ConfigMode) -> Result<()> {
    run_firewall_cmd(
        Some(mode),
        &[
            &format!("--zone={zone}"),
            &format!("--remove-interface={iface}"),
        ],
    )?;
    Ok(())
}

// ─── Services ───────────────────────────────────────────────────────────────

/// Load all available service names (fast, single call)
pub fn load_service_names() -> Result<Vec<String>> {
    let output = run_firewall_cmd(None, &["--get-services"])?;
    Ok(split_ws(&output))
}

fn load_service_details(name: &str) -> Option<Service> {
    let description = run_firewall_cmd(
        Some(ConfigMode::Permanent),
        &[&format!("--service={name}"), "--get-description"],
    )
    .unwrap_or_default();
    let ports = run_firewall_cmd(
        Some(ConfigMode::Permanent),
        &[&format!("--service={name}"), "--get-ports"],
    )
    .map(|out| parse_ports(&out))
    .unwrap_or_default();
    Some(Service {
        name: name.to_string(),
        ports,
        description,
    })
}

/// Background loader that fills in service details (ports + description).
///
/// There are hundreds of services, so details are fetched off the main
/// thread; `poll` collects whatever has finished without blocking.
pub struct ServiceLoader {
    rx: Receiver<Service>,
}

impl ServiceLoader {
    pub fn start(names: Vec<String>, workers: usize) -> Self {
        let (tx, rx) = mpsc::channel();
        let queue: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(names.into_iter().collect()));
        for _ in 0..workers {
            let tx = tx.clone();
            let queue = Arc::clone(&queue);
            thread::spawn(move || loop {
                let name = queue.lock().unwrap().pop_front();
                let Some(name) = name else {
                    break;
                };
                if let Some(svc) = load_service_details(&name) {
                    let _ = tx.send(svc);
                }
            });
        }
        drop(tx);
        Self { rx }
    }

    /// Collect all completed service details.
    /// Returns false once every worker has finished.
    pub fn poll(&self, into: &mut HashMap<String, Service>) -> bool {
        loop {
            match self.rx.try_recv() {
                Ok(svc) => {
                    into.insert(svc.name.clone(), svc);
                }
                Err(TryRecvError::Empty) => return true,
                Err(TryRecvError::Disconnected) => return false,
            }
        }
    }
}
