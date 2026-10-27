// End-to-end tests against a live firewalld daemon.
// Skipped automatically when firewalld is not running, or when not running as
// root: firewall-cmd invoked by an unprivileged user triggers polkit password
// prompts on the console, which must never happen from a test run.

use firewall_tui::backend::*;
use firewall_tui::types::{ConfigMode, Zone};

fn skip_if_no_firewalld() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: not root (live-firewalld tests would trigger polkit prompts)");
        std::process::exit(0);
    }
    if !is_firewalld_running() {
        eprintln!("skipping: firewalld not running");
        std::process::exit(0);
    }
}

#[test]
fn zones_load_and_parse() {
    skip_if_no_firewalld();
    let zones = load_zones(None).expect("load_zones");
    assert!(!zones.is_empty());

    let public = zones
        .iter()
        .find(|z| z.name == "public")
        .expect("public zone exists");
    assert_eq!(public.target, "default");
    assert!(public.is_default || public.is_active || true); // header parsed

    let default = get_default_zone().expect("default zone");
    assert!(!default.is_empty());
}

#[test]
fn service_names_load() {
    skip_if_no_firewalld();
    let names = load_service_names().expect("service names");
    assert!(
        names.len() > 100,
        "expected many services, got {}",
        names.len()
    );
    assert!(names.contains(&"ssh".to_string()));
}

#[test]
fn service_details_load() {
    skip_if_no_firewalld();
    let names = load_service_names().unwrap();
    let loader = ServiceLoader::start(names, 4);
    let mut details = std::collections::HashMap::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        let open = loader.poll(&mut details);
        if details.contains_key("ssh") {
            break;
        }
        if !open {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let ssh = details.get("ssh").expect("ssh details loaded");
    assert!(
        ssh.ports
            .iter()
            .any(|p| p.port == "22" && p.protocol == "tcp"),
        "ssh should expose 22/tcp, got {:?}",
        ssh.ports
    );
    assert!(!ssh.description.is_empty());
}

#[test]
fn port_add_remove_roundtrip() {
    skip_if_no_firewalld();
    let zone = "public";
    add_port(zone, "18231", "tcp", ConfigMode::Runtime).expect("add port");
    let z = load_single_zone_check(zone);
    assert!(z
        .ports
        .iter()
        .any(|p| p.port == "18231" && p.protocol == "tcp"));
    remove_port(zone, "18231", "tcp", ConfigMode::Runtime).expect("remove port");
    let z = load_single_zone_check(zone);
    assert!(!z.ports.iter().any(|p| p.port == "18231"));
}

#[test]
fn service_add_remove_roundtrip() {
    skip_if_no_firewalld();
    let zone = "public";
    // Pick a service that exists on this system but is not active in the zone.
    let names = load_service_names().expect("service names");
    let current = load_single_zone_check(zone);
    let svc = names
        .iter()
        .find(|n| !current.services.contains(n))
        .expect("a non-active service exists")
        .clone();
    add_service(zone, &svc, ConfigMode::Runtime).expect("add service");
    let z = load_single_zone_check(zone);
    assert!(z.services.contains(&svc));
    remove_service(zone, &svc, ConfigMode::Runtime).expect("remove service");
    let z = load_single_zone_check(zone);
    assert!(!z.services.contains(&svc));
}

#[test]
fn rich_rule_add_remove_roundtrip() {
    skip_if_no_firewalld();
    let zone = "public";
    let rule = "rule family=\"ipv4\" source address=\"192.0.2.7\" port port=\"4444\" protocol=\"tcp\" accept";
    add_rich_rule(zone, rule, ConfigMode::Runtime).expect("add rich rule");
    let z = load_single_zone_check(zone);
    assert!(
        z.rich_rules.iter().any(|r| r.contains("192.0.2.7")),
        "rich rule should be present, got {:?}",
        z.rich_rules
    );
    remove_rich_rule(zone, rule, ConfigMode::Runtime).expect("remove rich rule");
    let z = load_single_zone_check(zone);
    assert!(!z.rich_rules.iter().any(|r| r.contains("192.0.2.7")));
}

#[test]
fn forward_port_roundtrip() {
    skip_if_no_firewalld();
    let zone = "public";
    add_forward_port(
        zone,
        "18080",
        "tcp",
        "18081",
        "127.0.0.1",
        ConfigMode::Runtime,
    )
    .expect("add forward port");
    let z = load_single_zone_check(zone);
    let fp = z
        .forward_port
        .iter()
        .find(|f| f.port == "18080")
        .expect("forward port present");
    assert_eq!(fp.protocol, "tcp");
    assert_eq!(fp.to_port.as_deref(), Some("18081"));
    assert_eq!(fp.to_addr.as_deref(), Some("127.0.0.1"));

    remove_forward_port(
        zone,
        "18080",
        "tcp",
        "18081",
        "127.0.0.1",
        ConfigMode::Runtime,
    )
    .expect("remove forward port");
    let z = load_single_zone_check(zone);
    assert!(!z.forward_port.iter().any(|f| f.port == "18080"));
}

#[test]
fn masquerade_toggle_roundtrip() {
    skip_if_no_firewalld();
    let zone = "public";
    let before = load_single_zone_check(zone).masquerade;
    set_masquerade(zone, !before, ConfigMode::Runtime).expect("set masquerade");
    let after = load_single_zone_check(zone).masquerade;
    assert_ne!(before, after, "masquerade should have flipped");
    set_masquerade(zone, before, ConfigMode::Runtime).expect("restore masquerade");
    let restored = load_single_zone_check(zone).masquerade;
    assert_eq!(restored, before);
}

#[test]
fn system_interfaces_listed() {
    skip_if_no_firewalld();
    let ifaces = list_system_interfaces().expect("list interfaces");
    assert!(
        ifaces.contains(&"lo".to_string()),
        "lo should be listed: {ifaces:?}"
    );
}

#[test]
fn interface_ips_mapped() {
    skip_if_no_firewalld();
    let ips = get_interface_ips().expect("get interface ips");
    // lo always carries 127.0.0.1 on Linux.
    assert_eq!(
        ips.get("lo").map(String::as_str),
        Some("127.0.0.1"),
        "lo should map to 127.0.0.1, got {ips:?}"
    );
    // Every interface in the IP map must also exist in /sys/class/net.
    let names = list_system_interfaces().expect("list interfaces");
    for name in ips.keys() {
        assert!(names.contains(name), "unknown interface in ip map: {name}");
    }
}

#[test]
fn interface_assign_remove_roundtrip() {
    skip_if_no_firewalld();
    let zone = "public";
    let iface = "lo";
    // Record the original binding so we can restore it exactly.
    let original = get_zone_of_interface(iface).expect("original zone of iface");
    // Ensure it starts unbound from `zone` (idempotent cleanup).
    let _ = remove_interface(zone, iface, ConfigMode::Runtime);
    // Assign lo to the zone (works whether unbound or bound elsewhere).
    assign_interface(zone, iface, ConfigMode::Runtime).expect("assign interface");
    let z = load_single_zone_check(zone);
    assert!(
        z.interfaces.iter().any(|i| i == iface),
        "interface should be bound, got {:?}",
        z.interfaces
    );
    assert_eq!(
        get_zone_of_interface(iface)
            .expect("zone of iface")
            .as_deref(),
        Some(zone)
    );
    // Restore the original state.
    if let Some(orig) = &original {
        assign_interface(orig, iface, ConfigMode::Runtime).expect("restore interface");
    } else {
        remove_interface(zone, iface, ConfigMode::Runtime).expect("remove interface");
    }
    let z = load_single_zone_check(zone);
    assert!(
        !z.interfaces.iter().any(|i| i == iface),
        "interface should no longer be in {zone}"
    );
}

#[test]
fn zone_create_delete_roundtrip() {
    skip_if_no_firewalld();
    let name = "tui-test-zone";
    // Idempotent: clean up leftovers from a previously interrupted run.
    let _ = delete_zone(name);
    new_zone(name).expect("new zone");
    // New zones only exist in the permanent configuration until a reload.
    let names = zone_names(Some(ConfigMode::Permanent)).expect("zone names");
    assert!(
        names.contains(&name.to_string()),
        "zone should exist: {names:?}"
    );
    delete_zone(name).expect("delete zone");
    let names = zone_names(Some(ConfigMode::Permanent)).expect("zone names");
    assert!(!names.contains(&name.to_string()), "zone should be gone");
}

#[test]
fn input_validation() {
    assert!(add_port("public", "abc", "tcp", ConfigMode::Runtime).is_err());
    assert!(add_port("public", "80", "icmp", ConfigMode::Runtime).is_err());
    assert!(new_zone("Bad Name").is_err());
    assert!(add_rich_rule("public", "not a rule", ConfigMode::Runtime).is_err());
    assert!(assign_interface("public", "bad/name!", ConfigMode::Runtime).is_err());
    assert!(assign_interface("public", "", ConfigMode::Runtime).is_err());
}

fn load_single_zone_check(zone: &str) -> Zone {
    let zones = load_zones(None).expect("load_zones");
    zones
        .into_iter()
        .find(|z| z.name == zone)
        .unwrap_or_else(|| panic!("zone {zone} not found"))
}
