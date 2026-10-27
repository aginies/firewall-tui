// ─── Core Data Types for firewalld ─────────────────────────────────────────

use ratatui::layout::Rect;
use ratatui::widgets::TableState;
use std::collections::HashMap;

/// Represents a firewalld zone
#[derive(Debug, Clone)]
pub struct Zone {
    pub name: String,
    pub is_default: bool,
    pub is_active: bool,
    pub target: String,
    pub interfaces: Vec<String>,
    pub sources: Vec<String>,
    pub icmp_services: Vec<String>,
    pub icmp_blocks: Vec<String>,
    pub ports: Vec<PortEntry>,
    pub services: Vec<String>,
    pub masquerade: bool,
    pub forward: bool,
    pub forward_port: Vec<ForwardPort>,
    pub source_ports: Vec<PortEntry>,
    /// Zone-level protocols (e.g. ah, esp, sctp, ipip) — matched by protocol
    /// number, not tied to a port.
    pub protocols: Vec<String>,
    pub rich_rules: Vec<String>,
}

/// A single port/protocol entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortEntry {
    pub port: String,
    pub protocol: String, // "tcp" or "udp"
}

impl PortEntry {
    pub fn display(&self) -> String {
        format!("{}/{}", self.port, self.protocol)
    }
}

/// A port forwarding rule
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardPort {
    pub port: String,
    pub protocol: String,
    pub to_port: Option<String>,
    pub to_addr: Option<String>,
}

/// A firewalld service definition
#[derive(Debug, Clone)]
pub struct Service {
    pub name: String,
    pub ports: Vec<PortEntry>,
    pub description: String,
}

/// A parsed breakdown of a firewalld rich rule, for the read-only detail view.
/// Any component not present in the rule is left empty.
#[derive(Debug, Clone, Default)]
pub struct RichRuleDetail {
    pub family: String,
    pub source: String,
    pub destination: String,
    pub service: String,
    pub port: String,
    pub protocol: String,
    pub icmp: String,
    pub action: String,
    pub raw: String,
}

/// The next quoted value (`"…"`) at or after byte offset `from` in `s`.
fn next_quoted(s: &str, from: usize) -> Option<String> {
    let start = s[from..].find('"')? + from;
    let end = s[start + 1..].find('"')? + start + 1;
    Some(s[start + 1..end].to_string())
}

/// The first quoted value that follows the substring `key` in `body`.
fn value_after(body: &str, key: &str) -> Option<String> {
    let i = body.find(key)?;
    next_quoted(body, i + key.len())
}

/// Best-effort breakdown of a rich rule string into its components.
pub fn parse_rich_rule(s: &str) -> RichRuleDetail {
    let body = s
        .trim()
        .strip_prefix("rule")
        .map(str::trim)
        .unwrap_or(s.trim());
    let tokens: Vec<&str> = body.split_whitespace().collect();
    let action = tokens
        .iter()
        .rev()
        .copied()
        .find(|t| *t == "accept" || *t == "reject" || *t == "drop")
        .unwrap_or_default()
        .to_string();
    RichRuleDetail {
        family: value_after(body, "family").unwrap_or_default(),
        source: value_after(body, "source").unwrap_or_default(),
        destination: value_after(body, "destination").unwrap_or_default(),
        service: value_after(body, "service").unwrap_or_default(),
        port: value_after(body, "port").unwrap_or_default(),
        protocol: value_after(body, "protocol").unwrap_or_default(),
        icmp: value_after(body, "icmp-type").unwrap_or_default(),
        action,
        raw: s.trim().to_string(),
    }
}

/// Configuration mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigMode {
    Runtime,
    Permanent,
}

impl ConfigMode {
    /// The firewall-cmd flag for this mode, if any.
    ///
    /// Runtime mode needs no flag (firewall-cmd defaults to runtime-only);
    /// firewalld 2.x removed the old `--runtime-only` flag.
    pub fn flag(&self) -> Option<&'static str> {
        match self {
            ConfigMode::Runtime => None,
            ConfigMode::Permanent => Some("--permanent"),
        }
    }
}

impl std::fmt::Display for ConfigMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigMode::Runtime => write!(f, "runtime"),
            ConfigMode::Permanent => write!(f, "permanent"),
        }
    }
}

/// UI tab selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Zones,
    Ports,
    Services,
    Rules,
    Forward,
}

impl Tab {
    pub const ALL: [Tab; 5] = [
        Tab::Zones,
        Tab::Ports,
        Tab::Services,
        Tab::Rules,
        Tab::Forward,
    ];

    pub fn index(self) -> usize {
        match self {
            Tab::Zones => 0,
            Tab::Ports => 1,
            Tab::Services => 2,
            Tab::Rules => 3,
            Tab::Forward => 4,
        }
    }

    pub fn from_index(i: usize) -> Tab {
        match i % Self::ALL.len() {
            0 => Tab::Zones,
            1 => Tab::Ports,
            2 => Tab::Services,
            3 => Tab::Rules,
            _ => Tab::Forward,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Tab::Zones => "Zones",
            Tab::Ports => "Ports",
            Tab::Services => "Services",
            Tab::Rules => "Rules",
            Tab::Forward => "Forward",
        }
    }
}

// ─── Dialogs ────────────────────────────────────────────────────────────────

/// What a modal dialog is for
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogKind {
    NewPort,
    NewRichRule,
    NewForwardPort,
    NewZone,
    /// Assign a network interface to a zone
    AssignInterface,
    /// Remove an interface binding from a zone
    RemoveInterface,
    /// Confirmation dialog with no editable fields (Enter = confirm)
    DeleteZone,
    /// payload: "port|protocol"
    DeletePort,
    /// payload: service name
    DeleteService,
    /// payload: the rich rule string
    DeleteRule,
    /// payload: "port|protocol|to_port|to_addr"
    DeleteForward,
    /// payload: zone name
    SetDefaultZone,
    /// payload: "1" (enable) or "0" (disable)
    ToggleMasquerade,
    /// Toggle firewalld panic mode; payload: "1" (enable) or "0" (disable)
    TogglePanic,
    /// Set the zone's target (dropdown: default / reject / drop)
    SetZoneTarget,
    /// Set the zone's forward policy (dropdown: yes / no)
    SetZoneForward,
    /// Add an icmp-block to the zone (dropdown of common types + free text)
    NewIcmpBlock,
    /// Remove an icmp-block (dropdown lists the zone's current blocks)
    DeleteIcmpBlock,
    /// Add a source (IP/CIDR) to the zone
    NewSource,
    /// Remove a source (dropdown lists the zone's current sources)
    DeleteSource,
    /// Add a source port to the zone
    NewSourcePort,
    /// Remove a source port (dropdown lists the zone's current source ports)
    DeleteSourcePort,
    /// Add a zone-level protocol (ah/esp/sctp/ipip/…)
    NewProtocol,
    /// Remove a zone-level protocol (dropdown lists the zone's current protocols)
    DeleteProtocol,
    /// Cross-zone search: stage 1 (the query)
    Search,
    /// Cross-zone search: stage 2 (the results list)
    SearchResults,
    /// Confirm dialog shown when a rich rule has lint warnings ("Add anyway?")
    RichLintConfirm,
    /// Read-only breakdown of a rich rule
    RuleDetail,
    /// Read-only first-run intro overlay
    Intro,
    /// Read-only runtime-vs-permanent diff for the current zone
    ZoneDiff,
    /// Read-only help overlay
    Help,
    /// Read-only about overlay (version + GPLv3 notice)
    About,
    /// Read-only view of the full session activity log
    Log,
    /// Read-only preview of the firewall-cmd for the selected item
    CommandPreview,
    /// Edit an existing rich rule in place (fields pre-filled from the rule)
    EditRichRule,
    /// Import a zone from an exported file (single field: file path)
    ImportZone,
    /// Confirmation shown on quit when permanent changes are pending a reload
    QuitConfirm,
}

#[derive(Debug, Clone)]
pub struct DialogField {
    pub label: String,
    pub value: String,
    /// When set, ↑/↓ cycles through these options instead of editing text.
    pub options: Option<Vec<String>>,
    /// Example / explanation shown under the value (empty = none).
    pub hint: String,
}

#[derive(Debug, Clone)]
pub struct Dialog {
    pub kind: DialogKind,
    pub title: String,
    pub message: Option<String>,
    /// Extra data for the dialog (e.g. zone name to delete).
    pub payload: String,
    pub fields: Vec<DialogField>,
    pub active: usize,
}

/// Common icmp-block names offered in the "Add ICMP Block" dropdown (a custom
/// name can also be typed).
const ICMP_TYPES: &[&str] = &[
    "echo-request",
    "echo-reply",
    "destination-unreachable",
    "time-exceeded",
    "parameter-problem",
    "source-quench",
    "redirect",
    "router-solicitation",
    "router-advertisement",
    "neighbour-solicitation",
    "neighbour-advertisement",
];

/// Common zone-level protocols offered in the "Add Protocol" dropdown (any
/// valid IANA protocol name can also be typed).
const ZONE_PROTOCOLS: &[&str] = &[
    "ah",
    "esp",
    "sctp",
    "ipip",
    "ipv6-icmp",
    "rsvp",
    "vrrp",
    "igmp",
];

impl Dialog {
    fn field(label: &str) -> DialogField {
        DialogField {
            label: label.to_string(),
            value: String::new(),
            options: None,
            hint: String::new(),
        }
    }

    /// A free-text field with an example/explanation shown under the value.
    fn field_hint(label: &str, hint: &str) -> DialogField {
        DialogField {
            label: label.to_string(),
            value: String::new(),
            options: None,
            hint: hint.to_string(),
        }
    }

    /// A pre-filled free-text field (for editing) with a hint.
    fn field_hint_value(label: &str, value: &str, hint: &str) -> DialogField {
        DialogField {
            label: label.to_string(),
            value: value.to_string(),
            options: None,
            hint: hint.to_string(),
        }
    }

    /// A dropdown field (↑/↓ cycles) with a default value and a hint.
    fn field_options(label: &str, options: Vec<String>, default: &str, hint: &str) -> DialogField {
        DialogField {
            label: label.to_string(),
            value: default.to_string(),
            options: Some(options),
            hint: hint.to_string(),
        }
    }

    pub fn new_port() -> Self {
        Self {
            kind: DialogKind::NewPort,
            title: "Add Port".to_string(),
            message: Some("Open a port (or a range) in the current zone.".to_string()),
            payload: String::new(),
            fields: vec![
                Self::field_hint("Port", "single port 8080  or  range 8000-8010"),
                Self::field_options(
                    "Protocol",
                    vec!["tcp".into(), "udp".into()],
                    "tcp",
                    "tcp or udp",
                ),
            ],
            active: 0,
        }
    }

    pub fn new_rich_rule() -> Self {
        Self {
            kind: DialogKind::NewRichRule,
            title: "Add Rich Rule".to_string(),
            message: Some(
                "Build a rich rule. Set at least one match (Source / Destination / Service / Port / ICMP)."
                    .to_string(),
            ),
            payload: String::new(),
            fields: vec![
                Self::field_options(
                    "Action",
                    vec!["accept".into(), "reject".into(), "drop".into()],
                    "accept",
                    "what to do with matching traffic",
                ),
                Self::field_options(
                    "Family",
                    vec!["ipv4".into(), "ipv6".into()],
                    "ipv4",
                    "address family",
                ),
                Self::field_hint("Source", "source address/CIDR (blank = any), e.g. 10.0.0.0/24"),
                Self::field_hint("Destination", "destination address/CIDR (blank = any)"),
                Self::field_hint("Service", "service name (blank = none), e.g. ssh"),
                Self::field_hint("Port", "port to match (blank = any), e.g. 4444"),
                Self::field_options(
                    "Protocol",
                    vec!["tcp".into(), "udp".into()],
                    "tcp",
                    "used only when Port is set",
                ),
                Self::field_hint("ICMP type", "icmp-type name (blank = none), e.g. echo-request"),
            ],
            active: 0,
        }
    }

    pub fn new_forward_port() -> Self {
        Self {
            kind: DialogKind::NewForwardPort,
            title: "Add Forward Port".to_string(),
            message: Some("Forward incoming traffic to another port / address.".to_string()),
            payload: String::new(),
            fields: vec![
                Self::field_hint("Port", "forward FROM this port, e.g. 8080  or  8000-8010"),
                Self::field_options(
                    "Protocol",
                    vec!["tcp".into(), "udp".into()],
                    "tcp",
                    "tcp or udp",
                ),
                Self::field_hint("To port", "forward TO this port (blank = same), e.g. 80"),
                Self::field_hint(
                    "To address",
                    "destination host (blank = local), e.g. 192.168.1.5",
                ),
            ],
            active: 0,
        }
    }

    pub fn new_zone() -> Self {
        Self {
            kind: DialogKind::NewZone,
            title: "Create Zone (permanent)".to_string(),
            message: Some("Create a new firewalld zone.".to_string()),
            payload: String::new(),
            fields: vec![Self::field_hint(
                "Name",
                "lowercase a-z, 0-9, '-' '_'   e.g. lab-net",
            )],
            active: 0,
        }
    }

    /// Assign a network interface to a zone. `interfaces` are the system's
    /// interfaces (from /sys/class/net), offered as ↑/↓ options; the user may
    /// also type a name not in the list.
    pub fn new_assign_interface(interfaces: Vec<String>, zone: &str) -> Self {
        let mut field = Self::field("Interface");
        if !interfaces.is_empty() {
            field.options = Some(interfaces);
        }
        Self {
            kind: DialogKind::AssignInterface,
            title: "Assign Interface".to_string(),
            message: Some(format!(
                "Assign an interface to zone '{zone}'.\n\
                 ↑/↓ to pick from system interfaces, or type a name."
            )),
            payload: String::new(),
            fields: vec![field],
            active: 0,
        }
    }

    /// Remove an interface binding from a zone (dropdown lists the zone's
    /// currently assigned interfaces).
    pub fn remove_interface(zone: &str, interfaces: &[String]) -> Self {
        let mut field = Self::field("Interface");
        field.options = Some(interfaces.to_vec());
        field.value = interfaces.first().cloned().unwrap_or_default();
        field.hint = "↑/↓ to pick the interface to remove".to_string();
        Self {
            kind: DialogKind::RemoveInterface,
            title: "Remove Interface".to_string(),
            message: Some(format!(
                "Remove an interface from zone '{zone}'.\nThe interface becomes unbound (not deleted)."
            )),
            payload: zone.to_string(),
            fields: vec![field],
            active: 0,
        }
    }

    pub fn confirm_delete_zone(zone: &str) -> Self {
        Self {
            kind: DialogKind::DeleteZone,
            title: "Delete Zone".to_string(),
            message: Some(format!(
                "Delete zone '{zone}' (permanent)?\n\
                 The zone must not be in use."
            )),
            payload: zone.to_string(),
            fields: Vec::new(),
            active: 0,
        }
    }

    /// Generic confirmation dialog (no editable fields).
    pub fn confirm(kind: DialogKind, title: &str, message: String, payload: String) -> Self {
        Self {
            kind,
            title: title.to_string(),
            message: Some(message),
            payload,
            fields: Vec::new(),
            active: 0,
        }
    }

    /// Set the zone's target (default / reject / drop).
    pub fn new_target(zone: &str, current: &str, warn: &str) -> Self {
        Self {
            kind: DialogKind::SetZoneTarget,
            title: "Set Zone Target".to_string(),
            message: Some(format!(
                "Set the target for zone '{zone}'.\n\n                 default = normal policy · reject = reject packets · drop = silently drop.\n{warn}"
            )),
            payload: zone.to_string(),
            fields: vec![Self::field_options(
                "Target",
                vec!["default".into(), "reject".into(), "drop".into()],
                if ["default", "reject", "drop"].contains(&current) { current } else { "default" },
                "what to do with unmatched incoming traffic",
            )],
            active: 0,
        }
    }

    /// Set the zone's forward policy (yes / no).
    pub fn new_forward(zone: &str, current: bool) -> Self {
        Self {
            kind: DialogKind::SetZoneForward,
            title: "Set Forward Policy".to_string(),
            message: Some(format!(
                "Allow forwarding through zone '{zone}'?\n'yes' lets the zone forward traffic (e.g. a router); 'no' blocks it."
            )),
            payload: zone.to_string(),
            fields: vec![Self::field_options(
                "Forward",
                vec!["yes".into(), "no".into()],
                if current { "yes" } else { "no" },
                "whether the zone may forward packets",
            )],
            active: 0,
        }
    }

    /// Add an icmp-block to the zone (dropdown of common types + free text).
    pub fn new_icmp_block(zone: &str) -> Self {
        let options: Vec<String> = ICMP_TYPES.iter().map(|s| s.to_string()).collect();
        Self {
            kind: DialogKind::NewIcmpBlock,
            title: "Add ICMP Block".to_string(),
            message: Some(format!(
                "Block an ICMP type in zone '{zone}'.\n↑/↓ to pick a common type, or type any valid icmp-block name."
            )),
            payload: zone.to_string(),
            fields: vec![Self::field_options(
                "ICMP block",
                options,
                "echo-request",
                "e.g. echo-request (ping), time-exceeded, destination-unreachable",
            )],
            active: 0,
        }
    }

    /// Remove an icmp-block from the zone (dropdown lists the current blocks).
    pub fn delete_icmp_block(zone: &str, blocks: &[String]) -> Self {
        let mut field = Self::field("Remove");
        field.options = Some(blocks.to_vec());
        field.value = blocks.first().cloned().unwrap_or_default();
        field.hint = "↑/↓ to pick the block to remove".to_string();
        Self {
            kind: DialogKind::DeleteIcmpBlock,
            title: "Remove ICMP Block".to_string(),
            message: Some(format!("Remove an icmp-block from zone '{zone}'.")),
            payload: zone.to_string(),
            fields: vec![field],
            active: 0,
        }
    }

    /// Add a source (IP or CIDR) to the zone.
    pub fn new_source(zone: &str) -> Self {
        Self {
            kind: DialogKind::NewSource,
            title: "Add Source".to_string(),
            message: Some(format!(
                "Add a source address to zone '{zone}'.\nA source is matched by IP instead of interface."
            )),
            payload: zone.to_string(),
            fields: vec![Self::field_hint(
                "Source",
                "IP or CIDR, e.g. 192.168.1.50  or  10.0.0.0/24",
            )],
            active: 0,
        }
    }

    /// Remove a source from the zone (dropdown lists the current sources).
    pub fn delete_source(zone: &str, sources: &[String]) -> Self {
        let mut field = Self::field("Remove");
        field.options = Some(sources.to_vec());
        field.value = sources.first().cloned().unwrap_or_default();
        field.hint = "↑/↓ to pick the source to remove".to_string();
        Self {
            kind: DialogKind::DeleteSource,
            title: "Remove Source".to_string(),
            message: Some(format!("Remove a source from zone '{zone}'.")),
            payload: zone.to_string(),
            fields: vec![field],
            active: 0,
        }
    }

    /// Add a source port to the zone.
    pub fn new_source_port(zone: &str) -> Self {
        Self {
            kind: DialogKind::NewSourcePort,
            title: "Add Source Port".to_string(),
            message: Some(format!(
                "Add a source port to zone '{zone}'.\nMatches traffic originating from this port."
            )),
            payload: zone.to_string(),
            fields: vec![
                Self::field_hint("Port", "single port 8080  or  range 8000-8010"),
                Self::field_options(
                    "Protocol",
                    vec!["tcp".into(), "udp".into()],
                    "tcp",
                    "tcp or udp",
                ),
            ],
            active: 0,
        }
    }

    /// Remove a source port from the zone (dropdown lists the current source ports).
    pub fn delete_source_port(zone: &str, ports: &[String]) -> Self {
        let mut field = Self::field("Remove");
        field.options = Some(ports.to_vec());
        field.value = ports.first().cloned().unwrap_or_default();
        field.hint = "↑/↓ to pick the source port to remove".to_string();
        Self {
            kind: DialogKind::DeleteSourcePort,
            title: "Remove Source Port".to_string(),
            message: Some(format!("Remove a source port from zone '{zone}'.")),
            payload: zone.to_string(),
            fields: vec![field],
            active: 0,
        }
    }

    /// Add a zone-level protocol to the zone (dropdown of common ones + free text).
    pub fn new_protocol(zone: &str) -> Self {
        let options: Vec<String> = ZONE_PROTOCOLS.iter().map(|s| s.to_string()).collect();
        Self {
            kind: DialogKind::NewProtocol,
            title: "Add Protocol".to_string(),
            message: Some(format!(
                "Add a zone-level protocol to zone '{zone}'.\n↑/↓ to pick a common one (ah, esp, sctp, ipip…), or type any IANA protocol name."
            )),
            payload: zone.to_string(),
            fields: vec![Self::field_options(
                "Protocol",
                options,
                "sctp",
                "e.g. sctp, ah, esp, ipip, ipv6-icmp",
            )],
            active: 0,
        }
    }

    /// Remove a zone-level protocol from the zone (dropdown lists the current ones).
    pub fn delete_protocol(zone: &str, protocols: &[String]) -> Self {
        let mut field = Self::field("Remove");
        field.options = Some(protocols.to_vec());
        field.value = protocols.first().cloned().unwrap_or_default();
        field.hint = "↑/↓ to pick the protocol to remove".to_string();
        Self {
            kind: DialogKind::DeleteProtocol,
            title: "Remove Protocol".to_string(),
            message: Some(format!("Remove a protocol from zone '{zone}'.")),
            payload: zone.to_string(),
            fields: vec![field],
            active: 0,
        }
    }

    /// Cross-zone search, stage 1: the query. Submitting it (Enter) replaces the
    /// dialog with a `SearchResults` list built from the loaded zones.
    pub fn search() -> Self {
        Self {
            kind: DialogKind::Search,
            title: "Search".to_string(),
            message: Some(
                "Search all zones.\nType a substring, Enter to see matches.\nMatches zone names, ports, source-ports, services, protocols, sources and rich rules."
                    .to_string(),
            ),
            payload: String::new(),
            fields: vec![Self::field("Query")],
            active: 0,
        }
    }

    /// Cross-zone search, stage 2: the results list. Each option is encoded as
    /// `"{zone} :: {kind} {detail}"` so the selected zone can be recovered on submit.
    pub fn search_results(results: &[(String, String, String)]) -> Self {
        let options: Vec<String> = results
            .iter()
            .map(|(z, k, d)| format!("{z} :: {k} {d}"))
            .collect();
        let mut field = Self::field("Match");
        field.options = Some(options.clone());
        field.value = options.first().cloned().unwrap_or_default();
        field.hint = format!(
            "{} match{} — ↑/↓ to pick, Enter to jump to its zone",
            results.len(),
            if results.len() == 1 { "" } else { "es" }
        );
        Self {
            kind: DialogKind::SearchResults,
            title: "Search Results".to_string(),
            message: Some("Pick a match to jump to its zone.".to_string()),
            payload: String::new(),
            fields: vec![field],
            active: 0,
        }
    }

    /// Import a zone's config from an exported file (user types the path).
    pub fn import_zone(zone: &str) -> Self {
        Self {
            kind: DialogKind::ImportZone,
            title: format!("Import Zone → '{zone}'"),
            message: Some(format!(
                "Apply an exported zone file to '{zone}' (additive).\nType the path to a firewall-tui export file."
            )),
            payload: zone.to_string(),
            fields: vec![Self::field_hint(
                "File path",
                "e.g. ~/.config/firewall-tui/exports/public.txt",
            )],
            active: 0,
        }
    }

    /// Read-only breakdown of a rich rule.
    pub fn rule_detail(zone: &str, detail: &RichRuleDetail) -> Self {
        let mut msg = String::new();
        let mut add = |label: &str, val: &str| {
            if !val.is_empty() {
                msg.push_str(&format!("{label:<12} {val}\n"));
            }
        };
        add("family", &detail.family);
        add("source", &detail.source);
        add("destination", &detail.destination);
        add("service", &detail.service);
        add("port", &detail.port);
        add("protocol", &detail.protocol);
        add("icmp", &detail.icmp);
        add("action", &detail.action);
        if msg.is_empty() {
            msg = "(could not parse this rule)".to_string();
        }
        msg.push_str("\nraw:\n");
        msg.push_str(&detail.raw);
        Self {
            kind: DialogKind::RuleDetail,
            title: format!("Rule Detail — {zone}"),
            message: Some(msg.trim_end().to_string()),
            payload: detail.raw.clone(),
            fields: Vec::new(),
            active: 0,
        }
    }

    /// Read-only first-run intro.
    pub fn intro() -> Self {
        Self {
            kind: DialogKind::Intro,
            title: "Welcome to Firewall TUI".to_string(),
            message: Some(
                "A terminal UI for firewalld. The keys that matter most:\n\
                 \n\
                 ↑/↓ (or j/k) move  ·  Tab / ←/→ switch tabs  ·  1-5 jump\n                 mouse: click tabs/rows, wheel scrolls\n\
                 a add  ·  d remove  ·  Enter view/add  ·  / filter a list\n\
                 m runtime ⇄ permanent  ·  u undo (20 steps)\n\
                 L session log  ·  M all-zones map  ·  P panic\n\
                 r refresh  ·  R reload (permanent → runtime)  ·  p diff\n\
                 ? full help  ·  q quit\n\
                 \n\
                 The strip under the tabs shows the mode; the footer logs each\n\
                 action with the exact firewall-cmd behind it.\n\
                 \n\
                 Press Esc or Enter to start."
                    .to_string(),
            ),
            payload: String::new(),
            fields: Vec::new(),
            active: 0,
        }
    }

    /// Edit an existing rich rule in place: the NewRichRule field set, pre-filled
    /// from `old_rule`. The old rule is carried in `payload`.
    pub fn edit_rich_rule(zone: &str, old_rule: &str) -> Self {
        let d = parse_rich_rule(old_rule);
        let action = if d.action.is_empty() {
            "accept".to_string()
        } else {
            d.action
        };
        let family = if d.family.is_empty() {
            "ipv4".to_string()
        } else {
            d.family
        };
        let protocol = if d.protocol.is_empty() {
            "tcp".to_string()
        } else {
            d.protocol
        };
        Self {
            kind: DialogKind::EditRichRule,
            title: format!("Edit Rich Rule — {zone}"),
            message: Some("Adjust the fields, then submit to replace the rule.".to_string()),
            payload: old_rule.to_string(),
            fields: vec![
                Self::field_options(
                    "Action",
                    vec!["accept".into(), "reject".into(), "drop".into()],
                    &action,
                    "what to do with matching traffic",
                ),
                Self::field_options(
                    "Family",
                    vec!["ipv4".into(), "ipv6".into()],
                    &family,
                    "address family",
                ),
                Self::field_hint_value("Source", &d.source, "source address/CIDR (blank = any)"),
                Self::field_hint_value(
                    "Destination",
                    &d.destination,
                    "destination address/CIDR (blank = any)",
                ),
                Self::field_hint_value("Service", &d.service, "service name (blank = none)"),
                Self::field_hint_value("Port", &d.port, "port to match (blank = any)"),
                Self::field_options(
                    "Protocol",
                    vec!["tcp".into(), "udp".into()],
                    &protocol,
                    "used only when Port is set",
                ),
                Self::field_hint_value("ICMP type", &d.icmp, "icmp-type name (blank = none)"),
            ],
            active: 0,
        }
    }

    /// Read-only preview of the exact firewall-cmd for the selected item.
    pub fn command_preview(title: &str, command: &str) -> Self {
        Self {
            kind: DialogKind::CommandPreview,
            title: title.to_string(),
            message: Some(format!(
                "The exact command that manages this item:\n\n  {command}\n\nCopy it for scripts, or run it manually."
            )),
            payload: command.to_string(),
            fields: Vec::new(),
            active: 0,
        }
    }

    /// Read-only view of the full session activity log, most recent first.
    pub fn log(entries: &[LogEntry]) -> Self {
        let mut msg = String::new();
        if entries.is_empty() {
            msg.push_str("No actions recorded yet this session.");
        } else {
            for e in entries.iter().rev() {
                let icon = match e.kind {
                    LogKind::Success => "✓",
                    LogKind::Error => "⚠",
                    LogKind::Info => "·",
                };
                let time = if e.time.is_empty() {
                    String::new()
                } else {
                    format!("{} ", e.time)
                };
                msg.push_str(&format!("{time}{icon} {}  ({})\n", e.message, e.mode));
                if let Some(cmd) = &e.command {
                    msg.push_str(&format!("      {cmd}\n"));
                }
            }
        }
        Self {
            kind: DialogKind::Log,
            title: format!("Activity Log — {} entries", entries.len()),
            message: Some(msg.trim_end().to_string()),
            payload: String::new(),
            fields: Vec::new(),
            active: 0,
        }
    }

    /// Read-only runtime-vs-permanent diff for a zone.
    pub fn zone_diff(zone: &str, diff: &str) -> Self {
        Self {
            kind: DialogKind::ZoneDiff,
            title: format!("Runtime vs Permanent — {zone}"),
            message: Some(diff.to_string()),
            payload: zone.to_string(),
            fields: Vec::new(),
            active: 0,
        }
    }

    /// Read-only about overlay: version, author, and the GPLv3 notice required
    /// to be conveyed under GPL v3 section 5. Points the user at the LICENSE
    /// file. Version and author are read straight from Cargo.toml at compile
    /// time, so they can never drift from the manifest.
    pub fn about() -> Self {
        // Metadata read straight from Cargo.toml at compile time, so it can
        // never drift from the manifest.
        let version = env!("CARGO_PKG_VERSION");
        // CARGO_PKG_AUTHORS separates multiple authors with newlines.
        let authors = env!("CARGO_PKG_AUTHORS").replace('\n', ", ");
        let repository = env!("CARGO_PKG_REPOSITORY");
        let parts: &[&str] = &[
            "Firewall TUI",
            &format!("Version {version}"),
            "",
            &format!("Author: {authors}"),
            "",
            "A terminal UI for managing firewalld zones, ports, services,",
            "protocols, sources, ICMP blocks, port forwards and rich rules",
            "on Linux.",
            "",
            "Licensed under the GNU General Public License version 3 (the",
            "GPLv3). This is free software; you can redistribute it and/or",
            "modify it under the terms of the GPLv3. It is distributed",
            "on an as-is basis, without warranty of any kind.",
            "",
            "A copy of the GPLv3 is in this project's LICENSE file, and is",
            &format!("also available at: {repository}"),
        ];
        Self {
            kind: DialogKind::About,
            title: "About".to_string(),
            message: Some(parts.join("\n")),
            payload: String::new(),
            fields: Vec::new(),
            active: 0,
        }
    }
    pub fn help() -> Self {
        Self {
            kind: DialogKind::Help,
            title: "Help".to_string(),
            message: Some(
                "Zones list (left) · selected zone's map (right)\n  ↑/↓          move (the map follows)\n  a create · d delete · D set default\n  i assign interface · I remove interface\n  t target (default/reject/drop) · f forward (yes/no)\n  x toggle masquerade\n  c add icmp-block · C remove icmp-block\n  s add source (IP/CIDR) · S remove source\n  o add source port · O remove source port\n  b add protocol · B remove protocol\n  E export zone to file · v import a zone from file\n  p runtime vs permanent diff for this zone\n  Shift+←/→    resize panel  (or < / >)\n\nTabs (Tab / Shift+Tab, ←/→, 1-5, or click)\n  Ports    a add · d remove · / filter\n  Services a add · d remove · / filter (type, Enter add)\n  Rules    a add · d remove · e edit · Enter view · / filter\n  Forward  a add · d remove · / filter\n  (any list)  c copy the firewall-cmd for the selected item\n  PgUp/PgDn    page the list · Home/End jump to first/last\n  j/k          move (vim-style)\n\nRich-rule builder: source, destination, port, service,\n  protocol, icmp-type, log-prefix — leave a field blank to omit.\n  e edits a rule in place (fields pre-filled).\n\nGlobal\n  m runtime⇄permanent · u undo (keeps the last 20 changes)\n  L activity log · M all-zones map (full screen) · P panic mode\n  F search across all zones · T cycle theme (dark, light, dracula, nord, gruvbox, mocha, latte, monokai, solarized)\n  r refresh · R reload · ? help · A about · q quit\n  < / >        resize the zone panel\n  Preferences (start mode, panel width, last zone) are saved\n  to ~/.config/firewall-tui/config.toml on exit.\n\nConfirm dialogs: y yes · n no · Esc cancel\nMouse: click tabs/rows to select · wheel scrolls lists and\nlong dialogs (also PgUp/PgDn inside a dialog).\nThe strip under the tabs shows the current mode; the footer\nlogs recent actions with the exact firewall-cmd behind each."
                    .to_string(),
            ),
            payload: String::new(),
            fields: Vec::new(),
            active: 0,
        }
    }
}

// ─── Activity log ───────────────────────────────────────────────────────────

/// The nature of a log entry, driving its color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    Success,
    Error,
    Info,
}

/// One line of the activity log: what happened, in which mode, and the exact
/// `firewall-cmd` command behind it (if any).
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub message: String,
    pub kind: LogKind,
    pub mode: ConfigMode,
    pub command: Option<String>,
    /// Local wall-clock time (`HH:MM:SS`) when the entry was recorded.
    pub time: String,
}

impl LogEntry {
    /// Build an entry stamped with the current local time. Prefer this over a
    /// struct literal so future field additions don't break callers.
    pub fn new(message: String, kind: LogKind, mode: ConfigMode, command: Option<String>) -> Self {
        Self {
            message,
            kind,
            mode,
            command,
            time: now_hms(),
        }
    }
}

/// The current local time as `HH:MM:SS` (empty on failure).
fn now_hms() -> String {
    unsafe {
        let mut t: libc::time_t = 0;
        libc::time(&mut t);
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return String::new();
        }
        format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}

// ─── Undo ───────────────────────────────────────────────────────────────────

/// The inverse of the last mutation, so `u` can revert it. Each variant holds
/// exactly what is needed to perform the undoing backend call.
#[derive(Debug, Clone)]
pub enum UndoAction {
    AddPort {
        zone: String,
        port: String,
        protocol: String,
        mode: ConfigMode,
    },
    RemovePort {
        zone: String,
        port: String,
        protocol: String,
        mode: ConfigMode,
    },
    AddService {
        zone: String,
        name: String,
        mode: ConfigMode,
    },
    RemoveService {
        zone: String,
        name: String,
        mode: ConfigMode,
    },
    AddRule {
        zone: String,
        rule: String,
        mode: ConfigMode,
    },
    RemoveRule {
        zone: String,
        rule: String,
        mode: ConfigMode,
    },
    /// Undo re-adds `old_rule` and removes `new_rule` (inverse of an in-place edit).
    EditRule {
        zone: String,
        old_rule: String,
        new_rule: String,
        mode: ConfigMode,
    },
    AddForward {
        zone: String,
        port: String,
        protocol: String,
        to_port: String,
        to_addr: String,
        mode: ConfigMode,
    },
    RemoveForward {
        zone: String,
        port: String,
        protocol: String,
        to_port: String,
        to_addr: String,
        mode: ConfigMode,
    },
    SetMasquerade {
        zone: String,
        enabled: bool,
        mode: ConfigMode,
    },
    SetDefault {
        zone: String,
        mode: ConfigMode,
    },
    RemoveInterface {
        zone: String,
        iface: String,
        mode: ConfigMode,
    },
    AssignInterface {
        zone: String,
        iface: String,
        mode: ConfigMode,
    },
    DeleteZone {
        name: String,
    },
    AddIcmpBlock {
        zone: String,
        icmp: String,
        mode: ConfigMode,
    },
    RemoveIcmpBlock {
        zone: String,
        icmp: String,
        mode: ConfigMode,
    },
    AddSource {
        zone: String,
        source: String,
        mode: ConfigMode,
    },
    RemoveSource {
        zone: String,
        source: String,
        mode: ConfigMode,
    },
    AddSourcePort {
        zone: String,
        port: String,
        protocol: String,
        mode: ConfigMode,
    },
    RemoveSourcePort {
        zone: String,
        port: String,
        protocol: String,
        mode: ConfigMode,
    },
    AddProtocol {
        zone: String,
        protocol: String,
        mode: ConfigMode,
    },
    RemoveProtocol {
        zone: String,
        protocol: String,
        mode: ConfigMode,
    },
    /// Undo restores the zone's target to `previous`.
    SetTarget {
        zone: String,
        previous: String,
        mode: ConfigMode,
    },
    /// Undo restores the zone's forward policy to `previous`.
    SetForward {
        zone: String,
        previous: bool,
        mode: ConfigMode,
    },
}

// ─── Application State ──────────────────────────────────────────────────────

/// Application state that ties everything together
#[derive(Debug)]
pub struct AppState {
    pub running: bool,
    pub tab: Tab,
    pub current_zone: String,
    pub zones: Vec<Zone>,
    /// All service names known to firewalld (fast to load)
    pub service_names: Vec<String>,
    /// Service details (ports + description), filled in by a background loader
    pub service_details: HashMap<String, Service>,
    /// Human-readable zone descriptions (name → short description), read from
    /// firewalld's zone XML files. Falls back to the builtin map when absent.
    pub zone_descriptions: HashMap<String, String>,
    pub service_loading: bool,
    pub config_mode: ConfigMode,
    /// True when a permanent-mode change has been made but not yet pushed to
    /// the runtime (a reload / `R` is needed). Cleared on reload or mode switch.
    pub pending_reload: bool,
    /// A rich-rule submission held back by lint warnings, awaiting the user's
    /// confirm. `(rule, old_rule_to_replace)`; `old_rule` is `Some` when editing.
    pub pending_rich: Option<(String, Option<String>)>,
    pub error: Option<String>,
    pub info: Option<String>,
    /// Activity log (most recent last), capped at `LOG_CAP`.
    pub log: Vec<LogEntry>,
    /// Inverses of recent mutations, most recent last; `u` pops and executes.
    /// Capped at `UNDO_CAP` entries.
    pub undo_stack: Vec<UndoAction>,
    /// True while firewalld panic mode is active (all traffic dropped).
    pub panic: bool,
    pub dialog: Option<Dialog>,
    pub table_states: [TableState; 5],
    /// Typeahead filter for the list tabs (Ports/Services/Rules/Forward; press `/`)
    pub filter: String,
    /// True while typing into the filter
    pub filtering: bool,
    /// Width of the zone-list sidebar (resizable with Shift+←/→ or < / >)
    pub sidebar_width: u16,
    /// Last known terminal width (used to clamp the sidebar)
    pub term_width: u16,
    /// Height of the main content panel (set each frame; used to size PgUp/PgDn)
    pub main_height: u16,
    /// Scroll offset (in lines) for the modal dialog's content, so long help /
    /// diff / preview dialogs can be scrolled on small terminals.
    pub dialog_scroll: u16,
    /// Screen areas recorded during the last render, used for mouse hit-testing
    /// (clicking tabs / rows, wheel-scrolling lists).
    pub tab_bar_area: Rect,
    pub sidebar_area: Rect,
    pub main_area: Rect,
    /// True while the full-screen topology map overlay (`M`) is open.
    pub show_map: bool,
    /// Scroll offset (lines) for the topology map overlay.
    pub map_scroll: u16,
    /// Interface carrying the default route, sampled on every refresh (the
    /// map renders per frame, so subprocess-backed facts are cached).
    pub map_route_iface: Option<String>,
    /// Interface → primary IPv4, sampled on every refresh.
    pub map_iface_ips: HashMap<String, String>,
    /// Scroll offset (lines) of the Zones-tab topology panel; auto-follows
    /// the sidebar selection.
    pub map_panel_scroll: u16,
    /// Zone block ranges `(name, start, end)` in map-content lines, recorded
    /// by the last panel render — used for click hit-testing.
    pub map_blocks: Vec<(String, usize, usize)>,
    /// The map content viewport inside the Zones panel (excludes the borders
    /// and the pinned keys legend), recorded on render for click hit-testing.
    pub map_view_area: Rect,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            running: true,
            tab: Tab::Zones,
            current_zone: "public".to_string(),
            zones: Vec::new(),
            service_names: Vec::new(),
            service_details: HashMap::new(),
            zone_descriptions: HashMap::new(),
            service_loading: false,
            config_mode: ConfigMode::Runtime,
            pending_reload: false,
            pending_rich: None,
            error: None,
            info: None,
            log: Vec::new(),
            undo_stack: Vec::new(),
            panic: false,
            dialog: None,
            filter: String::new(),
            filtering: false,
            sidebar_width: 56,
            term_width: 120,
            main_height: 20,
            dialog_scroll: 0,
            tab_bar_area: Rect::default(),
            sidebar_area: Rect::default(),
            main_area: Rect::default(),
            show_map: false,
            map_scroll: 0,
            map_route_iface: None,
            map_iface_ips: HashMap::new(),
            map_panel_scroll: 0,
            map_blocks: Vec::new(),
            map_view_area: Rect::default(),
            table_states: [
                TableState::default(),
                TableState::default(),
                TableState::default(),
                TableState::default(),
                TableState::default(),
            ],
        }
    }

    pub fn current_zone_ref(&self) -> Option<&Zone> {
        self.zones.iter().find(|z| z.name == self.current_zone)
    }

    /// Maximum number of activity-log entries kept.
    const LOG_CAP: usize = 50;

    /// Maximum number of undo steps kept.
    const UNDO_CAP: usize = 20;

    /// Push the inverse of a change onto the undo stack (oldest dropped past
    /// the cap).
    pub fn push_undo(&mut self, action: UndoAction) {
        self.undo_stack.push(action);
        if self.undo_stack.len() > Self::UNDO_CAP {
            let drain = self.undo_stack.len() - Self::UNDO_CAP;
            self.undo_stack.drain(..drain);
        }
    }

    /// Record a successful action: update the status line and append to the log.
    ///
    /// A successful permanent-mode change is not visible at runtime until a
    /// reload, so this flags `pending_reload` (the reload / mode-switch handlers
    /// clear it). Runtime-mode successes leave the flag untouched.
    pub fn note_success(&mut self, message: String, command: Option<String>) {
        self.info = Some(message.clone());
        self.error = None;
        if self.config_mode == ConfigMode::Permanent {
            self.pending_reload = true;
        }
        self.push_log(LogEntry::new(
            message,
            LogKind::Success,
            self.config_mode,
            command,
        ));
    }

    /// Record a failure: update the error status and append to the log.
    pub fn note_error(&mut self, message: String, command: Option<String>) {
        self.error = Some(message.clone());
        self.push_log(LogEntry::new(
            message,
            LogKind::Error,
            self.config_mode,
            command,
        ));
    }

    /// Record an informational note (mode change, reload, …).
    pub fn note_info(&mut self, message: String) {
        self.info = Some(message.clone());
        self.push_log(LogEntry::new(
            message,
            LogKind::Info,
            self.config_mode,
            None,
        ));
    }

    fn push_log(&mut self, entry: LogEntry) {
        self.log.push(entry);
        if self.log.len() > Self::LOG_CAP {
            let drain = self.log.len() - Self::LOG_CAP;
            self.log.drain(..drain);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_rich_rule, AppState, ConfigMode};

    #[test]
    fn pending_reload_set_on_permanent_success_only() {
        let mut app = AppState::new();
        assert!(!app.pending_reload);
        // A runtime success must not flag a pending reload.
        app.config_mode = ConfigMode::Runtime;
        app.note_success("runtime change".into(), None);
        assert!(!app.pending_reload);
        // A permanent success flags a pending reload.
        app.config_mode = ConfigMode::Permanent;
        app.note_success("permanent change".into(), None);
        assert!(app.pending_reload);
    }

    #[test]
    fn parses_a_full_rich_rule() {
        let d = parse_rich_rule(
            "rule family=\"ipv4\" source address=\"10.1.2.3\" port port=\"443\" protocol=\"tcp\" accept",
        );
        assert_eq!(d.family, "ipv4");
        assert_eq!(d.source, "10.1.2.3");
        assert_eq!(d.port, "443");
        assert_eq!(d.protocol, "tcp");
        assert_eq!(d.action, "accept");
        assert!(d.raw.starts_with("rule "));
    }

    #[test]
    fn parses_reject_and_destination() {
        let d = parse_rich_rule(
            "rule family=\"ipv4\" destination address=\"192.168.0.0/24\" reject type=\"icmp-host-prohibited\"",
        );
        assert_eq!(d.destination, "192.168.0.0/24");
        assert_eq!(d.action, "reject");
    }

    #[test]
    fn handles_an_unparseable_rule_gracefully() {
        let d = parse_rich_rule("");
        assert!(d.family.is_empty());
        assert!(d.action.is_empty());
    }
}
