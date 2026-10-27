// ─── Main Entry Point ───────────────────────────────────────────────────────

use firewall_tui::backend::{
    add_forward_port, add_icmp_block, add_port, add_protocol, add_rich_rule, add_service,
    add_source, add_source_port, assign_interface, default_route_interface, delete_zone,
    get_default_zone, get_interface_ips, get_panic_state, is_firewalld_running, last_command,
    list_system_interfaces, load_service_names, load_zone, load_zone_descriptions, load_zones,
    new_zone, reload, remove_forward_port, remove_icmp_block, remove_interface, remove_port,
    remove_protocol, remove_rich_rule, remove_service, remove_source, remove_source_port,
    set_default_zone, set_masquerade, set_panic, set_zone_forward, set_zone_target, ServiceLoader,
};
use firewall_tui::theme;
use firewall_tui::types::{
    parse_rich_rule, AppState, ConfigMode, Dialog, DialogKind, ForwardPort, LogEntry, LogKind,
    PortEntry, Tab, UndoAction, Zone,
};

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers, KeyboardEnhancementFlags, MouseButton, MouseEvent, MouseEventKind,
        PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Position, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        block::Title, Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table, Wrap,
    },
    Frame, Terminal,
};
use std::io;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

/// The per-user config directory (`$XDG_CONFIG_HOME/firewall-tui` or
/// `~/.config/firewall-tui`).
fn config_dir() -> std::path::PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::Path::new(&h).join(".config")))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    base.join("firewall-tui")
}

/// Path to the one-time intro flag file.
fn intro_flag_path() -> std::path::PathBuf {
    config_dir().join("intro-seen")
}

/// True if the first-run intro has already been shown.
fn intro_seen() -> bool {
    intro_flag_path().exists()
}

/// Mark the first-run intro as shown (so it only appears once).
fn mark_intro_seen() {
    let path = intro_flag_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, "1");
}

/// Persisted user preferences, stored at `~/.config/firewall-tui/config.toml`.
/// Every field is optional so a partial (or absent) file is fine.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
struct AppConfig {
    /// "runtime" or "permanent" — the mode to start in.
    #[serde(default)]
    start_mode: Option<String>,
    /// Width of the zone-list sidebar.
    #[serde(default)]
    sidebar_width: Option<u16>,
    /// Zone to open on at startup (the last-viewed zone).
    #[serde(default)]
    default_zone: Option<String>,
    /// The active color theme ("dark", "light", "dracula", "nord",
    /// "gruvbox", "mocha", "latte", "monokai", or "solarized").
    #[serde(default)]
    theme: Option<String>,
}

fn config_path() -> std::path::PathBuf {
    config_dir().join("config.toml")
}

/// Load saved preferences (an absent or malformed file yields defaults).
fn load_config() -> AppConfig {
    std::fs::read_to_string(config_path())
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

/// Persist the current preferences (mode, sidebar width, last-viewed zone).
fn save_config(app: &AppState) {
    let path = config_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let cfg = AppConfig {
        start_mode: Some(match app.config_mode {
            ConfigMode::Runtime => "runtime".to_string(),
            ConfigMode::Permanent => "permanent".to_string(),
        }),
        sidebar_width: Some(app.sidebar_width),
        default_zone: Some(app.current_zone.clone()),
        theme: Some(theme::current_name().to_string()),
    };
    if let Ok(s) = toml::to_string_pretty(&cfg) {
        let _ = std::fs::write(path, s);
    }
}

fn main() -> io::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Check if firewalld is running
    // The app manages the live firewall, so it must run as root. We do not
    // escalate via sudo ourselves; start it as root, or with `sudo <app>`, so
    // the process is already root when it launches.
    if unsafe { libc::geteuid() != 0 } {
        eprintln!("Error: Firewall TUI must be run as root.");
        eprintln!("Start it with: sudo firewall-tui (or as the root user)");
        std::process::exit(1);
    }

    if !is_firewalld_running() {
        eprintln!("Error: firewalld is not running.");
        eprintln!("Start it with: systemctl start firewalld");
        std::process::exit(1);
    }

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    // Enable the kitty keyboard protocol so Shift+arrows are reported
    // distinctly. Progressive enhancement: terminals without support ignore it.
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableMouseCapture,
        PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Initialize app state
    let mut app = AppState::new();
    if let Ok(size) = terminal.size() {
        app.term_width = size.width;
    }

    // Apply saved preferences (start mode + sidebar width) before loading zones.
    let cfg = load_config();
    if let Some(m) = cfg.start_mode.as_deref() {
        app.config_mode = match m {
            "permanent" => ConfigMode::Permanent,
            _ => ConfigMode::Runtime,
        };
    }
    if let Some(w) = cfg.sidebar_width {
        let cap = app.term_width / 2;
        app.sidebar_width = if cap > 30 {
            w.max(30).min(cap)
        } else {
            w.max(30)
        };
    }
    if let Some(t) = cfg.theme.as_deref() {
        theme::set_theme_by_name(t);
    }

    refresh_state(&mut app);
    if let Ok(z) = get_default_zone() {
        app.current_zone = z;
    }
    // Prefer the last-viewed zone (from config) if it still exists.
    if let Some(z) = cfg.default_zone.clone() {
        if app.zones.iter().any(|zz| zz.name == z) {
            app.current_zone = z;
        }
    }
    // Start with the working zone highlighted in the sidebar so the selection
    // and the detail panel agree from the first frame.
    if let Some(i) = app.zones.iter().position(|z| z.name == app.current_zone) {
        app.table_states[Tab::Zones.index()].select(Some(i));
    }

    // Show a one-time intro on first run.
    if !intro_seen() {
        app.dialog = Some(Dialog::intro());
        mark_intro_seen();
    }

    // Load service details (ports + descriptions) in the background
    let loader = ServiceLoader::start(app.service_names.clone(), 8);

    // Main loop
    let result = run_app(&mut terminal, &mut app, &loader);

    // Persist preferences (mode, sidebar width, last-viewed zone).
    save_config(&app);

    // Restore terminal
    execute!(
        terminal.backend_mut(),
        PopKeyboardEnhancementFlags,
        DisableMouseCapture,
        LeaveAlternateScreen
    )?;
    disable_raw_mode()?;
    terminal.show_cursor()?;

    result
}

/// Order the zone list for display: zones that are in use (active —
/// have an interface or source) first, then the rest; alphabetical
/// within each group. The default zone is *not* pinned to the top — it
/// sorts by its own active status (still identifiable via the ● marker).
fn sort_zones(zones: &mut [Zone]) {
    zones.sort_by(|a, b| {
        b.is_active
            .cmp(&a.is_active)
            .then_with(|| a.name.cmp(&b.name))
    });
}

/// Reload zone state (and service names) from firewalld.
/// Sets `app.error` on failure, clears it on success.
fn refresh_state(app: &mut AppState) {
    let result = (|| {
        let zones = load_zones(Some(app.config_mode)).map_err(|e| e.to_string())?;
        let names = load_service_names().map_err(|e| e.to_string())?;
        Ok::<_, String>((zones, names))
    })();

    match result {
        Ok((zones, names)) => {
            app.zones = zones;
            sort_zones(&mut app.zones);
            app.service_names = names;
            app.zone_descriptions = load_zone_descriptions();
            app.panic = get_panic_state();
            // The topology map renders every frame on the Zones tab, so the
            // subprocess-backed facts it shows are sampled here (once per
            // refresh), never per frame.
            app.map_route_iface = default_route_interface();
            app.map_iface_ips = get_interface_ips().unwrap_or_default();
            // Keep the current zone if it still exists, else fall back to default.
            if !app.zones.iter().any(|z| z.name == app.current_zone) {
                app.current_zone = app
                    .zones
                    .iter()
                    .find(|z| z.is_default)
                    .map(|z| z.name.clone())
                    .unwrap_or_else(|| "public".to_string());
            }
            app.error = None;
        }
        Err(e) => {
            app.note_error(format!("Failed to load firewalld state: {e}"), None);
        }
    }
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut AppState,
    loader: &ServiceLoader,
) -> io::Result<()> {
    while app.running {
        // Collect service details that finished loading in the background.
        app.service_loading = loader.poll(&mut app.service_details);

        // A freshly opened dialog always starts at the top.
        if app.dialog.is_none() {
            app.dialog_scroll = 0;
        }

        terminal.draw(|f| render(f, app))?;

        if event::poll(Duration::from_millis(16))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => handle_keypress(key, app),
                Event::Mouse(m) => handle_mouse(m, app),
                Event::Resize(w, _) => app.term_width = w,
                _ => {}
            }
        }
    }

    Ok(())
}

// ─── Key handling ───────────────────────────────────────────────────────────

/// Scan every loaded zone for `query` (case-insensitive substring) across zone
/// names, ports, source-ports, services, protocols, sources and rich rules.
/// Returns `(zone, kind, detail)` tuples, grouped by zone.
fn search_zones(zones: &[Zone], query: &str) -> Vec<(String, String, String)> {
    let q = query.to_lowercase();
    let mut results: Vec<(String, String, String)> = Vec::new();
    for z in zones {
        if z.name.to_lowercase().contains(&q) {
            results.push((z.name.clone(), "zone".to_string(), z.name.clone()));
        }
        for p in &z.ports {
            let d = p.display();
            if d.to_lowercase().contains(&q) {
                results.push((z.name.clone(), "port".to_string(), d));
            }
        }
        for p in &z.source_ports {
            let d = p.display();
            if d.to_lowercase().contains(&q) {
                results.push((z.name.clone(), "source-port".to_string(), d));
            }
        }
        for s in &z.services {
            if s.to_lowercase().contains(&q) {
                results.push((z.name.clone(), "service".to_string(), s.clone()));
            }
        }
        for proto in &z.protocols {
            if proto.to_lowercase().contains(&q) {
                results.push((z.name.clone(), "protocol".to_string(), proto.clone()));
            }
        }
        for src in &z.sources {
            if src.to_lowercase().contains(&q) {
                results.push((z.name.clone(), "source".to_string(), src.clone()));
            }
        }
        for r in &z.rich_rules {
            if r.to_lowercase().contains(&q) {
                results.push((z.name.clone(), "rich rule".to_string(), r.clone()));
            }
        }
    }
    results
}

/// Client-side lint of a constructed rich rule. `firewall-cmd` has no
/// `--validate`, so we catch obvious problems before submitting. Returns
/// human-readable warnings; an empty vec means the rule looks fine. Warnings are
/// advisory — the user can still choose to add the rule.
fn lint_rich_rule(rule: &str) -> Vec<String> {
    // Rich rules use `key="value"` for most fields (e.g. `protocol="tcp"`), so
    // value-bearing keys are matched by substring while bare keywords (actions,
    // `log`) are matched as whitespace tokens.
    let tokens: Vec<&str> = rule.split_whitespace().collect();
    let has_token = |w: &str| tokens.contains(&w);
    let mut warnings = Vec::new();
    let has_action = ["accept", "drop", "reject", "log"]
        .iter()
        .any(|a| has_token(a));
    if !has_action {
        warnings.push(
            "No action (accept/drop/reject/log) — firewalld will reject this rule.".to_string(),
        );
    }
    let has_match = [
        "source address=",
        "destination address=",
        "service name=",
        "port port=",
        "icmp-type name=",
    ]
    .iter()
    .any(|m| rule.contains(m));
    if has_action && !has_match {
        warnings.push(
            "Matches ALL traffic — no source/destination/port/service/protocol specified."
                .to_string(),
        );
    }
    if rule.contains("port port=") && !rule.contains("protocol=") {
        warnings.push("Port without a protocol — firewalld defaults to tcp.".to_string());
    }
    if has_token("log") && !rule.contains("log-prefix") {
        warnings.push("log action without a log-prefix.".to_string());
    }
    warnings
}

/// Perform a rich-rule add (and optional replace of an old rule). Shared by the
/// immediate path and the lint-confirm path. `old_rule` is `Some` when editing.
fn do_add_rich(app: &mut AppState, rule: String, old_rule: Option<String>) {
    let undo = match &old_rule {
        Some(old) => UndoAction::EditRule {
            zone: app.current_zone.clone(),
            old_rule: old.clone(),
            new_rule: rule.clone(),
            mode: app.config_mode,
        },
        None => UndoAction::RemoveRule {
            zone: app.current_zone.clone(),
            rule: rule.clone(),
            mode: app.config_mode,
        },
    };
    match add_rich_rule(&app.current_zone, &rule, app.config_mode) {
        Ok(()) => {
            let cmd = last_command();
            if let Some(old) = &old_rule {
                // Add the new rule first, then drop the old one, so a failed add
                // never leaves the zone without its previous rule.
                let _ = remove_rich_rule(&app.current_zone, old, app.config_mode);
                app.note_success("Edited rich rule".to_string(), cmd);
            } else {
                app.note_success("Added rich rule".to_string(), cmd);
            }
            app.push_undo(undo);
            refresh_state(app);
        }
        Err(e) => {
            let cmd = last_command();
            app.note_error(format!("Failed to add rich rule: {e}"), cmd);
        }
    }
}

/// Lint a constructed rich rule and either add it immediately (no warnings) or
/// hold it back behind a confirm dialog (warnings). `old_rule` is `Some` when
/// editing an existing rule.
fn submit_rich(app: &mut AppState, rule: String, old_rule: Option<String>) {
    let warnings = lint_rich_rule(&rule);
    if warnings.is_empty() {
        do_add_rich(app, rule, old_rule);
        return;
    }
    app.pending_rich = Some((rule, old_rule));
    app.dialog = Some(Dialog {
        kind: DialogKind::RichLintConfirm,
        title: "Lint Warnings".to_string(),
        message: Some(format!(
            "The rule has potential issues:\n\n  - {}\n\nAdd it anyway?",
            warnings.join("\n  - ")
        )),
        payload: String::new(),
        fields: Vec::new(),
        active: 0,
    });
}

/// If permanent changes are pending a reload, show a quit-confirmation dialog
/// and return `false` (stay). Otherwise return `true` (safe to quit now).
fn quit_or_confirm(app: &mut AppState) -> bool {
    if !app.pending_reload {
        return true;
    }
    app.dialog = Some(Dialog::confirm(
        DialogKind::QuitConfirm,
        "Quit?",
        "You have permanent changes not yet applied to runtime.\nPress R to reload first, or quit anyway.\n\nQuit anyway?".to_string(),
        "1".to_string(),
    ));
    false
}

fn handle_keypress(key: KeyEvent, app: &mut AppState) {
    // A dialog swallows all input
    if app.dialog.is_some() {
        handle_dialog_key(key, app);
        return;
    }

    // The topology map is a full-screen takeover: it swallows all input too.
    if app.show_map {
        handle_map_key(key, app);
        return;
    }

    // The typeahead filter is meaningful on the list tabs (not the Zones panel).
    if app.tab == Tab::Zones {
        app.filtering = false;
    }

    // While typing into the filter, characters edit it.
    if app.filtering {
        match key.code {
            KeyCode::Esc => {
                app.filtering = false;
                app.filter.clear();
            }
            KeyCode::Enter => {
                app.filtering = false;
                handle_enter(app);
            }
            KeyCode::Backspace => {
                app.filter.pop();
            }
            KeyCode::Char(c) => {
                app.filter.push(c);
            }
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Char('q') => {
            if quit_or_confirm(app) {
                app.running = false;
            }
        }
        KeyCode::Esc => {
            // Clear the filter if there is one; otherwise confirm-and-quit.
            if !app.filter.is_empty() {
                app.filter.clear();
            } else if quit_or_confirm(app) {
                app.running = false;
            }
        }
        // Resize the zone-list sidebar. Shift+←/→ where the terminal reports
        // the modifier; < / > as a universal fallback.
        KeyCode::Left if key.modifiers.contains(KeyModifiers::SHIFT) => {
            app.sidebar_width = app.sidebar_width.saturating_sub(2).max(30);
        }
        KeyCode::Right if key.modifiers.contains(KeyModifiers::SHIFT) => {
            app.sidebar_width = (app.sidebar_width + 2).min(app.term_width / 2);
        }
        KeyCode::Char('F') => {
            app.dialog = Some(Dialog::search());
        }
        // Full session activity log (scrollable, most recent first).
        KeyCode::Char('L') => {
            let d = Dialog::log(&app.log);
            app.dialog = Some(d);
        }
        // Panic mode: drop ALL traffic (runtime-only), behind a loud confirm.
        KeyCode::Char('P') => handle_toggle_panic(app),
        // Full-screen topology map: interfaces ▸ zones ▸ allowed traffic.
        KeyCode::Char('M') => toggle_map(app),
        KeyCode::Char('T') => {
            let name = theme::next();
            app.note_info(format!("Theme: {}", name));
        }
        KeyCode::Char('<') => {
            app.sidebar_width = app.sidebar_width.saturating_sub(2).max(30);
        }
        KeyCode::Char('>') => {
            app.sidebar_width = (app.sidebar_width + 2).min(app.term_width / 2);
        }
        // Plain ←/→ switch tabs (Shift+←/→ resizes the sidebar).
        KeyCode::Left if !key.modifiers.contains(KeyModifiers::SHIFT) => cycle_tab(app, -1),
        KeyCode::Right if !key.modifiers.contains(KeyModifiers::SHIFT) => cycle_tab(app, 1),
        KeyCode::Tab => cycle_tab(app, 1),
        KeyCode::BackTab => cycle_tab(app, -1),
        KeyCode::Down | KeyCode::Char('j') => move_selection(app, 1),
        KeyCode::Up | KeyCode::Char('k') => move_selection(app, -1),
        KeyCode::PageDown => page_selection(app, 1),
        KeyCode::PageUp => page_selection(app, -1),
        KeyCode::Home | KeyCode::Char('g') => jump_selection(app, 0),
        KeyCode::End | KeyCode::Char('G') => jump_selection_end(app),
        KeyCode::Enter => handle_enter(app),
        KeyCode::Char('a') => handle_add(app),
        KeyCode::Char('d') => handle_delete(app),
        KeyCode::Char('D') => handle_set_default(app),
        KeyCode::Char('i') => handle_assign_interface(app),
        KeyCode::Char('I') => handle_remove_interface(app),
            KeyCode::Char('?') => app.dialog = Some(Dialog::help()),
        KeyCode::Char('A') => app.dialog = Some(Dialog::about()),
        KeyCode::Char('/') if app.tab != Tab::Zones => app.filtering = true,
        KeyCode::Char('x') => toggle_masquerade(app),
        KeyCode::Char('u') => handle_undo(app),
        // Preview the exact firewall-cmd for the selected item (copyable).
        // (`c` is taken by icmp-block on the Zones tab, handled below.)
        KeyCode::Char('c') if app.tab != Tab::Zones => handle_command_preview(app),
        // Edit the selected rich rule in place (Rules tab only).
        KeyCode::Char('e') if app.tab == Tab::Rules => handle_edit_rule(app),
        // Zone-property editors (Zones tab only).
        KeyCode::Char('t') if app.tab == Tab::Zones => handle_set_target(app),
        KeyCode::Char('f') if app.tab == Tab::Zones => handle_set_forward(app),
        KeyCode::Char('c') if app.tab == Tab::Zones => handle_add_icmp(app),
        KeyCode::Char('C') if app.tab == Tab::Zones => handle_remove_icmp(app),
        KeyCode::Char('s') if app.tab == Tab::Zones => handle_add_source(app),
        KeyCode::Char('S') if app.tab == Tab::Zones => handle_remove_source(app),
        KeyCode::Char('o') if app.tab == Tab::Zones => handle_add_source_port(app),
        KeyCode::Char('O') if app.tab == Tab::Zones => handle_remove_source_port(app),
        KeyCode::Char('b') if app.tab == Tab::Zones => handle_add_protocol(app),
        KeyCode::Char('B') if app.tab == Tab::Zones => handle_remove_protocol(app),
        KeyCode::Char('E') if app.tab == Tab::Zones => handle_export_zone(app),
        KeyCode::Char('v') if app.tab == Tab::Zones => handle_import_zone(app),
        // Runtime vs permanent diff for the current zone.
        KeyCode::Char('p') => handle_zone_diff(app),
        // Tab hotkeys: 1-5 jump straight to a tab.
        KeyCode::Char(c @ ('1'..='5')) => {
            app.tab = Tab::from_index(c as usize - '1' as usize);
            app.filtering = false;
            app.filter.clear();
        }
        KeyCode::Char('m') => {
            app.config_mode = match app.config_mode {
                ConfigMode::Runtime => ConfigMode::Permanent,
                ConfigMode::Permanent => ConfigMode::Runtime,
            };
            // Switching modes resets our pending-reload tracking.
            app.pending_reload = false;
            app.note_info(format!("Mode: {}", app.config_mode));
            refresh_state(app);
        }
        KeyCode::Char('r') => {
            // A refresh re-reads the live runtime state; clear pending-reload
            // tracking so the mode banner reflects what is actually loaded.
            app.pending_reload = false;
            refresh_state(app);
        }
        KeyCode::Char('R') => match reload() {
            Ok(()) => {
                let cmd = last_command();
                app.config_mode = ConfigMode::Runtime;
                // Reload pushed permanent → runtime; nothing is pending now.
                app.pending_reload = false;
                app.note_success("firewalld reloaded (permanent → runtime)".to_string(), cmd);
                refresh_state(app);
            }
            Err(e) => {
                let cmd = last_command();
                app.note_error(format!("Reload failed: {e}"), cmd);
            }
        },
        _ => {}
    }
}

// ─── Mouse handling ────────────────────────────────────────────────────────

/// The tab whose pill contains column `x` (pills are laid out centered, exactly
/// as `render_top_bar` draws them: `" {n} {name}  "` per pill).
fn tab_at(x: u16, area: Rect) -> Option<Tab> {
    let widths: Vec<u16> = Tab::ALL
        .iter()
        .map(|t| (t.name().chars().count() + 5) as u16)
        .collect();
    let total: u16 = widths.iter().sum();
    let mut cx = area.x + area.width.saturating_sub(total) / 2;
    for (t, w) in Tab::ALL.iter().zip(widths) {
        if x >= cx && x < cx + w {
            return Some(*t);
        }
        cx += w;
    }
    None
}

/// Row index under `row` for a table drawn in `area` (1 border row + 1 header
/// row on top), accounting for the table's scroll offset. `None` when the click
/// is outside the data rows or past the end of the list.
fn row_at(row: u16, area: Rect, offset: usize, len: usize) -> Option<usize> {
    let first = area.y + 2;
    if row < first || len == 0 {
        return None;
    }
    let idx = offset + (row - first) as usize;
    (idx < len).then_some(idx)
}

/// A left click in the zone sidebar selects that zone (and makes it current).
fn click_sidebar(row: u16, app: &mut AppState) {
    let offset = app.table_states[Tab::Zones.index()].offset();
    let Some(idx) = row_at(row, app.sidebar_area, offset, app.zones.len()) else {
        return;
    };
    app.table_states[Tab::Zones.index()].select(Some(idx));
    app.current_zone = app.zones[idx].name.clone();
}

/// A left click in the main panel selects that row (list tabs only; the Zones
/// detail panel has nothing to select).
fn click_main(row: u16, app: &mut AppState) {
    if app.tab == Tab::Zones {
        // The panel is the topology map: clicking a zone block selects it.
        // The recorded viewport excludes the borders and the pinned legend.
        let view = app.map_view_area;
        if row < view.y || row >= view.y + view.height {
            return;
        }
        let content_row = (row - view.y) as usize + app.map_panel_scroll as usize;
        let hit = app
            .map_blocks
            .iter()
            .find(|(_, s, e)| content_row >= *s && content_row < *e)
            .map(|(n, _, _)| n.clone());
        if let Some(name) = hit {
            if let Some(idx) = app.zones.iter().position(|z| z.name == name) {
                app.table_states[Tab::Zones.index()].select(Some(idx));
                app.current_zone = name;
            }
        }
        return;
    }
    let len = current_list_len(app);
    let offset = app.table_states[app.tab.index()].offset();
    if let Some(idx) = row_at(row, app.main_area, offset, len) {
        app.table_states[app.tab.index()].select(Some(idx));
        sync_current_zone(app);
    }
}

fn handle_mouse(m: MouseEvent, app: &mut AppState) {
    let pos = Position::new(m.column, m.row);

    // The map overlay only responds to the wheel (scroll).
    if app.show_map {
        match m.kind {
            MouseEventKind::ScrollUp => app.map_scroll = app.map_scroll.saturating_sub(1),
            MouseEventKind::ScrollDown => app.map_scroll = app.map_scroll.saturating_add(1),
            _ => {}
        }
        return;
    }

    // While a dialog is open it swallows the mouse: the wheel scrolls it.
    if app.dialog.is_some() {
        match m.kind {
            MouseEventKind::ScrollUp => app.dialog_scroll = app.dialog_scroll.saturating_sub(1),
            MouseEventKind::ScrollDown => app.dialog_scroll = app.dialog_scroll.saturating_add(1),
            _ => {}
        }
        return;
    }

    match m.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if app.tab_bar_area.contains(pos) {
                if let Some(tab) = tab_at(m.column, app.tab_bar_area) {
                    app.tab = tab;
                    app.filtering = false;
                    app.filter.clear();
                }
            } else if app.sidebar_area.contains(pos) {
                click_sidebar(m.row, app);
            } else if app.main_area.contains(pos) {
                click_main(m.row, app);
            }
        }
        MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
            if app.sidebar_area.contains(pos) || app.main_area.contains(pos) =>
        {
            let dir = if m.kind == MouseEventKind::ScrollUp {
                -1
            } else {
                1
            };
            move_selection(app, dir);
        }
        _ => {}
    }
}

fn cycle_tab(app: &mut AppState, dir: isize) {
    let len = Tab::ALL.len() as isize;
    let idx = (app.tab.index() as isize + dir).rem_euclid(len);
    app.tab = Tab::from_index(idx as usize);
    app.filtering = false;
    app.filter.clear();
}

/// Keep the working zone in sync with the highlighted row on the Zones tab, so
/// the detail panel follows the selection without needing Enter.
fn sync_current_zone(app: &mut AppState) {
    if app.tab != Tab::Zones {
        return;
    }
    let Some(sel) = app.table_states[Tab::Zones.index()].selected() else {
        return;
    };
    let Some(zone) = app.zones.get(sel) else {
        return;
    };
    if zone.name != app.current_zone {
        app.current_zone = zone.name.clone();
    }
}

fn move_selection(app: &mut AppState, dir: isize) {
    let state = &mut app.table_states[app.tab.index()];
    if dir > 0 {
        state.select_next();
    } else {
        state.select_previous();
    }
    sync_current_zone(app);
}

/// Number of rows in the currently displayed list for the active tab (must
/// match what each renderer draws, so selection stays in sync).
fn current_list_len(app: &AppState) -> usize {
    match app.tab {
        Tab::Zones => app.zones.len(),
        Tab::Ports => filtered_ports(app).len(),
        Tab::Services => service_rows(app).len(),
        Tab::Rules => filtered_rules(app).len(),
        Tab::Forward => filtered_forward(app).len(),
    }
}

/// Jump the selection to an absolute row index (clamped to the list length).
fn jump_selection(app: &mut AppState, index: usize) {
    let len = current_list_len(app);
    if len == 0 {
        return;
    }
    app.table_states[app.tab.index()].select(Some(index.min(len - 1)));
    sync_current_zone(app);
}

/// Jump the selection to the last row.
fn jump_selection_end(app: &mut AppState) {
    let len = current_list_len(app);
    if len == 0 {
        return;
    }
    app.table_states[app.tab.index()].select(Some(len - 1));
    sync_current_zone(app);
}

/// Move the selection by one visible page (the main panel height minus the
/// table chrome: 2 border rows + 1 header row).
fn page_selection(app: &mut AppState, dir: isize) {
    let len = current_list_len(app);
    if len == 0 {
        return;
    }
    let page = app.main_height.saturating_sub(3).max(1) as isize;
    let cur = app.table_states[app.tab.index()].selected().unwrap_or(0) as isize;
    let next = if dir > 0 {
        (cur + page).min(len as isize - 1)
    } else {
        (cur - page).max(0)
    };
    app.table_states[app.tab.index()].select(Some(next as usize));
    sync_current_zone(app);
}

/// Assemble a firewalld rich rule string from the builder's field values.
/// Returns `None` when no match condition (source/dest/service/port/icmp) is set.
fn build_rich_rule(
    action: &str,
    family: &str,
    source: &str,
    destination: &str,
    service: &str,
    port: &str,
    protocol: &str,
    icmp: &str,
) -> Option<String> {
    if source.is_empty()
        && destination.is_empty()
        && service.is_empty()
        && port.is_empty()
        && icmp.is_empty()
    {
        return None;
    }
    let mut rule = format!("rule family=\"{family}\"");
    if !source.is_empty() {
        rule.push_str(&format!(" source address=\"{source}\""));
    }
    if !destination.is_empty() {
        rule.push_str(&format!(" destination address=\"{destination}\""));
    }
    if !service.is_empty() {
        rule.push_str(&format!(" service name=\"{service}\""));
    }
    if !port.is_empty() {
        rule.push_str(&format!(" port port=\"{port}\" protocol=\"{protocol}\""));
    }
    if !icmp.is_empty() {
        rule.push_str(&format!(" icmp-type name=\"{icmp}\""));
    }
    rule.push_str(&format!(" {action}"));
    Some(rule)
}

/// The exact `firewall-cmd` that manages the currently selected item, per tab.
/// Returns `None` when nothing is selected.
fn command_for_selection(app: &AppState) -> Option<String> {
    let zone = app.current_zone.clone();
    let sel = app.table_states[app.tab.index()].selected()?;
    match app.tab {
        Tab::Zones => {
            let z = app.zones.get(sel)?;
            Some(format!("firewall-cmd --zone={} --list-all", z.name))
        }
        Tab::Ports => {
            let ports = filtered_ports(app);
            let p = ports.get(sel)?;
            Some(format!(
                "firewall-cmd --zone={} --add-port={}/{}",
                zone, p.port, p.protocol
            ))
        }
        Tab::Services => {
            let rows = service_rows(app);
            let r = rows.get(sel)?;
            Some(format!(
                "firewall-cmd --zone={} --add-service={}",
                zone, r.name
            ))
        }
        Tab::Rules => {
            let rules = filtered_rules(app);
            let rule = rules.get(sel)?;
            Some(format!(
                "firewall-cmd --zone={} --add-rich-rule='{}'",
                zone, rule
            ))
        }
        Tab::Forward => {
            let forwards = filtered_forward(app);
            let fp = forwards.get(sel)?;
            let mut cmd = format!(
                "firewall-cmd --zone={} --add-forward-port=port={}:proto={}",
                zone, fp.port, fp.protocol
            );
            if let Some(tp) = &fp.to_port {
                cmd.push_str(&format!(":to-port={tp}"));
            }
            if let Some(ta) = &fp.to_addr {
                cmd.push_str(&format!(":to-addr={ta}"));
            }
            Some(cmd)
        }
    }
}

/// `y`: show the exact firewall-cmd for the selected item (read-only dialog).
fn handle_command_preview(app: &mut AppState) {
    let Some(cmd) = command_for_selection(app) else {
        app.note_info("Nothing selected to preview".to_string());
        return;
    };
    app.dialog = Some(Dialog::command_preview("firewall-cmd for selection", &cmd));
}

/// `e` (Rules tab): edit the selected rich rule in place (pre-filled builder).
fn handle_edit_rule(app: &mut AppState) {
    if app.tab != Tab::Rules {
        return;
    }
    let rules = filtered_rules(app);
    let Some(sel) = app.table_states[Tab::Rules.index()].selected() else {
        return;
    };
    let Some(rule) = rules.get(sel).cloned() else {
        return;
    };
    app.dialog = Some(Dialog::edit_rich_rule(&app.current_zone, &rule));
}

/// Enter: the context action for the current tab.
/// Zones → view the selected zone (no system change). Services → add it.
fn handle_enter(app: &mut AppState) {
    match app.tab {
        Tab::Zones => {
            let Some(sel) = app.table_states[Tab::Zones.index()].selected() else {
                return;
            };
            let Some(zone) = app.zones.get(sel) else {
                return;
            };
            if zone.name != app.current_zone {
                app.current_zone = zone.name.clone();
                app.info = Some(format!("Viewing zone '{}'", zone.name));
            }
        }
        Tab::Rules => {
            let rules = filtered_rules(app);
            let Some(sel) = app.table_states[Tab::Rules.index()].selected() else {
                return;
            };
            let Some(rule) = rules.get(sel) else {
                return;
            };
            let detail = parse_rich_rule(rule);
            app.dialog = Some(Dialog::rule_detail(&app.current_zone, &detail));
        }
        Tab::Services => add_selected_service(app),
        _ => {}
    }
}

/// Add the currently selected (and filtered) service to the zone.
fn add_selected_service(app: &mut AppState) {
    let rows = service_rows(app);
    let Some(sel) = app.table_states[Tab::Services.index()].selected() else {
        return;
    };
    let Some(row) = rows.get(sel) else {
        return;
    };
    if row.active {
        app.error = Some(format!(
            "Service '{}' is already active in '{}'",
            row.name, app.current_zone
        ));
        return;
    }
    match add_service(&app.current_zone, &row.name, app.config_mode) {
        Ok(()) => {
            let cmd = last_command();
            app.note_success(
                format!("Added service '{}' to '{}'", row.name, app.current_zone),
                cmd,
            );
            app.push_undo(UndoAction::RemoveService {
                zone: app.current_zone.clone(),
                name: row.name.clone(),
                mode: app.config_mode,
            });
            refresh_state(app);
        }
        Err(e) => {
            let cmd = last_command();
            app.note_error(format!("Failed to add service: {e}"), cmd);
        }
    }
}

// ─── Lockout guard ──────────────────────────────────────────────────────

/// A change about to be confirmed, screened for remote-lockout risk.
enum PendingChange<'a> {
    RemovePort {
        zone: &'a str,
        port: &'a str,
        protocol: &'a str,
    },
    RemoveService {
        zone: &'a str,
        name: &'a str,
    },
    DeleteZone {
        name: &'a str,
    },
    SetDefault {
        name: &'a str,
    },
}

/// True when `z` allows SSH ingress (the ssh service or 22/tcp).
fn zone_allows_ssh(z: &Zone) -> bool {
    z.services.iter().any(|s| s == "ssh")
        || z.ports
            .iter()
            .any(|p| p.port == "22" && p.protocol == "tcp")
}

/// The zone that traffic on the default-route interface actually traverses:
/// the zone explicitly bound to that interface, or — when no zone claims it —
/// the system default zone (firewalld's fallback for unbound interfaces).
/// `None` when there is no default route: a purely local box has no remote
/// session to lock out.
fn remote_access_zone(app: &AppState) -> Option<&Zone> {
    let iface = default_route_interface()?;
    if let Some(z) = app.zones.iter().find(|z| z.interfaces.contains(&iface)) {
        return Some(z);
    }
    app.zones.iter().find(|z| z.is_default)
}

/// A warning suffix for confirm dialogs when the pending change could cut the
/// current remote (SSH) session; `None` when no risk is identifiable. The
/// generic SSH-port/service warnings remain as a fallback for boxes where the
/// default route can't be determined.
fn lockout_risk(app: &AppState, change: &PendingChange) -> Option<String> {
    let remote = remote_access_zone(app)?;
    let ssh_via_service = remote.services.iter().any(|s| s == "ssh");
    let ssh_via_port = remote
        .ports
        .iter()
        .any(|p| p.port == "22" && p.protocol == "tcp");
    let suffix = |why: String| {
        format!("\n\n⛔ LOCKOUT RISK: {why}\nThis may drop your session immediately.")
    };
    match change {
        PendingChange::RemovePort {
            zone,
            port,
            protocol,
        } if *zone == remote.name && *port == "22" && *protocol == "tcp" && !ssh_via_service => {
            Some(suffix(format!(
                "'{zone}' carries your current connection and 22/tcp is its ONLY SSH access."
            )))
        }
        PendingChange::RemoveService { zone, name }
            if *zone == remote.name && *name == "ssh" && !ssh_via_port =>
        {
            Some(suffix(format!(
                "'{zone}' carries your current connection and the ssh service is its ONLY SSH access."
            )))
        }
        PendingChange::DeleteZone { name } if *name == remote.name => Some(suffix(format!(
            "'{name}' carries your current connection; deleting it reassigns its interface(s) \
             to the default zone, which may not allow SSH."
        ))),
        PendingChange::SetDefault { name } => {
            // Only risky when the connection's interface is not explicitly
            // bound, so it follows the (new) default zone.
            let iface = default_route_interface()?;
            let bound = app.zones.iter().any(|z| z.interfaces.contains(&iface));
            if bound {
                return None;
            }
            let z = app.zones.iter().find(|z| z.name == *name)?;
            (!zone_allows_ssh(z)).then(|| {
                suffix(format!(
                    "your connection's interface ({iface}) is unbound and follows the default \
                     zone — and '{name}' does not allow SSH."
                ))
            })
        }
        _ => None,
    }
}

/// D on the Zones tab: make the selected zone the system default (confirm first).
fn handle_set_default(app: &mut AppState) {
    if app.tab != Tab::Zones {
        return;
    }
    let Some(sel) = app.table_states[Tab::Zones.index()].selected() else {
        return;
    };
    let Some(zone) = app.zones.get(sel) else {
        return;
    };
    let extra =
        lockout_risk(app, &PendingChange::SetDefault { name: &zone.name }).unwrap_or_default();
    app.dialog = Some(Dialog::confirm(
        DialogKind::SetDefaultZone,
        "Set Default Zone",
        format!(
            "Make '{}' the system default zone ({})?\nThis changes live firewall routing.{extra}",
            zone.name, app.config_mode
        ),
        zone.name.clone(),
    ));
}

/// i on the Zones tab: assign a network interface to the current zone.
fn handle_assign_interface(app: &mut AppState) {
    if app.tab != Tab::Zones {
        return;
    }
    let names = match list_system_interfaces() {
        Ok(names) => names,
        Err(e) => {
            app.error = Some(format!("Failed to list interfaces: {e}"));
            return;
        }
    };
    // Show each interface's primary IPv4 in parentheses (best-effort: if the
    // `ip` command is unavailable or an interface has no IPv4, show just the name).
    let ips = get_interface_ips().unwrap_or_default();
    let interfaces: Vec<String> = names
        .iter()
        .map(|name| match ips.get(name) {
            Some(ip) => format!("{name} ({ip})"),
            None => name.clone(),
        })
        .collect();
    app.dialog = Some(Dialog::new_assign_interface(interfaces, &app.current_zone));
}

/// I on the Zones tab: remove an interface binding from the current zone.
fn handle_remove_interface(app: &mut AppState) {
    if app.tab != Tab::Zones {
        return;
    }
    let Some(z) = app.current_zone_ref() else {
        return;
    };
    if z.interfaces.is_empty() {
        app.error = Some(format!("No interfaces assigned to '{}' to remove", z.name));
        return;
    }
    app.dialog = Some(Dialog::remove_interface(&z.name, &z.interfaces));
}

/// t on the Zones tab: set the zone's target (default / reject / drop).
fn handle_set_target(app: &mut AppState) {
    let Some(z) = app.current_zone_ref() else {
        return;
    };
    let in_use = z.is_default || z.interfaces.iter().any(|i| i != "lo");
    let warn = if remote_access_zone(app).is_some_and(|r| r.name == z.name) {
        "⛔ This zone carries your current connection: 'drop'/'reject' cuts SSH."
    } else if in_use {
        "⚠ This zone is in use. 'drop' or 'reject' will block its traffic."
    } else {
        ""
    };
    app.dialog = Some(Dialog::new_target(&z.name, &z.target, warn));
}

/// f on the Zones tab: set the zone's forward policy (yes / no).
fn handle_set_forward(app: &mut AppState) {
    let Some(z) = app.current_zone_ref() else {
        return;
    };
    app.dialog = Some(Dialog::new_forward(&z.name, z.forward));
}

/// c on the Zones tab: add an icmp-block to the zone.
fn handle_add_icmp(app: &mut AppState) {
    let Some(z) = app.current_zone_ref() else {
        return;
    };
    app.dialog = Some(Dialog::new_icmp_block(&z.name));
}

/// C on the Zones tab: remove an icmp-block from the zone.
fn handle_remove_icmp(app: &mut AppState) {
    let Some(z) = app.current_zone_ref() else {
        return;
    };
    if z.icmp_blocks.is_empty() {
        app.error = Some(format!("No icmp-blocks in '{}' to remove", z.name));
        return;
    }
    app.dialog = Some(Dialog::delete_icmp_block(&z.name, &z.icmp_blocks));
}

/// s on the Zones tab: add a source (IP/CIDR) to the zone.
fn handle_add_source(app: &mut AppState) {
    let Some(z) = app.current_zone_ref() else {
        return;
    };
    app.dialog = Some(Dialog::new_source(&z.name));
}

/// S on the Zones tab: remove a source from the zone.
fn handle_remove_source(app: &mut AppState) {
    let Some(z) = app.current_zone_ref() else {
        return;
    };
    if z.sources.is_empty() {
        app.error = Some(format!("No sources in '{}' to remove", z.name));
        return;
    };
    app.dialog = Some(Dialog::delete_source(&z.name, &z.sources));
}

/// o on the Zones tab: add a source port to the zone.
fn handle_add_source_port(app: &mut AppState) {
    let Some(z) = app.current_zone_ref() else {
        return;
    };
    app.dialog = Some(Dialog::new_source_port(&z.name));
}

/// O on the Zones tab: remove a source port from the zone.
fn handle_remove_source_port(app: &mut AppState) {
    let Some(z) = app.current_zone_ref() else {
        return;
    };
    if z.source_ports.is_empty() {
        app.error = Some(format!("No source ports in '{}' to remove", z.name));
        return;
    }
    let ports: Vec<String> = z.source_ports.iter().map(|p| p.display()).collect();
    app.dialog = Some(Dialog::delete_source_port(&z.name, &ports));
}

/// b on the Zones tab: add a zone-level protocol to the zone.
fn handle_add_protocol(app: &mut AppState) {
    let Some(z) = app.current_zone_ref() else {
        return;
    };
    app.dialog = Some(Dialog::new_protocol(&z.name));
}

/// B on the Zones tab: remove a zone-level protocol from the zone.
fn handle_remove_protocol(app: &mut AppState) {
    let Some(z) = app.current_zone_ref() else {
        return;
    };
    if z.protocols.is_empty() {
        app.error = Some(format!("No protocols in '{}' to remove", z.name));
        return;
    }
    app.dialog = Some(Dialog::delete_protocol(&z.name, &z.protocols));
}

/// Build a portable representation of a zone: (command sequence, structured text).
/// The command sequence is the `--permanent` firewall-cmd lines; the structured
/// text (`key: value`) is what import parses back.
fn zone_export(zone: &Zone) -> (String, String) {
    let mut cmds: Vec<String> = Vec::new();
    let mut st: Vec<String> = Vec::new();
    st.push(format!("target: {}", zone.target));
    st.push(format!(
        "forward: {}",
        if zone.forward { "yes" } else { "no" }
    ));
    st.push(format!(
        "masquerade: {}",
        if zone.masquerade { "yes" } else { "no" }
    ));
    for svc in &zone.services {
        cmds.push(format!(
            "firewall-cmd --permanent --zone={} --add-service={}",
            zone.name, svc
        ));
        st.push(format!("service: {svc}"));
    }
    for p in &zone.ports {
        cmds.push(format!(
            "firewall-cmd --permanent --zone={} --add-port={}",
            zone.name,
            p.display()
        ));
        st.push(format!("port: {}", p.display()));
    }
    for sp in &zone.source_ports {
        cmds.push(format!(
            "firewall-cmd --permanent --zone={} --add-source-port={}",
            zone.name,
            sp.display()
        ));
        st.push(format!("source-port: {}", sp.display()));
    }
    for proto in &zone.protocols {
        cmds.push(format!(
            "firewall-cmd --permanent --zone={} --add-protocol={}",
            zone.name, proto
        ));
        st.push(format!("protocol: {proto}"));
    }
    for icmp in &zone.icmp_blocks {
        cmds.push(format!(
            "firewall-cmd --permanent --zone={} --add-icmp-block={}",
            zone.name, icmp
        ));
        st.push(format!("icmp-block: {icmp}"));
    }
    for src in &zone.sources {
        cmds.push(format!(
            "firewall-cmd --permanent --zone={} --add-source={}",
            zone.name, src
        ));
        st.push(format!("source: {src}"));
    }
    for fp in &zone.forward_port {
        let mut spec = format!("port={}:proto={}", fp.port, fp.protocol);
        if let Some(tp) = &fp.to_port {
            spec.push_str(&format!(":toport={tp}"));
        }
        if let Some(ta) = &fp.to_addr {
            spec.push_str(&format!(":toaddr={ta}"));
        }
        cmds.push(format!(
            "firewall-cmd --permanent --zone={} --add-forward-port={}",
            zone.name, spec
        ));
        st.push(format!("forward-port: {spec}"));
    }
    for rule in &zone.rich_rules {
        cmds.push(format!(
            "firewall-cmd --permanent --zone={} --add-rich-rule='{}'",
            zone.name, rule
        ));
        st.push(format!("rich-rule: {rule}"));
    }
    let header = format!("# firewall-tui zone export: {}\n", zone.name);
    let cmds_out = format!("{header}{}", cmds.join("\n"));
    let st_out = format!("{header}{}", st.join("\n"));
    (cmds_out, st_out)
}

/// E on the Zones tab: export the current zone to a file and show the commands.
fn handle_export_zone(app: &mut AppState) {
    let Some(z) = app.current_zone_ref() else {
        return;
    };
    let zone_name = z.name.clone();
    let (cmds, structured) = zone_export(z);
    // Write the structured backup file.
    let dir = config_dir().join("exports");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("{zone_name}.txt"));
    match std::fs::write(&path, &structured) {
        Ok(()) => {
            let path_str = path.display().to_string();
            app.note_success(format!("Exported zone '{zone_name}' to {path_str}"), None);
            app.dialog = Some(Dialog::command_preview(
                &format!("Export — zone '{zone_name}'"),
                &cmds,
            ));
        }
        Err(e) => app.note_error(format!("Failed to write export: {e}"), None),
    }
}

/// v on the Zones tab: import a zone from an exported file (additive).
fn handle_import_zone(app: &mut AppState) {
    let Some(z) = app.current_zone_ref() else {
        return;
    };
    app.dialog = Some(Dialog::import_zone(&z.name));
}

/// Re-apply the structured export lines to a zone (additive). Returns an error
/// message on the first failure.
fn apply_zone_structured(lines: &[String], zone: &str, mode: ConfigMode) -> Result<(), String> {
    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "target" => set_zone_target(zone, value, mode).map_err(|e| e.to_string())?,
            "forward" => set_zone_forward(zone, value == "yes", mode).map_err(|e| e.to_string())?,
            "masquerade" => {
                set_masquerade(zone, value == "yes", mode).map_err(|e| e.to_string())?
            }
            "service" => add_service(zone, value, mode).map_err(|e| e.to_string())?,
            "port" => {
                let Some((p, proto)) = value.rsplit_once('/') else {
                    return Err(format!("bad port: {value}"));
                };
                add_port(zone, p, proto, mode).map_err(|e| e.to_string())?;
            }
            "source-port" => {
                let Some((p, proto)) = value.rsplit_once('/') else {
                    return Err(format!("bad source-port: {value}"));
                };
                add_source_port(zone, p, proto, mode).map_err(|e| e.to_string())?;
            }
            "protocol" => add_protocol(zone, value, mode).map_err(|e| e.to_string())?,
            "icmp-block" => add_icmp_block(zone, value, mode).map_err(|e| e.to_string())?,
            "source" => add_source(zone, value, mode).map_err(|e| e.to_string())?,
            "forward-port" => {
                let mut port = String::new();
                let mut proto = String::new();
                let mut to_port = String::new();
                let mut to_addr = String::new();
                for part in value.split(':') {
                    if let Some(v) = part.strip_prefix("port=") {
                        port = v.to_string();
                    } else if let Some(v) = part.strip_prefix("proto=") {
                        proto = v.to_string();
                    } else if let Some(v) = part.strip_prefix("toport=") {
                        to_port = v.to_string();
                    } else if let Some(v) = part.strip_prefix("toaddr=") {
                        to_addr = v.to_string();
                    }
                }
                add_forward_port(zone, &port, &proto, &to_port, &to_addr, mode)
                    .map_err(|e| e.to_string())?;
            }
            "rich-rule" => add_rich_rule(zone, value, mode).map_err(|e| e.to_string())?,
            _ => {} // unknown key: skip
        }
    }
    Ok(())
}

/// p: show a runtime-vs-permanent diff for the current zone.
fn handle_zone_diff(app: &mut AppState) {
    let zone = app.current_zone.clone();
    let rt = match load_zone(&zone, None) {
        Ok(z) => z,
        Err(e) => {
            app.note_error(format!("Failed to load zone: {e}"), None);
            return;
        }
    };
    let perm = match load_zone(&zone, Some(ConfigMode::Permanent)) {
        Ok(z) => z,
        Err(e) => {
            app.note_error(format!("Failed to load zone: {e}"), None);
            return;
        }
    };
    let diff = build_zone_diff(&zone, &rt, &perm);
    app.dialog = Some(Dialog::zone_diff(&zone, &diff));
}

/// Build a human-readable runtime-vs-permanent diff for a zone.
fn build_zone_diff(zone: &str, rt: &Zone, perm: &Zone) -> String {
    let mut lines: Vec<String> = vec![
        format!("Zone '{zone}' — what a reload (R) would apply:"),
        String::new(),
    ];

    // Single-value properties (shown only when they differ).
    let scalar = |label: &str, rt_v: &str, perm_v: &str| -> Option<String> {
        (rt_v != perm_v).then(|| format!("{label:<11} {rt_v}  →  {perm_v}"))
    };
    for l in [
        scalar("target", &rt.target, &perm.target),
        scalar(
            "masquerade",
            &rt.masquerade.to_string(),
            &perm.masquerade.to_string(),
        ),
        scalar(
            "forward",
            &rt.forward.to_string(),
            &perm.forward.to_string(),
        ),
    ]
    .into_iter()
    .flatten()
    {
        lines.push(l);
    }

    // List properties (show items that differ between the two).
    let list_diff = |label: &str, rt_items: &[String], perm_items: &[String]| -> Vec<String> {
        let mut out = Vec::new();
        let only_rt: Vec<&String> = rt_items
            .iter()
            .filter(|x| !perm_items.contains(x))
            .collect();
        let only_perm: Vec<&String> = perm_items
            .iter()
            .filter(|x| !rt_items.contains(x))
            .collect();
        if only_rt.is_empty() && only_perm.is_empty() {
            return out;
        }
        out.push(format!("{label}:"));
        for x in &only_rt {
            out.push(format!("  - {x}   (runtime only; lost on reload)"));
        }
        for x in &only_perm {
            out.push(format!("  + {x}   (permanent only; applied on reload)"));
        }
        out
    };

    let rt_ports: Vec<String> = rt.ports.iter().map(|p| p.display()).collect();
    let perm_ports: Vec<String> = perm.ports.iter().map(|p| p.display()).collect();
    let rt_fwd: Vec<String> = rt
        .forward_port
        .iter()
        .map(|f| {
            format!(
                "{} → {}",
                f.port,
                f.to_port.clone().unwrap_or_else(|| "any".into())
            )
        })
        .collect();
    let perm_fwd: Vec<String> = perm
        .forward_port
        .iter()
        .map(|f| {
            format!(
                "{} → {}",
                f.port,
                f.to_port.clone().unwrap_or_else(|| "any".into())
            )
        })
        .collect();

    for group in [
        list_diff("ports", &rt_ports, &perm_ports),
        list_diff("services", &rt.services, &perm.services),
        list_diff("protocols", &rt.protocols, &perm.protocols),
        list_diff("icmp-blocks", &rt.icmp_blocks, &perm.icmp_blocks),
        list_diff("sources", &rt.sources, &perm.sources),
        list_diff("fwd ports", &rt_fwd, &perm_fwd),
    ] {
        lines.extend(group);
    }

    if rt.rich_rules.len() != perm.rich_rules.len() {
        lines.push(format!(
            "rich rules  {} (runtime) vs {} (permanent)",
            rt.rich_rules.len(),
            perm.rich_rules.len()
        ));
    }

    if lines.iter().skip(2).all(|l| l.is_empty()) {
        lines.push("runtime and permanent are identical — nothing to reload.".into());
    }

    lines.join("\n")
}

fn handle_add(app: &mut AppState) {
    match app.tab {
        Tab::Zones => app.dialog = Some(Dialog::new_zone()),
        Tab::Ports => app.dialog = Some(Dialog::new_port()),
        Tab::Services => add_selected_service(app),
        Tab::Rules => app.dialog = Some(Dialog::new_rich_rule()),
        Tab::Forward => app.dialog = Some(Dialog::new_forward_port()),
    }
}

fn handle_delete(app: &mut AppState) {
    match app.tab {
        Tab::Zones => {
            let Some(sel) = app.table_states[Tab::Zones.index()].selected() else {
                return;
            };
            let Some(zone) = app.zones.get(sel) else {
                return;
            };
            let mut d = Dialog::confirm_delete_zone(&zone.name);
            if let Some(w) = lockout_risk(app, &PendingChange::DeleteZone { name: &zone.name }) {
                d.message = Some(format!("{}{}", d.message.take().unwrap_or_default(), w));
            }
            app.dialog = Some(d);
        }
        Tab::Ports => {
            let ports = filtered_ports(app);
            let Some(sel) = app.table_states[Tab::Ports.index()].selected() else {
                return;
            };
            let Some(p) = ports.get(sel) else {
                return;
            };
            let warn = match lockout_risk(
                app,
                &PendingChange::RemovePort {
                    zone: &app.current_zone,
                    port: &p.port,
                    protocol: &p.protocol,
                },
            ) {
                Some(w) => w,
                None if p.port == "22" && p.protocol == "tcp" => {
                    "\n\n⚠ This is the SSH port. Removing it may cut off remote access.".to_string()
                }
                None => String::new(),
            };
            app.dialog = Some(Dialog::confirm(
                DialogKind::DeletePort,
                "Remove Port",
                format!(
                    "Remove {} from '{}'?{}",
                    p.display(),
                    app.current_zone,
                    warn
                ),
                format!("{}|{}", p.port, p.protocol),
            ));
        }
        Tab::Services => {
            let rows = service_rows(app);
            let Some(sel) = app.table_states[Tab::Services.index()].selected() else {
                return;
            };
            let Some(row) = rows.get(sel) else {
                return;
            };
            if !row.active {
                app.error = Some(format!(
                    "Service '{}' is not active in '{}'",
                    row.name, app.current_zone
                ));
                return;
            }
            let warn = match lockout_risk(
                app,
                &PendingChange::RemoveService {
                    zone: &app.current_zone,
                    name: &row.name,
                },
            ) {
                Some(w) => w,
                None if row.name == "ssh" => {
                    "\n\n⚠ This is the SSH service. Removing it may cut off remote access."
                        .to_string()
                }
                None => String::new(),
            };
            app.dialog = Some(Dialog::confirm(
                DialogKind::DeleteService,
                "Remove Service",
                format!(
                    "Remove service '{}' from '{}'?{}",
                    row.name, app.current_zone, warn
                ),
                row.name.clone(),
            ));
        }
        Tab::Rules => {
            let rules = filtered_rules(app);
            let Some(sel) = app.table_states[Tab::Rules.index()].selected() else {
                return;
            };
            let Some(rule) = rules.get(sel) else {
                return;
            };
            app.dialog = Some(Dialog::confirm(
                DialogKind::DeleteRule,
                "Remove Rich Rule",
                format!("Remove this rule from '{}'?\n\n{}", app.current_zone, rule),
                rule.clone(),
            ));
        }
        Tab::Forward => {
            let fports = filtered_forward(app);
            let Some(sel) = app.table_states[Tab::Forward.index()].selected() else {
                return;
            };
            let Some(fp) = fports.get(sel) else {
                return;
            };
            app.dialog = Some(Dialog::confirm(
                DialogKind::DeleteForward,
                "Remove Forward Port",
                format!("Remove forward {} from '{}'?", fp.port, app.current_zone),
                format!(
                    "{}|{}|{}|{}",
                    fp.port,
                    fp.protocol,
                    fp.to_port.clone().unwrap_or_default(),
                    fp.to_addr.clone().unwrap_or_default()
                ),
            ));
        }
    }
}

/// x: toggle masquerade on the current zone (asks for confirmation first).
/// The actual change happens in `submit_dialog` once confirmed.
fn toggle_masquerade(app: &mut AppState) {
    let Some(zone) = app.current_zone_ref() else {
        return;
    };
    let enable = !zone.masquerade;
    app.dialog = Some(Dialog::confirm(
        DialogKind::ToggleMasquerade,
        "Toggle Masquerade",
        format!(
            "{} masquerade in '{}' ({})?\n\nThis {} NAT for the zone.",
            if enable { "Enable" } else { "Disable" },
            zone.name,
            app.config_mode,
            if enable { "enables" } else { "disables" },
        ),
        if enable {
            "1".to_string()
        } else {
            "0".to_string()
        },
    ));
}

/// P: toggle firewalld panic mode (runtime-only) behind a loud confirmation.
/// While panic mode is on, firewalld drops ALL traffic — including the
/// session you are typing on — so the dialog spells that out explicitly.
fn handle_toggle_panic(app: &mut AppState) {
    let enable = !app.panic;
    let msg = if enable {
        "Enable PANIC MODE?\n\n\
         firewalld will immediately DROP ALL traffic — incoming AND\n\
         outgoing, including this SSH session's packets.\n\n\
         Runtime-only: toggling off (P) or a reload (R) restores normal rules."
    } else {
        "Disable panic mode?\n\nNormal firewall rules resume immediately."
    };
    app.dialog = Some(Dialog::confirm(
        DialogKind::TogglePanic,
        if enable {
            "⛔ Panic Mode — DROP ALL"
        } else {
            "Panic Mode"
        },
        msg.to_string(),
        if enable { "1" } else { "0" }.to_string(),
    ));
}

/// u: undo the most recent change by executing the inverse operation popped
/// from the undo stack.
fn handle_undo(app: &mut AppState) {
    let Some(action) = app.undo_stack.pop() else {
        app.note_info("Nothing to undo".to_string());
        return;
    };
    let result = match action {
        UndoAction::AddPort {
            zone,
            port,
            protocol,
            mode,
        } => add_port(&zone, &port, &protocol, mode),
        UndoAction::RemovePort {
            zone,
            port,
            protocol,
            mode,
        } => remove_port(&zone, &port, &protocol, mode),
        UndoAction::AddService { zone, name, mode } => add_service(&zone, &name, mode),
        UndoAction::RemoveService { zone, name, mode } => remove_service(&zone, &name, mode),
        UndoAction::AddRule { zone, rule, mode } => add_rich_rule(&zone, &rule, mode),
        UndoAction::RemoveRule { zone, rule, mode } => remove_rich_rule(&zone, &rule, mode),
        UndoAction::EditRule {
            zone,
            old_rule,
            new_rule,
            mode,
        } => add_rich_rule(&zone, &old_rule, mode)
            .and_then(|()| remove_rich_rule(&zone, &new_rule, mode)),
        UndoAction::AddForward {
            zone,
            port,
            protocol,
            to_port,
            to_addr,
            mode,
        } => add_forward_port(&zone, &port, &protocol, &to_port, &to_addr, mode),
        UndoAction::RemoveForward {
            zone,
            port,
            protocol,
            to_port,
            to_addr,
            mode,
        } => remove_forward_port(&zone, &port, &protocol, &to_port, &to_addr, mode),
        UndoAction::SetMasquerade {
            zone,
            enabled,
            mode,
        } => set_masquerade(&zone, enabled, mode),
        UndoAction::SetDefault { zone, mode } => set_default_zone(&zone, mode),
        UndoAction::RemoveInterface { zone, iface, mode } => remove_interface(&zone, &iface, mode),
        UndoAction::AssignInterface { zone, iface, mode } => assign_interface(&zone, &iface, mode),
        UndoAction::DeleteZone { name } => delete_zone(&name),
        UndoAction::SetTarget {
            zone,
            previous,
            mode,
        } => set_zone_target(&zone, &previous, mode),
        UndoAction::SetForward {
            zone,
            previous,
            mode,
        } => set_zone_forward(&zone, previous, mode),
        UndoAction::AddIcmpBlock { zone, icmp, mode } => add_icmp_block(&zone, &icmp, mode),
        UndoAction::RemoveIcmpBlock { zone, icmp, mode } => remove_icmp_block(&zone, &icmp, mode),
        UndoAction::AddSource { zone, source, mode } => add_source(&zone, &source, mode),
        UndoAction::RemoveSource { zone, source, mode } => remove_source(&zone, &source, mode),
        UndoAction::AddSourcePort {
            zone,
            port,
            protocol,
            mode,
        } => add_source_port(&zone, &port, &protocol, mode),
        UndoAction::RemoveSourcePort {
            zone,
            port,
            protocol,
            mode,
        } => remove_source_port(&zone, &port, &protocol, mode),
        UndoAction::AddProtocol {
            zone,
            protocol,
            mode,
        } => add_protocol(&zone, &protocol, mode),
        UndoAction::RemoveProtocol {
            zone,
            protocol,
            mode,
        } => remove_protocol(&zone, &protocol, mode),
    };
    match result {
        Ok(()) => {
            let cmd = last_command();
            let left = app.undo_stack.len();
            let msg = if left > 0 {
                format!("Undid last change ({left} more in undo stack)")
            } else {
                "Undid last change".to_string()
            };
            app.note_success(msg, cmd);
            refresh_state(app);
        }
        Err(e) => {
            let cmd = last_command();
            app.note_error(format!("Undo failed: {e}"), cmd);
        }
    }
}

// ─── Dialog handling ────────────────────────────────────────────────────────

fn handle_dialog_key(key: KeyEvent, app: &mut AppState) {
    // PgUp/PgDn scroll any dialog whose content is taller than the box.
    match key.code {
        KeyCode::PageUp => {
            app.dialog_scroll = app.dialog_scroll.saturating_sub(10);
            return;
        }
        KeyCode::PageDown => {
            app.dialog_scroll = app.dialog_scroll.saturating_add(10);
            return;
        }
        _ => {}
    }

    let Some(dialog) = app.dialog.as_mut() else {
        return;
    };

    match key.code {
        KeyCode::Esc => {
            // Discard a held-back rich-rule submission on cancel.
            let was_rich_lint = matches!(dialog.kind, DialogKind::RichLintConfirm);
            app.dialog = None;
            if was_rich_lint {
                app.pending_rich = None;
            }
            return;
        }
        KeyCode::Enter => {
            submit_dialog(app);
            return;
        }
        _ => {}
    }

    // Confirmation / read-only dialogs have no fields to edit; y confirms,
    // n cancels, and ↑/↓ (or j/k) scroll long content.
    if dialog.fields.is_empty() {
        let scrollable = matches!(
            dialog.kind,
            DialogKind::Help
                | DialogKind::About
                | DialogKind::RuleDetail
                | DialogKind::ZoneDiff
                | DialogKind::Intro
                | DialogKind::CommandPreview
                | DialogKind::Log
        );
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                submit_dialog(app);
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                app.dialog = None;
            }
            KeyCode::Up | KeyCode::Char('k') if scrollable => {
                app.dialog_scroll = app.dialog_scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') if scrollable => {
                app.dialog_scroll = app.dialog_scroll.saturating_add(1);
            }
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Tab | KeyCode::Right => {
            dialog.active = (dialog.active + 1) % dialog.fields.len();
        }
        KeyCode::BackTab | KeyCode::Left => {
            dialog.active = (dialog.active + dialog.fields.len() - 1) % dialog.fields.len();
        }
        KeyCode::Down | KeyCode::Up => {
            let dir: isize = if key.code == KeyCode::Down { 1 } else { -1 };
            let field = &mut dialog.fields[dialog.active];
            if let Some(opts) = &field.options {
                if let Some(pos) = opts.iter().position(|o| o == &field.value) {
                    let next = (pos as isize + dir).rem_euclid(opts.len() as isize);
                    field.value = opts[next as usize].clone();
                } else if field.value.trim().is_empty() {
                    // Empty value: start cycling from the nearest end
                    let next = if dir > 0 { 0 } else { opts.len() - 1 };
                    field.value = opts[next].clone();
                }
            } else {
                dialog.active = (dialog.active as isize + dir)
                    .rem_euclid(dialog.fields.len() as isize)
                    as usize;
            }
        }
        KeyCode::Backspace => {
            dialog.fields[dialog.active].value.pop();
        }
        KeyCode::Char(c) => {
            dialog.fields[dialog.active].value.push(c);
        }
        _ => {}
    }
}

fn submit_dialog(app: &mut AppState) {
    let Some(dialog) = app.dialog.take() else {
        return;
    };
    let field = |i: usize| {
        dialog
            .fields
            .get(i)
            .map(|f| f.value.trim().to_string())
            .unwrap_or_default()
    };

    match dialog.kind {
        DialogKind::NewPort => {
            let port = field(0);
            let protocol = if field(1).is_empty() {
                "tcp".to_string()
            } else {
                field(1)
            };
            if port.is_empty() {
                app.error = Some("Port is required".to_string());
            } else {
                match add_port(&app.current_zone, &port, &protocol, app.config_mode) {
                    Ok(()) => {
                        let cmd = last_command();
                        app.note_success(
                            format!("Added port {port}/{protocol} to '{}'", app.current_zone),
                            cmd,
                        );
                        app.push_undo(UndoAction::RemovePort {
                            zone: app.current_zone.clone(),
                            port: port.clone(),
                            protocol: protocol.clone(),
                            mode: app.config_mode,
                        });
                        refresh_state(app);
                    }
                    Err(e) => {
                        let cmd = last_command();
                        app.note_error(format!("Failed to add port: {e}"), cmd);
                    }
                }
            }
        }
        DialogKind::NewRichRule => {
            let action = field(0);
            let family = field(1);
            let source = field(2);
            let destination = field(3);
            let service = field(4);
            let port = field(5);
            let protocol = if field(6).is_empty() {
                "tcp".to_string()
            } else {
                field(6)
            };
            let icmp = field(7);
            match build_rich_rule(
                &action,
                &family,
                &source,
                &destination,
                &service,
                &port,
                &protocol,
                &icmp,
            ) {
                None => {
                    app.error = Some(
                        "Set at least one match: Source / Destination / Service / Port / ICMP"
                            .to_string(),
                    );
                }
                Some(rule) => submit_rich(app, rule, None),
            }
        }
        DialogKind::EditRichRule => {
            let old_rule = dialog.payload.clone();
            let action = field(0);
            let family = field(1);
            let source = field(2);
            let destination = field(3);
            let service = field(4);
            let port = field(5);
            let protocol = if field(6).is_empty() {
                "tcp".to_string()
            } else {
                field(6)
            };
            let icmp = field(7);
            match build_rich_rule(
                &action,
                &family,
                &source,
                &destination,
                &service,
                &port,
                &protocol,
                &icmp,
            ) {
                None => {
                    app.error = Some(
                        "Set at least one match: Source / Destination / Service / Port / ICMP"
                            .to_string(),
                    );
                }
                Some(rule) => {
                    if rule == old_rule {
                        // No change; just close.
                    } else {
                        submit_rich(app, rule, Some(old_rule));
                    }
                }
            }
        }
        DialogKind::NewForwardPort => {
            let port = field(0);
            let protocol = if field(1).is_empty() {
                "tcp".to_string()
            } else {
                field(1)
            };
            let to_port = field(2);
            let to_addr = field(3);
            if port.is_empty() {
                app.error = Some("Port is required".to_string());
            } else {
                match add_forward_port(
                    &app.current_zone,
                    &port,
                    &protocol,
                    &to_port,
                    &to_addr,
                    app.config_mode,
                ) {
                    Ok(()) => {
                        let cmd = last_command();
                        app.note_success(
                            format!("Added forward port {port} to '{}'", app.current_zone),
                            cmd,
                        );
                        app.push_undo(UndoAction::RemoveForward {
                            zone: app.current_zone.clone(),
                            port: port.clone(),
                            protocol: protocol.clone(),
                            to_port: to_port.clone(),
                            to_addr: to_addr.clone(),
                            mode: app.config_mode,
                        });
                        refresh_state(app);
                    }
                    Err(e) => {
                        let cmd = last_command();
                        app.note_error(format!("Failed to add forward port: {e}"), cmd);
                    }
                }
            }
        }
        DialogKind::NewZone => {
            let name = field(0);
            match new_zone(&name) {
                Ok(()) => {
                    let cmd = last_command();
                    app.note_success(format!("Created zone '{name}' (permanent)"), cmd);
                    app.push_undo(UndoAction::DeleteZone { name: name.clone() });
                    refresh_state(app);
                }
                Err(e) => {
                    let cmd = last_command();
                    app.note_error(format!("Failed to create zone: {e}"), cmd);
                }
            }
        }
        DialogKind::DeleteZone => {
            let name = dialog.payload;
            let was_current = name == app.current_zone;
            match delete_zone(&name) {
                Ok(()) => {
                    let cmd = last_command();
                    app.note_success(format!("Deleted zone '{name}'"), cmd);
                    // The deleted zone can't be restored; drop any stale
                    // "delete this zone" undo entries recorded for it.
                    app.undo_stack
                        .retain(|a| !matches!(a, UndoAction::DeleteZone { name: n } if n == &name));
                    if was_current {
                        if let Ok(z) = get_default_zone() {
                            app.current_zone = z;
                        }
                    }
                    refresh_state(app);
                }
                Err(e) => {
                    let cmd = last_command();
                    app.note_error(format!("Failed to delete zone: {e}"), cmd);
                }
            }
        }
        DialogKind::DeletePort => {
            let (p, pr) = dialog.payload.split_once('|').unwrap_or(("", ""));
            let port = p.to_string();
            let protocol = pr.to_string();
            match remove_port(&app.current_zone, &port, &protocol, app.config_mode) {
                Ok(()) => {
                    let cmd = last_command();
                    app.note_success(
                        format!("Removed port {port}/{protocol} from '{}'", app.current_zone),
                        cmd,
                    );
                    app.push_undo(UndoAction::AddPort {
                        zone: app.current_zone.clone(),
                        port: port.clone(),
                        protocol: protocol.clone(),
                        mode: app.config_mode,
                    });
                    refresh_state(app);
                }
                Err(e) => {
                    let cmd = last_command();
                    app.note_error(format!("Failed to remove port: {e}"), cmd);
                }
            }
        }
        DialogKind::DeleteService => {
            let name = dialog.payload.clone();
            match remove_service(&app.current_zone, &name, app.config_mode) {
                Ok(()) => {
                    let cmd = last_command();
                    app.note_success(
                        format!("Removed service '{name}' from '{}'", app.current_zone),
                        cmd,
                    );
                    app.push_undo(UndoAction::AddService {
                        zone: app.current_zone.clone(),
                        name: name.clone(),
                        mode: app.config_mode,
                    });
                    refresh_state(app);
                }
                Err(e) => {
                    let cmd = last_command();
                    app.note_error(format!("Failed to remove service: {e}"), cmd);
                }
            }
        }
        DialogKind::DeleteRule => {
            let rule = dialog.payload.clone();
            match remove_rich_rule(&app.current_zone, &rule, app.config_mode) {
                Ok(()) => {
                    let cmd = last_command();
                    app.note_success("Removed rich rule".to_string(), cmd);
                    app.push_undo(UndoAction::AddRule {
                        zone: app.current_zone.clone(),
                        rule: rule.clone(),
                        mode: app.config_mode,
                    });
                    refresh_state(app);
                }
                Err(e) => {
                    let cmd = last_command();
                    app.note_error(format!("Failed to remove rich rule: {e}"), cmd);
                }
            }
        }
        DialogKind::DeleteForward => {
            let mut parts = dialog.payload.split('|');
            let port = parts.next().unwrap_or("").to_string();
            let protocol = parts.next().unwrap_or("").to_string();
            let to_port = parts.next().unwrap_or("").to_string();
            let to_addr = parts.next().unwrap_or("").to_string();
            match remove_forward_port(
                &app.current_zone,
                &port,
                &protocol,
                &to_port,
                &to_addr,
                app.config_mode,
            ) {
                Ok(()) => {
                    let cmd = last_command();
                    app.note_success(
                        format!("Removed forward port {port} from '{}'", app.current_zone),
                        cmd,
                    );
                    app.push_undo(UndoAction::AddForward {
                        zone: app.current_zone.clone(),
                        port: port.clone(),
                        protocol: protocol.clone(),
                        to_port: to_port.clone(),
                        to_addr: to_addr.clone(),
                        mode: app.config_mode,
                    });
                    refresh_state(app);
                }
                Err(e) => {
                    let cmd = last_command();
                    app.note_error(format!("Failed to remove forward port: {e}"), cmd);
                }
            }
        }
        DialogKind::SetDefaultZone => {
            let name = dialog.payload.clone();
            // Remember the current default so undo can restore it.
            let previous = app
                .zones
                .iter()
                .find(|z| z.is_default)
                .map(|z| z.name.clone());
            match set_default_zone(&name, app.config_mode) {
                Ok(()) => {
                    let cmd = last_command();
                    app.current_zone = name.clone();
                    app.note_success(format!("'{name}' is now the default zone"), cmd);
                    if let Some(prev) = previous {
                        app.push_undo(UndoAction::SetDefault {
                            zone: prev,
                            mode: app.config_mode,
                        });
                    }
                    refresh_state(app);
                }
                Err(e) => {
                    let cmd = last_command();
                    app.note_error(format!("Failed to set default zone: {e}"), cmd);
                }
            }
        }
        DialogKind::TogglePanic => {
            let enable = dialog.payload == "1";
            match set_panic(enable) {
                Ok(()) => {
                    let cmd = last_command();
                    app.panic = enable;
                    // Panic mode is runtime-only; don't let note_success (in
                    // permanent mode) flag a pending reload for it.
                    let prev_pending = app.pending_reload;
                    app.note_success(
                        if enable {
                            "PANIC MODE ON — all traffic dropped".to_string()
                        } else {
                            "Panic mode off — normal rules resumed".to_string()
                        },
                        cmd,
                    );
                    app.pending_reload = prev_pending;
                    refresh_state(app);
                }
                Err(e) => {
                    let cmd = last_command();
                    app.note_error(format!("Failed to toggle panic mode: {e}"), cmd);
                }
            }
        }
        DialogKind::ToggleMasquerade => {
            let enable = dialog.payload == "1";
            let zone = app.current_zone.clone();
            match set_masquerade(&zone, enable, app.config_mode) {
                Ok(()) => {
                    let cmd = last_command();
                    app.note_success(
                        format!(
                            "Masquerade {} in '{}'",
                            if enable { "enabled" } else { "disabled" },
                            zone
                        ),
                        cmd,
                    );
                    app.push_undo(UndoAction::SetMasquerade {
                        zone: app.current_zone.clone(),
                        enabled: !enable,
                        mode: app.config_mode,
                    });
                    refresh_state(app);
                }
                Err(e) => {
                    let cmd = last_command();
                    app.note_error(format!("Failed to toggle masquerade: {e}"), cmd);
                }
            }
        }
        DialogKind::AssignInterface => {
            // Dropdown options are shown as "name (ip)"; an interface name never
            // contains " (", so strip the IP suffix to get the real name.
            let iface = field(0);
            let iface = iface.split(" (").next().unwrap_or("").trim().to_string();
            if iface.is_empty() {
                app.error = Some("No interface specified".to_string());
                return;
            }
            match assign_interface(&app.current_zone, &iface, app.config_mode) {
                Ok(()) => {
                    let cmd = last_command();
                    app.note_success(
                        format!("Assigned interface '{iface}' to '{}'", app.current_zone),
                        cmd,
                    );
                    app.push_undo(UndoAction::RemoveInterface {
                        zone: app.current_zone.clone(),
                        iface: iface.clone(),
                        mode: app.config_mode,
                    });
                    refresh_state(app);
                }
                Err(e) => {
                    let cmd = last_command();
                    app.note_error(format!("Failed to assign interface: {e}"), cmd);
                }
            }
        }
        DialogKind::RemoveInterface => {
            let iface = field(0);
            if iface.is_empty() {
                app.error = Some("No interface specified".to_string());
                return;
            }
            match remove_interface(&app.current_zone, &iface, app.config_mode) {
                Ok(()) => {
                    let cmd = last_command();
                    app.note_success(
                        format!("Removed interface '{iface}' from '{}'", app.current_zone),
                        cmd,
                    );
                    app.push_undo(UndoAction::AssignInterface {
                        zone: app.current_zone.clone(),
                        iface: iface.clone(),
                        mode: app.config_mode,
                    });
                    refresh_state(app);
                }
                Err(e) => {
                    let cmd = last_command();
                    app.note_error(format!("Failed to remove interface: {e}"), cmd);
                }
            }
        }
        DialogKind::SetZoneTarget => {
            let zone = app.current_zone.clone();
            let old_target = app
                .current_zone_ref()
                .map(|z| z.target.clone())
                .unwrap_or_default();
            let value = field(0);
            if value.is_empty() {
                app.error = Some("Target cannot be empty".to_string());
                return;
            }
            match set_zone_target(&zone, &value, app.config_mode) {
                Ok(()) => {
                    app.note_success(
                        format!("Set target '{value}' for zone '{zone}'"),
                        last_command(),
                    );
                    app.push_undo(UndoAction::SetTarget {
                        zone,
                        previous: old_target,
                        mode: app.config_mode,
                    });
                    refresh_state(app);
                }
                Err(e) => app.note_error(format!("Failed to set target: {e}"), None),
            }
        }
        DialogKind::SetZoneForward => {
            let zone = app.current_zone.clone();
            let old_forward = app.current_zone_ref().map(|z| z.forward).unwrap_or(false);
            let value = field(0);
            if value != "yes" && value != "no" {
                app.error = Some("Forward must be 'yes' or 'no'".to_string());
                return;
            }
            let new_fwd = value == "yes";
            match set_zone_forward(&zone, new_fwd, app.config_mode) {
                Ok(()) => {
                    app.note_success(
                        format!("Set forward to '{value}' for zone '{zone}'"),
                        last_command(),
                    );
                    app.push_undo(UndoAction::SetForward {
                        zone,
                        previous: old_forward,
                        mode: app.config_mode,
                    });
                    refresh_state(app);
                }
                Err(e) => app.note_error(format!("Failed to set forward: {e}"), None),
            }
        }
        DialogKind::NewIcmpBlock => {
            let zone = app.current_zone.clone();
            let value = field(0);
            if value.is_empty() {
                app.error = Some("ICMP type cannot be empty".to_string());
                return;
            }
            match add_icmp_block(&zone, &value, app.config_mode) {
                Ok(()) => {
                    app.note_success(
                        format!("Added icmp-block '{value}' to zone '{zone}'"),
                        last_command(),
                    );
                    app.push_undo(UndoAction::RemoveIcmpBlock {
                        zone,
                        icmp: value.clone(),
                        mode: app.config_mode,
                    });
                    refresh_state(app);
                }
                Err(e) => app.note_error(format!("Failed to add icmp-block: {e}"), None),
            }
        }
        DialogKind::DeleteIcmpBlock => {
            let zone = app.current_zone.clone();
            let value = field(0);
            if value.is_empty() {
                app.error = Some("ICMP type cannot be empty".to_string());
                return;
            }
            match remove_icmp_block(&zone, &value, app.config_mode) {
                Ok(()) => {
                    app.note_success(
                        format!("Removed icmp-block '{value}' from zone '{zone}'"),
                        last_command(),
                    );
                    app.push_undo(UndoAction::AddIcmpBlock {
                        zone,
                        icmp: value.clone(),
                        mode: app.config_mode,
                    });
                    refresh_state(app);
                }
                Err(e) => app.note_error(format!("Failed to remove icmp-block: {e}"), None),
            }
        }
        DialogKind::NewSource => {
            let zone = app.current_zone.clone();
            let value = field(0);
            if value.is_empty() {
                app.error = Some("Source cannot be empty".to_string());
                return;
            }
            match add_source(&zone, &value, app.config_mode) {
                Ok(()) => {
                    app.note_success(
                        format!("Added source '{value}' to zone '{zone}'"),
                        last_command(),
                    );
                    app.push_undo(UndoAction::RemoveSource {
                        zone,
                        source: value.clone(),
                        mode: app.config_mode,
                    });
                    refresh_state(app);
                }
                Err(e) => app.note_error(format!("Failed to add source: {e}"), None),
            }
        }
        DialogKind::DeleteSource => {
            let zone = app.current_zone.clone();
            let value = field(0);
            if value.is_empty() {
                app.error = Some("Source cannot be empty".to_string());
                return;
            }
            match remove_source(&zone, &value, app.config_mode) {
                Ok(()) => {
                    app.note_success(
                        format!("Removed source '{value}' from zone '{zone}'"),
                        last_command(),
                    );
                    app.push_undo(UndoAction::AddSource {
                        zone,
                        source: value.clone(),
                        mode: app.config_mode,
                    });
                    refresh_state(app);
                }
                Err(e) => app.note_error(format!("Failed to remove source: {e}"), None),
            }
        }
        DialogKind::NewSourcePort => {
            let zone = app.current_zone.clone();
            let port = field(0);
            let protocol = if field(1).is_empty() {
                "tcp".to_string()
            } else {
                field(1)
            };
            if port.is_empty() {
                app.error = Some("Port cannot be empty".to_string());
                return;
            }
            match add_source_port(&zone, &port, &protocol, app.config_mode) {
                Ok(()) => {
                    app.note_success(
                        format!("Added source port {port}/{protocol} to zone '{zone}'"),
                        last_command(),
                    );
                    app.push_undo(UndoAction::RemoveSourcePort {
                        zone,
                        port: port.clone(),
                        protocol: protocol.clone(),
                        mode: app.config_mode,
                    });
                    refresh_state(app);
                }
                Err(e) => app.note_error(format!("Failed to add source port: {e}"), None),
            }
        }
        DialogKind::DeleteSourcePort => {
            let zone = app.current_zone.clone();
            let value = field(0);
            let Some((port, protocol)) = value.rsplit_once('/') else {
                app.error = Some("Invalid source port".to_string());
                return;
            };
            match remove_source_port(&zone, port, protocol, app.config_mode) {
                Ok(()) => {
                    app.note_success(
                        format!("Removed source port {value} from zone '{zone}'"),
                        last_command(),
                    );
                    app.push_undo(UndoAction::AddSourcePort {
                        zone,
                        port: port.to_string(),
                        protocol: protocol.to_string(),
                        mode: app.config_mode,
                    });
                    refresh_state(app);
                }
                Err(e) => app.note_error(format!("Failed to remove source port: {e}"), None),
            }
        }
        DialogKind::NewProtocol => {
            let zone = app.current_zone.clone();
            let value = field(0);
            if value.is_empty() {
                app.error = Some("Protocol cannot be empty".to_string());
                return;
            }
            match add_protocol(&zone, &value, app.config_mode) {
                Ok(()) => {
                    app.note_success(
                        format!("Added protocol '{value}' to zone '{zone}'"),
                        last_command(),
                    );
                    app.push_undo(UndoAction::RemoveProtocol {
                        zone,
                        protocol: value.clone(),
                        mode: app.config_mode,
                    });
                    refresh_state(app);
                }
                Err(e) => app.note_error(format!("Failed to add protocol: {e}"), None),
            }
        }
        DialogKind::DeleteProtocol => {
            let zone = app.current_zone.clone();
            let value = field(0);
            if value.is_empty() {
                app.error = Some("Protocol cannot be empty".to_string());
                return;
            }
            match remove_protocol(&zone, &value, app.config_mode) {
                Ok(()) => {
                    app.note_success(
                        format!("Removed protocol '{value}' from zone '{zone}'"),
                        last_command(),
                    );
                    app.push_undo(UndoAction::AddProtocol {
                        zone,
                        protocol: value.clone(),
                        mode: app.config_mode,
                    });
                    refresh_state(app);
                }
                Err(e) => app.note_error(format!("Failed to remove protocol: {e}"), None),
            }
        }
        DialogKind::ImportZone => {
            let zone = app.current_zone.clone();
            let raw_path = field(0);
            if raw_path.is_empty() {
                app.error = Some("File path cannot be empty".to_string());
                return;
            }
            // Expand a leading `~` to $HOME.
            let path = if let Some(rest) = raw_path.strip_prefix("~") {
                std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()))
                    .join(rest)
            } else {
                std::path::PathBuf::from(&raw_path)
            };
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    app.note_error(format!("Failed to read {}: {e}", path.display()), None);
                    return;
                }
            };
            let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
            match apply_zone_structured(&lines, &zone, ConfigMode::Permanent) {
                Ok(()) => {
                    app.note_success(
                        format!("Imported zone config into '{zone}' (permanent). Reload to apply."),
                        None,
                    );
                    refresh_state(app);
                }
                Err(e) => app.note_error(format!("Import failed: {e}"), None),
            }
        }
        DialogKind::QuitConfirm => {
            app.running = false;
        }
        DialogKind::Search => {
            let query = field(0);
            if query.trim().is_empty() {
                app.dialog = None;
                return;
            }
            let results = search_zones(&app.zones, &query);
            if results.is_empty() {
                app.error = Some(format!("No matches for '{query}'"));
                app.dialog = None;
                return;
            }
            app.dialog = Some(Dialog::search_results(&results));
        }
        DialogKind::SearchResults => {
            let value = field(0);
            let zone = value.split(" :: ").next().unwrap_or("").to_string();
            if !zone.is_empty() {
                app.current_zone = zone.clone();
                app.tab = Tab::Zones;
                app.note_info(format!("Jumped to zone '{zone}'"));
            }
            app.dialog = None;
        }
        DialogKind::RichLintConfirm => {
            if let Some((rule, old_rule)) = app.pending_rich.take() {
                do_add_rich(app, rule, old_rule);
            } else {
                app.dialog = None;
            }
        }
        // Read-only info dialogs (rule detail, intro, zone diff, command
        // preview, activity log, about): just close.
        DialogKind::RuleDetail
        | DialogKind::About
        | DialogKind::Intro
        | DialogKind::ZoneDiff
        | DialogKind::CommandPreview
        | DialogKind::Log => {}
        DialogKind::Help => {}
    }
}

// ─── UI Rendering ───────────────────────────────────────────────────────────

fn render(f: &mut Frame, app: &mut AppState) {
    // The topology map takes over the whole screen while open.
    if app.show_map {
        render_map(f, app);
        return;
    }

    let size = f.area();

    // Overall layout. The mode banner is always shown (a persistent reminder
    // of runtime vs permanent); the footer carries the per-tab key hints plus
    // a short activity log with the exact command behind each recent action.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Top bar (brand/status + numbered tabs)
            Constraint::Min(3),    // Main content
            Constraint::Length(1), // Status line (error / info)
            Constraint::Length(3), // Footer (key hints + recent actions)
        ])
        .split(size);

    render_top_bar(f, app, chunks[0]);

    // Main content area. The zone-list sidebar is user-resizable
    // (Shift+←/→ or < / >); cap it at half the width so the main
    // panel always has room.
    let sidebar_w = app.sidebar_width.min(chunks[1].width / 2);
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(sidebar_w), Constraint::Fill(1)])
        .split(chunks[1]);

    // Record the hit-test areas for the mouse handler (tab pills live on the
    // second row of the top bar).
    app.tab_bar_area = Rect::new(chunks[0].x, chunks[0].y + 1, chunks[0].width, 1);
    app.sidebar_area = main_chunks[0];
    app.main_area = main_chunks[1];

    // Remember the main panel height so PgUp/PgDn can page by the visible rows.
    app.main_height = main_chunks[1].height;
    render_zone_list(f, app, main_chunks[0]);
    render_main_panel(f, app, main_chunks[1]);
    render_status_line(f, app, chunks[2]);
    render_footer(f, app, chunks[3]);

    // Modal dialog on top of everything
    if app.dialog.is_some() {
        render_dialog(f, app);
    }
}

/// A compact two-row top bar that merges the previous separate header, tab
/// bar, and mode banner. The first row carries the brand (left) and a live
/// zone/mode/pending-reload summary (right); the second carries the numbered
/// tab pills. This reclaims five rows for the content while keeping the mode
/// and pending-reload state always visible.
fn render_top_bar(f: &mut Frame, app: &AppState, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);

    // Row 1 (top): brand on the left, live summary on the right.
    let title = Line::from(vec![
        Span::styled("🔥 ", theme::bold(theme::danger())),
        Span::styled("Firewall TUI", theme::bold(theme::accent())),
        Span::styled("  ·  firewalld", theme::fg(theme::muted())),
    ]);

    let mode = match app.config_mode {
        ConfigMode::Runtime => Span::styled(
            " runtime (m) ",
            Style::default()
                .fg(theme::on_accent())
                .bg(theme::banner_runtime_bg()),
        ),
        ConfigMode::Permanent => Span::styled(
            " permanent (m) ",
            Style::default()
                .fg(theme::on_accent())
                .bg(theme::banner_permanent_bg())
                .add_modifier(Modifier::BOLD),
        ),
    };
    let mut status: Vec<Span> = vec![
        Span::styled(
            format!("zones: {}   ", app.zones.len()),
            theme::fg(theme::muted()),
        ),
        Span::styled("active: ", theme::fg(theme::muted())),
        Span::styled(app.current_zone.clone(), theme::bold(theme::accent())),
        Span::raw("  "),
        mode,
    ];
    if app.panic {
        status.push(Span::raw(" "));
        status.push(Span::styled(
            " ⛔ PANIC — all traffic dropped (P) ",
            Style::default()
                .fg(theme::on_accent())
                .bg(theme::danger())
                .add_modifier(Modifier::BOLD),
        ));
    }
    if app.pending_reload {
        status.push(Span::raw(" "));
        status.push(Span::styled(
            " ⏳ pending reload (R) ",
            Style::default()
                .fg(theme::on_accent())
                .bg(theme::warning())
                .add_modifier(Modifier::BOLD),
        ));
    }

    let split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Fill(1), Constraint::Fill(1)])
        .split(rows[0]);
    f.render_widget(Paragraph::new(title), split[0]);
    f.render_widget(
        Paragraph::new(Line::from(status)).alignment(Alignment::Right),
        split[1],
    );

    // Row 2 (bottom): numbered tab pills (1-5 are also keyboard shortcuts).
    let spans: Vec<Span> = Tab::ALL
        .iter()
        .map(|tab| {
            let is_current = *tab == app.tab;
            let style = if is_current {
                Style::default()
                    .fg(theme::on_accent())
                    .bg(theme::tab_color(*tab))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme::muted())
            };
            Span::styled(format!(" {} {}  ", tab.index() + 1, tab.name()), style)
        })
        .collect();

    let tab_bar = Paragraph::new(Line::from(spans).centered()).style(theme::fg(theme::bg_panel()));
    f.render_widget(tab_bar, rows[1]);
}

/// A one-line status toast under the main panel that surfaces the latest error
/// or informational message. Errors render as a danger bar, info as an info
/// bar; when neither is set the line is blank. Previously these fields were
/// written but never displayed, so some failures were silently dropped.
fn render_status_line(f: &mut Frame, app: &AppState, area: Rect) {
    let (icon, text, bg) = if let Some(e) = &app.error {
        ("!", e.clone(), theme::danger())
    } else if let Some(info) = &app.info {
        ("i", info.clone(), theme::info())
    } else {
        return;
    };

    // Truncate so a long error/command never wraps past the line.
    let avail = area.width.saturating_sub(4) as usize;
    let text = if text.chars().count() > avail {
        let mut t: String = text.chars().take(avail.saturating_sub(1)).collect();
        t.push('…');
        t
    } else {
        text
    };

    let line = Line::from(vec![
        Span::styled(
            format!(" {icon} "),
            Style::default()
                .fg(theme::on_accent())
                .bg(bg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {text} "),
            Style::default().fg(theme::on_accent()).bg(bg),
        ),
    ]);
    let para = Paragraph::new(line).style(Style::default().bg(bg));
    f.render_widget(para, area);
}

fn render_zone_list(f: &mut Frame, app: &mut AppState, area: Rect) {
    let header = Row::new(vec!["Zone", "Default", "Active", "Masquerade"])
        .style(theme::bold(theme::zones()));

    let rows: Vec<Row> = app
        .zones
        .iter()
        .enumerate()
        .map(|(i, zone)| {
            let is_current = zone.name == app.current_zone;
            let name_style = if is_current {
                theme::bold(theme::accent())
            } else {
                theme::fg(theme::text())
            };
            // Zebra striping for readability (selected row overrides via highlight).
            let zebra = if i % 2 == 1 {
                theme::bg_zebra()
            } else {
                Color::Reset
            };

            // Three labeled status columns; a marker means "on", a dim dot "off".
            let on = |on: bool, mark: &'static str, on_color: Color| {
                Span::styled(
                    if on { mark } else { "·" },
                    theme::fg(if on { on_color } else { theme::dim() }),
                )
            };

            Row::new(vec![
                Cell::from(Span::styled(zone.name.clone(), name_style)),
                Cell::from(on(zone.is_default, "●", theme::success())),
                Cell::from(on(zone.is_active, "●", theme::success())),
                Cell::from(on(zone.masquerade, "✓", theme::warning())),
            ])
            .style(Style::default().bg(zebra))
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(12), // Zone
            Constraint::Length(9),  // Default
            Constraint::Length(8),  // Active
            Constraint::Length(12), // Masquerade
        ],
    )
    .header(header)
    .row_highlight_style(Style::default().bg(theme::bg_selected()))
    .block(
        Block::default()
            .title(Title::from(Line::from(Span::styled(
                format!(" ZONES ({}) ", app.zones.len()),
                theme::bold(theme::zones()),
            ))))
            .borders(if app.dialog.is_none() {
                Borders::ALL
            } else {
                Borders::LEFT | Borders::TOP | Borders::BOTTOM
            })
            .border_set(ratatui::symbols::border::DOUBLE)
            .border_style(theme::border(theme::zones()))
            .style(theme::fg(theme::bg_panel())),
    );

    // The sidebar always uses the Zones tab's table state
    let state = &mut app.table_states[Tab::Zones.index()];
    f.render_stateful_widget(table, area, state);
}

fn render_main_panel(f: &mut Frame, app: &mut AppState, area: Rect) {
    match app.tab {
        Tab::Zones => render_map_panel(f, app, area),
        Tab::Ports => render_ports_table(f, app, area),
        Tab::Services => render_services_table(f, app, area),
        Tab::Rules => render_rules_table(f, app, area),
        Tab::Forward => render_forward_table(f, app, area),
    }
}

fn render_ports_table(f: &mut Frame, app: &mut AppState, area: Rect) {
    let accent = theme::ports();
    let header = Row::new(vec!["Port", "Proto", "Description"]).style(theme::bold(accent));

    // Reserve a 1-wide gutter on the right for the scrollbar.
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Fill(1), Constraint::Length(1)])
        .split(area);
    let (table_area, bar_area) = (layout[0], layout[1]);

    let zone_ports = filtered_ports(app);
    let total = app.current_zone_ref().map(|z| z.ports.len()).unwrap_or(0);
    let has_any = app
        .current_zone_ref()
        .map(|z| !z.ports.is_empty())
        .unwrap_or(false);
    let empty_msg = if app.filter.trim().is_empty() || !has_any {
        format!(
            "No ports open in '{}' — press a to add one (e.g. 8080/tcp)",
            app.current_zone
        )
    } else {
        format!("No ports match '{}'", app.filter)
    };

    let rows: Vec<Row> = if zone_ports.is_empty() {
        vec![Row::new(vec![Cell::from(Span::styled(
            empty_msg,
            theme::fg(theme::dim()),
        ))])]
    } else {
        zone_ports
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let zebra = if i % 2 == 1 {
                    theme::bg_zebra()
                } else {
                    Color::Reset
                };
                let svc = port_to_service(&p.port, &p.protocol);
                Row::new(vec![
                    Cell::from(Span::styled(p.port.clone(), theme::bold(theme::text()))),
                    Cell::from(Span::styled(p.protocol.clone(), theme::fg(accent))),
                    Cell::from(Span::styled(
                        if svc.is_empty() {
                            "".to_string()
                        } else {
                            svc.to_string()
                        },
                        theme::fg(theme::muted()),
                    )),
                ])
                .style(Style::default().bg(zebra))
            })
            .collect()
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(14),
            Constraint::Length(8),
            Constraint::Fill(1),
        ],
    )
    .header(header)
    .row_highlight_style(Style::default().bg(theme::bg_selected()))
    .block(
        Block::default()
            .title(Title::from(Line::from(Span::styled(
                count_tag(filter_title("PORTS", app), zone_ports.len(), total),
                theme::bold(accent),
            ))))
            .borders(if app.dialog.is_none() {
                Borders::ALL
            } else {
                Borders::RIGHT | Borders::TOP | Borders::BOTTOM
            })
            .border_set(ratatui::symbols::border::DOUBLE)
            .border_style(theme::border(accent))
            .style(theme::fg(theme::bg_panel())),
    );

    let state = &mut app.table_states[Tab::Ports.index()];
    let selected = state.selected();
    f.render_stateful_widget(table, table_area, state);
    render_list_scrollbar(f, bar_area, selected, zone_ports.len(), accent);
}

/// Case-insensitive substring match for the typeahead filter.
fn matches_filter(haystack: &str, filter: &str) -> bool {
    haystack.to_lowercase().contains(&filter.to_lowercase())
}

/// A table title that shows the active filter (if any).
fn filter_title(tab_name: &str, app: &AppState) -> String {
    let f = app.filter.trim();
    if f.is_empty() {
        format!(" {tab_name} — {} ", app.current_zone)
    } else {
        format!(
            " {tab_name} — {}  (filter: \"{f}\", esc clears) ",
            app.current_zone
        )
    }
}

/// Append a row count to a table title: `shown/total` while filtering, or just
/// `total` when the full list is shown.
fn count_tag(title: String, shown: usize, total: usize) -> String {
    let title = title.trim_end();
    if shown != total {
        format!("{title} · {shown}/{total} ")
    } else {
        format!("{title} · {total} ")
    }
}

/// Draw a slim vertical scrollbar for a list, aligned to the selected row.
/// The table keeps the selection in view; this gives position feedback.
fn render_list_scrollbar(
    f: &mut Frame,
    area: Rect,
    selected: Option<usize>,
    total: usize,
    accent: Color,
) {
    if total <= 1 {
        return;
    }
    // One header row plus two border rows are not part of the scrollable data.
    let viewport = area.height.saturating_sub(3).max(1) as usize;
    let mut state = ScrollbarState::new(total)
        .viewport_content_length(viewport)
        .position(selected.unwrap_or(0));
    let bar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(None)
        .end_symbol(None)
        .thumb_symbol("┃")
        .track_symbol(Some("│"))
        .thumb_style(Style::default().fg(accent))
        .track_style(Style::default().fg(theme::dim()));
    f.render_stateful_widget(bar, area, &mut state);
}

/// The current zone's ports, filtered by the typeahead filter (if any).
fn filtered_ports(app: &AppState) -> Vec<PortEntry> {
    let ports = app
        .current_zone_ref()
        .map(|z| z.ports.clone())
        .unwrap_or_default();
    let filter = app.filter.trim();
    if filter.is_empty() {
        return ports;
    }
    ports
        .into_iter()
        .filter(|p| {
            matches_filter(&p.display(), filter)
                || matches_filter(&p.port, filter)
                || matches_filter(&p.protocol, filter)
        })
        .collect()
}

/// The current zone's rich rules, filtered by the typeahead filter (if any).
fn filtered_rules(app: &AppState) -> Vec<String> {
    let rules = app
        .current_zone_ref()
        .map(|z| z.rich_rules.clone())
        .unwrap_or_default();
    let filter = app.filter.trim();
    if filter.is_empty() {
        return rules;
    }
    rules
        .into_iter()
        .filter(|r| matches_filter(r, filter))
        .collect()
}

/// The current zone's forward ports, filtered by the typeahead filter (if any).
fn filtered_forward(app: &AppState) -> Vec<ForwardPort> {
    let fports = app
        .current_zone_ref()
        .map(|z| z.forward_port.clone())
        .unwrap_or_default();
    let filter = app.filter.trim();
    if filter.is_empty() {
        return fports;
    }
    fports
        .into_iter()
        .filter(|fp| {
            matches_filter(&fp.port, filter)
                || matches_filter(&fp.protocol, filter)
                || fp
                    .to_port
                    .as_deref()
                    .map(|v| matches_filter(v, filter))
                    .unwrap_or(false)
                || fp
                    .to_addr
                    .as_deref()
                    .map(|v| matches_filter(v, filter))
                    .unwrap_or(false)
        })
        .collect()
}

/// One row of the services table (zone services first, then the rest)
struct ServiceRow {
    name: String,
    active: bool,
    ports: String,
    description: String,
    loaded: bool,
}

fn service_rows(app: &AppState) -> Vec<ServiceRow> {
    let zone_services: Vec<String> = app
        .current_zone_ref()
        .map(|z| z.services.clone())
        .unwrap_or_default();

    let mut rows = Vec::new();
    for name in &zone_services {
        let details = app.service_details.get(name);
        rows.push(ServiceRow {
            name: name.clone(),
            active: true,
            ports: details.map(|d| format_ports(&d.ports)).unwrap_or_default(),
            description: details.map(|d| d.description.clone()).unwrap_or_default(),
            loaded: details.is_some(),
        });
    }
    for name in &app.service_names {
        if zone_services.contains(name) {
            continue;
        }
        let details = app.service_details.get(name);
        rows.push(ServiceRow {
            name: name.clone(),
            active: false,
            ports: details.map(|d| format_ports(&d.ports)).unwrap_or_default(),
            description: details.map(|d| d.description.clone()).unwrap_or_default(),
            loaded: details.is_some(),
        });
    }

    // Apply the typeahead filter (case-insensitive substring on name or description).
    let filter = app.filter.to_lowercase();
    if !filter.is_empty() {
        rows.retain(|r| {
            r.name.to_lowercase().contains(&filter)
                || r.description.to_lowercase().contains(&filter)
        });
    }
    rows
}

fn format_ports(ports: &[PortEntry]) -> String {
    ports
        .iter()
        .map(|p| p.display())
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_services_table(f: &mut Frame, app: &mut AppState, area: Rect) {
    let rows_data = service_rows(app);
    let total = app.service_names.len();

    // Table + a description strip for the selected service
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(4)])
        .split(area);
    // Reserve a 1-wide gutter on the right of the table for the scrollbar.
    let table_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Fill(1), Constraint::Length(1)])
        .split(chunks[0]);
    let (table_area, bar_area) = (table_layout[0], table_layout[1]);

    let accent = theme::services();
    let header = Row::new(vec!["Service", "Port(s)", "Active"]).style(theme::bold(accent));

    let rows: Vec<Row> = rows_data
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let zebra = if i % 2 == 1 {
                theme::bg_zebra()
            } else {
                Color::Reset
            };
            let name_style = if r.active {
                theme::bold(theme::text())
            } else {
                theme::fg(theme::muted())
            };
            Row::new(vec![
                Cell::from(Span::styled(r.name.clone(), name_style)),
                Cell::from(Span::styled(
                    if r.loaded {
                        r.ports.clone()
                    } else {
                        "…".to_string()
                    },
                    theme::fg(theme::muted()),
                )),
                Cell::from(Span::styled(
                    if r.active { "✓" } else { " " },
                    theme::fg(if r.active {
                        theme::success()
                    } else {
                        theme::dim()
                    }),
                )),
            ])
            .style(Style::default().bg(zebra))
        })
        .collect();

    let title_text = count_tag(filter_title("SERVICES", app), rows_data.len(), total);

    let table = Table::new(
        rows,
        [
            Constraint::Length(18),
            Constraint::Length(34),
            Constraint::Length(6),
        ],
    )
    .header(header)
    .row_highlight_style(Style::default().bg(theme::bg_selected()))
    .block(
        Block::default()
            .title(Title::from(Line::from(Span::styled(
                title_text,
                theme::bold(accent),
            ))))
            .borders(if app.dialog.is_none() {
                Borders::ALL
            } else {
                Borders::RIGHT | Borders::TOP | Borders::BOTTOM
            })
            .border_set(ratatui::symbols::border::DOUBLE)
            .border_style(theme::border(accent))
            .style(theme::fg(theme::bg_panel())),
    );

    let state = &mut app.table_states[Tab::Services.index()];
    let selected = state.selected();
    f.render_stateful_widget(table, table_area, state);
    render_list_scrollbar(f, bar_area, selected, rows_data.len(), accent);

    // Description of the selected service
    let desc = app.table_states[Tab::Services.index()]
        .selected()
        .and_then(|i| rows_data.get(i))
        .map(|r| r.description.clone())
        .unwrap_or_default();
    let text = if desc.is_empty() {
        if app.service_loading {
            "Loading service details…".to_string()
        } else {
            " ".to_string()
        }
    } else {
        desc
    };
    let para = Paragraph::new(Line::from(Span::styled(text, theme::fg(theme::text()))))
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(if app.dialog.is_none() {
                    Borders::ALL
                } else {
                    Borders::RIGHT | Borders::TOP | Borders::BOTTOM
                })
                .border_set(ratatui::symbols::border::DOUBLE)
                .border_style(theme::border(theme::services()))
                .style(theme::fg(theme::bg_panel()))
                .title(Title::from(Line::from(Span::styled(
                    " DESCRIPTION ",
                    theme::bold(theme::services()),
                )))),
        );
    f.render_widget(para, chunks[1]);
}

fn render_rules_table(f: &mut Frame, app: &mut AppState, area: Rect) {
    let accent = theme::rules();
    let header = Row::new(vec!["Rule"]).style(theme::bold(accent));

    // Reserve a 1-wide gutter on the right for the scrollbar.
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Fill(1), Constraint::Length(1)])
        .split(area);
    let (table_area, bar_area) = (layout[0], layout[1]);

    let zone_rules = filtered_rules(app);
    let total = app
        .current_zone_ref()
        .map(|z| z.rich_rules.len())
        .unwrap_or(0);
    let has_any = app
        .current_zone_ref()
        .map(|z| !z.rich_rules.is_empty())
        .unwrap_or(false);
    let empty_msg = if app.filter.trim().is_empty() || !has_any {
        format!(
            "No rich rules in '{}' — press a to add one",
            app.current_zone
        )
    } else {
        format!("No rich rules match '{}'", app.filter)
    };

    let rows: Vec<Row> = if zone_rules.is_empty() {
        vec![Row::new(vec![Cell::from(Span::styled(
            empty_msg,
            theme::fg(theme::dim()),
        ))])]
    } else {
        zone_rules
            .iter()
            .enumerate()
            .map(|(i, rule)| {
                let zebra = if i % 2 == 1 {
                    theme::bg_zebra()
                } else {
                    Color::Reset
                };
                Row::new(vec![Cell::from(Span::styled(
                    rule.clone(),
                    theme::fg(theme::text()),
                ))])
                .style(Style::default().bg(zebra))
            })
            .collect()
    };

    let table = Table::new(rows, [Constraint::Fill(1)])
        .header(header)
        .row_highlight_style(Style::default().bg(theme::bg_selected()))
        .block(
            Block::default()
                .title(Title::from(Line::from(Span::styled(
                    count_tag(filter_title("RICH RULES", app), zone_rules.len(), total),
                    theme::bold(accent),
                ))))
                .borders(if app.dialog.is_none() {
                    Borders::ALL
                } else {
                    Borders::RIGHT | Borders::TOP | Borders::BOTTOM
                })
                .border_set(ratatui::symbols::border::DOUBLE)
                .border_style(theme::border(accent))
                .style(theme::fg(theme::bg_panel())),
        );

    let state = &mut app.table_states[Tab::Rules.index()];
    let selected = state.selected();
    f.render_stateful_widget(table, table_area, state);
    render_list_scrollbar(f, bar_area, selected, zone_rules.len(), accent);
}

fn render_forward_table(f: &mut Frame, app: &mut AppState, area: Rect) {
    let accent = theme::forward();
    let header = Row::new(vec!["Port", "Proto", "To Port", "To Addr"]).style(theme::bold(accent));

    // Reserve a 1-wide gutter on the right for the scrollbar.
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Fill(1), Constraint::Length(1)])
        .split(area);
    let (table_area, bar_area) = (layout[0], layout[1]);

    let zone_fports = filtered_forward(app);
    let total = app
        .current_zone_ref()
        .map(|z| z.forward_port.len())
        .unwrap_or(0);
    let has_any = app
        .current_zone_ref()
        .map(|z| !z.forward_port.is_empty())
        .unwrap_or(false);
    let empty_msg = if app.filter.trim().is_empty() || !has_any {
        format!(
            "No forwarded ports in '{}' — press a to add one",
            app.current_zone
        )
    } else {
        format!("No forwarded ports match '{}'", app.filter)
    };

    let rows: Vec<Row> = if zone_fports.is_empty() {
        vec![Row::new(vec![Cell::from(Span::styled(
            empty_msg,
            theme::fg(theme::dim()),
        ))])]
    } else {
        zone_fports
            .iter()
            .enumerate()
            .map(|(i, fp)| {
                let zebra = if i % 2 == 1 {
                    theme::bg_zebra()
                } else {
                    Color::Reset
                };
                Row::new(vec![
                    Cell::from(Span::styled(fp.port.clone(), theme::bold(theme::text()))),
                    Cell::from(Span::styled(fp.protocol.clone(), theme::fg(accent))),
                    Cell::from(Span::styled(
                        fp.to_port.clone().unwrap_or_else(|| "any".to_string()),
                        theme::fg(theme::text()),
                    )),
                    Cell::from(Span::styled(
                        fp.to_addr.clone().unwrap_or_else(|| "any".to_string()),
                        theme::fg(theme::muted()),
                    )),
                ])
                .style(Style::default().bg(zebra))
            })
            .collect()
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Fill(1),
        ],
    )
    .header(header)
    .row_highlight_style(Style::default().bg(theme::bg_selected()))
    .block(
        Block::default()
            .title(Title::from(Line::from(Span::styled(
                count_tag(
                    filter_title("PORT FORWARDING", app),
                    zone_fports.len(),
                    total,
                ),
                theme::bold(accent),
            ))))
            .borders(if app.dialog.is_none() {
                Borders::ALL
            } else {
                Borders::RIGHT | Borders::TOP | Borders::BOTTOM
            })
            .border_set(ratatui::symbols::border::DOUBLE)
            .border_style(theme::border(accent))
            .style(theme::fg(theme::bg_panel())),
    );

    let state = &mut app.table_states[Tab::Forward.index()];
    let selected = state.selected();
    f.render_stateful_widget(table, table_area, state);
    render_list_scrollbar(f, bar_area, selected, zone_fports.len(), accent);
}

fn render_footer(f: &mut Frame, app: &mut AppState, area: Rect) {
    // A keycap: bold accent text on a subtle background, like a physical key.
    let key = |s: &str| {
        Span::styled(
            format!(" {s} "),
            Style::default()
                .fg(theme::accent())
                .bg(theme::bg_selected())
                .add_modifier(Modifier::BOLD),
        )
    };
    let desc = |s: &str| Span::styled(s.to_string(), theme::fg(theme::muted()));
    let sep = || Span::raw("  ");

    // Line 1: the keys that matter on the active tab (instead of a fixed
    // wall of keycaps).
    let line1 = match app.tab {
        Tab::Zones => Line::from(vec![
            key("↑↓ Pg"),
            desc("move"),
            sep(),
            key("a"),
            desc("new"),
            sep(),
            key("d"),
            desc("del"),
            sep(),
            key("D"),
            desc("default"),
            sep(),
            key("i"),
            desc("iface"),
            sep(),
            key("t"),
            desc("target"),
            sep(),
            key("f"),
            desc("fwd"),
            sep(),
            key("c"),
            desc("icmp"),
            sep(),
            key("s"),
            desc("src"),
            sep(),
            key("x"),
            desc("masq"),
            sep(),
            key("M"),
            desc("full map"),
        ]),
        Tab::Ports => Line::from(vec![
            key("↑↓ Pg"),
            desc("move"),
            sep(),
            key("a"),
            desc("add"),
            sep(),
            key("d"),
            desc("remove"),
            sep(),
            key("/"),
            desc("filter"),
            sep(),
            key("c"),
            desc("cmd"),
        ]),
        Tab::Services => Line::from(vec![
            key("↑↓ Pg"),
            desc("move"),
            sep(),
            key("Enter"),
            desc("add"),
            sep(),
            key("d"),
            desc("remove"),
            sep(),
            key("/"),
            desc("filter"),
            sep(),
            key("c"),
            desc("cmd"),
        ]),
        Tab::Rules => Line::from(vec![
            key("↑↓ Pg"),
            desc("move"),
            sep(),
            key("Enter"),
            desc("view"),
            sep(),
            key("e"),
            desc("edit"),
            sep(),
            key("a"),
            desc("add"),
            sep(),
            key("d"),
            desc("remove"),
            sep(),
            key("/"),
            desc("filter"),
            sep(),
            key("c"),
            desc("cmd"),
        ]),
        Tab::Forward => Line::from(vec![
            key("↑↓ Pg"),
            desc("move"),
            sep(),
            key("a"),
            desc("add"),
            sep(),
            key("d"),
            desc("remove"),
            sep(),
            key("/"),
            desc("filter"),
            sep(),
            key("c"),
            desc("cmd"),
        ]),
    };

    // Lines 2-3: the last two actions, most recent first, each with the exact
    // firewall-cmd behind it. The current mode is already shown in the header
    // and mode banner, so it no longer needs its own footer row.
    let mut lines = vec![line1];
    let entries: Vec<&LogEntry> = app.log.iter().rev().take(2).collect();
    if entries.is_empty() {
        lines.push(Line::from(Span::styled(
            "● ready",
            theme::fg(theme::success()),
        )));
    } else {
        for (i, e) in entries.iter().enumerate() {
            let (icon, color) = match e.kind {
                LogKind::Success => ("✓", theme::success()),
                LogKind::Error => ("⚠", theme::danger()),
                LogKind::Info => ("·", theme::info()),
            };
            let dim = i > 0;
            let icon_style = if dim {
                theme::fg(theme::dim())
            } else {
                theme::bold(color)
            };
            let msg_style = if dim {
                theme::fg(theme::dim())
            } else {
                theme::fg(theme::text())
            };
            let mut spans = vec![
                Span::styled(format!("{icon} "), icon_style),
                Span::styled(e.message.clone(), msg_style),
                Span::styled(
                    format!(" ({})", e.mode),
                    theme::fg(if dim { theme::dim() } else { theme::muted() }),
                ),
            ];
            if let Some(cmd) = &e.command {
                spans.push(Span::styled(format!("  ·  {cmd}"), theme::fg(theme::dim())));
            }
            lines.push(Line::from(spans));
        }
    }

    let footer = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::TOP)
            .border_set(ratatui::symbols::border::DOUBLE)
            .border_style(theme::border(theme::accent()))
            .style(theme::fg(theme::bg_panel())),
    );
    f.render_widget(footer, area);
}

fn render_dialog(f: &mut Frame, app: &mut AppState) {
    let area = f.area();
    let Some(dialog) = &app.dialog else {
        return;
    };

    let width = if matches!(
        dialog.kind,
        DialogKind::Help
            | DialogKind::About
            | DialogKind::RuleDetail
            | DialogKind::ZoneDiff
            | DialogKind::Intro
            | DialogKind::CommandPreview
            | DialogKind::Log
    ) {
        72.min(area.width.saturating_sub(4))
    } else {
        64.min(area.width.saturating_sub(4))
    };
    let msg_lines = dialog
        .message
        .as_ref()
        .map(|m| m.lines().count() as u16)
        .unwrap_or(0);
    // Each field takes one line, plus a second line when it carries a hint.
    let field_lines: u16 = dialog
        .fields
        .iter()
        .map(|f| 1 + u16::from(!f.hint.is_empty()))
        .sum();
    // Box height must cover every content line (title, spacer, message lines,
    // spacer, field lines, spacer, hint) plus the top and bottom borders.
    let content_lines = field_lines + msg_lines + 5;
    let height = (content_lines + 2).min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let box_area = Rect::new(x, y, width, height);

    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(
            dialog.title.clone(),
            theme::bold(theme::accent()),
        )),
        Line::from(" "),
    ];

    if let Some(msg) = &dialog.message {
        for m in msg.lines() {
            lines.push(Line::from(Span::styled(
                m.to_string(),
                theme::fg(theme::muted()),
            )));
        }
        lines.push(Line::from(" "));
    }

    for (i, field) in dialog.fields.iter().enumerate() {
        let active = i == dialog.active;
        let label_style = if active {
            theme::bold(theme::accent())
        } else {
            theme::fg(theme::muted())
        };
        let value_style = if active {
            Style::default().fg(theme::text()).bg(theme::bg_selected())
        } else {
            theme::fg(theme::text())
        };
        let cursor = if active && field.options.is_none() {
            Span::styled(
                "█",
                Style::default()
                    .fg(theme::accent())
                    .bg(theme::bg_selected()),
            )
        } else {
            Span::raw("")
        };
        let cycle_hint = if active && field.options.is_some() {
            Span::styled("  (↑↓ to cycle)", theme::fg(theme::dim()))
        } else {
            Span::raw("")
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{:<12}", field.label), label_style),
            Span::styled(field.value.clone(), value_style),
            cursor,
            cycle_hint,
        ]));
        // Example / explanation under the value, indented to align with it.
        if !field.hint.is_empty() {
            lines.push(Line::from(vec![
                Span::raw("            "),
                Span::styled(field.hint.clone(), theme::fg(theme::dim())),
            ]));
        }
    }

    lines.push(Line::from(" "));
    let hint = if dialog.fields.is_empty() {
        match dialog.kind {
            DialogKind::RuleDetail
            | DialogKind::About
            | DialogKind::Intro
            | DialogKind::ZoneDiff
            | DialogKind::CommandPreview
            | DialogKind::Log => "Esc or Enter to close",
            _ => "y confirm · n cancel · Esc cancel",
        }
    } else {
        "Enter submit · Tab/←→ field · ↑↓ option · Esc cancel"
    };
    // Clamp the scroll offset to the overflow (content lines beyond the box's
    // inner height) and hint that scrolling is possible.
    let inner_height = box_area.height.saturating_sub(2) as usize;
    let max_scroll = lines.len().saturating_sub(inner_height);
    if app.dialog_scroll as usize > max_scroll {
        app.dialog_scroll = max_scroll as u16;
    }
    let hint = if max_scroll > 0 {
        format!(
            "{hint} · PgUp/PgDn scroll ({}/{})",
            app.dialog_scroll + 1,
            max_scroll + 1
        )
    } else {
        hint.to_string()
    };
    lines.push(Line::from(Span::styled(hint, theme::fg(theme::dim()))));

    let para = Paragraph::new(lines).scroll((app.dialog_scroll, 0)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_set(ratatui::symbols::border::DOUBLE)
            .border_style(theme::border(theme::accent()))
            // A solid background so the dialog is opaque and the content
            // behind it (e.g. the active tab's table) does not show through.
            .style(Style::default().bg(theme::bg_panel())),
    );
    f.render_widget(para, box_area);
}

// ─── Topology map ───────────────────────────────────────────────────────

/// Ports that are rarely intentional on a server and are heavily scanned /
/// exploited in the wild; flagged red on the map.
const RISKY_PORTS: &[&str] = &[
    "21", "23", "135", "139", "445", "512", "513", "514", "1433", "3389", "5900",
];

/// Service names with the same risk profile as `RISKY_PORTS`.
const RISKY_SERVICES: &[&str] = &[
    "telnet",
    "ftp",
    "rsh",
    "rexec",
    "login",
    "shell",
    "tftp",
    "vnc-server",
    "ms-wbt-server",
    "samba",
];

/// Truncate `s` to at most `w` display chars, appending '…' when cut.
fn trunc(s: &str, w: usize) -> String {
    if s.chars().count() <= w {
        return s.to_string();
    }
    if w == 0 {
        return String::new();
    }
    let mut t: String = s.chars().take(w - 1).collect();
    t.push('…');
    t
}

/// The display width (chars) of a styled line.
fn line_width(l: &Line) -> usize {
    l.spans.iter().map(|s| s.content.chars().count()).sum()
}

/// M: open the full-screen topology overlay. The system facts it shows
/// (interface IPs, default route) are sampled by `refresh_state`, so opening
/// is instantaneous and frame-safe.
fn toggle_map(app: &mut AppState) {
    app.show_map = true;
    app.map_scroll = 0;
}

/// Key handling while the topology map is open: M/Esc/q close, navigation
/// keys scroll, r re-samples live state.
fn handle_map_key(key: KeyEvent, app: &mut AppState) {
    match key.code {
        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('M') => {
            app.show_map = false;
        }
        KeyCode::Up | KeyCode::Char('k') => app.map_scroll = app.map_scroll.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => app.map_scroll = app.map_scroll.saturating_add(1),
        KeyCode::PageUp => app.map_scroll = app.map_scroll.saturating_sub(10),
        KeyCode::PageDown => app.map_scroll = app.map_scroll.saturating_add(10),
        KeyCode::Home | KeyCode::Char('g') => app.map_scroll = 0,
        // Clamped to the real maximum at render time.
        KeyCode::End | KeyCode::Char('G') => app.map_scroll = u16::MAX,
        KeyCode::Char('r') => refresh_state(app),
        _ => {}
    }
}

/// The zone carrying the current remote session, using the map's cached
/// default-route interface: the zone bound to it, else the system default
/// zone (firewalld's fallback for unbound interfaces).
fn map_session_zone(app: &AppState) -> Option<&Zone> {
    if let Some(iface) = &app.map_route_iface {
        if let Some(z) = app
            .zones
            .iter()
            .find(|z| z.interfaces.iter().any(|i| i == iface))
        {
            return Some(z);
        }
    }
    app.zones.iter().find(|z| z.is_default)
}

/// Build the topology map's content: for every zone — or just `only_zone`
/// when set (the Zones panel passes the selected zone; the M overlay passes
/// `None` for all) — what feeds it (interfaces / sources) on the left and
/// what it allows (services / ports / rules / …) on the right, with the
/// session path starred, risky exposures flagged, and the selected zone
/// marked. Returns the lines plus each zone block's range
/// `(name, start, end)` for follow-scrolling and hit-testing.
fn build_map_lines(
    app: &AppState,
    inner_w: usize,
    only_zone: Option<&str>,
) -> (Vec<Line<'static>>, Vec<(String, usize, usize)>) {
    let session = map_session_zone(app).map(|z| z.name.clone());
    let left_w = (inner_w * 2 / 5).clamp(12, 38);

    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut blocks: Vec<(String, usize, usize)> = Vec::new();

    if app.panic {
        lines.push(Line::from(Span::styled(
            " ⛔ PANIC MODE — ALL traffic dropped; nothing below is being hit (P toggles) ",
            Style::default()
                .fg(theme::on_accent())
                .bg(theme::danger())
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
    }

    // Column legend.
    lines.push(Line::from(vec![
        Span::styled(
            format!("{:<w$}", " ◂ IN — interfaces / sources", w = left_w + 1),
            theme::bold(theme::muted()),
        ),
        Span::styled(" ▸ OUT — allowed traffic", theme::bold(theme::muted())),
    ]));
    lines.push(Line::from(Span::styled(
        "─".repeat(inner_w),
        theme::fg(theme::dim()),
    )));

    for z in &app.zones {
        if only_zone.is_some_and(|n| n != z.name) {
            continue;
        }
        let block_start = lines.len();
        let selected = z.name == app.current_zone;
        let is_session = session.as_deref() == Some(z.name.as_str());

        // ── Zone header row ──
        let target_color = match z.target.to_lowercase().as_str() {
            "default" | "accept" => theme::success(),
            "reject" => theme::warning(),
            "drop" => theme::danger(),
            _ => theme::muted(),
        };
        let mut header = vec![
            if selected {
                Span::styled("▸ ", theme::bold(theme::accent()))
            } else {
                Span::raw("  ")
            },
            Span::styled(
                if z.is_active { "● " } else { "○ " },
                theme::fg(if z.is_active {
                    theme::success()
                } else {
                    theme::dim()
                }),
            ),
            Span::styled(z.name.clone(), theme::bold(theme::accent())),
        ];
        if z.is_default {
            header.push(Span::styled(" (default)", theme::bold(theme::success())));
        }
        if is_session {
            header.push(Span::styled(
                " ★ YOUR SESSION",
                theme::bold(theme::warning()),
            ));
        }
        header.push(Span::styled(
            format!("  target: {}", z.target),
            theme::bold(target_color),
        ));
        // ON states get a bright color so they pop at a glance: masq follows
        // the sidebar's warning color, fwd is green; off stays dim.
        let on_off = |b: bool, on_color: Color| {
            if b {
                Span::styled("ON", theme::bold(on_color))
            } else {
                Span::styled("off", theme::fg(theme::dim()))
            }
        };
        header.push(Span::styled("  masq ", theme::fg(theme::muted())));
        header.push(on_off(z.masquerade, theme::warning()));
        header.push(Span::styled(" · fwd ", theme::fg(theme::muted())));
        header.push(on_off(z.forward, theme::success()));
        lines.push(Line::from(header));
        // The selected zone also shows its firewalld description — unless it
        // merely repeats the zone name (firewalld's <short> for builtin zones
        // is just the capitalized name, e.g. "Public" for "public").
        if selected {
            let desc = app
                .zone_descriptions
                .get(&z.name)
                .cloned()
                .unwrap_or_else(|| zone_description(&z.name).to_string());
            let d = desc.trim();
            if !d.is_empty() && !d.eq_ignore_ascii_case(&z.name) {
                lines.push(Line::from(Span::styled(
                    format!("   {}", trunc(d, inner_w.saturating_sub(3))),
                    theme::fg(theme::dim()),
                )));
            }
        }

        // ── Left column: what feeds the zone ──
        let mut inp: Vec<Line> = Vec::new();
        for i in &z.interfaces {
            let route = app.map_route_iface.as_deref() == Some(i.as_str());
            let mut spans = vec![
                Span::styled("◂ ", theme::fg(theme::dim())),
                Span::styled(
                    i.clone(),
                    theme::fg(if route {
                        theme::warning()
                    } else {
                        theme::text()
                    }),
                ),
            ];
            if let Some(ip) = app.map_iface_ips.get(i) {
                spans.push(Span::styled(format!(" ({ip})"), theme::fg(theme::muted())));
            }
            if route {
                spans.push(Span::styled(" ★", theme::bold(theme::warning())));
            }
            inp.push(Line::from(spans));
        }
        for s in &z.sources {
            inp.push(Line::from(vec![
                Span::styled("◂ ", theme::fg(theme::dim())),
                Span::styled(format!("net {s}"), theme::fg(theme::info())),
            ]));
        }
        if inp.is_empty() {
            inp.push(Line::from(Span::styled(
                "◂ (unbound)",
                theme::fg(theme::dim()),
            )));
        }

        // ── Right column: what the zone allows ──
        let mut out: Vec<Line> = Vec::new();
        for s in &z.services {
            let risky = RISKY_SERVICES.contains(&s.as_str());
            let ports = app
                .service_details
                .get(s)
                .map(|d| {
                    let v: Vec<String> = d.ports.iter().map(|p| p.display()).collect();
                    if v.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", v.join(","))
                    }
                })
                .unwrap_or_default();
            let mut spans = vec![
                Span::styled("▸ ", theme::fg(theme::dim())),
                Span::styled(
                    format!("{s}{ports}"),
                    theme::fg(if risky {
                        theme::danger()
                    } else {
                        theme::services()
                    }),
                ),
            ];
            if risky {
                spans.push(Span::styled(" ⚠ risky", theme::bold(theme::danger())));
            }
            if is_session && s == "ssh" {
                spans.push(Span::styled(" ✓ lifeline", theme::bold(theme::success())));
            }
            out.push(Line::from(spans));
        }
        for p in &z.ports {
            let risky = RISKY_PORTS.contains(&p.port.as_str());
            let mut spans = vec![
                Span::styled("▸ ", theme::fg(theme::dim())),
                Span::styled(
                    p.display(),
                    theme::fg(if risky {
                        theme::danger()
                    } else {
                        theme::ports()
                    }),
                ),
            ];
            if risky {
                spans.push(Span::styled(" ⚠ risky", theme::bold(theme::danger())));
            }
            if is_session && p.port == "22" && p.protocol == "tcp" {
                spans.push(Span::styled(" ✓ lifeline", theme::bold(theme::success())));
            }
            out.push(Line::from(spans));
        }
        for proto in &z.protocols {
            out.push(Line::from(vec![
                Span::styled("▸ ", theme::fg(theme::dim())),
                Span::styled(format!("proto {proto}"), theme::fg(theme::info())),
            ]));
        }
        for sp in &z.source_ports {
            out.push(Line::from(vec![
                Span::styled("▸ ", theme::fg(theme::dim())),
                Span::styled(
                    format!("src-port {}", sp.display()),
                    theme::fg(theme::muted()),
                ),
            ]));
        }
        for icmp in &z.icmp_blocks {
            out.push(Line::from(vec![
                Span::styled("▸ ", theme::fg(theme::dim())),
                Span::styled(format!("icmp-block {icmp}"), theme::fg(theme::zones())),
            ]));
        }
        for fp in &z.forward_port {
            let mut t = format!("fwd {}/{} → ", fp.port, fp.protocol);
            match (&fp.to_port, &fp.to_addr) {
                (Some(tp), Some(ta)) => t.push_str(&format!("{tp} @{ta}")),
                (Some(tp), None) => t.push_str(tp),
                (None, Some(ta)) => t.push_str(&format!("@{ta}")),
                (None, None) => t.push_str("same"),
            }
            out.push(Line::from(vec![
                Span::styled("▸ ", theme::fg(theme::dim())),
                Span::styled(t, theme::fg(theme::forward())),
            ]));
        }
        const RULE_MAX: usize = 4;
        for (n, r) in z.rich_rules.iter().enumerate() {
            if n >= RULE_MAX {
                out.push(Line::from(Span::styled(
                    format!("▸ +{} more rules…", z.rich_rules.len() - n),
                    theme::fg(theme::dim()),
                )));
                break;
            }
            let d = parse_rich_rule(r);
            let mut parts: Vec<String> = Vec::new();
            if !d.source.is_empty() {
                parts.push(format!("src {}", d.source));
            }
            if !d.destination.is_empty() {
                parts.push(format!("dst {}", d.destination));
            }
            if !d.service.is_empty() {
                parts.push(d.service.clone());
            }
            if !d.port.is_empty() {
                parts.push(format!("{}/{}", d.port, d.protocol));
            }
            if !d.icmp.is_empty() {
                parts.push(format!("icmp {}", d.icmp));
            }
            let color = match d.action.as_str() {
                "drop" | "reject" => theme::danger(),
                "accept" => theme::success(),
                _ => theme::rules(),
            };
            out.push(Line::from(vec![
                Span::styled("▸ ", theme::fg(theme::dim())),
                Span::styled(
                    trunc(&format!("rule {} → {}", parts.join(" "), d.action), 80),
                    theme::fg(color),
                ),
            ]));
        }
        if out.is_empty() {
            out.push(Line::from(Span::styled(
                "▸ (nothing allowed)",
                theme::fg(theme::dim()),
            )));
        }
        if is_session && !zone_allows_ssh(z) {
            out.push(Line::from(Span::styled(
                "⛔ NO SSH — lockout risk!",
                theme::bold(theme::danger()),
            )));
        }

        // ── Merge the two columns row by row ──
        let rows = inp.len().max(out.len());
        for r in 0..rows {
            let mut spans: Vec<Span> = Vec::new();
            let w = inp.get(r).map(line_width).unwrap_or(0);
            if let Some(line) = inp.get(r) {
                spans.extend(line.spans.iter().cloned());
            }
            spans.push(Span::raw(" ".repeat(left_w.saturating_sub(w) + 1)));
            if let Some(line) = out.get(r) {
                spans.extend(line.spans.iter().cloned());
            }
            lines.push(Line::from(spans));
        }
        lines.push(Line::from(Span::styled(
            "─".repeat(inner_w),
            theme::fg(theme::dim()),
        )));
        blocks.push((z.name.clone(), block_start, lines.len()));
    }

    if blocks.is_empty() {
        let msg = if app.zones.is_empty() {
            "no zones loaded (r to refresh)".to_string()
        } else {
            format!(
                "zone '{}' not loaded (r to refresh)",
                only_zone.unwrap_or("?")
            )
        };
        lines.push(Line::from(Span::styled(msg, theme::fg(theme::dim()))));
    }

    (lines, blocks)
}

/// The minimal scroll that keeps the selected zone's header in view:
/// re-anchor to the block top only when the header leaves the viewport.
fn follow_scroll(cur: u16, start: usize, vh: usize, max_scroll: usize) -> u16 {
    if vh == 0 {
        return 0;
    }
    let cur = (cur as usize).min(max_scroll);
    let next = if start < cur || start >= cur + vh {
        start
    } else {
        cur
    };
    next.min(max_scroll) as u16
}

/// M: the full-screen topology overlay — the same content as the Zones
/// panel, with manual scrolling.
fn render_map(f: &mut Frame, app: &mut AppState) {
    let area = f.area();
    let inner_w = area.width.saturating_sub(2) as usize;
    let (lines, _) = build_map_lines(app, inner_w, None);

    // Clamp the scroll offset to the real overflow and render.
    let inner_h = area.height.saturating_sub(2) as usize;
    let max_scroll = lines.len().saturating_sub(inner_h);
    if app.map_scroll as usize > max_scroll {
        app.map_scroll = max_scroll as u16;
    }

    let block = Block::default()
        .title(Title::from(Line::from(Span::styled(
            format!(" TOPOLOGY — {} zones ", app.zones.len()),
            theme::bold(theme::accent()),
        ))))
        .title(Title::from(
            Line::from(Span::styled(
                format!(
                    " ★ session · ⚠ risky · M/Esc close · ↑↓ scroll {}/{} ",
                    app.map_scroll + 1,
                    max_scroll + 1
                ),
                theme::fg(theme::dim()),
            ))
            .right_aligned(),
        ))
        .borders(Borders::ALL)
        .border_set(ratatui::symbols::border::DOUBLE)
        .border_style(theme::border(if app.panic {
            theme::danger()
        } else {
            theme::accent()
        }))
        .style(Style::default().bg(theme::bg_panel()));
    let para = Paragraph::new(lines)
        .scroll((app.map_scroll, 0))
        .block(block);
    f.render_widget(para, area);
}

/// The Zones tab's main panel: the selected zone's topology inline (inputs ▸
/// allowed traffic), auto-scrolled to keep its header in view, with the
/// zone-keys legend pinned at the bottom (as the old details panel had it).
/// `M` opens the all-zone map full-screen.
fn render_map_panel(f: &mut Frame, app: &mut AppState, area: Rect) {
    let block = Block::default()
        .title(Title::from(Line::from(Span::styled(
            format!(" TOPOLOGY — {} ", app.current_zone),
            theme::bold(theme::zones()),
        ))))
        .title(Title::from(
            Line::from(Span::styled(" M all zones ", theme::fg(theme::dim()))).right_aligned(),
        ))
        .borders(if app.dialog.is_none() {
            Borders::ALL
        } else {
            Borders::RIGHT | Borders::TOP | Borders::BOTTOM
        })
        .border_set(ratatui::symbols::border::DOUBLE)
        .border_style(theme::border(theme::zones()))
        .style(Style::default().bg(theme::bg_panel()));
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Pin the keys legend at the bottom when the panel is tall enough; the
    // scrollable map gets the rest.
    let legend_h: u16 = if inner.height >= 6 { 3 } else { 0 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Fill(1), Constraint::Length(legend_h)])
        .split(inner);
    app.map_view_area = chunks[0];

    let inner_w = chunks[0].width as usize;
    let inner_h = chunks[0].height as usize;
    let (lines, blocks) = build_map_lines(app, inner_w, Some(&app.current_zone));
    let max_scroll = lines.len().saturating_sub(inner_h);

    // Follow the selected zone, then publish the block geometry for clicks.
    let sel_start = blocks
        .iter()
        .find(|(n, _, _)| *n == app.current_zone)
        .map(|(_, start, _)| *start);
    app.map_panel_scroll = match sel_start {
        Some(start) => follow_scroll(app.map_panel_scroll, start, inner_h, max_scroll),
        None => (app.map_panel_scroll as usize).min(max_scroll) as u16,
    };
    app.map_blocks = blocks;

    f.render_widget(
        Paragraph::new(lines).scroll((app.map_panel_scroll, 0)),
        chunks[0],
    );

    if legend_h > 0 {
        let legend = Paragraph::new(zone_keys_legend()).block(
            Block::default()
                .borders(Borders::TOP)
                .border_set(ratatui::symbols::border::DOUBLE)
                .border_style(theme::border(theme::dim()))
                .title(Title::from(Line::from(Span::styled(
                    " keys ",
                    theme::bold(theme::muted()),
                )))),
        );
        f.render_widget(legend, chunks[1]);
    }
}

/// The zone-keys legend pinned under the map panel (the shortcut list the old
/// zone-details view carried).
fn zone_keys_legend() -> Vec<Line<'static>> {
    let key = |k: &str| Span::styled(k.to_string(), theme::bold(theme::accent()));
    let keyd = |k: &str| Span::styled(k.to_string(), theme::bold(theme::danger()));
    let kd = |s: &str| Span::styled(s.to_string(), theme::fg(theme::muted()));
    vec![
        Line::from(vec![
            key("t"),
            kd(" target  "),
            key("f"),
            kd(" fwd  "),
            key("x"),
            kd(" masq  "),
            key("c/C"),
            kd(" icmp  "),
            key("s/S"),
            kd(" src  "),
            key("o/O"),
            kd(" spt  "),
            key("b/B"),
            kd(" proto"),
        ]),
        Line::from(vec![
            key("i/I"),
            kd(" iface  "),
            key("p"),
            kd(" diff  "),
            key("E"),
            kd(" export  "),
            key("v"),
            kd(" import  "),
            key("a"),
            kd(" new  "),
            key("D"),
            kd(" def  "),
            keyd("d"),
            kd(" del"),
        ]),
    ]
}

// ─── Helper Functions ───────────────────────────────────────────────────────

fn zone_description(name: &str) -> &'static str {
    match name {
        "drop" => "Drops all incoming",
        "public" => "Minimal, selective",
        "external" => "For masquerading",
        "internal" => "Trust internal net",
        "home" => "Home networks",
        "work" => "Work networks",
        "trusted" => "All connections",
        "block" => "Reject all incoming",
        "dmz" => "Semi-trusted DMZ",
        "docker" => "Docker networks",
        _ => "Custom zone",
    }
}

fn port_to_service(port: &str, protocol: &str) -> &'static str {
    let key = format!("{port}/{protocol}");
    match key.as_str() {
        "22/tcp" => "ssh",
        "80/tcp" => "http",
        "443/tcp" => "https",
        "53/tcp" | "53/udp" => "dns",
        "25/tcp" => "smtp",
        "21/tcp" => "ftp",
        "8080/tcp" => "http-alt",
        "3306/tcp" => "mysql",
        "5432/tcp" => "postgresql",
        "6379/tcp" => "redis",
        "5900/tcp" | "5900/udp" => "vnc",
        _ => "",
    }
}

#[cfg(test)]
mod export_tests {
    use super::zone_export;
    use firewall_tui::types::{ForwardPort, PortEntry, Zone};

    #[test]
    fn export_includes_all_properties() {
        let z = Zone {
            name: "testzone".into(),
            is_default: false,
            is_active: true,
            target: "default".into(),
            forward: true,
            masquerade: false,
            services: vec!["ssh".into(), "http".into()],
            ports: vec![PortEntry {
                port: "8080".into(),
                protocol: "tcp".into(),
            }],
            source_ports: vec![PortEntry {
                port: "12345".into(),
                protocol: "udp".into(),
            }],
            protocols: vec!["sctp".into()],
            icmp_blocks: vec!["echo-request".into()],
            sources: vec!["10.0.0.0/24".into()],
            rich_rules: vec!["rule family=\"ipv4\" source address=\"1.2.3.4\" drop".into()],
            forward_port: vec![ForwardPort {
                port: "80".into(),
                protocol: "tcp".into(),
                to_port: Some("8080".into()),
                to_addr: Some("10.0.0.5".into()),
            }],
            icmp_services: vec![],
            interfaces: vec![],
        };
        let (cmds, st) = zone_export(&z);
        assert!(cmds.contains("--add-service=ssh"));
        assert!(cmds.contains("--add-port=8080/tcp"));
        assert!(cmds.contains("--add-source-port=12345/udp"));
        assert!(cmds.contains("--add-protocol=sctp"));
        assert!(cmds.contains("--add-icmp-block=echo-request"));
        assert!(cmds.contains("--add-source=10.0.0.0/24"));
        assert!(cmds.contains("--add-forward-port=port=80:proto=tcp:toport=8080:toaddr=10.0.0.5"));
        assert!(
            cmds.contains("--add-rich-rule='rule family=\"ipv4\" source address=\"1.2.3.4\" drop'")
        );
        assert!(st.contains("target: default"));
        assert!(st.contains("forward: yes"));
        assert!(st.contains("masquerade: no"));
        assert!(st.contains("service: http"));
        assert!(st.contains("port: 8080/tcp"));
        assert!(st.contains("source-port: 12345/udp"));
        assert!(st.contains("protocol: sctp"));
        assert!(st.contains("icmp-block: echo-request"));
        assert!(st.contains("source: 10.0.0.0/24"));
        assert!(st.contains("forward-port: port=80:proto=tcp:toport=8080:toaddr=10.0.0.5"));
        assert!(st.contains("rich-rule: rule family=\"ipv4\" source address=\"1.2.3.4\" drop"));
    }
}

#[cfg(test)]
mod sort_tests {
    use super::sort_zones;
    use firewall_tui::types::Zone;

    fn mk(name: &str, active: bool) -> Zone {
        Zone {
            name: name.into(),
            is_default: false,
            is_active: active,
            target: "default".into(),
            forward: false,
            masquerade: false,
            services: vec![],
            ports: vec![],
            source_ports: vec![],
            protocols: vec![],
            icmp_blocks: vec![],
            sources: vec![],
            rich_rules: vec![],
            forward_port: vec![],
            icmp_services: vec![],
            interfaces: vec![],
        }
    }

    #[test]
    fn active_zones_sort_first_then_alphabetical() {
        let mut zones = vec![
            mk("work", false),
            mk("home", true),
            mk("public", false),
            mk("dmz", true),
            mk("internal", false),
        ];
        sort_zones(&mut zones);
        let names: Vec<&str> = zones.iter().map(|z| z.name.as_str()).collect();
        // active first (dmz, home), then inactive (internal, public, work)
        assert_eq!(names, vec!["dmz", "home", "internal", "public", "work"]);
    }

    #[test]
    fn default_zone_not_pinned_sorts_by_active_status() {
        let mut zones = vec![mk("home", true), mk("public", false)];
        zones[1].is_default = true; // default but inactive
        sort_zones(&mut zones);
        let names: Vec<&str> = zones.iter().map(|z| z.name.as_str()).collect();
        assert_eq!(names, vec!["home", "public"]);
    }
}

#[cfg(test)]
mod lint_tests {
    use super::lint_rich_rule;

    #[test]
    fn clean_rule_has_no_warnings() {
        let rule =
            r#"rule family="ipv4" source address="1.2.3.4" port port="22" protocol="tcp" drop"#;
        assert!(lint_rich_rule(rule).is_empty());
    }

    #[test]
    fn missing_action_is_flagged() {
        let rule = r#"rule family="ipv4" source address="1.2.3.4" port port="22" protocol="tcp""#;
        let w = lint_rich_rule(rule);
        assert!(w.iter().any(|x| x.contains("No action")));
    }

    #[test]
    fn match_all_traffic_is_flagged() {
        let rule = "rule family=\"ipv4\" drop";
        let w = lint_rich_rule(rule);
        assert!(w.iter().any(|x| x.contains("ALL traffic")));
    }

    #[test]
    fn port_without_protocol_is_flagged() {
        let rule = r#"rule family="ipv4" source address="1.2.3.4" port port="22" drop"#;
        let w = lint_rich_rule(rule);
        assert!(w.iter().any(|x| x.contains("without a protocol")));
    }

    #[test]
    fn log_without_prefix_is_flagged() {
        let rule = r#"rule family="ipv4" source address="1.2.3.4" log"#;
        let w = lint_rich_rule(rule);
        assert!(w.iter().any(|x| x.contains("log-prefix")));
    }
}

#[cfg(test)]
mod map_tests {
    use super::{click_main, follow_scroll, line_width, map_session_zone, trunc};
    use firewall_tui::types::{AppState, Zone};
    use ratatui::text::{Line, Span};

    fn mk(name: &str, ifaces: &[&str], is_default: bool) -> Zone {
        Zone {
            name: name.into(),
            is_default,
            is_active: !ifaces.is_empty(),
            target: "default".into(),
            forward: false,
            masquerade: false,
            services: vec![],
            ports: vec![],
            source_ports: vec![],
            protocols: vec![],
            icmp_blocks: vec![],
            sources: vec![],
            rich_rules: vec![],
            forward_port: vec![],
            icmp_services: vec![],
            interfaces: ifaces.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn trunc_shortens_with_ellipsis() {
        assert_eq!(trunc("abcdef", 6), "abcdef");
        assert_eq!(trunc("abcdef", 4), "abc…");
        assert_eq!(trunc("abc", 0), "");
    }

    #[test]
    fn session_zone_prefers_route_binding_then_default() {
        let mut app = AppState::new();
        app.zones = vec![mk("public", &[], true), mk("work", &["eth0"], false)];
        // No route info → the default zone.
        app.map_route_iface = None;
        assert_eq!(
            map_session_zone(&app).map(|z| z.name.as_str()),
            Some("public")
        );
        // The route interface bound to "work" → work.
        app.map_route_iface = Some("eth0".into());
        assert_eq!(
            map_session_zone(&app).map(|z| z.name.as_str()),
            Some("work")
        );
        // Unknown route interface → falls back to the default zone.
        app.map_route_iface = Some("wlan9".into());
        assert_eq!(
            map_session_zone(&app).map(|z| z.name.as_str()),
            Some("public")
        );
    }

    #[test]
    fn line_width_counts_chars() {
        let l = Line::from(vec![Span::raw("ab"), Span::raw("cde")]);
        assert_eq!(line_width(&l), 5);
    }

    #[test]
    fn map_renders_without_panicking_at_any_size() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = AppState::new();
        app.zones = vec![mk("public", &["eth0"], true), mk("work", &[], false)];
        app.map_route_iface = Some("eth0".into());
        app.map_iface_ips.insert("eth0".into(), "10.0.0.5".into());
        app.show_map = true;
        // Degenerate sizes must not underflow/panic in the column math.
        for (w, h) in [(2u16, 2u16), (20, 5), (100, 40)] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| super::render_map(f, &mut app)).unwrap();
        }
        // The map content survives a normal-size render.
        let mut term = Terminal::new(TestBackend::new(100, 40)).unwrap();
        term.draw(|f| super::render_map(f, &mut app)).unwrap();
        let buf = term.backend().buffer().clone();
        let text: String = buf
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<Vec<_>>()
            .join("");
        assert!(text.contains("TOPOLOGY"));
        assert!(text.contains("PUBLIC") || text.contains("public"));
        assert!(text.contains("eth0"));
        // The overlay shows every zone.
        assert!(text.contains("work"));
    }

    #[test]
    fn follow_scroll_keeps_selected_block_in_view() {
        // Visible → no movement.
        assert_eq!(follow_scroll(0, 5, 10, 100), 0);
        // Header above the viewport → re-anchor to it.
        assert_eq!(follow_scroll(20, 5, 10, 100), 5);
        // Header below the viewport → re-anchor to it.
        assert_eq!(follow_scroll(0, 15, 10, 100), 15);
        // Never past the real overflow.
        assert_eq!(follow_scroll(0, 95, 10, 40), 40);
        // Zero viewport → 0.
        assert_eq!(follow_scroll(7, 3, 0, 100), 0);
    }

    #[test]
    fn panel_shows_only_the_selected_zone() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = AppState::new();
        app.zones = (0..8).map(|i| mk(&format!("z{i}"), &[], i == 0)).collect();
        app.current_zone = "z7".into();
        // Degenerate sizes must not panic.
        for (w, h) in [(2u16, 2u16), (30, 8)] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| {
                let area = f.area();
                super::render_map_panel(f, &mut app, area);
            })
            .unwrap();
        }
        let mut term = Terminal::new(TestBackend::new(100, 20)).unwrap();
        term.draw(|f| {
            let area = f.area();
            super::render_map_panel(f, &mut app, area);
        })
        .unwrap();
        // Only the selected zone's block is recorded…
        assert_eq!(app.map_blocks.len(), 1);
        assert_eq!(app.map_blocks[0].0, "z7");
        // …and only it is drawn.
        let buf = term.backend().buffer().clone();
        let text: String = buf
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<Vec<_>>()
            .join("");
        assert!(text.contains("z7"));
        assert!(!text.contains("z3"));
        assert!(!text.contains("z0"));
        // The pinned keys legend is rendered with the map.
        assert!(text.contains("export"));
    }

    #[test]
    fn click_on_map_block_selects_its_zone() {
        let mut app = AppState::new();
        app.zones = vec![mk("public", &[], true), mk("work", &[], false)];
        app.map_view_area = ratatui::layout::Rect::new(0, 1, 80, 18);
        app.map_blocks = vec![("public".to_string(), 0, 4), ("work".to_string(), 4, 8)];
        app.map_panel_scroll = 0;
        // Screen row 6 → content row 5 (the viewport starts at row 1) → "work".
        click_main(6, &mut app);
        assert_eq!(app.current_zone, "work");
        assert_eq!(app.table_states[0].selected(), Some(1));
        // A row outside any block changes nothing.
        click_main(100, &mut app);
        assert_eq!(app.current_zone, "work");
        // The top border row is ignored.
        click_main(0, &mut app);
        assert_eq!(app.current_zone, "work");
    }

    #[test]
    fn description_skipped_when_it_repeats_the_zone_name() {
        let mut app = AppState::new();
        app.zones = vec![mk("public", &[], true)];
        // firewalld's <short> for builtin zones is just the capitalized name.
        app.zone_descriptions
            .insert("public".into(), "Public".into());
        let (dup, _) = super::build_map_lines(&app, 100, Some("public"));
        // A real description is rendered (one extra line).
        app.zone_descriptions
            .insert("public".into(), "Minimal, selective".into());
        let (desc, _) = super::build_map_lines(&app, 100, Some("public"));
        assert_eq!(desc.len(), dup.len() + 1);
        let joined: String = desc
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.as_ref().to_string()))
            .collect::<Vec<_>>()
            .join("");
        assert!(joined.contains("Minimal, selective"));
    }
}
