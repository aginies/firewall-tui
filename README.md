# Firewall TUI

A terminal UI for managing [firewalld](https://firewalld.org/) zones, ports,
services, protocols, sources, ICMP blocks, port forwards and rich rules on Linux.

It talks to firewalld through `firewall-cmd`, and must be **run as root** (it
never escalates via `sudo` itself). Supports both
the **runtime** and **permanent** configuration modes, and lets you undo the last
change, preview the exact `firewall-cmd` for any item, and export/import zone
config.

## Features

- Browse and switch between firewalld zones, with zones-in-use sorted to the top.
- Per-zone management of services, ports, source-ports, protocols, sources,
  ICMP blocks, port forwards and rich rules (add / remove / edit).
- Runtime ⇄ Permanent mode switching, with a live runtime-vs-permanent diff and a
  reload indicator so you never lose sight of what will actually be applied.
- A 20-step **undo** stack (`u` reverts the most recent change, repeatedly).
- **Command preview** showing the exact `firewall-cmd …` for the selected item.
- Cross-zone **search**, zone **export/import**, 9 color **themes**, and a
  resizable zone panel.
- **Mouse support** — click tabs and list rows to select, wheel-scroll lists
  and long dialogs.
- An activity log in the footer that records each action with the command behind
  it; `L` opens the full scrollable session log with timestamps.
- **Panic mode** (`P`) — instantly drop ALL traffic (runtime-only), behind a loud
  confirmation, with a persistent red top-bar banner while active.
- A live **topology map**: the Zones panel shows the selected zone's inputs
  (interfaces/sources) ▸ allowed traffic — session path starred, SSH lifeline
  marked, risky ports/services flagged red, panic banner; `M` opens the
  all-zone map full-screen.
- A **lockout guard** — changes that could cut your SSH session (removing the only
  SSH access from the zone carrying your default route, deleting that zone, making
  a zone without SSH the default while your interface is unbound) carry an explicit
  ⛔ LOCKOUT RISK warning in the confirmation dialog.

## Requirements

- A Linux system with **firewalld** installed and **running**
  (`systemctl start firewalld`).
- `firewall-cmd` on your `PATH`.
- **Root privileges.** The app manages the live firewall, so it must be started
  as root — either log in as root, or launch it with `sudo firewall-tui`. The
  process must already be root; the app does not prompt for a password or escalate
  itself, so it never interrupts the raw-mode terminal.

## Build & run

The project is a single Rust package under `firewall-tui/`.

```bash
# Option A: the provided script (builds release, then launches the app)
./build.sh

# Option B: build and run directly
cd firewall-tui
cargo build --release
./target/release/firewall-tui
```

You **must** run the app as root (it does not use `sudo` itself). Start it as the
root user, or with `sudo firewall-tui`.

## Using it

On first launch a short intro walks you through the keys. The layout is:

- **Top bar** — two rows: the brand plus a live summary (zone count, active
  zone, runtime/permanent mode, and a "pending reload" badge), with the
  numbered tab pills (1–5) on the row below.
- **Left panel** — the zone list, with labeled `Default`, `Active`, and
  `Masquerade` columns (`●` = on, `·` = off).
- **Main panel** — the active tab's contents. The Zones tab shows the selected
  zone's **topology** (what feeds it ▸ what it allows, with its description);
  other tabs: Ports, Services, Rich Rules, Port Forwarding.
- **Status line** — a one-line toast for the latest error or informational message.
- **Footer** — per-tab key hints and the last few actions with their `firewall-cmd`.

Press `?` for the in-app help overlay at any time.

## Keybindings

### Zones (left panel)

| Key | Action |
| --- | --- |
| `↑` / `↓` (or `j` / `k`, `PgUp`/`PgDn`, `Home`/`End`, `g`/`G`) | Move (the map panel follows) |
| `a` | Create a zone (permanent) |
| `d` | Delete the selected zone |
| `D` | Set the selected zone as the system default |
| `i` | Assign an interface to the zone |
| `I` | Remove an interface from the zone |
| `t` | Set the zone target (default / reject / drop) |
| `f` | Set the zone forward policy (yes / no) |
| `x` | Toggle masquerade |
| `c` | Add an ICMP block · `C` remove one |
| `s` | Add a source (IP/CIDR) · `S` remove one |
| `o` | Add a source port · `O` remove one |
| `b` | Add a zone-level protocol · `B` remove one |
| `E` | Export the zone to a file · `v` import a zone from a file |
| `p` | Show the runtime-vs-permanent diff for this zone |
| `Shift`+`←`/`→` (or `<` / `>`) | Resize the zone panel |

### Tabs

Switch tabs with `Tab` / `Shift+Tab`, `←`/`→`, the number keys `1`–`5`, or by
clicking a tab pill.

| Tab | Keys |
| --- | --- |
| Ports | `a` add · `d` remove · `/` filter |
| Services | `a` add · `d` remove · `/` filter · `Enter` add selected |
| Rules | `a` add · `d` remove · `e` edit · `Enter` view · `/` filter |
| Forward | `a` add · `d` remove · `/` filter |
| Any list | `c` show the `firewall-cmd` for the selected item |

`/` starts a typeahead filter on the list tabs; `Esc` clears it.

### Global

| Key | Action |
| --- | --- |
| `m` | Switch runtime ⇄ permanent mode |
| `u` | Undo the most recent change (20-step stack) |
| `L` | Full session activity log (scrollable, with timestamps and each `firewall-cmd`) |
| `P` | Panic mode: drop ALL traffic (runtime; loud confirm, red top-bar banner while on) |
| `M` | Full-screen topology map of EVERY zone (the Zones panel shows just the selected zone's; ★ session path, ⚠ risky exposures, `r` re-samples) |
| `F` | Search across all zones |
| `T` | Cycle the color theme (dark, light, dracula, nord, gruvbox, mocha, latte, monokai, solarized) |
| `r` | Refresh state from firewalld |
| `R` | Reload (apply permanent → runtime) |
| `?` | Help |
| `q` | Quit (confirms if permanent changes are pending a reload) |

Confirmation dialogs: `y` yes · `n` no · `Esc` cancel.

### Mouse

| Action | Effect |
| --- | --- |
| Click a tab pill | Switch to that tab |
| Click a zone row (left panel) | Select it and make it the working zone |
| Click a row in a list tab | Select that row |
| Wheel over a list | Scroll the selection |
| Wheel / `PgUp` / `PgDn` in a dialog | Scroll long content (help, diff, preview) |

## Configuration

Preferences (start mode, zone-panel width, last-viewed zone, active theme) are
saved to `~/.config/firewall-tui/config.toml` on exit. An absent or partial file
simply falls back to defaults. Zone exports are written to
`~/.config/firewall-tui/exports/`.

## Testing

```bash
cd firewall-tui
cargo test                 # unit tests (no firewalld required)
cargo test --test backend_integration   # requires a live firewalld (skipped otherwise)
```

## License

MIT.
