//! firewall-tui: a terminal UI for managing firewalld.
//!
//! The library exposes the firewalld backend (via `firewall-cmd`) and the
//! shared data types; the binary is the TUI.

pub mod backend;
pub mod theme;
pub mod types;
