#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$SCRIPT_DIR/firewall-tui"

CLEAN=0
if [[ "${1:-}" == "clean" ]]; then
    CLEAN=1
fi

echo "=== Firewall TUI Build & Run ==="

# Clean (optional)
if [[ $CLEAN -eq 1 ]]; then
    echo "Cleaning..."
    cd "$APP_DIR"
    cargo clean
fi

# Build as the current user (never build as root)
echo "Building..."
cd "$APP_DIR"
cargo build --release

# The app must run as root (it does not use sudo itself). Launch build.sh as
# root, or with `sudo ./build.sh`, so the app is already privileged on start.
echo "Starting Firewall TUI..."
exec "$APP_DIR/target/release/firewall-tui"
