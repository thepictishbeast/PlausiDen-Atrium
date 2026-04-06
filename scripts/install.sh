#!/usr/bin/env bash
# Install PlausiDen-Atrium as a clickable desktop application.
#
# Usage:
#   ./scripts/install.sh            # install for the current user
#   sudo ./scripts/install.sh       # install system-wide
#
# Does:
#   1. Builds a release binary with `cargo build --release`.
#   2. Copies the binary to an appropriate bin directory.
#   3. Installs the SVG icon under the hicolor icon theme.
#   4. Installs the .desktop entry so Atrium appears in the app menu.
#   5. Runs update-desktop-database and gtk-update-icon-cache when
#      those tools are available.

set -euo pipefail

BOLD="$(tput bold 2>/dev/null || true)"
RESET="$(tput sgr0 2>/dev/null || true)"
say() { printf "%s==>%s %s\n" "$BOLD" "$RESET" "$*"; }
warn() { printf "%s!!%s %s\n" "$BOLD" "$RESET" "$*" >&2; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

if ! command -v cargo >/dev/null 2>&1; then
  warn "cargo is not installed. Install Rust from https://rustup.rs/ first."
  exit 1
fi

say "Building release binary (this takes a while on first run)…"
SSH_ASKPASS="" cargo build --release

BIN_SRC="$HERE/target/release/atrium"
ICON_SRC="$HERE/assets/atrium.svg"
DESKTOP_SRC="$HERE/assets/atrium.desktop"

if [[ ! -x "$BIN_SRC" ]]; then
  warn "Expected binary at $BIN_SRC but nothing is there."
  exit 1
fi

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  BIN_DEST="/usr/local/bin/atrium"
  ICON_DEST_DIR="/usr/local/share/icons/hicolor/scalable/apps"
  ICON_DEST="$ICON_DEST_DIR/plausiden-atrium.svg"
  DESKTOP_DEST_DIR="/usr/local/share/applications"
  DESKTOP_DEST="$DESKTOP_DEST_DIR/plausiden-atrium.desktop"
  say "Installing system-wide as root."
else
  BIN_DEST="$HOME/.local/bin/atrium"
  ICON_DEST_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
  ICON_DEST="$ICON_DEST_DIR/plausiden-atrium.svg"
  DESKTOP_DEST_DIR="$HOME/.local/share/applications"
  DESKTOP_DEST="$DESKTOP_DEST_DIR/plausiden-atrium.desktop"
  say "Installing for the current user under \$HOME/.local."
fi

mkdir -p "$(dirname "$BIN_DEST")" "$ICON_DEST_DIR" "$DESKTOP_DEST_DIR"

install -Dm755 "$BIN_SRC" "$BIN_DEST"
install -Dm644 "$ICON_SRC" "$ICON_DEST"
install -Dm644 "$DESKTOP_SRC" "$DESKTOP_DEST"

say "Binary:      $BIN_DEST"
say "Icon:        $ICON_DEST"
say "Desktop entry: $DESKTOP_DEST"

if command -v update-desktop-database >/dev/null 2>&1; then
  say "Refreshing desktop database…"
  update-desktop-database "$DESKTOP_DEST_DIR" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  say "Refreshing icon cache…"
  gtk-update-icon-cache -f -t "$(dirname "$(dirname "$(dirname "$ICON_DEST")")")" 2>/dev/null || true
fi

say "Done. Look for 'PlausiDen Atrium' in your application menu."
if [[ "${EUID:-$(id -u)}" -ne 0 && ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  warn "\$HOME/.local/bin is not on your PATH. Add it to your shell rc to run 'atrium' from the terminal."
fi
