#!/usr/bin/env bash
# Install the single-host Rust service for the current Linux user. No sudo.
set -euo pipefail
umask 077
siem_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $(uname -s) != Linux ]]; then
  echo 'This installer requires Linux, systemd --user and journalctl.' >&2
  exit 1
fi
systemctl --user show-environment >/dev/null
command -v journalctl >/dev/null
cd "$siem_root"
CARGO_PROFILE_RELEASE_STRIP=symbols cargo build --locked --release -p athernex-siem
install -d -m 700 "$HOME/.local/lib/athernex-siem" "$HOME/.local/share/athernex-siem" "$HOME/.config/athernex-siem"
mkdir -p "$HOME/.config/systemd/user"
# Atomic binary replacement works while an existing service is running.
install -m 700 target/release/athernex-siem "$HOME/.local/lib/athernex-siem/athernex-siem.new"
mv -f "$HOME/.local/lib/athernex-siem/athernex-siem.new" "$HOME/.local/lib/athernex-siem/athernex-siem"
if [[ ! -e "$HOME/.config/athernex-siem/operator.key" ]]; then
  "$HOME/.local/lib/athernex-siem/athernex-siem" --init-operator-key "$HOME/.config/athernex-siem/operator.key"
fi
install -m 600 infrastructure/systemd/athernex-siem.service "$HOME/.config/systemd/user/athernex-siem.service"
systemctl --user daemon-reload
systemctl --user enable athernex-siem.service
systemctl --user restart athernex-siem.service
systemctl --user is-active athernex-siem.service
printf '%s\n' 'Console: http://127.0.0.1:8787' 'Operator key: ~/.config/athernex-siem/operator.key (read privately; not logged)' 'Readiness: curl -f http://127.0.0.1:8787/readyz' 'User-service lifetime follows the systemd user manager. See README for boot/linger setup.'
