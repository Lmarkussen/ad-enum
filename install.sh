#!/usr/bin/env bash
set -euo pipefail

# AD-Enum installer for Kali/Debian. It never uses sudo pip.
mode="default"
case "${1:-}" in
  "") ;;
  --minimal) mode="minimal" ;;
  --full) mode="full" ;;
  *) echo "Usage: $0 [--minimal|--full]" >&2; exit 2 ;;
esac

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$repo_dir"

need_apt=()
command -v python3 >/dev/null 2>&1 || need_apt+=(python3)
python3 -c 'import venv' >/dev/null 2>&1 || need_apt+=(python3-venv)
if [[ "$mode" != minimal ]] && ! command -v pipx >/dev/null 2>&1; then need_apt+=(pipx); fi
if [[ "$mode" != minimal ]] && ! command -v nxc >/dev/null 2>&1; then need_apt+=(netexec); fi
if [[ "$mode" != minimal ]] && ! command -v kinit >/dev/null 2>&1; then need_apt+=(krb5-user); fi
if ((${#need_apt[@]})); then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "Missing system packages: ${need_apt[*]} (sudo unavailable)" >&2; exit 1
  fi
  sudo apt-get update
  sudo apt-get install -y "${need_apt[@]}"
fi

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .

if [[ "$mode" != minimal ]]; then
  pipx ensurepath >/dev/null 2>&1 || true
  pipx install --force certipy-ad
  pipx install --force bloodhound
  pipx install --force ldapdomaindump
fi
if [[ "$mode" == full ]]; then
  pipx install --force impacket || true
fi

echo "AD-Enum installed in $repo_dir/.venv"
echo "Run: python3 ad-enum.py doctor"
