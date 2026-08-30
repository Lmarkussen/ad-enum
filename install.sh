#!/usr/bin/env bash
set -euo pipefail

mode="default"; verbose=0
for arg in "$@"; do
  case "$arg" in
    --minimal) mode="minimal" ;;
    --full) mode="full" ;;
    --verbose) verbose=1 ;;
    -h|--help) echo "Usage: $0 [--minimal|--full] [--verbose]"; exit 0 ;;
    *) echo "Usage: $0 [--minimal|--full] [--verbose]" >&2; exit 2 ;;
  esac
done

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"; cd "$repo_dir"
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  cyan=$'\033[36m'; green=$'\033[32m'; yellow=$'\033[33m'; red=$'\033[31m'; reset=$'\033[0m'
else cyan=""; green=""; yellow=""; red=""; reset=""; fi
say() { printf '%s[*]%s %s\n' "$cyan" "$reset" "$1"; }
ok() { printf '%s[+]%s %s\n' "$green" "$reset" "$1"; }
warn() { printf '%s[!]%s %s\n' "$yellow" "$reset" "$1"; }
fail() { printf '%s[-]%s %s\n' "$red" "$reset" "$1" >&2; }
run_logged() {
  local label="$1"; shift; local log
  log="$(mktemp -t ad-enum-install.XXXXXX)"
  if (( verbose )); then printf '+ '; printf '%q ' "$@"; printf '\n'; fi
  if "$@" >"$log" 2>&1; then
    (( verbose )) && cat "$log"
    rm -f "$log"; return 0
  fi
  fail "$label failed"; cat "$log" >&2
  warn "Installer log retained at $log"
  return 1
}

say "Checking system requirements"
apt_packages=()
command -v python3 >/dev/null 2>&1 || apt_packages+=(python3)
python3 -c 'import venv' >/dev/null 2>&1 || apt_packages+=(python3-venv)
if [[ "$mode" != minimal ]] && ! command -v pipx >/dev/null 2>&1; then apt_packages+=(pipx); fi
if [[ "$mode" != minimal ]] && ! command -v nxc >/dev/null 2>&1; then apt_packages+=(netexec); fi
if [[ "$mode" != minimal ]] && ! command -v kinit >/dev/null 2>&1; then apt_packages+=(krb5-user); fi
if ((${#apt_packages[@]})); then
  command -v sudo >/dev/null 2>&1 || { fail "Missing system packages: ${apt_packages[*]} (sudo unavailable)"; exit 1; }
  run_logged "System dependency installation" sudo apt-get update
  run_logged "System dependency installation" sudo apt-get install -y "${apt_packages[@]}"
fi
command -v python3 >/dev/null 2>&1 && ok "Python 3 available"

say "Creating AD-Enum virtual environment"
run_logged "Virtual environment creation" python3 -m venv .venv
ok "Virtual environment ready"

say "Installing AD-Enum core"
run_logged "AD-Enum core installation" .venv/bin/python -m pip install --quiet --upgrade pip
run_logged "AD-Enum core installation" .venv/bin/python -m pip install --quiet -e .
ok "AD-Enum core installed"

if [[ "$mode" != minimal ]]; then
  command -v pipx >/dev/null 2>&1 || { fail "pipx is unavailable; default toolset is incomplete"; exit 1; }
  run_logged "pipx path setup" pipx ensurepath
  for spec in "certipy-ad:Certipy" "bloodhound:BloodHound" "ldapdomaindump:LDAPDomainDump"; do
    package="${spec%%:*}"; label="${spec##*:}"
    say "Installing $label"; run_logged "$label installation" pipx install --force "$package"
    ok "$label installed"
  done
  if command -v nxc >/dev/null 2>&1; then ok "NetExec installed"; else warn "NetExec is not available; default toolset is incomplete"; fi
fi
if [[ "$mode" == full ]]; then
  say "Installing Impacket"; run_logged "Impacket installation" pipx install --force impacket
  ok "Impacket installed"
fi

say "Running AD-Enum doctor"
if .venv/bin/python ad-enum.py doctor; then ok "Installation complete"; else fail "Doctor reported an installation problem"; exit 1; fi
