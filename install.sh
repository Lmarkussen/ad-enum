#!/usr/bin/env bash
set -Eeuo pipefail

CURRENT_STAGE="startup"
trap 'rc=$?; printf "\033[31m[!]\033[0m Installation failed during: %s (exit code %s)\n" "$CURRENT_STAGE" "$rc" >&2' ERR

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
  CURRENT_STAGE="$label"
  log="$(mktemp -t ad-enum-install.XXXXXX)"
  say "$label"
  if (( verbose )); then printf '+ '; printf '%q ' "$@"; printf '\n'; fi
  if "$@" 2>&1 | tee "$log"; then
    rm -f "$log"; return 0
  fi
  fail "$label failed"; cat "$log" >&2
  warn "Installer log retained at $log"
  return 1
}
nxc_runtime_ok() {
  command -v nxc >/dev/null 2>&1 || return 1
  local output
  output="$(timeout 4s nxc smb 127.0.0.1 --timeout 1 --no-progress 2>&1 || true)"
  [[ "$output" != *"ImportError"* && "$output" != *"ModuleNotFoundError"* ]]
}
package_manager_available() {
  local lock holder
  for lock in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock; do
    [[ -e "$lock" ]] || continue
    holder="$(sudo fuser "$lock" 2>/dev/null || true)"
    if [[ -n "$holder" ]]; then
      warn "Package manager is busy (lock: $lock; process: $holder)"
      warn "Wait for the existing apt/dpkg operation to finish, then rerun ./install.sh"
      return 1
    fi
  done
}

say "Checking system requirements"
apt_packages=()
command -v python3 >/dev/null 2>&1 || apt_packages+=(python3)
python3 -c 'import venv' >/dev/null 2>&1 || apt_packages+=(python3-venv)
# gssapi is a core dependency for --force-kerb and may need to compile on
# Kali/Python versions without a published wheel.
python_header="/usr/include/$(python3 -c 'import sys; print("python" + str(sys.version_info.major) + "." + str(sys.version_info.minor))')/Python.h"
[[ -f "$python_header" ]] || apt_packages+=(python3-dev)
[[ -f /usr/include/krb5.h ]] || apt_packages+=(libkrb5-dev)
if [[ "$mode" != minimal ]] && ! command -v pipx >/dev/null 2>&1; then apt_packages+=(pipx); fi
if [[ "$mode" != minimal ]] && ! command -v nxc >/dev/null 2>&1; then apt_packages+=(netexec); fi
if [[ "$mode" != minimal ]] && ! command -v kinit >/dev/null 2>&1; then apt_packages+=(krb5-user); fi
if [[ "$mode" != minimal ]] && ! command -v go >/dev/null 2>&1; then apt_packages+=(golang-go); fi
if ((${#apt_packages[@]})); then
  command -v sudo >/dev/null 2>&1 || { fail "Missing system packages: ${apt_packages[*]} (sudo unavailable)"; exit 1; }
  CURRENT_STAGE="Checking sudo access"
  say "$CURRENT_STAGE"
  if ! sudo -v; then
    fail "Sudo authentication failed; cannot install system dependencies"
    exit 1
  fi
  ok "Sudo access available"
  if ! package_manager_available; then
    fail "Cannot safely start package installation while apt/dpkg is busy"
    exit 1
  fi
  run_logged "Updating package indexes" timeout 900s sudo apt-get update
  run_logged "Installing system dependencies" timeout 900s sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "${apt_packages[@]}"
fi
command -v python3 >/dev/null 2>&1 && ok "Python 3 available"

say "Creating AD-Enum virtual environment"
run_logged "Creating Python virtual environment" python3 -m venv .venv
ok "Virtual environment ready"

say "Installing AD-Enum core"
run_logged "Upgrading pip" timeout 900s .venv/bin/python -m pip install --upgrade pip
run_logged "Installing AD-Enum dependencies" timeout 900s .venv/bin/python -m pip install -e .
ok "AD-Enum core installed"

if [[ "$mode" != minimal ]]; then
  command -v pipx >/dev/null 2>&1 || { fail "pipx is unavailable; default toolset is incomplete"; exit 1; }
  run_logged "Configuring pipx path" pipx ensurepath
  for spec in "certipy-ad:Certipy" "bloodhound:BloodHound" "ldapdomaindump:LDAPDomainDump"; do
    package="${spec%%:*}"; label="${spec##*:}"
    run_logged "Installing $label" timeout 900s pipx install --force "$package"
    ok "$label installed"
  done
  run_logged "Installing Impacket" timeout 900s pipx install --force impacket
  ok "Impacket installed"
  if command -v nxc >/dev/null 2>&1; then
    if nxc_runtime_ok; then
      ok "NetExec installed and protocol loader is available"
    elif command -v pipx >/dev/null 2>&1; then
      warn "Existing NetExec is present but its protocol loader failed; repairing with pipx"
      run_logged "Installing NetExec" timeout 900s pipx install --force netexec
      nxc_runtime_ok && ok "NetExec installed and protocol loader is available" || warn "NetExec remains unusable; inspect its bundled dependencies"
    else
      warn "NetExec is present but its protocol loader failed; install a supported NetExec build with pipx"
    fi
  else
    # Use the maintained PyPI package through the same isolated pipx path as
    # the other external collectors. Do not guess legacy CME flags here.
    run_logged "Installing NetExec" timeout 900s pipx install --force netexec
    if command -v nxc >/dev/null 2>&1; then ok "NetExec installed"; else warn "NetExec is not available; default toolset is incomplete"; fi
  fi
  if command -v go >/dev/null 2>&1; then
    say "Installing CinderPath CRED-1 adapter"
    cinderpath_bin="$repo_dir/.venv/bin/cinderpath"
    cinderpath_source="$repo_dir/.cache/CinderPath"
    if [[ ! -x "$cinderpath_bin" ]]; then
      if [[ ! -d "$cinderpath_source/.git" ]]; then
        mkdir -p "$(dirname "$cinderpath_source")"
        run_logged "Cloning CinderPath source" timeout 120s git clone --depth 1 https://github.com/Lmarkussen/CinderPath.git "$cinderpath_source"
      fi
      run_logged "Building CinderPath" timeout 900s go -C "$cinderpath_source" build -o "$cinderpath_bin" ./cmd/cinderpath
    fi
    CURRENT_STAGE="Checking CinderPath CRED-1 support"
    if "$cinderpath_bin" assess CRED-1 --help >/dev/null 2>&1; then
      ok "CinderPath CRED-1 adapter available"
    else
      warn "CinderPath is present but CRED-1 structured output is unavailable"
    fi
    say "Building bounded SCCM PXE helper"
    run_logged "Building bounded SCCM PXE helper" timeout 900s go -C helpers/sccm_pxe build -o "$repo_dir/.venv/bin/ad-enum-sccm-pxe" .
    ok "Bounded SCCM PXE helper built"
  else
    warn "Go is unavailable; bounded SCCM PXE helper was not built"
  fi
fi

CURRENT_STAGE="Running AD-Enum doctor"
say "$CURRENT_STAGE"
if .venv/bin/python ad-enum.py doctor; then ok "Installation complete"; else fail "Doctor reported an installation problem"; exit 1; fi
