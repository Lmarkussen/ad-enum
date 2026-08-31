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
DISTRO_FAMILY=""
PACKAGE_MANAGER=""
PYTHON_BIN=""
detect_platform() {
  local distro_id distro_like
  if [[ ! -r /etc/os-release ]]; then
    fail "Cannot detect Linux distribution: /etc/os-release is unavailable"
    exit 1
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  distro_id="${ID:-}"
  distro_like="${ID_LIKE:-}"
  case " $distro_id $distro_like " in
    *" debian "*)
      DISTRO_FAMILY="debian"
      PACKAGE_MANAGER="apt-get"
      PYTHON_BIN="python3"
      ;;
    *" arch "*)
      DISTRO_FAMILY="arch"
      PACKAGE_MANAGER="pacman"
      PYTHON_BIN="python"
      ;;
    *)
      fail "Unsupported Linux distribution (ID=${distro_id:-unknown}, ID_LIKE=${distro_like:-unknown})"
      fail "Supported families are Debian/Kali and Arch Linux/derivatives"
      exit 1
      ;;
  esac
  command -v "$PACKAGE_MANAGER" >/dev/null 2>&1 || {
    fail "${DISTRO_FAMILY^} package manager '$PACKAGE_MANAGER' is unavailable"
    exit 1
  }
}
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
  local locks=()
  case "$DISTRO_FAMILY" in
    debian) locks=(/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock) ;;
    arch) locks=(/var/lib/pacman/db.lck) ;;
  esac
  for lock in "${locks[@]}"; do
    [[ -e "$lock" ]] || continue
    holder="$(sudo fuser "$lock" 2>/dev/null || true)"
    if [[ -n "$holder" ]]; then
      warn "Package manager is busy (lock: $lock; process: $holder)"
      if [[ "$DISTRO_FAMILY" == arch ]]; then
        warn "Wait for the existing pacman operation to finish, then rerun ./install.sh"
      else
        warn "Wait for the existing apt/dpkg operation to finish, then rerun ./install.sh"
      fi
      return 1
    fi
  done
}
system_package_name() {
  local logical_package="$1"
  case "$DISTRO_FAMILY:$logical_package" in
    debian:*) printf '%s\n' "$logical_package" ;;
    arch:python3|arch:python3-dev|arch:python3-venv) printf '%s\n' python ;;
    arch:libkrb5-dev) printf '%s\n' krb5 ;;
    arch:golang-go) printf '%s\n' go ;;
    arch:libpcap-dev) printf '%s\n' libpcap ;;
    arch:pipx) printf '%s\n' python-pipx ;;
    arch:netexec) printf '%s\n' netexec ;;
    arch:krb5-user) printf '%s\n' krb5 ;;
    *)
      fail "No package mapping for '$logical_package' on $DISTRO_FAMILY"
      return 1
      ;;
  esac
}
package_installed() {
  local package="$1"
  case "$DISTRO_FAMILY" in
    debian)
      command -v dpkg-query >/dev/null 2>&1 || return 1
      dpkg-query -W -f='${Status}\n' "$package" 2>/dev/null | grep -q '^install ok installed$'
      ;;
    arch)
      pacman -Q "$package" >/dev/null 2>&1
      ;;
  esac
}
libpcap_dev_installed() {
  package_installed "$(system_package_name libpcap-dev)"
}
add_system_package() {
  local logical_package="$1" package existing
  package="$(system_package_name "$logical_package")"
  for existing in "${system_packages[@]}"; do
    [[ "$existing" == "$package" ]] && return 0
  done
  system_packages+=("$package")
}
install_system_packages() {
  case "$DISTRO_FAMILY" in
    debian)
      package_manager_available || {
        fail "Cannot safely start package installation while apt/dpkg is busy"
        exit 1
      }
      run_logged "Updating package indexes" timeout 900s sudo apt-get update
      run_logged "Installing system dependencies" timeout 900s sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "${system_packages[@]}"
      ;;
    arch)
      package_manager_available || {
        fail "Cannot safely start package installation while pacman is busy"
        exit 1
      }
      say "Checking Arch package state"
      ok "Arch package manager ready"
      if ! run_logged "Installing system dependencies" timeout 900s sudo pacman -S --needed --noconfirm "${system_packages[@]}"; then
        warn "If pacman reported a stale package database or partial upgrade, update the Arch system first:"
        warn "  sudo pacman -Syu"
        warn "Then rerun ./install.sh"
        return 1
      fi
      ;;
  esac
}

detect_platform
say "Checking system requirements"
system_packages=()
command -v "$PYTHON_BIN" >/dev/null 2>&1 || add_system_package python3
if command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  "$PYTHON_BIN" -c 'import venv' >/dev/null 2>&1 || add_system_package python3-venv
else
  add_system_package python3-venv
fi
# gssapi is a core dependency for --force-kerb and may need to compile on
# Kali/Python versions without a published wheel.
python_header=""
if command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  python_header="/usr/include/$("$PYTHON_BIN" -c 'import sys; print("python" + str(sys.version_info.major) + "." + str(sys.version_info.minor))')/Python.h"
fi
[[ -n "$python_header" && -f "$python_header" ]] || add_system_package python3-dev
[[ -f /usr/include/krb5.h ]] || add_system_package libkrb5-dev
if [[ "$mode" != minimal ]] && ! command -v pipx >/dev/null 2>&1; then add_system_package pipx; fi
if [[ "$mode" != minimal ]] && ! command -v nxc >/dev/null 2>&1; then add_system_package netexec; fi
if [[ "$mode" != minimal ]] && ! command -v kinit >/dev/null 2>&1; then add_system_package krb5-user; fi
if [[ "$mode" != minimal ]] && ! command -v go >/dev/null 2>&1; then add_system_package golang-go; fi
if [[ "$mode" != minimal ]] && ! libpcap_dev_installed; then add_system_package libpcap-dev; fi
if ((${#system_packages[@]})); then
  command -v sudo >/dev/null 2>&1 || { fail "Missing system packages: ${system_packages[*]} (sudo unavailable)"; exit 1; }
  CURRENT_STAGE="Checking sudo access"
  say "$CURRENT_STAGE"
  if ! sudo -v; then
    fail "Sudo authentication failed; cannot install system dependencies"
    exit 1
  fi
  ok "Sudo access available"
  install_system_packages
fi
command -v "$PYTHON_BIN" >/dev/null 2>&1 && ok "Python 3 available"

say "Creating AD-Enum virtual environment"
run_logged "Creating Python virtual environment" "$PYTHON_BIN" -m venv .venv
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
    cinderpath_url="https://github.com/Lmarkussen/CinderPath.git"
    cinderpath_checkout_ok=0
    if [[ -d "$cinderpath_source/.git" ]] && git -C "$cinderpath_source" rev-parse --is-inside-work-tree >/dev/null 2>&1 && git -C "$cinderpath_source" remote get-url origin >/dev/null 2>&1; then
      cinderpath_checkout_ok=1
    elif [[ -e "$cinderpath_source" ]]; then
      warn "Removing incomplete installer-managed CinderPath checkout"
      rm -rf -- "$cinderpath_source"
    fi
    mkdir -p "$(dirname "$cinderpath_source")"
    if [[ ! -f /usr/include/pcap/pcap.h && ! -f /usr/include/pcap.h ]]; then
      CURRENT_STAGE="Checking CinderPath libpcap development headers"
      fail "CinderPath build prerequisite missing: libpcap development headers (install $(system_package_name libpcap-dev))"
      exit 1
    fi
    if (( cinderpath_checkout_ok )); then
      run_logged "Updating CinderPath source" timeout 120s git -C "$cinderpath_source" remote set-url origin "$cinderpath_url"
      run_logged "Fetching current CinderPath source" timeout 120s git -C "$cinderpath_source" fetch --depth 1 origin
      run_logged "Selecting current CinderPath source" git -C "$cinderpath_source" reset --hard FETCH_HEAD
    else
      run_logged "Cloning CinderPath from public GitHub" timeout 120s git clone --depth 1 "$cinderpath_url" "$cinderpath_source"
    fi
    ok "CinderPath source available"
    run_logged "Building CinderPath" timeout 900s go -C "$cinderpath_source" build -o "$cinderpath_bin" ./cmd/cinderpath
    ok "CinderPath built"
    CURRENT_STAGE="Checking CinderPath CRED-1 support"
    if "$cinderpath_bin" assess CRED-1 --help >/dev/null 2>&1; then
      ok "CRED-1 structured output supported"
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
