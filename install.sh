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
    arch:rustc|arch:cargo) printf '%s\n' rust ;;
    arch:git) printf '%s\n' git ;;
    arch:build-essential) printf '%s\n' base-devel ;;
    arch:dnsutils) printf '%s\n' bind ;;
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

# Script-only upstreams retain their own import trees and dependencies.
install_script_tool() {
  local label="$1" url="$2" revision="$3" script="$4"
  local source="$repo_dir/.cache/$label" launcher="$repo_dir/.venv/bin/$script"
  if [[ ! -d "$source/.git" ]]; then
    if [[ -e "$source" ]]; then
      fail "$label checkout is incomplete: $source; move it aside and rerun"
      return 1
    fi
    run_logged "Cloning $label from public HTTPS" timeout 120s git clone --depth 1 "$url" "$source"
  fi
  if [[ "$(git -C "$source" rev-parse HEAD)" != "$revision" ]]; then
    run_logged "Fetching supported $label revision" timeout 120s git -C "$source" fetch --depth 1 "$url" "$revision"
    run_logged "Selecting supported $label revision" git -C "$source" checkout --detach "$revision"
  fi
  run_logged "Creating $label environment" "$PYTHON_BIN" -m venv "$source/.venv"
  run_logged "Installing $label dependencies" timeout 900s "$source/.venv/bin/python" -m pip install -r "$source/requirements.txt"
  # Keep .py launchers valid Python while selecting the isolated interpreter.
  "$PYTHON_BIN" - "$source" "$script" "$launcher" <<'PYTHON'
import pathlib, sys
source, script, launcher = sys.argv[1:]
python = str(pathlib.Path(source) / ".venv/bin/python")
target = str(pathlib.Path(source) / script)
pathlib.Path(launcher).write_text(
    "#!/usr/bin/env python3\nimport os, sys\n"
    f"os.execv({python!r}, [{python!r}, {target!r}, *sys.argv[1:]])\n")
PYTHON
  chmod +x "$launcher"
  if [[ "$script" == relayking.py ]]; then
    # Upstream catches argparse's successful SystemExit and returns 1 for help.
    # Import the entry module instead; doctor also validates its help options.
    run_logged "Checking $label startup" timeout 30s "$source/.venv/bin/python" -c 'import sys; sys.path.insert(0, sys.argv[1]); import relayking' "$source"
  else
    run_logged "Checking $label startup" timeout 30s "$launcher" --help
  fi
}

detect_platform
say "Checking system requirements"
system_packages=()
command -v git >/dev/null 2>&1 || add_system_package git
command -v cc >/dev/null 2>&1 || add_system_package build-essential
if [[ "$mode" != minimal ]]; then
  command -v rustc >/dev/null 2>&1 || add_system_package rustc
  command -v cargo >/dev/null 2>&1 || add_system_package cargo
fi
if [[ "$mode" != minimal ]] && ! command -v nslookup >/dev/null 2>&1; then add_system_package dnsutils; fi
command -v "$PYTHON_BIN" >/dev/null 2>&1 || add_system_package python3
if command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  "$PYTHON_BIN" -c 'import venv, ensurepip' >/dev/null 2>&1 || add_system_package python3-venv
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
if [[ "$mode" != minimal ]] && ! command -v kinit >/dev/null 2>&1; then add_system_package krb5-user; fi
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
  # Keep pipx isolation without user-wide launchers or shell PATH edits.
  export PIPX_HOME="$repo_dir/.cache/pipx"
  export PIPX_BIN_DIR="$repo_dir/.venv/bin"
  export PATH="$repo_dir/.venv/bin:$PATH"
  run_logged "Installing pipx" timeout 900s .venv/bin/python -m pip install pipx
  for package in certipy-ad; do
    run_logged "Installing $package" timeout 900s .venv/bin/python -m pipx install --python "$repo_dir/.venv/bin/python" "$package"
  done
  run_logged "Installing NetExec" timeout 900s .venv/bin/python -m pipx install --python "$repo_dir/.venv/bin/python" "git+https://github.com/Pennyw0rth/NetExec.git@d640fb78b8f2cf25838405aa1ac615f3f27628db"
  run_logged "Installing LDAPDomainDump" timeout 900s .venv/bin/python -m pip install ldapdomaindump
  # Impacket and supporting scripts come with AD-Enum core.
  install_script_tool NetworkHound https://github.com/MorDavid/NetworkHound.git 47ea549fef664ad29b1239b370c1220a6fffa1e0 NetworkHound.py
  install_script_tool RelayKing-Depth https://github.com/depthsecurity/RelayKing-Depth.git 74e15350ff3610ed083d8886fa804f84c9a66238 relayking.py
  say "Installing PXEThief (required PR #11 checkout)"
  pxethief_root="$repo_dir/.cache/PXEThief"
  pxethief_url="https://github.com/MWR-CyberSec/PXEThief.git"
  mkdir -p "$(dirname "$pxethief_root")"
  if [[ -d "$pxethief_root/.git" ]] && git -C "$pxethief_root" remote get-url origin >/dev/null 2>&1; then
    run_logged "Fetching PXEThief source" timeout 300s git -C "$pxethief_root" fetch origin
  else
    if [[ -e "$pxethief_root" ]]; then
      warn "Removing incomplete installer-managed PXEThief checkout"
      rm -rf -- "$pxethief_root"
    fi
    run_logged "Cloning PXEThief from public GitHub" timeout 300s git clone "$pxethief_url" "$pxethief_root"
  fi
  # PR #11 is required; the default branch does not work for these targets.
  run_logged "Fetching required PXEThief PR #11" timeout 300s git -C "$pxethief_root" fetch origin pull/11/head
  run_logged "Selecting PXEThief PR #11" git -C "$pxethief_root" checkout -B pr-11 FETCH_HEAD
  ok "PXEThief PR #11 source available"
  run_logged "Creating PXEThief environment" "$PYTHON_BIN" -m venv "$pxethief_root/.venv"
  run_logged "Installing PXEThief dependencies" timeout 900s "$pxethief_root/.venv/bin/python" -m pip install -r "$pxethief_root/requirements.txt"
  CURRENT_STAGE="Checking PXEThief startup"
  if "$pxethief_root/.venv/bin/python" -c "import scapy, tftpy, lxml, requests, Crypto, certipy" >/dev/null 2>&1; then
    ok "PXEThief environment ready"
  else
    fail "PXEThief startup failed: dependency import check"
    exit 1
  fi
fi

CURRENT_STAGE="Running AD-Enum doctor"
say "$CURRENT_STAGE"
if [[ "$mode" == minimal ]]; then
  .venv/bin/python ad-enum.py doctor || warn "Core-only install: default scan tools are unavailable"
else
  run_logged "Verifying required scan tools with doctor" .venv/bin/python ad-enum.py doctor
fi
ok "Installation complete"
