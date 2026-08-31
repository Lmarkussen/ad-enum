# Installation

AD-Enum targets Linux with Python 3.11 or newer. The installer creates
`.venv`, installs the project without system `pip`, installs the default
external collectors through supported package mechanisms, and builds the
CinderPath CRED-1 adapter for full/default installs.

For a fresh checkout:

```bash
git clone https://github.com/Lmarkussen/ad-enum.git
cd ad-enum
./install.sh
```

The full/default path installs required Linux build dependencies, including
`libpcap-dev` on Debian/Kali or `libpcap` on Arch, before building CinderPath.
It does not silently grant packet-capture capabilities. When SCCM/PXE evidence
is found, AD-Enum checks the local interface and capabilities and can offer an
explicit, operator-approved setup of CinderPath.

```bash
./install.sh                 # core plus default collectors
./install.sh --minimal       # core only
./install.sh --full          # extended tool set
./install.sh --verbose       # show installer diagnostics
python3 ad-enum.py doctor
```

For Kerberos, verify DNS and the client/DC clocks. `--sync-time` explicitly
authorizes one-shot clock synchronization; `--auto-config` alone does not
change system time. Do not put lab or scanner credentials in scripts.

Use `--minimal` when CinderPath and the extended external collectors are not
needed. Use `--verbose` to retain command diagnostics in the installer log.
