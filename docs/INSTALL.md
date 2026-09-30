# Installation

AD-Enum targets Linux with Python 3.11 or newer. The installer creates
`.venv`, installs the project without system `pip`, installs the default
external collectors through supported package mechanisms, and provisions the
`SCCMHunter` discovery tool, the SCCMSecrets Distribution Point inspection tool,
and the PXEThief SCCM/PXE validation tool. NetworkHound, RelayKing, SCCMHunter,
SCCMSecrets, and PXEThief are installed from public HTTPS source checkouts at
tested revisions, with isolated environments under `.cache/`. Doctor verifies
every required tool and returns a failure if one is missing or cannot start.

For a fresh checkout:

```bash
git clone https://github.com/Lmarkussen/ad-enum.git
cd ad-enum
./install.sh
```

The PXEThief checkout is pinned to pull request #11
(`pull/11/head:pr-11`), which is required for the supported SCCM/PXE targets;
the installer never falls back to the default branch. PXEThief runs in its own
environment under `.cache/PXEThief/.venv`, so it does not contaminate the
project `.venv`. The installer does not silently grant packet-capture
capabilities: a PXE validation that needs raw sockets reports `NOT TESTED`
unless AD-Enum runs with the required privileges (root or
`CAP_NET_RAW`/`CAP_NET_ADMIN`).

```bash
./install.sh                 # core plus default collectors
./install.sh --verbose       # show installer diagnostics
python3 ad-enum.py doctor
```

For Kerberos, verify DNS and the client/DC clocks. `--sync-time` explicitly
authorizes one-shot clock synchronization; `--auto-config` alone does not
change system time. Do not put lab or scanner credentials in scripts.

Failed steps retain a diagnostic log and stop installation. Rerunning
`./install.sh` reuses installed environments. Use `--verbose` to show commands.
