# Installation

AD-Enum targets a Linux environment with Python 3.11 or newer. The installer
creates `.venv`, installs the project without system `pip`, and installs the
default external collectors through the supported package mechanisms.

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
