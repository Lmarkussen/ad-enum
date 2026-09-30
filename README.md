# AD-Enum

Active Directory reconnaissance and security-posture enumeration with one
consolidated operator view.

AD-Enum combines native LDAP checks with mature collectors such as Certipy,
LDAPDomainDump, and NetExec. It normalizes their observations,
correlates findings, and keeps detailed source artifacts available—so an
operator does not have to search every tool's output directory.

## Features

- AD inventory, AD CS, Kerberos, delegation, GPO/SYSVOL, ACL, SMB, LDAP, and domain security posture
- SCCM/MECM and relay-exposure reconnaissance, including SCCMHunter topology
  corroboration and PXE-enabled distribution-point validation through PXEThief
- DNS/host mapping and cross-source identity correlation
- Discovered credential/secret evidence with protected scanner credentials
- Current-scan-identity access checks and explicit coverage states
- Concise live progress followed by grouped findings and consolidated reports

## Installation

```bash
git clone https://github.com/Lmarkussen/ad-enum.git
cd ad-enum
./install.sh
```

The default install provisions all required scan tools, including NetworkHound,
RelayKing, SCCMHunter, and PXEThief (pinned PR #11), and verifies them with
credential-free startup checks. Tools stay under `.venv/` and `.cache/`; no PATH
changes or second setup step are needed. Use `--verbose` for installer
diagnostics. Packet-capture capabilities for PXEThief remain explicit and
operator-managed.

## Quick start

```bash
python3 ad-enum.py -u scanuser -p '<password>' \
  -domain example.local -dc-ip 192.0.2.10
```

Useful options include `--verbose`, `--debug`, `--tool-output`, `--no-color`, `--ldaps`,
`--force-kerb`, `--sync-time`, `--modules`, and `--timeout`. Passing a
password on a command line can expose it through shell history or process
inspection; omit `-p` to use the supported interactive prompt.

SCCM topology is discovered natively first, then corroborated and enriched by
SCCMHunter's read-only `find` command. Every unique distribution point or site
system in the merged topology is then validated through PXEThief; `--pxe-dp` is
only an explicit target override for debugging. PXEThief needs a suitable local
Ethernet/broadcast path and packet-capture privileges, so a routed tunnel may be
usable for LDAP/SMB while remaining unsuitable for PXE.

Use `--html-out report.html` for an optional standalone browser-readable report.
The default `results.txt` remains authoritative. `--tool-output` is an opt-in,
very verbose troubleshooting mode for streaming external collector output.

## Example output

```text
Checking credentials...
Credentials are Valid

[ * ] Running Native LDAP...
[ + ] Native LDAP complete

Findings

------------[ ADCS ]------------

ESC1 — ExampleTemplate
  Status ........... CONFIRMED

------------[ KERBEROS ]------------

Kerberoastable — svc-sql
  SPNs ............. 2
  Status ........... CORROBORATED
```

## Output

Each completed scan uses `./<domain>/`:

```text
<domain>/
    results.txt
    credentials.txt
    credentials.json
    vulnerabilities/
    LDAP/
    GPO/
    ACL/
    SCCM/
    SMB/
    Relay/
    scans/
```

`results.txt` is the complete human-readable report. `credentials.txt` and
`credentials.json` index confidently discovered target credentials/secrets.
Module directories retain evidence and source artifacts; `scans/` preserves
historical snapshots.

When a target credential or secret is confidently discovered, AD-Enum displays
that evidence for the authorized operator. This includes PXE media material
recovered by PXEThief during authorized PXE validation. It never displays or
persists the scanner's supplied password, temporary Kerberos material, tickets,
or caches.

## Safety and scope

Use AD-Enum only for authorized assessments, defensive review, and disposable
lab environments. AD-Enum is reconnaissance and enumeration only: it does not
perform spraying, password cracking, active relay, coercion, poisoning, or
deployment execution. SCCM/PXE validation is delegated to PXEThief and is
strictly limited to the discovered distribution points in scope.

## Development

```bash
python3 -m pytest
python3 ad-enum.py doctor
```

See [`docs/INSTALL.md`](docs/INSTALL.md) and [`docs/OUTPUT.md`](docs/OUTPUT.md)
for concise operational guidance. See [FINDINGS_GUIDE.md](FINDINGS_GUIDE.md)
for findings interpretation and remediation guidance.

## License

See the repository license file.
