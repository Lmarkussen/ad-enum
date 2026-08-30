# AD-Enum

Active Directory reconnaissance and security-posture enumeration with one
consolidated operator view.

AD-Enum combines native LDAP checks with mature collectors such as BloodHound,
Certipy, LDAPDomainDump, and NetExec. It normalizes their observations,
correlates findings, and keeps detailed source artifacts available—so an
operator does not have to search every tool's output directory.

## Features

- AD inventory, AD CS, Kerberos, delegation, GPO/SYSVOL, ACL, SMB, LDAP, and domain security posture
- SCCM/MECM and relay-exposure reconnaissance
- DNS/host mapping and cross-source identity correlation
- Discovered credential/secret evidence with protected scanner credentials
- Concise live progress followed by grouped findings and consolidated reports

## Installation

```bash
git clone git@github.com:Lmarkussen/ad-enum.git
cd ad-enum
./install.sh
```

Use `./install.sh --minimal` for core dependencies, `--full` for the extended
tool set, or `--verbose` for installer diagnostics.

## Quick start

```bash
python3 ad-enum.py -u localuser -p 'password' \
  -domain sccm.lab -dc-ip 10.1.10.40
```

Useful options include `--verbose`, `--debug`, `--no-color`, `--ldaps`,
`--force-kerb`, `--sync-time`, `--modules`, and `--timeout`. Passing a
password on a command line can expose it through shell history or process
inspection; omit `-p` to use the supported interactive prompt.

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
    BloodHound/
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
that evidence for the authorized operator. It never displays or persists the
scanner's supplied password, temporary Kerberos material, tickets, or caches.

## Safety and scope

Use AD-Enum only for authorized assessments, defensive review, and disposable
lab environments. AD-Enum is reconnaissance and enumeration only: it does not
perform spraying, cracking, active relay, coercion, poisoning, secret
retrieval, or exploitation.

## Development

```bash
python3 -m pytest
python3 ad-enum.py doctor
```

See [`docs/INSTALL.md`](docs/INSTALL.md), [`docs/OUTPUT.md`](docs/OUTPUT.md),
and [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) for concise operational and
contributor notes.

## License

See the repository license file.
