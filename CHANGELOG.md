# AD-Enum v1.0.3

Patch release focused on recovered-credential visibility, hardened-LDAP
compatibility for LDAPDomainDump, and clearer PXE privilege handling.

## Recovered credentials

- Recovered target credentials are now shown directly in normal operator output
  instead of being hidden behind a generic `Recovered N` count.
- Target credentials continue to be written to `credentials.txt` and
  `credentials.json`. Human output is bounded for large sets while the complete
  credential artifacts retain every finding.
- Scanner/operator credentials remain redacted and are never intentionally
  surfaced.

## SCCM / OSD credentials

- PXEThief task-sequence variables are correlated into meaningful credentials:
  - `OSDJoinAccount` + `OSDJoinPassword` -> Domain Join Credential
  - `OSDLocalAdminPassword` -> Local Administrator Password
  - `NetworkAccessAccount` remains a paired account/password credential
  - `OSDRegisteredUserName` is shown as deployment metadata, not a credential
- Original PXE variable names remain preserved in structured evidence and
  provenance.
- Credential artifacts now use the real domain-join account instead of
  `UNKNOWN` when the account/password pair is available.

## LDAPDomainDump

- LDAPDomainDump now automatically uses `ldaps://` when AD-Enum has already
  negotiated protected LDAP against a hardened DC.
- `strongerAuthRequired` no longer results in a generic unexplained
  LDAPDomainDump failure. External-tool failures surface concise reasons such
  as protected LDAP required, TLS failure, authentication rejected, or
  MD4 / missing-module dependency errors.
- Scanner-password redaction remains intact.

## PXE privilege UX

- AD-Enum now warns near startup when the current process lacks the raw-socket
  privilege PXEThief needs.
- Normal AD-Enum operation does not generally require root. SCCM PXE validation
  requires `root` or effective `CAP_NET_RAW` (`CAP_NET_ADMIN` is not required).
- Without that privilege all other checks continue normally and PXE validation
  is reported `NOT TESTED`. No automatic sudo, `setcap`, or persistent
  capability changes are introduced.

## Validation

- 369 automated tests pass.
- Live validation confirmed protected LDAP / StartTLS, LDAPDomainDump via
  LDAPS, SCCMHunter auto-LDAPS, PXEThief with temporary `CAP_NET_RAW`,
  SCCMSecrets DP indexing, semantic OSD credential correlation, and
  scanner-secret containment.

# AD-Enum v1.0.2

Correctness and reliability release: hardened-LDAP compatibility, an SCCM
pipeline overhaul, and secret-safety fixes.

## Hardened LDAP

- LDAP signing/integrity is handled correctly: `strongerAuthRequired`
  (result code 8) is never treated as invalid credentials. The bind is retried
  over StartTLS with an LDAPS fallback, and the negotiated protected transport
  is reused for the rest of the scan.
- A protected-transport failure is reported distinctly from a credential
  failure, and valid credentials still report `Credentials are Valid`.
- SCCMHunter automatically selects its LDAPS mode when AD-Enum negotiated
  protected LDAP, so SCCM discovery works against hardened DCs.

## SCCM pipeline

- The retired CinderPath/custom CRED-1 path and its helper were removed.
- PXE exposure validation now uses PXEThief (pinned PR #11), and every unique
  PXE endpoint is validated with per-endpoint artifacts.
- SCCMHunter supplies read-only SCCM LDAP discovery that corroborates and
  enriches the native topology.
- SCCMSecrets supplies read-only Distribution Point content indexing, and every
  unique DP is inspected.
- Native SCCM host classification was restored (`name`/`cn` are collected
  again, and list-valued LDAP attributes are unwrapped where host/role
  comparisons need scalars), so SQL and site-server topology no longer
  disappear.
- Normal output stays concise; raw external-tool output stays in per-endpoint
  artifact directories.

## Fixes

- PXEThief privilege reporting now states the actual requirement: raw-socket
  privilege (root or `CAP_NET_RAW`). `CAP_NET_ADMIN` is not required, and the
  misleading "packet capture" wording was removed.
- Privileged-group handling unwraps LDAP list values, so
  `ACL/privileged-groups.json` populates correctly.
- External-collector failure text is redacted before it is persisted, so tool
  stderr can no longer record the scanner password. Target secrets and their
  provenance deduplication are unchanged.

## Behavior notes

- PXEThief needs raw-socket privilege: run as root or grant `CAP_NET_RAW`. Do
  not grant permanent capabilities to a global Python interpreter.
- SCCMSecrets `policies` mode is intentionally not automated because it can
  register persistent SCCM client state; it remains an explicit operator action.

## Validation

- 325 automated tests pass.
- Installer (two consecutive runs) and `doctor` pass.
- Full live regression passed against the hardened disposable lab.

# AD-Enum v1.0.1

## Fixes

- Fresh installs now provision all tooling required for normal scans, including NetworkHound, RelayKing, and NetExec protocol support.
- Added complete required-tool verification to `doctor`.
- Corrected native ESC1 effective-principal and authorization evaluation.
- Corrected ADCS source disagreement status handling.
- Preserved and rendered Certipy-confirmed ESC8 findings.
- Improved Certipy ADCS evidence handling and deduplication.
- Improved report clarity for findings, relay paths, SMB access, Kerberos, delegation, and credential/admin evidence.
- Added Arch Linux installer support.
- Improved canonical `-dc-ip` CLI handling.

## Validation

- Full automated test suite passes.
- Installer and doctor coverage passes.
- ADCS ESC1 regression matrix passes.
- Disposable lab validation confirmed negative ESC1 cases, a positive ESC1 case, and ESC8 preservation.
