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
