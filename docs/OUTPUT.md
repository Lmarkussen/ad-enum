# Output model

Completed scans are written below `./<domain>/`. The root `results.txt` is the
consolidated, plain-text operator report. It mirrors the useful final finding
view without progress chatter, raw tool output, or ANSI escape sequences.

`credentials.txt` and `credentials.json` contain only confidently discovered
target credentials/secrets. Scanner authentication credentials and temporary
Kerberos state are never written there.

For SCCM/PXE validation, the normalized finding records the distribution point,
state, and recovered-item count. Recovered target credentials and their
provenance are retained in structured evidence and the credential artifacts;
raw PXEThief stdout and intermediate crypto media stay under
`SCCM/pxethief/raw/` and are never part of the console report.

When PXE validation cannot run because raw-socket privilege is missing
(`root` or `CAP_NET_RAW`), a single startup warning is printed and the finding
is recorded as:

```text
PXE — mecm.sccm.lab
  State   NOT TESTED
  Reason  PXEThief requires raw-socket privilege (root or CAP_NET_RAW) to send the PXE request
```

SCCMHunter discovery runs in an isolated `HOME` under `SCCM/sccmhunter/raw/`;
its console output and discovery database stay there, and the normalized
topology is merged into the native SCCM inventory.

SCCMSecrets run only in read-only `files` mode. Each Distribution Point gets an
isolated `SCCM/sccmsecrets/raw/<dp>/` workspace holding its `loot/` index and
retrieved files; the normalized per-DP summary is `SCCM/dp-content.json`.

Module directories contain normalized inventory, findings, provenance, and
source artifacts. `vulnerabilities/` contains active normalized findings, while
`scans/<scan-id>/` retains completed historical output.

Use `--html-out path/report.html` for an optional standalone browser-readable
report. It complements, and does not replace, the default `results.txt`.

Coverage distinguishes a successful collection with zero observations from an
unqueried or failed source. Typical states include `PASS`, `PARTIAL`,
`NOT TESTED`, and `FAILED`; the exact detail in `coverage.json` explains the
reason.
