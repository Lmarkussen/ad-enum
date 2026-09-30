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

Module directories contain normalized inventory, findings, provenance, and
source artifacts. `vulnerabilities/` contains active normalized findings, while
`scans/<scan-id>/` retains completed historical output.

Use `--html-out path/report.html` for an optional standalone browser-readable
report. It complements, and does not replace, the default `results.txt`.

Coverage distinguishes a successful collection with zero observations from an
unqueried or failed source. Typical states include `PASS`, `PARTIAL`,
`NOT TESTED`, and `FAILED`; the exact detail in `coverage.json` explains the
reason.
