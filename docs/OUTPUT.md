# Output model

Completed scans are written below `./<domain>/`. The root `results.txt` is the
consolidated, plain-text operator report. It mirrors the useful final finding
view without progress chatter, raw tool output, or ANSI escape sequences.

`credentials.txt` and `credentials.json` contain only confidently discovered
target credentials/secrets. Scanner authentication credentials and temporary
Kerberos state are never written there.

For SCCM CRED-1, the normalized finding includes the recovered target
credential and its DP/site/policy provenance when present. Temporary CinderPath
media keys, PFX material, and other operational crypto material are not report
artifacts.

Module directories contain normalized inventory, findings, provenance, and
source artifacts. `BloodHound/` stores its source JSON/ZIP artifacts directly.
`vulnerabilities/` contains active normalized findings, while
`scans/<scan-id>/` retains completed historical output.

Use `--html-out path/report.html` for an optional standalone browser-readable
report. It complements, and does not replace, the default `results.txt`.

Coverage distinguishes a successful collection with zero observations from an
unqueried or failed source. Typical states include `PASS`, `PARTIAL`,
`NOT TESTED`, and `FAILED`; the exact detail in `coverage.json` explains the
reason.
