# Output model

Completed scans are written below `./<domain>/`. The root `results.txt` is the
consolidated, plain-text operator report. It mirrors the useful final finding
view without progress chatter, raw tool output, or ANSI escape sequences.

`credentials.txt` and `credentials.json` contain only confidently discovered
target credentials/secrets. Scanner authentication credentials and temporary
Kerberos state are never written there.

Module directories contain normalized inventory, findings, provenance, and
source artifacts. `BloodHound/` stores its source JSON/ZIP artifacts directly.
`vulnerabilities/` contains active normalized findings, while
`scans/<scan-id>/` retains completed historical output.

Use `--html-out path/report.html` for an optional standalone browser-readable
report. It complements, and does not replace, the default `results.txt`.
