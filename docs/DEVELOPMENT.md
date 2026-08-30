# Development

Run the offline suite with:

```bash
python3 -m pytest
```

Keep protocol collection, normalization, correlation, and rendering separate.
Live fixtures belong to explicitly authorized disposable environments; tests
should consume sanitized representations and synthetic values only. Never
commit scanner passwords, administrative credentials, tickets, ccaches, keys,
or retrieved secret material.

AD-Enum remains read-only/reconnaissance-only. Lab setup and cleanup scripts
must be credential-free, deterministic, reversible, and never invoked by the
scanner automatically.
