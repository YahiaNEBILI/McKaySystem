# Architecture decisions

Status: Derived  
Last reviewed: 2026-02-01

# Architecture Decisions

- Findings are immutable
- Parquet is the system of record
- Wire vs storage is explicit
- Checkers never touch storage
- Services are injected via RunContext
- Fingerprint defines logical identity
