# Changelog

All notable changes to this project are documented in this file.

## 1.0.0 — 2026-09-30

Initial public release of the VibeSec local-first security analysis CLI.

### Shipped capabilities

- Offline `vibesec scan <path>` CLI with `terminal`, `json`, and `markdown`
  reporters
- Exit codes: `0` (clean), `1` (findings), `2` (usage/failure)
- Local inventory, optional Git provenance, extractors, Facts → Rules → Findings
- Rule families: `VS-SEC-*`, `VS-ENV-*`, `VS-SUP-*`, `VS-AUTH-*`, `VS-AUTHZ-*`,
  `VS-DANG-*` (see `docs/rules.md`)
- Secret redaction and target-relative path reporting
- Resource budgets for files, bytes, candidates, Git output, and SQL facts
- Zero runtime npm dependencies; no install lifecycle scripts
- Node.js `>=20` engine requirement
- Apache License 2.0

### Explicit non-goals in 1.0.0

- Remote Git / SaaS / UI / telemetry
- CVE or dependency vulnerability lookup
- Confirmed production exploit verification
- Execution of scanned target code
