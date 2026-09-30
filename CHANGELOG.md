# Changelog

All notable changes to this project are documented in this file.

## 1.1.0 — 2026-09-30

VibeSec Code MVP plus External E1: passive, bounded public-surface analysis.

### Added

- `vibesec external <target>` CLI alongside offline `vibesec scan <path>`
- Secure External transport (SSRF classification, DNS validation, address
  pinning, post-connect verification, manual redirects, budgets, TLS verify)
- Response observation extraction (headers, cookies attributes, TLS, redirects)
- Bounded same-origin script/stylesheet asset inventory (no map fetch, no crawl)
- External rules `VS-EXT-001` … `VS-EXT-011`
- External reporters: terminal, JSON (`schemaVersion: "ext-1"`), Markdown
- Exit codes for External: `0` / `1` / `2` (same contract as Code)

### Security

- Fail-closed private/loopback/link-local/special destination handling
- Mixed public/private DNS answers denied; rebinding mitigated via pin set
- HTTPS→HTTP downgrade blocked; asset redirects cannot leave document origin
- Cookie values and raw remote bodies excluded from graphs/findings/reports
- Code scanner remains offline; External network capability is isolated
- Adversarial hardening coverage for parser, SSRF, budgets, and reporters

### Fixed

- Multi-hop same-origin→off-origin asset redirect request-budget under-count
- Cookie SameSite `absent` vs `unknown` semantics for `VS-EXT-007`

### Changed

- Package version `1.1.0`
- README documents Code and External modes, limitations, and responsible use

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
