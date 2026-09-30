# VibeSec rule catalog (v1.0.0)

Source of truth: rule `metadata` and evaluate status in `src/rules/*`.
Only rules registered in the local scan pipeline are listed.

Finding **status** describes evidence strength for the claimed local repository
condition — not production exploit confirmation. See `docs/finding-semantics.md`.

Default severity comes from rule metadata; some rules raise severity when Git
tracking is `tracked`.

## Secrets — `VS-SEC-*`

| ID           | Title                                | Default severity               | Typical status | Purpose                                                                                      |
| ------------ | ------------------------------------ | ------------------------------ | -------------- | -------------------------------------------------------------------------------------------- |
| `VS-SEC-001` | Private key material in local source | high (critical if Git-tracked) | confirmed      | Reports PEM private-key material observed in scanned files.                                  |
| `VS-SEC-002` | High-specificity credential material | high (critical if Git-tracked) | confirmed      | Reports high-specificity credential candidates (API keys, JWTs, DB URLs, etc.).              |
| `VS-SEC-003` | Generic credential candidate         | medium                         | suspicious     | Reports generic high-entropy credential-like assignments without format-specific validation. |

## Environment — `VS-ENV-*`

| ID           | Title                                              | Default severity | Typical status | Purpose                                                                                      |
| ------------ | -------------------------------------------------- | ---------------- | -------------- | -------------------------------------------------------------------------------------------- |
| `VS-ENV-001` | Privileged value exposed through public env prefix | critical         | confirmed      | Reports sensitive values bound to public client env prefixes (e.g. `VITE_`, `NEXT_PUBLIC_`). |
| `VS-ENV-002` | Sensitive value in a Git-tracked env file          | high             | confirmed      | Reports sensitive values in env files that Git provenance marks as tracked.                  |

## Supabase — `VS-SUP-*`

| ID           | Title                                                     | Default severity | Typical status         | Purpose                                                                           |
| ------------ | --------------------------------------------------------- | ---------------- | ---------------------- | --------------------------------------------------------------------------------- |
| `VS-SUP-001` | Supabase service-role key in client context               | critical         | confirmed              | Reports service-role key material in client-side contexts.                        |
| `VS-SUP-002` | Supabase service-role key in server repository material   | high             | confirmed              | Reports service-role key material in server/repository material.                  |
| `VS-SUP-003` | Final observed migration disables RLS                     | high             | confirmed              | Reports that the final observed migration state disables RLS for a table.         |
| `VS-SUP-004` | Table created without observable RLS enablement or policy | medium           | requires_authorization | Reports tables created without observed ENABLE RLS or policy in local migrations. |
| `VS-SUP-005` | Broad Supabase policy for anon or authenticated           | medium           | suspicious             | Reports policies with broad true predicates for `anon` / `authenticated`.         |

## Authentication — `VS-AUTH-*`

| ID            | Title                                       | Default severity | Typical status | Purpose                                                           |
| ------------- | ------------------------------------------- | ---------------- | -------------- | ----------------------------------------------------------------- |
| `VS-AUTH-001` | Frontend-only authentication or role check  | medium           | suspicious     | Reports auth/role checks that appear confined to frontend code.   |
| `VS-AUTH-002` | Authorization decision from browser storage | medium           | suspicious     | Reports authorization decisions driven by browser storage values. |

## Authorization — `VS-AUTHZ-*`

| ID             | Title                                                 | Default severity | Typical status         | Purpose                                                                                                  |
| -------------- | ----------------------------------------------------- | ---------------- | ---------------------- | -------------------------------------------------------------------------------------------------------- |
| `VS-AUTHZ-001` | Client query without ownership filter or observed RLS | medium           | requires_authorization | Reports client queries lacking an apparent ownership filter when compatible RLS/policy was not observed. |

## Dangerous sinks — `VS-DANG-*`

| ID            | Title                                            | Default severity | Typical status | Purpose                                                                 |
| ------------- | ------------------------------------------------ | ---------------- | -------------- | ----------------------------------------------------------------------- |
| `VS-DANG-001` | Dynamic eval or Function constructor             | high             | suspicious     | Reports `eval` / `Function` usage with non-constant input (heuristic).  |
| `VS-DANG-002` | Unsafe HTML sink without recognized sanitization | medium           | suspicious     | Reports HTML sinks without a recognized sanitizer (heuristic).          |
| `VS-DANG-003` | Dynamic shell or child_process execution         | high             | suspicious     | Reports dynamic shell / `child_process` execution patterns (heuristic). |
| `VS-DANG-004` | Raw SQL with dynamic interpolation               | high             | suspicious     | Reports raw SQL constructed with dynamic interpolation (heuristic).     |

## Notes

- Analysis of JS/TS/SQL for several families is **heuristic**; false positives and
  false negatives are expected.
- `requires_authorization` findings need operator-owned validation; VibeSec does
  not contact production infrastructure.
- Rule **versions** (e.g. `VS-SEC-001` at `1.1.0`) are independent of the npm
  package version (`1.0.0`).
