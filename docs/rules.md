# VibeSec rule catalog

Source of truth:

- Code: rule `metadata` in `src/rules/*` (local scan pipeline)
- External: rule `metadata` in `src/external/rules/*` (`VS-EXT-001` … `VS-EXT-011`)

Finding **status** describes evidence strength for the claimed condition — not
production exploit confirmation. See `docs/finding-semantics.md`.

Default severity comes from rule metadata; some Code rules raise severity when
Git tracking is `tracked`.

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

## External — `VS-EXT-*`

Passive External E1 rules. Evaluated only by `vibesec external` against an
observation graph (no network inside rules).

| ID           | Title                                                               | Default severity | Purpose                                                                                        |
| ------------ | ------------------------------------------------------------------- | ---------------- | ---------------------------------------------------------------------------------------------- |
| `VS-EXT-001` | Final document URL is not HTTPS                                     | medium           | Final effective document URL uses `http:`.                                                     |
| `VS-EXT-002` | HTTPS to HTTP redirect downgrade blocked                            | medium           | HTTPS response attempted a redirect to HTTP (transport blocked the hop).                       |
| `VS-EXT-003` | Strict-Transport-Security header was not observed                   | low              | HTTPS document response with HSTS status MISSING (not UNKNOWN).                                |
| `VS-EXT-004` | Content-Security-Policy header was not observed                     | medium           | Document response with CSP status MISSING (presence only; no policy strength scoring).         |
| `VS-EXT-005` | X-Content-Type-Options is missing or not nosniff                    | low              | Document XCTO missing or observed value is not `nosniff`.                                      |
| `VS-EXT-006` | Cookie lacks Secure and/or HttpOnly attributes                      | medium           | Observed cookie attributes incomplete (values never retained).                                 |
| `VS-EXT-007` | Cookie SameSite attribute is absent or SameSite=None without Secure | low              | SameSite absent, or None without Secure; unrecognized SameSite is `unknown` and does not fire. |
| `VS-EXT-008` | TLS certificate validity period has ended                           | high             | Known certificate `validTo` is earlier than injected evaluation time.                          |
| `VS-EXT-009` | TLS hostname verification failure observed                          | high             | Explicit hostname-attributable TLS authorization failure only (not all TLS failures).          |
| `VS-EXT-010` | Public source map reference advertised on first-party asset         | medium           | Public `sourceMappingURL` reference on a fetched same-origin asset (map file is not fetched).  |
| `VS-EXT-011` | Referrer-Policy header was not observed                             | low              | Document Referrer-Policy status MISSING (not UNKNOWN).                                         |

## Notes

- Analysis of JS/TS/SQL for several Code families is **heuristic**; false
  positives and false negatives are expected.
- `requires_authorization` findings need operator-owned validation; VibeSec Code
  does not contact production infrastructure.
- External UNKNOWN facts must not be treated as MISSING.
- Rule **versions** inside metadata are independent of the npm package version
  (`1.1.0`).
