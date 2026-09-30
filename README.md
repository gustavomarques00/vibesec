# VibeSec

Local-first security analysis CLI for JavaScript/TypeScript applications and
public web surfaces. VibeSec reports **observed evidence** — not confirmed
production exploits and not a substitute for a penetration test.

VibeSec has two modes:

| Mode         | Command                     | Network                            |
| ------------ | --------------------------- | ---------------------------------- |
| **Code**     | `vibesec scan <path>`       | Offline — no network access        |
| **External** | `vibesec external <target>` | Bounded HTTP(S) to the target only |

## What VibeSec is

1. **Code** — inventories a local project tree, extracts facts (secrets, env
   bindings, Supabase migrations, auth patterns, dangerous sinks), evaluates
   fixed rule families, and emits findings.
2. **External** — performs passive, bounded analysis of the publicly observable
   surface of an authorized HTTP(S) target (transport, headers, cookies,
   same-origin assets, VS-EXT rules).

```bash
vibesec scan <path> [--format terminal|json|markdown]
vibesec external <target> [--format terminal|json|markdown]
```

## What VibeSec is NOT

- a complete vulnerability scanner or pentest substitute;
- a guarantee of zero false positives or zero false negatives;
- a production exploit confirmation tool;
- a CVE / dependency advisory database;
- a SaaS dashboard, cloud scanner, or remote Git analyzer;
- a crawler, fuzzer, authenticator, or exploit engine;
- a runtime that executes your application code (Code mode).

`confirmed` means the stated **observed condition** was established from local
repository material or External observations — not that a credential is valid
or that production is compromised. Exit code `0` means **no findings detected
by this scan**, not that the target is free of vulnerabilities.

## Requirements

- **Node.js 20+** (Active LTS or newer)
- Optional (Code): `git` on `PATH` for tracked/untracked provenance

## Installation

From source (recommended until a public npm publish exists):

```bash
git clone https://github.com/gustavomarques00/vibesec.git
cd vibesec
npm ci
npm run build
node dist/cli/main.js scan ./project
node dist/cli/main.js external example.com
```

From a packed local tarball:

```bash
npm pack
npm install -g ./vibesec-1.1.0.tgz
```

Public npm registry install is intentionally deferred.

## Quick start — Code (offline)

```bash
vibesec scan ./my-app
vibesec scan ./my-app --format json
vibesec scan ./my-app --format markdown
```

Code analysis remains **local and offline**. External must not be confused with
this guarantee.

### JSON in CI (Code)

```bash
vibesec scan . --format json > vibesec-report.json
# exit 0 = no findings; exit 1 = findings; exit 2 = usage/failure
```

## Quick start — External (bounded HTTP/S)

Use only against targets you own or are authorized to assess.

```bash
vibesec external example.com
vibesec external https://example.com
vibesec external https://example.com --format json
vibesec external https://example.com --format markdown
```

External performs **passive, bounded public-surface analysis**. It issues
HTTP(S) requests to the target. It is **not** offline.

Example terminal summary (illustrative):

```text
VibeSec External

Target: https://example.com/
Effective URL: https://example.com/
Findings: 0
Critical: 0 | High: 0 | Medium: 0 | Low: 0 | Info: 0
Passive bounded analysis of the publicly observable surface (no auth, exploitation, fuzzing, or crawling).

No findings detected by this scan.
```

## Output formats

| Format     | Code                    | External                         |
| ---------- | ----------------------- | -------------------------------- |
| `terminal` | Human-readable default  | Human-readable default           |
| `json`     | `schemaVersion: "1"`    | `schemaVersion: "ext-1"`         |
| `markdown` | Reviewable text reports | Reviewable External text reports |

## Exit codes

| Code | Meaning                                                                  |
| ---- | ------------------------------------------------------------------------ |
| `0`  | Scan completed; no findings detected by this scan                        |
| `1`  | Scan completed; one or more findings                                     |
| `2`  | Usage error or scan failed safely (generic message; no stack by default) |

Applies to both Code and External, including all three formats. Exit `0` does
**not** prove absence of vulnerabilities.

---

## External mode

### Purpose

External inspects publicly observable facts such as:

- final URL / redirect behavior (including blocked HTTPS→HTTP downgrades);
- HTTPS / TLS observations (when applicable);
- selected security headers (HSTS, CSP, XCTO, Referrer-Policy, …);
- cookie **attribute** facts (Secure, HttpOnly, SameSite, Domain, Path);
- explicitly referenced same-origin scripts and stylesheets;
- `sourceMappingURL` **references** on fetched first-party assets.

It does **not** attempt exploitation, authentication, or crawling.

### Security model (summary)

- HTTP/HTTPS only; credentials/userinfo rejected; ports limited to 80/443
- SSRF destination classification (private/loopback/link-local/special ranges denied)
- DNS answers validated; mixed public/private sets fail closed
- Approved-address pinning and post-connect `remoteAddress` verification
- Manual redirect authorization; HTTPS→HTTP downgrade blocked
- Bounded requests, redirects, response/header sizes, and assets
- Same-origin restriction for asset fetches; TLS verification enabled
- No cookie replay; no Authorization forwarding
- Cookie values and raw remote bodies are not retained in the observation/report model

Production requests identify as:

`VibeSec-External/1.1 (+https://github.com/gustavomarques00/vibesec)`

### Limitations / non-goals (External E1)

External does **not** perform:

- authentication or credentialed scanning;
- exploitation, brute force, or fuzzing;
- form submission;
- indiscriminate crawling, directory/subdomain enumeration, or port scanning;
- hidden-path / `.env` / `.git` probing;
- business-logic or authenticated authorization testing;
- fetching of advertised source-map **files** (only references may be observed);
- third-party/CDN asset fetching or recursive dependency graphs.

### Assets

Only explicitly referenced **same-origin** `script` / stylesheet URLs are
eligible. Selection is bounded (`maxAssets` / shared request budget). No
recursive crawl.

### Cookies

Attributes such as Secure, HttpOnly, SameSite, Domain, and Path may be
evaluated. **Cookie values are discarded** and never included in findings or
reports. VibeSec does not authenticate with observed cookies.

### External rules (`VS-EXT-*`)

| ID           | Title                                                               | Default severity | Observation                                                              |
| ------------ | ------------------------------------------------------------------- | ---------------- | ------------------------------------------------------------------------ |
| `VS-EXT-001` | Final document URL is not HTTPS                                     | medium           | Final effective document URL uses `http:`                                |
| `VS-EXT-002` | HTTPS to HTTP redirect downgrade blocked                            | medium           | HTTPS response attempted redirect to HTTP (blocked)                      |
| `VS-EXT-003` | Strict-Transport-Security header was not observed                   | low              | HTTPS document response; HSTS status MISSING                             |
| `VS-EXT-004` | Content-Security-Policy header was not observed                     | medium           | Document response; CSP status MISSING                                    |
| `VS-EXT-005` | X-Content-Type-Options is missing or not nosniff                    | low              | Document XCTO missing or not `nosniff`                                   |
| `VS-EXT-006` | Cookie lacks Secure and/or HttpOnly attributes                      | medium           | Observed cookie attributes incomplete                                    |
| `VS-EXT-007` | Cookie SameSite attribute is absent or SameSite=None without Secure | low              | SameSite absent, or None without Secure (`unknown` does not mean absent) |
| `VS-EXT-008` | TLS certificate validity period has ended                           | high             | Known `validTo` earlier than scan evaluation time                        |
| `VS-EXT-009` | TLS hostname verification failure observed                          | high             | Explicit hostname-attributable TLS authorization failure                 |
| `VS-EXT-010` | Public source map reference advertised on first-party asset         | medium           | Public `sourceMappingURL` reference observed (map file not fetched)      |
| `VS-EXT-011` | Referrer-Policy header was not observed                             | low              | Document Referrer-Policy status MISSING                                  |

Metadata authority: `src/external/rules/*`.

### Responsible use

Run External only against hosts you own or are explicitly authorized to assess.
Unauthorized scanning may violate law or terms of service.

### Privacy (External)

- No telemetry and no automatic upload of scan results
- Cookie values are not persisted
- Raw remote bodies are not retained in observation graphs or reports
- Findings use URL-native identity (not local filesystem paths)

---

## Code mode — security model

- **Offline local scan** — no network access is required or used for analysis.
- **Non-execution** — target application code, hooks, package scripts, and
  migrations are not executed.
- **Redaction** — raw secrets must not appear in findings, reporters, or CLI
  errors.
- **Paths** — findings use target-relative paths; absolute host paths are not
  emitted in normal outputs.
- **Budgets** — resource limits bound files, bytes, candidates, Git output, and
  SQL facts.

See `docs/threat-model.md` and `docs/redaction-invariants.md`.

## Supported Code rule families

| Family       | Focus                                                    |
| ------------ | -------------------------------------------------------- |
| `VS-SEC-*`   | Secrets / credential material                            |
| `VS-ENV-*`   | Environment / public-prefix exposure                     |
| `VS-SUP-*`   | Supabase keys, RLS, policies                             |
| `VS-AUTH-*`  | Frontend-only / storage-driven auth patterns             |
| `VS-AUTHZ-*` | Client queries without observed ownership/RLS            |
| `VS-DANG-*`  | Dangerous sinks (eval, HTML, shell, raw SQL) — heuristic |

Full Code IDs: [`docs/rules.md`](docs/rules.md). External IDs are listed above
and in the same catalog section for External.

## Limitations (Code)

- Detectors are **heuristic** for several JS/TS/SQL patterns.
- Missing evidence is never promoted to `confirmed`.
- Git absence degrades provenance; it does not invent tracking claims.
- Cross-file interprocedural taint, full SQL AST, remote Git, and SaaS features
  are out of scope for the Code MVP.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for setup, gates, and engineering
invariants.

## Vulnerability reporting

See [`SECURITY.md`](SECURITY.md). Distinguish:

- **A)** defects in VibeSec itself — use
  [GitHub private vulnerability reporting](https://github.com/gustavomarques00/vibesec/security/advisories/new);
- **B)** findings VibeSec reports about a scanned project (usually not a VibeSec
  vulnerability).

## License

Licensed under the [Apache License 2.0](LICENSE).

## Documentation

- `docs/rules.md` — Code and External rule catalogs
- `docs/finding-semantics.md` — status / confidence / severity
- `docs/threat-model.md` — trust boundaries
- `docs/redaction-invariants.md` — secret handling
- `docs/phase-*-scope.md` — historical phase contracts
- `CHANGELOG.md` — release notes
