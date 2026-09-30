# VibeSec

Local-first, **offline** security analysis CLI for vibe-coded JavaScript and
TypeScript applications. VibeSec inspects a local directory and reports
**repository evidence** — not confirmed production exploits.

## What VibeSec is

A deterministic scan kernel and CLI that:

1. inventories a local project tree;
2. optionally reads Git provenance for tracked/untracked files;
3. extracts facts (secrets, env bindings, Supabase migrations, auth patterns,
   dangerous sinks);
4. evaluates fixed rule families;
5. emits findings via terminal, JSON, or Markdown reporters.

```bash
vibesec scan <path> [--format terminal|json|markdown]
```

## What VibeSec is NOT

- a complete vulnerability scanner or pentest substitute;
- a guarantee of zero false positives or zero false negatives;
- a production exploit confirmation tool;
- a CVE / dependency advisory database;
- a SaaS dashboard, cloud scanner, or remote Git analyzer;
- a runtime that executes your application code.

Many findings are intentionally `suspicious` or `requires_authorization`.
`confirmed` means the stated **local repository condition** was observed — not
that a credential is valid or that production is compromised.

## Requirements

- **Node.js 20+** (Active LTS or newer)
- Optional: `git` on `PATH` for tracked/untracked provenance (otherwise
  provenance is `unknown` and “versioned” claims are not made)

## Installation

From source (recommended until a public npm publish exists):

```bash
git clone https://github.com/gustavomarques00/vibesec.git
cd vibesec
npm ci
npm run build
node dist/cli/main.js scan ./project
```

From a packed local tarball:

```bash
npm pack
npm install -g ./vibesec-1.0.0.tgz
```

Public npm registry install is intentionally deferred to a later milestone.

## Quick start

```bash
vibesec scan ./my-app
vibesec scan ./my-app --format json
vibesec scan ./my-app --format markdown
```

### JSON in CI

```bash
vibesec scan . --format json > vibesec-report.json
# exit 0 = no findings; exit 1 = findings; exit 2 = usage/failure
```

## Output formats

| Format     | Use                                             |
| ---------- | ----------------------------------------------- |
| `terminal` | Human-readable default                          |
| `json`     | Machine-readable `schemaVersion: "1"` documents |
| `markdown` | Reviewable text reports                         |

## Exit codes

| Code | Meaning                                                            |
| ---- | ------------------------------------------------------------------ |
| `0`  | Scan completed; no findings                                        |
| `1`  | Scan completed; one or more findings                               |
| `2`  | Usage error or scan failure (generic message; no stack by default) |

## Security model

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

## Supported rule families

| Family       | Focus                                                    |
| ------------ | -------------------------------------------------------- |
| `VS-SEC-*`   | Secrets / credential material                            |
| `VS-ENV-*`   | Environment / public-prefix exposure                     |
| `VS-SUP-*`   | Supabase keys, RLS, policies                             |
| `VS-AUTH-*`  | Frontend-only / storage-driven auth patterns             |
| `VS-AUTHZ-*` | Client queries without observed ownership/RLS            |
| `VS-DANG-*`  | Dangerous sinks (eval, HTML, shell, raw SQL) — heuristic |

Full IDs, titles, severities, and status semantics: [`docs/rules.md`](docs/rules.md).

## Limitations

- Detectors are **heuristic** for several JS/TS/SQL patterns.
- Missing evidence is never promoted to `confirmed`.
- Git absence degrades provenance; it does not invent tracking claims.
- Cross-file interprocedural taint, full SQL AST, remote Git, and SaaS features
  are out of scope for v1.0.0.

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

## Roadmap boundaries

v1.0.0 completes the documented MVP (phases 1–6). There is **no** documented
“Phase 7.” Further work is release operations (repository hosting, CI on a
remote, npm publish) and optional post-MVP quality/detection items — not new
SaaS product scope by default.

## Documentation

- `docs/rules.md` — rule catalog
- `docs/finding-semantics.md` — status / confidence / severity
- `docs/threat-model.md` — trust boundaries
- `docs/redaction-invariants.md` — secret handling
- `docs/phase-*-scope.md` — historical phase contracts
- `CHANGELOG.md` — release notes
