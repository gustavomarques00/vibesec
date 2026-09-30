# Contributing to VibeSec

Thank you for helping improve VibeSec. This project prioritizes honest local
security analysis over feature volume.

## Requirements

- Node.js **20+**
- npm (lockfile-based installs)

## Setup

```bash
npm ci
npm run build
```

## Local quality gates

Run the same checks CI is expected to run:

```bash
npm run typecheck
npm run lint
npm run format:check
npm test
npm run build
npm run pack:check
```

Optional convenience:

```bash
npm run check
```

## Engineering invariants

These are security boundaries, not style preferences:

1. **Never leak raw secrets** in findings, evidence snippets, reporters, CLI
   errors, logs, or diagnostics. Prefer redacted tokens and fingerprints.
2. **Deterministic output** for finding IDs and report ordering given the same
   target and tool version (ephemeral fingerprints may differ across scans).
3. **Do not execute target code** — no `require`/`import` of scanned modules,
   no running package scripts, hooks, or migrations from the target tree.
4. **Network boundaries stay explicit** — the local scan path must remain
   offline. Do not add implicit remote calls.
5. **Security-sensitive changes need regression tests** — especially redaction,
   path handling, CLI exit codes, hostile/malformed inputs, and rule status
   semantics.

## Scope guidance

- Prefer small, reviewable changes.
- Do not expand detection surface merely to grow test counts.
- Rule semantics changes require fixture updates and documentation updates
  (`docs/rules.md`, phase/threat-model docs when relevant).
- Do not add SaaS, telemetry, billing, or cloud persistence in drive-by PRs.

## Pull requests

- Keep the description focused on why the change is needed.
- Note any intentional limitation or deferred follow-up.
- Ensure gates above pass locally before requesting review.
