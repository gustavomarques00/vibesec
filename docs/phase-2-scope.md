# Phase 2 scope: local vertical slice

Source of truth: the existing VibeSec MVP architecture plan, implementation phase 2
(`CLI → inventory → one secret rule → terminal/JSON/Markdown`).

## Deliverables

- local directory target only;
- safe deterministic filesystem inventory;
- no symlink following;
- bounded text-file reads and binary-file skipping;
- default resource caps: 1 MiB per file, 10,000 candidate files, 50,000 visited
  entries, 100 MiB of candidate bytes, and 10,000 private-key candidates;
- caller-configured per-file limits are capped at 16 MiB;
- one high-confidence private-key secret extractor and rule;
- orchestration through the existing `ScanKernelContext`;
- terminal, JSON, and Markdown outputs;
- a minimal `vibesec scan <path>` CLI;
- integration, security, and reporter tests.

## Explicitly out of scope

- remote Git cloning;
- Git tracked/untracked provenance;
- broad secret taxonomy or entropy detection;
- Supabase, auth, authorization, SQL, CORS, dependency, or deployment analyzers;
- network access, credential validation, DAST, browser automation, UI, SaaS, or
  telemetry.

## Security constraints

- target code is data and is never executed;
- raw secret material may exist only inside extraction and must be passed immediately
  to `ScanKernelContext.protectSecret`;
- rules receive only validated facts and provenance-bound tokens;
- absolute host paths never enter facts, findings, IDs, or reports;
- filesystem input remains `unknown` until normalized and validated;
- output must be authorized by the same finalized scan context;
- inventory and reporter ordering must be deterministic.

Concurrent hostile filesystem mutation is not a portable guarantee: callers must scan
an immutable target snapshot. The inventory still performs real-path containment,
identity checks, bounded handle reads, and repeated directory checks, aborting when it
observes a race.
