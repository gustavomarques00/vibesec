# Phase 3 scope: secrets, environment, and local Git provenance

Source of truth: VibeSec MVP architecture plan
(`vibesec_mvp_architecture_5602fde2.plan.md`), implementation phase 3:

> Secrets/environment: provenance Git, detectors tipados, public prefixes /
> envPrefix / define, dedupe. Output: SEC/ENV rules and negative fixtures.

Supporting evidence:

- `docs/phase-2-scope.md` explicitly deferred Git tracked/untracked provenance and
  broad secret taxonomy to later phases;
- MVP ruleset section **Secrets e environment**;
- MVP false-positive strategy: Git provenance is mandatory before claiming a
  secret is versioned.

## REQUIRED

- local Git provenance only (`tracked` / `untracked` / `ignored` / `unknown`);
- no remote clone;
- no shell interpolation; fixed argv arrays; hooks disabled;
- if Git is unavailable or not a repository, never claim “versioned”;
- typed high-specificity secret detection (`VS-SEC-002`);
- generic name+entropy credential candidates as `suspicious` (`VS-SEC-003`);
- private-key findings remain (`VS-SEC-001`) and must not claim Git tracking when
  provenance is unknown;
- client-bundle env exposure via known public prefixes (`VS-ENV-001`);
- tracked `.env*` files containing confirmed sensitive values (`VS-ENV-002`);
- deterministic rule precedence / dedupe so generic rules do not duplicate
  high-specificity findings at the same location;
- budgets for Git output size, candidates, and env bindings;
- fixtures / negative tests for placeholders, unknown Git, and safe samples.

## OPTIONAL

- lightweight discovery of custom Vite `envPrefix` / `define` from config text
  without executing the target;
- richer JWT claim decoding beyond structural validation.

## DEFERRED

- Supabase inventory, RLS, policies, and service-role correlation (MVP phase 4);
- auth / ownership / dangerous-pattern AST analysis (MVP phase 5);
- remote Git clone threat model and implementation;
- archive/decompression bombs;
- release packaging / schema compatibility work beyond what Phase 3 needs.

## OUT OF SCOPE

- network access, credential validation, DAST, browser automation;
- UI, SaaS, dashboard, telemetry, cloud persistence;
- CVE / dependency vulnerability lookup;
- CORS / deployment header analyzers;
- AI remediation;
- executing target code, hooks, install, build, or package scripts.
