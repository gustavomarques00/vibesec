# Phase 6 scope: hardening and MVP release readiness

Source of truth: VibeSec MVP architecture plan
(`vibesec_mvp_architecture_5602fde2.plan.md`), implementation phase 6:

> Hardening/release candidate (2–4 dias): performance, malformed files,
> cross-platform, documentação, schema compatibility e pacote CLI.

Supporting evidence:

- Phase 5 deferred “Phase 6 hardening/release packaging”;
- Open decisions: Active LTS Node + lockfile; stabilize `schemaVersion` /
  rule IDs / ordering; license chosen Apache-2.0 (public hosting/npm still
  operator-gated);
- Product boundary remains offline, no target execution, no network.

Phase 6 is **validation and hardening**, not new detection categories.

## REQUIRED

| Item                                                 | Source              | Completion criteria                                                   |
| ---------------------------------------------------- | ------------------- | --------------------------------------------------------------------- |
| Malformed / hostile target hardening                 | Phase 6 plan        | Scan does not crash; generic errors; no secret/path leak              |
| Performance / resource budgets verified              | Phase 6 plan        | Boundary tests for existing budgets; no unbounded growth              |
| Cross-platform path/Git behavior documented & tested | Phase 6 plan        | Windows/POSIX PathFlavor; Git degrade to `unknown`                    |
| Documentation accuracy                               | Phase 6 plan        | README + threat model match actual behavior                           |
| Schema compatibility                                 | Phase 6 plan        | `schemaVersion: "1"` stable; rule IDs unchanged                       |
| CLI package readiness                                | Phase 6 plan        | `bin`, shebang, `files`, `engines`, pack dry-run, clean-install smoke |
| Determinism / secret containment regression          | Phase 1–5 + Phase 6 | Existing canaries + Phase 6 hostile fixtures pass                     |
| False-positive / false-negative fixture audit        | Release readiness   | Negative corpus + evasion positives for supported patterns            |
| Risk register disposition                            | Phase 6 audit       | Every Phase 1–5 residual risk: FIXED / ACCEPTED / DEFERRED / N/A      |

## OPTIONAL

- Property/fuzz helpers with deterministic seeds (no new heavy deps);
- Broader sanitizer catalog;
- TypeScript AST migration.

## DEFERRED

- Public npm publish and repository visibility change (operator-gated);
- Full SQL AST;
- Interprocedural taint;
- Remote Git clone threat model;
- CI SaaS integrations beyond local gates;
- Suppression UX (records exist in model; product UX later).

## OUT OF SCOPE

- New rule families beyond Phase 5;
- Cloud persistence / SaaS / UI;
- Claiming universal JS support or confirmed exploitability;
- Publishing to the npm registry in this phase.

## Explicit non-goals

Do not expand detection surface merely to grow tests. Prefer a smaller,
honest, offline scanner with documented limitations.
