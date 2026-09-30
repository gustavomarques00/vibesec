# Phase 5 scope: AUTH / AUTHZ / DANG

Source of truth: VibeSec MVP architecture plan
(`vibesec_mvp_architecture_5602fde2.plan.md`), implementation phase 5:

> Auth/authorization/dangerous patterns (4–6 dias): AST facts, guards, queries,
> ownership, sinks e taint-lite. Saída: AUTH/AUTHZ/DANG rules sem claims
> dinâmicos.

Supporting evidence:

- MVP todo `auth-dangerous`;
- MVP ruleset sections **Authentication e authorization** and **Dangerous
  patterns**;
- Fact contracts already declare `auth.guard`, `client.query`,
  `dangerous.sink`;
- False-positive strategy: intra-file conservative taint-lite; absence of
  local enforcement is never “confirmed IDOR” or “XSS confirmed”;
- `docs/phase-4-scope.md` deferred auth/ownership/dangerous AST work to Phase 5.

## REQUIRED

### Authentication

- `VS-AUTH-001` — protection/role check exclusively on the frontend without
  correlated server/enforcement evidence in the repository: `suspicious`.
  Source: MVP AUTH section.
- `VS-AUTH-002` — authorization decision based on `role` / `isAdmin` (or
  equivalent) read directly from `localStorage` / `sessionStorage`:
  `suspicious`. Standard Supabase session storage usage alone does **not**
  generate a finding.
  Source: MVP AUTH section.

### Authorization

- `VS-AUTHZ-001` — client-side `select` / `update` / `delete` without apparent
  ownership filter and without observed RLS/policy for the resource:
  `requires_authorization`. Never claim confirmed IDOR.
  Source: MVP AUTHZ section.
- Inventory of `.insert()`, `.update()`, `.delete()`, `.rpc()` as
  `client.query` facts (findings only when the AUTHZ rule correlates).

### Dangerous patterns

- `VS-DANG-001` — `eval` / `new Function` with non-constant input:
  `suspicious`, default severity high.
- `VS-DANG-002` — `dangerouslySetInnerHTML`, `.innerHTML`, or
  `document.write` with non-literal source and without recognized
  sanitization: `suspicious`, default severity medium; never “XSS confirmed”.
- `VS-DANG-003` — `child_process.exec` / shell-style execution with
  interpolation or non-constant input: `suspicious`, default severity high.
- `VS-DANG-004` — raw SQL with non-parameterized interpolation in
  server/edge context: `suspicious`, default severity high.

### Shared requirements

- typed Facts (`auth.guard`, `client.query`, `dangerous.sink`) with runtime
  validation; no severity/status on Facts;
- same-file / bounded heuristic correlation only (no whole-program taint);
- budgets for auth/query/sink candidates;
- negative fixtures for comments, strings, constants, sanitized sinks,
  ownership filters, and server enforcement;
- offline scan; never execute target code;
- preserve Phase 1–4 secret and path invariants.

## OPTIONAL

- TypeScript Compiler API AST (typescript is currently a.devtools-only
  dependency; Phase 5 uses bounded text heuristics unless promoted);
- inter-file middleware/route registration graphs;
- broader sanitizer catalogs beyond common `DOMPurify` / `sanitizeHtml`.

## DEFERRED

- Phase 6 hardening/release packaging;
- full AST SQL / interprocedural taint;
- CORS / CSRF / dependency CVE / DAST;
- cloud persistence, remote clone, SaaS UI.

## OUT OF SCOPE

- claiming confirmed RCE, XSS, or IDOR from syntactic presence alone;
- executing target modules, configs, hooks, or package scripts;
- universal framework coverage beyond heuristic JS/TS/JSX text patterns;
- inventing alternate rule IDs.

## Analysis honesty

Phase 5 correlation is **intra-repository, primarily same-file or
scan-indexed fact correlation**, not full dataflow. Findings must state
limitations accordingly.
