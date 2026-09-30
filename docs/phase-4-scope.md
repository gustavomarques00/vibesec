# Phase 4 scope: Supabase inventory and SUP rules

Source of truth: VibeSec MVP architecture plan
(`vibesec_mvp_architecture_5602fde2.plan.md`), implementation phase 4:

> Supabase (4–6 dias): inventory SQL tolerante, estado RLS/policies, taxonomy
> de keys e correlação inicial. Saída: relatório por tabela e SUP rules.

Supporting evidence:

- MVP todo `supabase`: “Implementar inventário de migrations, RLS, policies e
  service-role correlation”;
- MVP ruleset section **Supabase** (`VS-SUP-001` … `VS-SUP-005`);
- `docs/phase-3-scope.md` deferred exactly this work to Phase 4;
- Fact contracts already declare `supabase.table`, `supabase.rls`,
  `supabase.policy`, and `secretType: 'supabase_key'`;
- Product boundary: “Nunca … acessa rede, banco ou APIs.”

## Clarification: Phase 4 is analysis, not persistence

Phase 4 does **not** introduce:

- cloud persistence of scan results;
- Supabase as VibeSec’s application database;
- migrations owned by VibeSec;
- authentication, tenants, organizations, or RLS policies for VibeSec itself;
- network calls to a live Supabase project.

Those ideas appear only as hypotheses in some Phase 4 task prompts. They
contradict the MVP product boundary and are classified **OUT OF SCOPE**.

## REQUIRED

- tolerant local SQL inventory over migration-like files (no network);
- facts for tables, RLS enable/disable observations, and policies;
- Supabase key taxonomy distinguishing anon/publishable (inventory) from
  service-role/secret (findings);
- `VS-SUP-001` — service-role/secret literal in client/public context:
  `confirmed`, critical;
- `VS-SUP-002` — service-role/secret literal in server-side tracked context:
  `confirmed`, high (repository exposure claim only);
- `VS-SUP-003` — final observed migration disables RLS for a table:
  `confirmed` for repository state, with production limitation;
- `VS-SUP-004` — table created without observable ENABLE RLS/policy:
  `requires_authorization` (never “disabled in production”);
- `VS-SUP-005` — broad policy (`using (true)` / `with check (true)`) for
  `anon` or `authenticated`: `suspicious`;
- rule precedence so service-role client findings beat generic SEC/ENV
  duplicates for the same location where applicable;
- budgets for SQL statements / tables / policies / key candidates;
- offline `vibesec scan <path>` remains fully functional without Supabase.

## OPTIONAL

- richer JWT claim decoding beyond `role` for taxonomy;
- ordered migration heuristics beyond filename lexicographic order under
  common `supabase/migrations` layouts;
- positive inventory reporting of anon keys in JSON summary (beyond facts).

## DEFERRED

- auth / ownership / dangerous-pattern AST analysis (MVP phase 5);
- full SQL AST;
- remote clone;
- cloud persistence / SaaS / dashboards;
- live verification against a deployed Supabase project.

## OUT OF SCOPE

- connecting to, migrating, or mutating any remote database;
- storing Findings in Postgres/Supabase;
- service-role credentials for VibeSec itself;
- UI, telemetry, billing, organizations;
- executing SQL against the target.

## Persistence / data-boundary note

No Finding fields cross an external persistence boundary in Phase 4.

If a future phase introduces persistence, only already-safe export DTOs may
cross that boundary. Raw secrets, extractor internals, and unprotected Facts
remain **MUST NOT PERSIST**.
