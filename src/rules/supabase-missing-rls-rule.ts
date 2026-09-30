import type { FindingDraft, Rule, RuleMetadata } from '../core/rules/rule.js'
import type { RuleContext } from '../core/rules/rule-context.js'

const metadata: RuleMetadata = Object.freeze({
  id: 'VS-SUP-004',
  version: '1.0.0',
  title: 'Table created without observable RLS enablement or policy',
  category: 'supabase',
  defaultSeverity: 'medium',
  supportedFacts: Object.freeze([
    'supabase.table',
    'supabase.rls',
    'supabase.policy',
  ] as const),
  references: Object.freeze([
    'https://supabase.com/docs/guides/database/postgres/row-level-security',
  ]),
})

export const supabaseMissingRlsRule: Rule = Object.freeze({
  metadata,
  evaluate(context: RuleContext): readonly FindingDraft[] {
    const enabled = new Set(
      context
        .factsOfKind('supabase.rls')
        .filter((fact) => fact.enabled)
        .map((fact) => tableKey(fact.schema, fact.table)),
    )
    const policies = new Set(
      context
        .factsOfKind('supabase.policy')
        .map((fact) => tableKey(fact.schema, fact.table)),
    )

    const drafts = context
      .factsOfKind('supabase.table')
      .filter((fact) => fact.operation === 'create')
      .filter((fact) => {
        const key = tableKey(fact.schema, fact.table)
        return !enabled.has(key) && !policies.has(key)
      })
      .map((fact): FindingDraft =>
        Object.freeze({
          description: `Table ${fact.schema}.${fact.table} is created in migrations without an observed ENABLE RLS or policy.`,
          confidence: 'medium',
          status: 'requires_authorization',
          primaryLocation: fact.location,
          relatedLocations: Object.freeze([]),
          evidence: Object.freeze([
            Object.freeze({
              kind: 'migration',
              summary:
                'CREATE TABLE was observed without a correlating ENABLE ROW LEVEL SECURITY or CREATE POLICY in the scanned migrations.',
              locations: Object.freeze([fact.location]),
            }),
          ]),
          impact:
            'If the deployed database also lacks RLS/policies, privileged API roles may read or write broader row sets than intended.',
          remediation:
            'Confirm production RLS and policies for this table. Prefer enabling RLS and adding explicit policies in migrations.',
          limitations: Object.freeze([
            'Absence of local RLS/policy evidence must not be interpreted as proof that production RLS is disabled.',
            'Only scanned migration-like SQL files were considered.',
          ]),
          tags: Object.freeze(['supabase', 'rls', 'requires-authorization']),
        }),
      )
    return Object.freeze(drafts)
  },
})

function tableKey(schema: string, table: string): string {
  return `${schema.normalize('NFC')}.${table.normalize('NFC')}`
}
