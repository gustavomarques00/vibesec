import type { FindingDraft, Rule, RuleMetadata } from '../core/rules/rule.js'
import type { RuleContext } from '../core/rules/rule-context.js'
import type { SupabaseRlsFact } from '../core/models/fact.js'

const metadata: RuleMetadata = Object.freeze({
  id: 'VS-SUP-003',
  version: '1.0.0',
  title: 'Final observed migration disables RLS',
  category: 'supabase',
  defaultSeverity: 'high',
  supportedFacts: Object.freeze(['supabase.rls'] as const),
  references: Object.freeze([
    'https://supabase.com/docs/guides/database/postgres/row-level-security',
  ]),
})

export const supabaseRlsDisabledRule: Rule = Object.freeze({
  metadata,
  evaluate(context: RuleContext): readonly FindingDraft[] {
    const byTable = new Map<string, SupabaseRlsFact>()
    const ordered = [...context.factsOfKind('supabase.rls')].sort(compareMigrationFacts)
    for (const fact of ordered) {
      byTable.set(tableKey(fact.schema, fact.table), fact)
    }

    const drafts: FindingDraft[] = []
    for (const fact of byTable.values()) {
      if (fact.enabled) continue
      drafts.push(
        Object.freeze({
          description: `The final observed migration disables Row Level Security for ${fact.schema}.${fact.table}.`,
          confidence: fact.confidence,
          status: 'confirmed',
          primaryLocation: fact.location,
          relatedLocations: Object.freeze([]),
          evidence: Object.freeze([
            Object.freeze({
              kind: 'migration',
              summary: `DISABLE ROW LEVEL SECURITY was the last observed RLS change for ${fact.schema}.${fact.table}.`,
              locations: Object.freeze([fact.location]),
            }),
          ]),
          impact:
            'If this repository state is applied, table access may rely solely on API privileges without row filtering.',
          remediation:
            'Re-enable RLS for the table and add policies that encode the intended access model before deploying.',
          limitations: Object.freeze([
            'This finding confirms the final state observed in local migrations. It does not prove the production database currently has RLS disabled.',
          ]),
          tags: Object.freeze(['supabase', 'rls', 'disabled']),
        }),
      )
    }
    return Object.freeze(drafts)
  },
})

function tableKey(schema: string, table: string): string {
  return `${schema.normalize('NFC')}.${table.normalize('NFC')}`
}

function compareMigrationFacts(left: SupabaseRlsFact, right: SupabaseRlsFact): number {
  const file = left.location.file.localeCompare(right.location.file, 'en')
  if (file !== 0) return file
  return left.location.startLine - right.location.startLine
}
