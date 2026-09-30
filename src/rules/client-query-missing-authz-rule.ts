import type { FindingDraft, Rule, RuleMetadata } from '../core/rules/rule.js'
import type { RuleContext } from '../core/rules/rule-context.js'

const metadata: RuleMetadata = Object.freeze({
  id: 'VS-AUTHZ-001',
  version: '1.0.0',
  title: 'Client query without ownership filter or observed RLS',
  category: 'authorization',
  defaultSeverity: 'medium',
  supportedFacts: Object.freeze([
    'client.query',
    'supabase.rls',
    'supabase.policy',
  ] as const),
  references: Object.freeze(['https://cwe.mitre.org/data/definitions/639.html']),
})

export const clientQueryMissingAuthzRule: Rule = Object.freeze({
  metadata,
  evaluate(context: RuleContext): readonly FindingDraft[] {
    const protectedTables = new Set<string>()
    for (const fact of context.factsOfKind('supabase.rls')) {
      if (fact.enabled) protectedTables.add(normalizeTable(fact.table))
    }
    for (const fact of context.factsOfKind('supabase.policy')) {
      if (fact.referencesAuthUid || !fact.isBroad) {
        protectedTables.add(normalizeTable(fact.table))
      }
    }

    const drafts = context
      .factsOfKind('client.query')
      .filter(
        (fact) =>
          (fact.operation === 'select' ||
            fact.operation === 'update' ||
            fact.operation === 'delete') &&
          fact.hasOwnershipFilter !== true &&
          !protectedTables.has(normalizeTable(fact.resource)),
      )
      .map((fact): FindingDraft =>
        Object.freeze({
          description: `Client-side ${fact.operation} on ${fact.resource} lacks an apparent ownership filter and no compatible RLS/policy was observed.`,
          confidence: 'low',
          status: 'requires_authorization',
          primaryLocation: fact.location,
          relatedLocations: Object.freeze([]),
          evidence: Object.freeze([
            Object.freeze({
              kind: 'correlation',
              summary:
                'A client query candidate was correlated against observed RLS/policy facts; no ownership filter or compatible policy was found.',
              locations: Object.freeze([fact.location]),
            }),
          ]),
          impact:
            'If production also lacks ownership enforcement, callers may access or modify unintended rows.',
          remediation:
            'Add ownership filters in client queries and enforce equivalent RLS/policies server-side.',
          limitations: Object.freeze([
            'This never confirms IDOR. Missing local evidence is not proof that production lacks authorization.',
            'Correlation is bounded and heuristic; policies or filters outside scanned files may exist.',
          ]),
          tags: Object.freeze(['authorization', 'client-query', fact.operation]),
        }),
      )
    return Object.freeze(drafts)
  },
})

function normalizeTable(value: string): string {
  return value.normalize('NFC').toLowerCase().replaceAll(/"/gu, '')
}
