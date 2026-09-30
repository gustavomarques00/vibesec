import type { FindingDraft, Rule, RuleMetadata } from '../core/rules/rule.js'
import type { RuleContext } from '../core/rules/rule-context.js'

const BROAD_ROLES = new Set(['anon', 'authenticated', 'public'])

const metadata: RuleMetadata = Object.freeze({
  id: 'VS-SUP-005',
  version: '1.0.0',
  title: 'Broad Supabase policy for anon or authenticated',
  category: 'supabase',
  defaultSeverity: 'medium',
  supportedFacts: Object.freeze(['supabase.policy'] as const),
  references: Object.freeze([
    'https://supabase.com/docs/guides/database/postgres/row-level-security',
  ]),
})

export const supabaseBroadPolicyRule: Rule = Object.freeze({
  metadata,
  evaluate(context: RuleContext): readonly FindingDraft[] {
    const drafts = context
      .factsOfKind('supabase.policy')
      .filter(
        (fact) =>
          fact.isBroad &&
          fact.roles.some((role) => BROAD_ROLES.has(role.toLowerCase())),
      )
      .map((fact): FindingDraft =>
        Object.freeze({
          description: `Policy ${fact.policyName} on ${fact.schema}.${fact.table} uses a broad true predicate for role(s) ${fact.roles.join(', ')}.`,
          confidence: fact.confidence,
          status: 'suspicious',
          primaryLocation: fact.location,
          relatedLocations: Object.freeze([]),
          evidence: Object.freeze([
            Object.freeze({
              kind: 'migration',
              summary:
                'CREATE POLICY was observed with USING (true) and/or WITH CHECK (true) for an open role.',
              locations: Object.freeze([fact.location]),
            }),
          ]),
          impact:
            'Broad policies can allow wide read or write access for anon or authenticated clients when combined with exposed API keys.',
          remediation:
            'Replace true predicates with ownership or attribute checks such as auth.uid() correlations appropriate to the table.',
          limitations: Object.freeze([
            'This finding is suspicious based on local SQL text. Intentional public-read tables may still use broad policies by design.',
          ]),
          tags: Object.freeze(['supabase', 'policy', 'broad']),
        }),
      )
    return Object.freeze(drafts)
  },
})
