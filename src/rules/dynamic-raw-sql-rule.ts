import type { FindingDraft, Rule, RuleMetadata } from '../core/rules/rule.js'
import type { RuleContext } from '../core/rules/rule-context.js'

const metadata: RuleMetadata = Object.freeze({
  id: 'VS-DANG-004',
  version: '1.0.0',
  title: 'Raw SQL with dynamic interpolation',
  category: 'dangerous',
  defaultSeverity: 'high',
  supportedFacts: Object.freeze(['dangerous.sink'] as const),
  references: Object.freeze(['https://cwe.mitre.org/data/definitions/89.html']),
})

export const dynamicRawSqlRule: Rule = Object.freeze({
  metadata,
  evaluate(context: RuleContext): readonly FindingDraft[] {
    const drafts = context
      .factsOfKind('dangerous.sink')
      .filter((fact) => fact.sink === 'raw_sql' && fact.input !== 'constant')
      .map((fact): FindingDraft =>
        Object.freeze({
          description:
            'A raw SQL API appears to interpolate non-constant input without evident parameterization.',
          confidence: fact.confidence,
          status: 'suspicious',
          primaryLocation: fact.location,
          relatedLocations: Object.freeze([]),
          evidence: Object.freeze([
            Object.freeze({
              kind: 'code',
              summary:
                'query/raw/sql usage with dynamic template or concatenation heuristics was observed.',
              locations: Object.freeze([fact.location]),
            }),
          ]),
          impact:
            'If untrusted data is interpolated into SQL, it may enable SQL injection against the database.',
          remediation:
            'Use parameterized queries or bound placeholders. Avoid string-built SQL.',
          limitations: Object.freeze([
            'Same-file heuristics do not confirm exploitability.',
            'Only server/edge-oriented paths are considered for this sink class.',
          ]),
          tags: Object.freeze(['dangerous', 'sql']),
        }),
      )
    return Object.freeze(drafts)
  },
})
