import type { FindingDraft, Rule, RuleMetadata } from '../core/rules/rule.js'
import type { RuleContext } from '../core/rules/rule-context.js'
import type { DangerousSinkFact } from '../core/models/fact.js'

const metadata: RuleMetadata = Object.freeze({
  id: 'VS-DANG-001',
  version: '1.0.0',
  title: 'Dynamic eval or Function constructor',
  category: 'dangerous',
  defaultSeverity: 'high',
  supportedFacts: Object.freeze(['dangerous.sink'] as const),
  references: Object.freeze(['https://cwe.mitre.org/data/definitions/95.html']),
})

export const dynamicEvalRule: Rule = Object.freeze({
  metadata,
  evaluate(context: RuleContext): readonly FindingDraft[] {
    return Object.freeze(
      context
        .factsOfKind('dangerous.sink')
        .filter(
          (fact) =>
            (fact.sink === 'eval' || fact.sink === 'new_function') &&
            fact.input !== 'constant',
        )
        .map((fact) => draftFor(fact)),
    )
  },
})

function draftFor(fact: DangerousSinkFact): FindingDraft {
  return Object.freeze({
    description: `A${fact.sink === 'eval' ? 'n eval' : ' Function'} call appears to receive non-constant input.`,
    confidence: fact.confidence,
    status: 'suspicious',
    primaryLocation: fact.location,
    relatedLocations: Object.freeze([]),
    evidence: Object.freeze([
      Object.freeze({
        kind: 'code',
        summary:
          'A dynamic code-execution sink was observed with non-constant input heuristics.',
        locations: Object.freeze([fact.location]),
      }),
    ]),
    impact:
      'If attacker-controlled data reaches this sink, it may enable arbitrary JavaScript execution in the process context.',
    remediation:
      'Remove dynamic code execution. Prefer explicit parsers, maps, or allowlisted operations.',
    limitations: Object.freeze([
      'Same-file heuristics do not prove remote code execution or attacker control.',
      'Constant-only calls are suppressed.',
    ]),
    tags: Object.freeze(['dangerous', fact.sink]),
  })
}
