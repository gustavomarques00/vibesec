import type { FindingDraft, Rule, RuleMetadata } from '../core/rules/rule.js'
import type { RuleContext } from '../core/rules/rule-context.js'

const metadata: RuleMetadata = Object.freeze({
  id: 'VS-DANG-003',
  version: '1.0.0',
  title: 'Dynamic shell or child_process execution',
  category: 'dangerous',
  defaultSeverity: 'high',
  supportedFacts: Object.freeze(['dangerous.sink'] as const),
  references: Object.freeze(['https://cwe.mitre.org/data/definitions/78.html']),
})

export const dynamicShellExecRule: Rule = Object.freeze({
  metadata,
  evaluate(context: RuleContext): readonly FindingDraft[] {
    const drafts = context
      .factsOfKind('dangerous.sink')
      .filter((fact) => fact.sink === 'shell_exec' && fact.input !== 'constant')
      .map((fact): FindingDraft =>
        Object.freeze({
          description:
            'A child_process/shell execution API appears to receive non-constant input.',
          confidence: fact.confidence,
          status: 'suspicious',
          primaryLocation: fact.location,
          relatedLocations: Object.freeze([]),
          evidence: Object.freeze([
            Object.freeze({
              kind: 'code',
              summary:
                'exec/spawn-style invocation was observed with dynamic argument heuristics.',
              locations: Object.freeze([fact.location]),
            }),
          ]),
          impact:
            'If untrusted data reaches the command string, it may enable OS command injection.',
          remediation:
            'Use argument arrays without a shell, validate allowlists, and avoid string concatenation.',
          limitations: Object.freeze([
            'Heuristics do not prove attacker control or successful exploitation.',
            'Constant command strings are suppressed.',
          ]),
          tags: Object.freeze(['dangerous', 'shell']),
        }),
      )
    return Object.freeze(drafts)
  },
})
