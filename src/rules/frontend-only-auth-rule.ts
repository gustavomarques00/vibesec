import type { FindingDraft, Rule, RuleMetadata } from '../core/rules/rule.js'
import type { RuleContext } from '../core/rules/rule-context.js'

const metadata: RuleMetadata = Object.freeze({
  id: 'VS-AUTH-001',
  version: '1.0.0',
  title: 'Frontend-only authentication or role check',
  category: 'authentication',
  defaultSeverity: 'medium',
  supportedFacts: Object.freeze(['auth.guard'] as const),
  references: Object.freeze(['https://cwe.mitre.org/data/definitions/602.html']),
})

export const frontendOnlyAuthRule: Rule = Object.freeze({
  metadata,
  evaluate(context: RuleContext): readonly FindingDraft[] {
    const guards = context.factsOfKind('auth.guard')
    const hasServer = guards.some((fact) => fact.enforcement === 'server')
    if (hasServer) return Object.freeze([])

    const drafts = guards
      .filter(
        (fact) =>
          fact.enforcement === 'client' &&
          (fact.guardType === 'authentication' || fact.guardType === 'role') &&
          fact.subject !== undefined &&
          !fact.subject.startsWith('storage:'),
      )
      .map((fact): FindingDraft =>
        Object.freeze({
          description:
            'An authentication or role check appears only in client-side code without correlated server enforcement in the repository.',
          confidence: fact.confidence,
          status: 'suspicious',
          primaryLocation: fact.location,
          relatedLocations: Object.freeze([]),
          evidence: Object.freeze([
            Object.freeze({
              kind: 'code',
              summary:
                'A client-side guard or role check was observed without a matching server auth.guard fact.',
              locations: Object.freeze([fact.location]),
            }),
          ]),
          impact:
            'Client-only checks can be bypassed by calling APIs or mutating client state directly.',
          remediation:
            'Enforce authentication and authorization on the server or edge. Treat client checks as UX only.',
          limitations: Object.freeze([
            'This scan uses bounded heuristics and may miss server enforcement outside scanned JS/TS files.',
            'Absence of local server guards is not proof that production endpoints are unprotected.',
          ]),
          tags: Object.freeze(['authentication', 'client-only']),
        }),
      )
    return Object.freeze(drafts)
  },
})
