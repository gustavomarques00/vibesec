import type { FindingDraft, Rule, RuleMetadata } from '../core/rules/rule.js'
import type { RuleContext } from '../core/rules/rule-context.js'

const metadata: RuleMetadata = Object.freeze({
  id: 'VS-AUTH-002',
  version: '1.0.0',
  title: 'Authorization decision from browser storage',
  category: 'authentication',
  defaultSeverity: 'medium',
  supportedFacts: Object.freeze(['auth.guard'] as const),
  references: Object.freeze(['https://cwe.mitre.org/data/definitions/602.html']),
})

export const storageRoleAuthRule: Rule = Object.freeze({
  metadata,
  evaluate(context: RuleContext): readonly FindingDraft[] {
    const drafts = context
      .factsOfKind('auth.guard')
      .filter(
        (fact) =>
          fact.enforcement === 'client' &&
          fact.guardType === 'role' &&
          fact.subject?.startsWith('storage:'),
      )
      .map((fact): FindingDraft =>
        Object.freeze({
          description:
            'An authorization-like decision appears to read role/admin state directly from localStorage or sessionStorage.',
          confidence: fact.confidence,
          status: 'suspicious',
          primaryLocation: fact.location,
          relatedLocations: Object.freeze([]),
          evidence: Object.freeze([
            Object.freeze({
              kind: 'code',
              summary:
                'Browser storage was read for a role/admin-like key used as an authorization signal.',
              locations: Object.freeze([fact.location]),
            }),
          ]),
          impact:
            'Storage values are attacker-controllable in the browser and must not be trusted for authorization.',
          remediation:
            'Derive authorization from verified server sessions or tokens. Do not trust role flags stored in localStorage/sessionStorage.',
          limitations: Object.freeze([
            'Standard Supabase auth-token storage patterns are excluded and do not generate this finding by themselves.',
            'This does not prove the value is used as the sole authorization decision at runtime.',
          ]),
          tags: Object.freeze(['authentication', 'storage', 'role']),
        }),
      )
    return Object.freeze(drafts)
  },
})
