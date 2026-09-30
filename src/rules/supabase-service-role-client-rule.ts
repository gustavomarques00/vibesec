import type { FindingDraft, Rule, RuleMetadata } from '../core/rules/rule.js'
import type { RuleContext } from '../core/rules/rule-context.js'
import { classifyRuntimeExposure } from '../utils/runtime-exposure.js'

const metadata: RuleMetadata = Object.freeze({
  id: 'VS-SUP-001',
  version: '1.0.0',
  title: 'Supabase service-role key in client context',
  category: 'supabase',
  defaultSeverity: 'critical',
  supportedFacts: Object.freeze(['secret.candidate', 'git.file'] as const),
  references: Object.freeze(['https://supabase.com/docs/guides/api/api-keys']),
})

export const supabaseServiceRoleClientRule: Rule = Object.freeze({
  metadata,
  evaluate(context: RuleContext): readonly FindingDraft[] {
    const drafts = context
      .factsOfKind('secret.candidate')
      .filter(
        (fact) =>
          fact.secretType === 'supabase_key' &&
          !fact.isPlaceholder &&
          classifyRuntimeExposure(fact.location.file) !== 'server',
      )
      .map((fact): FindingDraft =>
        Object.freeze({
          description:
            'A Supabase service-role or secret key literal was observed in a client/public context.',
          confidence: fact.confidence,
          status: 'confirmed',
          primaryLocation: fact.location,
          relatedLocations: Object.freeze([]),
          evidence: Object.freeze([
            Object.freeze({
              kind: 'code',
              summary:
                'Service-role/secret material was present where client-exposed code or config is expected.',
              redactedSnippet: fact.protectedValue.redacted,
              locations: Object.freeze([fact.location]),
              secretFingerprint: fact.protectedValue.fingerprint,
            }),
          ]),
          impact:
            'Service-role keys bypass Row Level Security and grant privileged API access if recovered from client assets.',
          remediation:
            'Remove service-role keys from client bundles and public configuration. Keep them only on trusted server runtimes and rotate exposed keys.',
          limitations: Object.freeze([
            'This finding confirms repository evidence of a privileged Supabase key in a client-facing path, not that the key is currently accepted by a remote project.',
          ]),
          tags: Object.freeze(['supabase', 'service-role', 'client']),
        }),
      )
    return Object.freeze(drafts)
  },
})
