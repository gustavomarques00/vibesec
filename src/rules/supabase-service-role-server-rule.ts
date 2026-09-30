import type { FindingDraft, Rule, RuleMetadata } from '../core/rules/rule.js'
import type { RuleContext } from '../core/rules/rule-context.js'
import { classifyRuntimeExposure } from '../utils/runtime-exposure.js'

const metadata: RuleMetadata = Object.freeze({
  id: 'VS-SUP-002',
  version: '1.0.0',
  title: 'Supabase service-role key in server repository material',
  category: 'supabase',
  defaultSeverity: 'high',
  supportedFacts: Object.freeze(['secret.candidate', 'git.file'] as const),
  references: Object.freeze(['https://supabase.com/docs/guides/api/api-keys']),
})

export const supabaseServiceRoleServerRule: Rule = Object.freeze({
  metadata,
  evaluate(context: RuleContext): readonly FindingDraft[] {
    const drafts = context
      .factsOfKind('secret.candidate')
      .filter(
        (fact) =>
          fact.secretType === 'supabase_key' &&
          !fact.isPlaceholder &&
          classifyRuntimeExposure(fact.location.file) === 'server',
      )
      .map((fact): FindingDraft => {
        const tracking =
          context
            .factsOfKind('git.file')
            .find((item) => item.location.file === fact.location.file)?.tracking ??
          'unknown'
        return Object.freeze({
          description:
            'A Supabase service-role or secret key literal was observed in server-side repository material.',
          severity: tracking === 'tracked' ? 'high' : 'high',
          confidence: fact.confidence,
          status: 'confirmed',
          primaryLocation: fact.location,
          relatedLocations: Object.freeze([]),
          evidence: Object.freeze([
            Object.freeze({
              kind: 'code',
              summary:
                'Privileged Supabase credential material was present in a server-oriented path.',
              redactedSnippet: fact.protectedValue.redacted,
              locations: Object.freeze([fact.location]),
              secretFingerprint: fact.protectedValue.fingerprint,
            }),
          ]),
          impact:
            'Anyone with repository access may recover a privileged key and bypass intended data access controls.',
          remediation:
            'Store service-role keys in a secret manager, remove literals from source, and rotate if the repository was shared.',
          limitations: Object.freeze([
            'This finding confirms repository exposure evidence only. It does not validate remote acceptance of the key.',
            ...(tracking === 'tracked'
              ? Object.freeze([])
              : Object.freeze([
                  'Git provenance does not confirm the file is tracked; versioning is not claimed.',
                ])),
          ]),
          tags: Object.freeze(['supabase', 'service-role', 'server']),
        })
      })
    return Object.freeze(drafts)
  },
})
