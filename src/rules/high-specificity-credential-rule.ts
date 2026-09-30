import type { FindingDraft, Rule, RuleMetadata } from '../core/rules/rule.js'
import type { RuleContext } from '../core/rules/rule-context.js'
import type { GitFileFact, SecretCandidateFact } from '../core/models/fact.js'

const HIGH_SPECIFICITY_TYPES = new Set<SecretCandidateFact['secretType']>([
  'api_key',
  'bearer_token',
  'database_url',
  'jwt',
  'webhook_secret',
  'password',
])

const metadata: RuleMetadata = Object.freeze({
  id: 'VS-SEC-002',
  version: '1.0.0',
  title: 'High-specificity credential material',
  category: 'secrets',
  defaultSeverity: 'high',
  supportedFacts: Object.freeze(['secret.candidate', 'git.file'] as const),
  references: Object.freeze(['https://cwe.mitre.org/data/definitions/798.html']),
})

export const highSpecificityCredentialRule: Rule = Object.freeze({
  metadata,
  evaluate(context: RuleContext): readonly FindingDraft[] {
    const drafts = context
      .factsOfKind('secret.candidate')
      .filter(
        (fact) =>
          !fact.isPlaceholder &&
          fact.secretType !== 'private_key' &&
          fact.secretType !== 'unknown' &&
          HIGH_SPECIFICITY_TYPES.has(fact.secretType),
      )
      .map((fact): FindingDraft => {
        const gitStatus = gitStatusFor(context, fact.location.file)
        return Object.freeze({
          description: trackedClaim(fact.secretType, gitStatus),
          severity: gitStatus === 'tracked' ? 'critical' : 'high',
          confidence: fact.confidence,
          status: 'confirmed',
          primaryLocation: fact.location,
          relatedLocations: Object.freeze([]),
          evidence: Object.freeze([
            Object.freeze({
              kind: 'code',
              summary: `A high-specificity ${fact.secretType} candidate was observed.`,
              redactedSnippet: fact.protectedValue.redacted,
              locations: Object.freeze([fact.location]),
              secretFingerprint: fact.protectedValue.fingerprint,
            }),
          ]),
          impact:
            'If this credential is active, unintended possession could enable unauthorized access to protected systems.',
          remediation:
            'Remove the credential from source, rotate it, and load it from an approved secret manager at runtime.',
          limitations: Object.freeze([
            'This scan does not validate that the credential is accepted by any remote service.',
            ...gitLimitation(gitStatus),
          ]),
          tags: Object.freeze(['credential', fact.secretType]),
        })
      })
    return Object.freeze(drafts)
  },
})

function trackedClaim(
  secretType: SecretCandidateFact['secretType'],
  status: GitFileFact['tracking'],
): string {
  if (status === 'tracked') {
    return `High-specificity ${secretType} material was observed in a Git-tracked file.`
  }
  return `High-specificity ${secretType} material was observed in a scanned local file.`
}

function gitStatusFor(context: RuleContext, file: string): GitFileFact['tracking'] {
  return (
    context.factsOfKind('git.file').find((fact) => fact.location.file === file)
      ?.tracking ?? 'unknown'
  )
}

function gitLimitation(status: GitFileFact['tracking']): readonly string[] {
  if (status === 'tracked') return Object.freeze([])
  if (status === 'unknown') {
    return Object.freeze([
      'Git provenance was unavailable or inconclusive, so versioning is not claimed.',
    ])
  }
  return Object.freeze(['Local Git provenance indicates this file is not tracked.'])
}
