import type { FindingDraft, Rule, RuleMetadata } from '../core/rules/rule.js'
import type { RuleContext } from '../core/rules/rule-context.js'
import type { GitFileFact } from '../core/models/fact.js'

const metadata: RuleMetadata = Object.freeze({
  id: 'VS-SEC-001',
  version: '1.1.0',
  title: 'Private key material in local source',
  category: 'secrets',
  defaultSeverity: 'high',
  supportedFacts: Object.freeze(['secret.candidate', 'git.file'] as const),
  references: Object.freeze(['https://cwe.mitre.org/data/definitions/321.html']),
})

export const privateKeyMaterialRule: Rule = Object.freeze({
  metadata,
  evaluate(context: RuleContext): readonly FindingDraft[] {
    const drafts: FindingDraft[] = context
      .factsOfKind('secret.candidate')
      .filter((fact) => fact.secretType === 'private_key' && !fact.isPlaceholder)
      .map((fact): FindingDraft => {
        const gitStatus = gitStatusFor(context, fact.location.file)
        const tracked = gitStatus === 'tracked'
        return Object.freeze({
          description: tracked
            ? 'Private-key material was directly observed in a Git-tracked local file.'
            : 'Private-key material was directly observed in a scanned local file.',
          severity: tracked ? 'critical' : 'high',
          confidence: fact.confidence,
          status: 'confirmed',
          primaryLocation: fact.location,
          relatedLocations: Object.freeze([]),
          evidence: Object.freeze([
            Object.freeze({
              kind: 'code',
              summary:
                'A complete PEM private-key block was observed at this location.',
              redactedSnippet: fact.protectedValue.redacted,
              locations: Object.freeze([fact.location]),
              secretFingerprint: fact.protectedValue.fingerprint,
            }),
          ]),
          impact:
            'If this is an active key, unintended possession could enable impersonation or unauthorized access.',
          remediation:
            'Remove the key from source, store it in an approved secret manager, and rotate it if exposure is possible.',
          limitations: Object.freeze(limitationsFor(gitStatus)),
          tags: Object.freeze(['private-key', 'secret']),
        })
      })
    return Object.freeze(drafts)
  },
})

function gitStatusFor(context: RuleContext, file: string): GitFileFact['tracking'] {
  const matches = context
    .factsOfKind('git.file')
    .filter((fact) => fact.location.file === file)
  return matches[0]?.tracking ?? 'unknown'
}

function limitationsFor(status: GitFileFact['tracking']): readonly string[] {
  switch (status) {
    case 'tracked':
      return Object.freeze([
        'This scan does not establish that the key is valid, deployed, or accepted by any service.',
      ])
    case 'untracked':
    case 'ignored':
      return Object.freeze([
        'Local Git provenance indicates this file is not tracked.',
        'This scan does not establish that the key is valid, deployed, or accepted by any service.',
      ])
    case 'unknown':
      return Object.freeze([
        'This scan does not establish that the key is valid, tracked by Git, deployed, or accepted by any service.',
      ])
  }
}
