import type { FindingDraft, Rule, RuleMetadata } from '../core/rules/rule.js'
import type { RuleContext } from '../core/rules/rule-context.js'
import { isDotenvPath } from '../utils/dotenv-path.js'

const metadata: RuleMetadata = Object.freeze({
  id: 'VS-ENV-002',
  version: '1.0.0',
  title: 'Sensitive value in a Git-tracked env file',
  category: 'environment',
  defaultSeverity: 'high',
  supportedFacts: Object.freeze(['secret.candidate', 'git.file'] as const),
  references: Object.freeze(['https://cwe.mitre.org/data/definitions/798.html']),
})

export const trackedEnvSecretRule: Rule = Object.freeze({
  metadata,
  evaluate(context: RuleContext): readonly FindingDraft[] {
    const trackedEnvFiles = new Set(
      context
        .factsOfKind('git.file')
        .filter(
          (fact) => fact.tracking === 'tracked' && isDotenvPath(fact.location.file),
        )
        .map((fact) => fact.location.file),
    )

    const drafts = context
      .factsOfKind('secret.candidate')
      .filter(
        (fact) =>
          !fact.isPlaceholder &&
          trackedEnvFiles.has(fact.location.file) &&
          isDotenvPath(fact.location.file),
      )
      .map((fact): FindingDraft =>
        Object.freeze({
          description:
            'Sensitive material was observed in a Git-tracked environment file.',
          confidence: fact.confidence,
          status: 'confirmed',
          primaryLocation: fact.location,
          relatedLocations: Object.freeze([]),
          evidence: Object.freeze([
            Object.freeze({
              kind: 'config',
              summary: 'A sensitive value was present in a tracked .env file.',
              redactedSnippet: fact.protectedValue.redacted,
              locations: Object.freeze([fact.location]),
              secretFingerprint: fact.protectedValue.fingerprint,
            }),
          ]),
          impact:
            'Tracked env files can expose secrets to anyone with repository access and to CI clones.',
          remediation:
            'Remove secrets from tracked env files, rotate them, and keep only non-secret templates such as placeholders in examples.',
          limitations: Object.freeze([
            'This finding confirms repository evidence only and does not validate remote credential acceptance.',
          ]),
          tags: Object.freeze(['environment', 'dotenv', 'tracked']),
        }),
      )
    return Object.freeze(drafts)
  },
})
