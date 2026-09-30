import type { FindingDraft, Rule, RuleMetadata } from '../core/rules/rule.js'
import type { RuleContext } from '../core/rules/rule-context.js'

const metadata: RuleMetadata = Object.freeze({
  id: 'VS-SEC-003',
  version: '1.0.0',
  title: 'Generic credential candidate',
  category: 'secrets',
  defaultSeverity: 'medium',
  supportedFacts: Object.freeze(['secret.candidate'] as const),
  references: Object.freeze(['https://cwe.mitre.org/data/definitions/798.html']),
})

export const genericCredentialCandidateRule: Rule = Object.freeze({
  metadata,
  evaluate(context: RuleContext): readonly FindingDraft[] {
    const specificLocations = new Set(
      context
        .factsOfKind('secret.candidate')
        .filter(
          (fact) =>
            fact.secretType !== 'unknown' &&
            fact.secretType !== 'private_key' &&
            !fact.isPlaceholder,
        )
        .map((fact) => locationKey(fact.location.file, fact.location.startLine)),
    )

    const drafts = context
      .factsOfKind('secret.candidate')
      .filter(
        (fact) =>
          fact.secretType === 'unknown' &&
          !fact.isPlaceholder &&
          !specificLocations.has(
            locationKey(fact.location.file, fact.location.startLine),
          ),
      )
      .map((fact): FindingDraft =>
        Object.freeze({
          description:
            'A generic credential-like assignment with elevated entropy was observed.',
          confidence: fact.confidence,
          status: 'suspicious',
          primaryLocation: fact.location,
          relatedLocations: Object.freeze([]),
          evidence: Object.freeze([
            Object.freeze({
              kind: 'code',
              summary:
                'A name/value pattern resembles a credential, but format-specific validation was not available.',
              redactedSnippet: fact.protectedValue.redacted,
              locations: Object.freeze([fact.location]),
              secretFingerprint: fact.protectedValue.fingerprint,
            }),
          ]),
          impact:
            'If this value is a real credential, exposure could enable unauthorized access.',
          remediation:
            'Confirm whether the value is sensitive. Prefer secret managers and remove live credentials from source.',
          limitations: Object.freeze([
            'This finding is suspicious only; the value was not validated as a known credential format.',
            'Placeholders and low-entropy samples are suppressed by the extractor.',
          ]),
          tags: Object.freeze(['credential', 'generic', 'suspicious']),
        }),
      )
    return Object.freeze(drafts)
  },
})

function locationKey(file: string, startLine: number): string {
  return `${file.normalize('NFC')}:${String(startLine)}`
}
