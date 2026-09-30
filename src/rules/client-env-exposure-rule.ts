import type { FindingDraft, Rule, RuleMetadata } from '../core/rules/rule.js'
import type { RuleContext } from '../core/rules/rule-context.js'

const metadata: RuleMetadata = Object.freeze({
  id: 'VS-ENV-001',
  version: '1.0.0',
  title: 'Privileged value exposed through public env prefix',
  category: 'environment',
  defaultSeverity: 'critical',
  supportedFacts: Object.freeze(['environment.binding', 'secret.candidate'] as const),
  references: Object.freeze(['https://cwe.mitre.org/data/definitions/200.html']),
})

export const clientEnvExposureRule: Rule = Object.freeze({
  metadata,
  evaluate(context: RuleContext): readonly FindingDraft[] {
    const clientBindings = context
      .factsOfKind('environment.binding')
      .filter((fact) => fact.exposure === 'client')

    const seenSecretLocations = new Set<string>()
    const drafts: FindingDraft[] = []
    for (const binding of clientBindings) {
      const secrets = context
        .factsOfKind('secret.candidate')
        .filter(
          (secret) =>
            !secret.isPlaceholder &&
            secret.location.file === binding.location.file &&
            secret.bindingName === binding.name,
        )
      for (const secret of secrets) {
        const key = [
          secret.location.file.normalize('NFC'),
          String(secret.location.startLine),
          String(secret.location.startColumn ?? 0),
          String(secret.location.endLine ?? 0),
          String(secret.location.endColumn ?? 0),
        ].join(':')
        if (seenSecretLocations.has(key)) continue
        seenSecretLocations.add(key)
        drafts.push(
          Object.freeze({
            description: `A sensitive value bound to public env name ${binding.name} may be exposed to client bundles.`,
            confidence: 'high',
            status: 'confirmed',
            primaryLocation: secret.location,
            relatedLocations: Object.freeze([binding.location]),
            evidence: Object.freeze([
              Object.freeze({
                kind: 'config',
                summary: `Public prefix binding ${binding.name} correlates with sensitive material.`,
                redactedSnippet: secret.protectedValue.redacted,
                locations: Object.freeze([secret.location, binding.location]),
                secretFingerprint: secret.protectedValue.fingerprint,
              }),
            ]),
            impact:
              'Client-exposed privileged values can be recovered from built assets or browser contexts.',
            remediation:
              'Remove privileged values from public env prefixes. Keep secrets on the server and rotate exposed credentials.',
            limitations: Object.freeze([
              'This finding confirms repository evidence of a public-prefix binding with sensitive material, not a deployed bundle contents dump.',
            ]),
            tags: Object.freeze(['environment', 'client-exposure', binding.name]),
          }),
        )
      }
    }
    return Object.freeze(drafts)
  },
})
