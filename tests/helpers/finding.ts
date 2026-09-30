import type {
  FindingDraft,
  ProtectedSensitiveValue,
  Rule,
  RuleMetadata,
} from '../../src/index.js'

export function createTestDraft(
  protectedValue: ProtectedSensitiveValue,
  overrides: Partial<Pick<FindingDraft, 'confidence' | 'severity' | 'status'>> = {},
): FindingDraft {
  const location = {
    file: 'src/config.ts',
    startLine: 8,
    startColumn: 3,
  } as const

  return {
    description: 'A narrow repository condition was directly observed.',
    severity: overrides.severity ?? 'high',
    confidence: overrides.confidence ?? 'high',
    status: overrides.status ?? 'confirmed',
    primaryLocation: location,
    relatedLocations: [],
    evidence: [
      {
        kind: 'config',
        summary: 'A sensitive binding contains a literal value.',
        redactedSnippet: protectedValue.redacted,
        locations: [location],
        secretFingerprint: protectedValue.fingerprint,
      },
    ],
    impact: 'A privileged credential may be exposed in repository material.',
    remediation: 'Remove and rotate the credential without using it.',
    limitations: ['Credential validity was not tested.'],
    tags: ['secret', 'repository'],
  }
}

export function createTestRule(
  draft: FindingDraft,
  metadataOverrides: Partial<RuleMetadata> = {},
): Rule {
  return {
    metadata: {
      id: 'VS-SEC-001',
      version: '1.0.0',
      title: 'Privileged credential literal observed',
      category: 'secrets',
      defaultSeverity: 'high',
      supportedFacts: [],
      references: ['https://example.invalid/vibesec/VS-SEC-001'],
      ...metadataOverrides,
    },
    evaluate() {
      return [draft]
    },
  }
}
