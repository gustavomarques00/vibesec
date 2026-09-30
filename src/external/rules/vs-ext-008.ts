import type { ExternalRule } from './types.js'
import { selectDocumentResponse } from './helpers.js'

export const vsExt008: ExternalRule = Object.freeze({
  metadata: Object.freeze({
    id: 'VS-EXT-008',
    version: '1.0.0',
    title: 'TLS certificate validity period has ended',
    category: 'tls',
    defaultSeverity: 'high',
    evidenceKind: 'tls',
    description:
      'Emits when TLS certificate validTo is known and evaluation time is after validTo.',
  }),
  evaluate(graph, context) {
    const document = selectDocumentResponse(graph)
    if (document === undefined) return Object.freeze([])
    if (!document.tlsUsed || document.tls === undefined) return Object.freeze([])
    const validToIso = document.tls.validToIso
    if (validToIso === undefined) return Object.freeze([])

    const validToMs = Date.parse(validToIso)
    if (!Number.isFinite(validToMs)) return Object.freeze([])
    if (context.evaluationTimeMs <= validToMs) return Object.freeze([])

    return Object.freeze([
      Object.freeze({
        ruleId: 'VS-EXT-008' as const,
        primaryUrl: document.url,
        description:
          'TLS certificate validTo is earlier than the scan evaluation timestamp.',
        confidence: 'high' as const,
        status: 'confirmed' as const,
        evidence: Object.freeze([
          Object.freeze({
            kind: 'tls' as const,
            summary: `Certificate validTo=${validToIso}.`,
            location: Object.freeze({ kind: 'url' as const, url: document.url }),
            redactedSnippet: validToIso,
          }),
        ]),
        impact:
          'Clients that enforce certificate validity may refuse the TLS connection.',
        remediation: 'Renew the TLS certificate before validTo.',
        limitations: Object.freeze([
          'Evaluation uses the injected scan timestamp, not browser-local clocks.',
        ]),
        tags: Object.freeze(['tls', 'certificate']),
      }),
    ])
  },
})
