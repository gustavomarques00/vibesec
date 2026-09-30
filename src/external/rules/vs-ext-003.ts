import type { ExternalRule } from './types.js'
import { selectDocumentResponse } from './helpers.js'

export const vsExt003: ExternalRule = Object.freeze({
  metadata: Object.freeze({
    id: 'VS-EXT-003',
    version: '1.0.0',
    title: 'Strict-Transport-Security header was not observed',
    category: 'headers',
    defaultSeverity: 'low',
    evidenceKind: 'header',
    description:
      'Emits when an HTTPS document response positively reports HSTS as missing.',
  }),
  evaluate(graph) {
    const document = selectDocumentResponse(graph)
    if (document === undefined) return Object.freeze([])
    if (document.scheme !== 'https') return Object.freeze([])
    if (document.hsts.status !== 'MISSING') return Object.freeze([])

    return Object.freeze([
      Object.freeze({
        ruleId: 'VS-EXT-003' as const,
        primaryUrl: document.url,
        description:
          'Strict-Transport-Security header was not observed on the HTTPS document response.',
        confidence: 'high' as const,
        status: 'confirmed' as const,
        evidence: Object.freeze([
          Object.freeze({
            kind: 'header' as const,
            summary: 'HSTS status is MISSING.',
            location: Object.freeze({ kind: 'url' as const, url: document.url }),
          }),
        ]),
        impact:
          'Browsers are not instructed by HSTS to enforce HTTPS for subsequent visits.',
        remediation:
          'Publish a Strict-Transport-Security header on HTTPS document responses.',
        limitations: Object.freeze([
          'This rule evaluates header presence only; max-age quality is not assessed.',
        ]),
        tags: Object.freeze(['hsts', 'headers']),
      }),
    ])
  },
})
