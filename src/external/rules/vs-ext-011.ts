import type { ExternalRule } from './types.js'
import { findSecurityHeader, selectDocumentResponse } from './helpers.js'

export const vsExt011: ExternalRule = Object.freeze({
  metadata: Object.freeze({
    id: 'VS-EXT-011',
    version: '1.0.0',
    title: 'Referrer-Policy header was not observed',
    category: 'headers',
    defaultSeverity: 'low',
    evidenceKind: 'header',
    description:
      'Emits when a document response positively reports Referrer-Policy as missing.',
  }),
  evaluate(graph) {
    const document = selectDocumentResponse(graph)
    if (document === undefined) return Object.freeze([])
    const header = findSecurityHeader(document, 'referrer-policy')
    if (header?.status !== 'MISSING') return Object.freeze([])

    return Object.freeze([
      Object.freeze({
        ruleId: 'VS-EXT-011' as const,
        primaryUrl: document.url,
        description:
          'Referrer-Policy header was not observed on the document response.',
        confidence: 'high' as const,
        status: 'confirmed' as const,
        evidence: Object.freeze([
          Object.freeze({
            kind: 'header' as const,
            summary: 'Referrer-Policy status is MISSING.',
            location: Object.freeze({ kind: 'url' as const, url: document.url }),
          }),
        ]),
        impact:
          'No Referrer-Policy was advertised for controlling referrer transmission.',
        remediation: 'Publish a Referrer-Policy header on document responses.',
        limitations: Object.freeze([
          'This rule evaluates presence only; policy value quality is not assessed.',
        ]),
        tags: Object.freeze(['referrer-policy', 'headers']),
      }),
    ])
  },
})
