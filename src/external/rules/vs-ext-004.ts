import type { ExternalRule } from './types.js'
import { findSecurityHeader, selectDocumentResponse } from './helpers.js'

export const vsExt004: ExternalRule = Object.freeze({
  metadata: Object.freeze({
    id: 'VS-EXT-004',
    version: '1.0.0',
    title: 'Content-Security-Policy header was not observed',
    category: 'headers',
    defaultSeverity: 'medium',
    evidenceKind: 'header',
    description: 'Emits when a document response positively reports CSP as missing.',
  }),
  evaluate(graph) {
    const document = selectDocumentResponse(graph)
    if (document === undefined) return Object.freeze([])
    const csp = findSecurityHeader(document, 'content-security-policy')
    if (csp?.status !== 'MISSING') return Object.freeze([])

    return Object.freeze([
      Object.freeze({
        ruleId: 'VS-EXT-004' as const,
        primaryUrl: document.url,
        description:
          'Content-Security-Policy header was not observed on the document response.',
        confidence: 'high' as const,
        status: 'confirmed' as const,
        evidence: Object.freeze([
          Object.freeze({
            kind: 'header' as const,
            summary: 'CSP status is MISSING.',
            location: Object.freeze({ kind: 'url' as const, url: document.url }),
          }),
        ]),
        impact: 'No Content-Security-Policy was advertised for the document response.',
        remediation: 'Publish a Content-Security-Policy header for document responses.',
        limitations: Object.freeze([
          'This rule evaluates presence only; CSP directive quality is not assessed.',
        ]),
        tags: Object.freeze(['csp', 'headers']),
      }),
    ])
  },
})
