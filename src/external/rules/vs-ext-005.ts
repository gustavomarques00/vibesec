import type { ExternalRule } from './types.js'
import { boundSnippet, findSecurityHeader, selectDocumentResponse } from './helpers.js'

export const vsExt005: ExternalRule = Object.freeze({
  metadata: Object.freeze({
    id: 'VS-EXT-005',
    version: '1.0.0',
    title: 'X-Content-Type-Options is missing or not nosniff',
    category: 'headers',
    defaultSeverity: 'low',
    evidenceKind: 'header',
    description:
      'Emits when X-Content-Type-Options is missing or not canonically nosniff.',
  }),
  evaluate(graph) {
    const document = selectDocumentResponse(graph)
    if (document === undefined) return Object.freeze([])
    const header = findSecurityHeader(document, 'x-content-type-options')
    if (header === undefined) return Object.freeze([])

    if (header.status === 'MISSING') {
      return Object.freeze([missingDraft(document.url)])
    }

    const value = header.values[0] ?? ''
    const canonical = value.trim().toLowerCase()
    if (canonical === 'nosniff') return Object.freeze([])

    return Object.freeze([
      Object.freeze({
        ruleId: 'VS-EXT-005' as const,
        primaryUrl: document.url,
        description:
          'X-Content-Type-Options was observed but is not the canonical nosniff value.',
        confidence: 'high' as const,
        status: 'confirmed' as const,
        evidence: Object.freeze([
          Object.freeze({
            kind: 'header' as const,
            summary: 'X-Content-Type-Options value is not nosniff.',
            location: Object.freeze({ kind: 'url' as const, url: document.url }),
            redactedSnippet: boundSnippet(value),
          }),
        ]),
        impact: 'Browsers are not instructed to disable MIME sniffing via nosniff.',
        remediation: 'Set X-Content-Type-Options to nosniff.',
        limitations: Object.freeze([
          'Only the canonical nosniff token is accepted by this rule.',
        ]),
        tags: Object.freeze(['xcto', 'headers']),
      }),
    ])
  },
})

function missingDraft(url: string) {
  return Object.freeze({
    ruleId: 'VS-EXT-005' as const,
    primaryUrl: url,
    description:
      'X-Content-Type-Options header was not observed on the document response.',
    confidence: 'high' as const,
    status: 'confirmed' as const,
    evidence: Object.freeze([
      Object.freeze({
        kind: 'header' as const,
        summary: 'X-Content-Type-Options status is MISSING.',
        location: Object.freeze({ kind: 'url' as const, url }),
      }),
    ]),
    impact: 'Browsers are not instructed to disable MIME sniffing via nosniff.',
    remediation: 'Set X-Content-Type-Options to nosniff.',
    limitations: Object.freeze(['This rule evaluates the document response only.']),
    tags: Object.freeze(['xcto', 'headers']),
  })
}
