import type { ExternalRule } from './types.js'
import { readSchemeFromUrl, selectDocumentResponse } from './helpers.js'

export const vsExt001: ExternalRule = Object.freeze({
  metadata: Object.freeze({
    id: 'VS-EXT-001',
    version: '1.0.0',
    title: 'Final document URL is not HTTPS',
    category: 'transport',
    defaultSeverity: 'medium',
    evidenceKind: 'http',
    description: 'Emits when the final effective document URL uses the http scheme.',
  }),
  evaluate(graph) {
    const finalUrl = graph.finalUrl
    if (finalUrl === undefined) return Object.freeze([])
    if (readSchemeFromUrl(finalUrl) !== 'http') return Object.freeze([])

    const document = selectDocumentResponse(graph)
    const url = document?.url ?? finalUrl

    return Object.freeze([
      Object.freeze({
        ruleId: 'VS-EXT-001' as const,
        primaryUrl: url,
        description: 'The final effective document URL uses http rather than https.',
        confidence: 'high' as const,
        status: 'confirmed' as const,
        evidence: Object.freeze([
          Object.freeze({
            kind: 'http' as const,
            summary: 'Final document URL scheme is http.',
            location: Object.freeze({ kind: 'url' as const, url }),
            redactedSnippet: url.length <= 120 ? url : `${url.slice(0, 119)}…`,
          }),
        ]),
        impact: 'Traffic to the final document URL is not protected by TLS encryption.',
        remediation: 'Serve the final document over HTTPS.',
        limitations: Object.freeze([
          'This finding describes the final effective URL only.',
        ]),
        tags: Object.freeze(['https', 'transport']),
      }),
    ])
  },
})
