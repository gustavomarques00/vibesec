import type { ExternalRule } from './types.js'
import { boundSnippet } from './helpers.js'

export const vsExt002: ExternalRule = Object.freeze({
  metadata: Object.freeze({
    id: 'VS-EXT-002',
    version: '1.0.0',
    title: 'HTTPS to HTTP redirect downgrade blocked',
    category: 'transport',
    defaultSeverity: 'medium',
    evidenceKind: 'redirect',
    description:
      'Emits when an HTTPS response attempted a redirect to HTTP and transport blocked it.',
  }),
  evaluate(graph) {
    const drafts = []
    for (const blocked of graph.blockedRedirects) {
      if (blocked.reason !== 'https-to-http') continue
      const fromUrl = blocked.fromUrl
      const toUrl = blocked.toUrl ?? '<unavailable>'
      drafts.push(
        Object.freeze({
          ruleId: 'VS-EXT-002' as const,
          primaryUrl: fromUrl,
          discriminator: toUrl,
          description:
            'An HTTPS response attempted a redirect to an HTTP URL; the downgrade was not followed.',
          confidence: 'high' as const,
          status: 'confirmed' as const,
          evidence: Object.freeze([
            Object.freeze({
              kind: 'redirect' as const,
              summary: 'Blocked HTTPS→HTTP redirect.',
              location: Object.freeze({ kind: 'url' as const, url: fromUrl }),
              redactedSnippet: boundSnippet(`${fromUrl} → ${toUrl}`),
            }),
          ]),
          impact:
            'A downgrade redirect would move subsequent navigation onto cleartext HTTP.',
          remediation:
            'Ensure redirects from HTTPS targets remain on HTTPS destinations.',
          limitations: Object.freeze([
            'Transport blocked the redirect; the HTTP destination was not fetched.',
          ]),
          tags: Object.freeze(['https', 'redirect', 'downgrade']),
        }),
      )
    }
    return Object.freeze(drafts)
  },
})
