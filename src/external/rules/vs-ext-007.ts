import type { ExternalRule } from './types.js'
import { cookieDiscriminator, selectDocumentResponse } from './helpers.js'

export const vsExt007: ExternalRule = Object.freeze({
  metadata: Object.freeze({
    id: 'VS-EXT-007',
    version: '1.0.0',
    title: 'Cookie SameSite attribute is absent or SameSite=None without Secure',
    category: 'cookies',
    defaultSeverity: 'low',
    evidenceKind: 'cookie-attr',
    description:
      'Emits when SameSite is absent, or SameSite=None is set without Secure.',
  }),
  evaluate(graph) {
    const document = selectDocumentResponse(graph)
    if (document === undefined) return Object.freeze([])

    const drafts = []
    for (const cookie of document.cookies) {
      if (cookie.malformed === true) continue

      const missingSameSite = cookie.sameSite === 'unknown'
      const noneWithoutSecure = cookie.sameSite === 'None' && !cookie.secure
      if (!missingSameSite && !noneWithoutSecure) continue

      const description = missingSameSite
        ? `Cookie ${JSON.stringify(cookie.name)} does not declare a SameSite attribute.`
        : `Cookie ${JSON.stringify(cookie.name)} declares SameSite=None without Secure.`

      drafts.push(
        Object.freeze({
          ruleId: 'VS-EXT-007' as const,
          primaryUrl: document.url,
          discriminator: cookieDiscriminator(cookie),
          description,
          confidence: 'high' as const,
          status: 'confirmed' as const,
          evidence: Object.freeze([
            Object.freeze({
              kind: 'cookie-attr' as const,
              summary: `SameSite=${cookie.sameSite}; Secure=${String(cookie.secure)}.`,
              location: Object.freeze({ kind: 'url' as const, url: document.url }),
              redactedSnippet:
                cookie.name.length <= 120
                  ? cookie.name
                  : `${cookie.name.slice(0, 119)}…`,
            }),
          ]),
          impact:
            'Cross-site cookie attachment behavior is less constrained than SameSite hardening recommends.',
          remediation:
            'Declare SameSite=Lax or Strict where appropriate; SameSite=None requires Secure.',
          limitations: Object.freeze([
            'This rule does not claim CSRF exploitability.',
            'Cookie values are never retained or reported.',
          ]),
          tags: Object.freeze(['cookie', 'samesite']),
        }),
      )
    }
    return Object.freeze(drafts)
  },
})
