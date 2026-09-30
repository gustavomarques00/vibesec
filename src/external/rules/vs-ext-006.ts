import type { ExternalRule } from './types.js'
import { cookieDiscriminator, selectDocumentResponse } from './helpers.js'

export const vsExt006: ExternalRule = Object.freeze({
  metadata: Object.freeze({
    id: 'VS-EXT-006',
    version: '1.0.0',
    title: 'Cookie lacks Secure and/or HttpOnly attributes',
    category: 'cookies',
    defaultSeverity: 'medium',
    evidenceKind: 'cookie-attr',
    description:
      'Emits when observed cookies lack Secure (on HTTPS) and/or HttpOnly attributes.',
  }),
  evaluate(graph) {
    const document = selectDocumentResponse(graph)
    if (document === undefined) return Object.freeze([])

    const drafts = []
    for (const cookie of document.cookies) {
      if (cookie.malformed === true) continue

      const missingSecure = document.scheme === 'https' && !cookie.secure
      const missingHttpOnly = !cookie.httpOnly
      if (!missingSecure && !missingHttpOnly) continue

      const parts: string[] = []
      if (missingSecure) parts.push('Secure')
      if (missingHttpOnly) parts.push('HttpOnly')

      drafts.push(
        Object.freeze({
          ruleId: 'VS-EXT-006' as const,
          primaryUrl: document.url,
          discriminator: cookieDiscriminator(cookie),
          description: `Cookie ${JSON.stringify(cookie.name)} does not declare ${parts.join(' and ')}.`,
          confidence: 'high' as const,
          status: 'confirmed' as const,
          evidence: Object.freeze([
            Object.freeze({
              kind: 'cookie-attr' as const,
              summary: `Cookie attributes: Secure=${String(cookie.secure)}, HttpOnly=${String(cookie.httpOnly)}.`,
              location: Object.freeze({ kind: 'url' as const, url: document.url }),
              redactedSnippet:
                cookie.name.length <= 120
                  ? cookie.name
                  : `${cookie.name.slice(0, 119)}…`,
            }),
          ]),
          impact:
            'Cookie attribute hardening recommended by browser security guidance is incomplete.',
          remediation:
            'Declare Secure on HTTPS cookies and HttpOnly where script access is unnecessary.',
          limitations: Object.freeze([
            'Cookie purpose is not inferred; the finding describes attribute presence only.',
            'Cookie values are never retained or reported.',
          ]),
          tags: Object.freeze(['cookie', 'secure', 'httponly']),
        }),
      )
    }
    return Object.freeze(drafts)
  },
})
