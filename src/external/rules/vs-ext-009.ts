import type { ExternalRule } from './types.js'
import { boundSnippet, selectDocumentResponse } from './helpers.js'

export const vsExt009: ExternalRule = Object.freeze({
  metadata: Object.freeze({
    id: 'VS-EXT-009',
    version: '1.0.0',
    title: 'TLS hostname verification failure observed',
    category: 'tls',
    defaultSeverity: 'high',
    evidenceKind: 'tls',
    description:
      'Emits when TLS authorization failure is explicitly attributable to hostname verification.',
  }),
  evaluate(graph) {
    const document = selectDocumentResponse(graph)
    if (document === undefined) return Object.freeze([])
    if (!document.tlsUsed || document.tls === undefined) return Object.freeze([])
    if (document.tls.authorized) return Object.freeze([])

    const error = document.tls.authorizationError
    if (!isHostnameVerificationFailure(error)) return Object.freeze([])

    return Object.freeze([
      Object.freeze({
        ruleId: 'VS-EXT-009' as const,
        primaryUrl: document.url,
        description:
          'TLS authorization failed with an error attributable to hostname verification.',
        confidence: 'high' as const,
        status: 'confirmed' as const,
        evidence: Object.freeze([
          Object.freeze({
            kind: 'tls' as const,
            summary: 'Hostname verification failure indicated by authorizationError.',
            location: Object.freeze({ kind: 'url' as const, url: document.url }),
            redactedSnippet: boundSnippet(error ?? 'hostname-verification-failure'),
          }),
        ]),
        impact:
          'Clients that verify certificate hostnames may refuse the TLS connection.',
        remediation:
          'Serve a certificate whose subject/SAN matches the requested hostname.',
        limitations: Object.freeze([
          'Generic TLS failures without hostname indicators are not classified here.',
        ]),
        tags: Object.freeze(['tls', 'hostname']),
      }),
    ])
  },
})

function isHostnameVerificationFailure(error: string | undefined): boolean {
  if (error === undefined || error.length === 0) return false
  if (error === 'unknown') return false
  const lower = error.toLowerCase()
  return (
    lower.includes('hostname') ||
    lower.includes('altname') ||
    lower.includes('cert_altname') ||
    lower.includes('host name') ||
    error.includes('ERR_TLS_CERT_ALTNAME_INVALID')
  )
}
