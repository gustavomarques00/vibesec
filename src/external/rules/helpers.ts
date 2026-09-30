import type {
  ExternalHttpResponseObservation,
  ExternalObservationGraph,
  ExternalSecurityHeaderId,
  ExternalSecurityHeaderObservation,
} from '../domain/observations.js'

/**
 * Document response = response whose URL matches finalUrl, else last response.
 * Header rules apply to this response only — not to asset responses.
 */
export function selectDocumentResponse(
  graph: ExternalObservationGraph,
): ExternalHttpResponseObservation | undefined {
  if (graph.responses.length === 0) return undefined
  const finalUrl = graph.finalUrl
  if (finalUrl !== undefined) {
    const match = graph.responses.find((response) => response.url === finalUrl)
    if (match !== undefined) return match
  }
  return graph.responses[graph.responses.length - 1]
}

export function findSecurityHeader(
  response: ExternalHttpResponseObservation,
  name: ExternalSecurityHeaderId,
): ExternalSecurityHeaderObservation | undefined {
  return response.securityHeaders.find((header) => header.name === name)
}

export function readSchemeFromUrl(url: string): 'http' | 'https' | 'unknown' {
  if (url.startsWith('https:')) return 'https'
  if (url.startsWith('http:')) return 'http'
  return 'unknown'
}

export function boundSnippet(value: string, max = 120): string {
  const normalized = value.normalize('NFC')
  if (normalized.length <= max) return normalized
  return `${normalized.slice(0, max - 1)}…`
}

export function cookieDiscriminator(cookie: {
  name: string
  domain?: string
  path?: string
}): string {
  return [cookie.name, cookie.domain ?? '', cookie.path ?? ''].join('\u0000')
}
