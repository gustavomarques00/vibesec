import type {
  ExternalHttpMethod,
  ExternalHttpResponseObservation,
} from '../domain/observations.js'
import { extractCookieAttributeObservations } from './cookies.js'
import {
  extractAllowlistedHeaderPairs,
  extractHstsObservation,
  extractSecurityHeaderObservations,
  type RawHeaderInput,
} from './headers.js'
import { extractTlsObservation, type RawTlsInput } from './tls.js'

export type ExternalTransportHopInput = Readonly<{
  requestUrl: string
  method: ExternalHttpMethod
  statusCode: number
  headers: readonly RawHeaderInput[]
  /** Byte length only — body bytes must not be copied into observations. */
  bodyByteLength: number
  tls?: RawTlsInput
}>

export function extractHttpResponseObservation(
  hop: ExternalTransportHopInput,
): ExternalHttpResponseObservation {
  const scheme = readScheme(hop.requestUrl)
  const securityHeaders = extractSecurityHeaderObservations(hop.headers)
  const headers = extractAllowlistedHeaderPairs(hop.headers)
  const cookies = extractCookieAttributeObservations(hop.headers)
  const hsts = extractHstsObservation(securityHeaders, scheme)
  const tlsFacts = extractTlsObservation(scheme, hop.tls)

  const contentType = firstHeaderValue(securityHeaders, 'content-type')
  const contentEncoding = firstHeaderValue(securityHeaders, 'content-encoding')

  return Object.freeze({
    url: hop.requestUrl.normalize('NFC'),
    method: hop.method,
    statusCode: hop.statusCode,
    scheme,
    headers,
    securityHeaders,
    hsts,
    ...(contentType !== undefined ? { contentType } : {}),
    ...(contentEncoding !== undefined ? { contentEncoding } : {}),
    bodyByteLength: Math.max(0, hop.bodyByteLength),
    cookies,
    tlsUsed: tlsFacts.tlsUsed,
    ...(tlsFacts.tls !== undefined ? { tls: tlsFacts.tls } : {}),
  })
}

function readScheme(url: string): 'http' | 'https' {
  if (url.startsWith('https:')) return 'https'
  if (url.startsWith('http:')) return 'http'
  return 'https'
}

function firstHeaderValue(
  securityHeaders: ReturnType<typeof extractSecurityHeaderObservations>,
  name: 'content-type' | 'content-encoding',
): string | undefined {
  const entry = securityHeaders.find((header) => header.name === name)
  if (entry?.status !== 'OBSERVED') return undefined
  return entry.values[0]
}
