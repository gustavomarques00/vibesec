import type {
  ExternalBlockedRedirectObservation,
  ExternalHttpMethod,
  ExternalObservationGraph,
  ExternalRedirectObservation,
} from '../domain/observations.js'
import { extractHttpResponseObservation } from './http-response.js'
import type { RawHeaderInput } from './headers.js'
import type { RawTlsInput } from './tls.js'
import {
  extractBlockedRedirectObservations,
  extractRedirectObservations,
} from './redirects.js'

/**
 * Structural transport observation input for E1.4.
 * Compatible with E1.3 ExternalRawObservation without importing infra.
 * Body bytes, if present on hops, are read only for length then discarded.
 */
export type ExternalTransportObservationInput = Readonly<{
  initialRequestUrl: string
  finalUrl: string
  method: ExternalHttpMethod
  hops: readonly ExternalTransportHopSource[]
  redirects: readonly ExternalRedirectObservation[]
  blockedRedirects?: readonly ExternalBlockedRedirectObservation[]
}>

export type ExternalTransportHopSource = Readonly<{
  requestUrl: string
  method: ExternalHttpMethod
  statusCode: number
  headers: readonly RawHeaderInput[]
  /** Prefer bodyByteLength; `body` is accepted only to measure length. */
  bodyByteLength?: number
  body?: Uint8Array
  tls?: RawTlsInput
}>

/**
 * Build an immutable ExternalObservationGraph from bounded transport results.
 * Pure transformation — no network I/O and no rule evaluation.
 */
export function buildExternalObservationGraph(
  input: ExternalTransportObservationInput,
): ExternalObservationGraph {
  const responses = Object.freeze(
    input.hops.map((hop) =>
      extractHttpResponseObservation({
        requestUrl: hop.requestUrl,
        method: hop.method,
        statusCode: hop.statusCode,
        headers: hop.headers,
        bodyByteLength: resolveBodyByteLength(hop),
        ...(hop.tls !== undefined ? { tls: hop.tls } : {}),
      }),
    ),
  )

  return Object.freeze({
    initialRequestUrl: input.initialRequestUrl.normalize('NFC'),
    finalUrl: input.finalUrl.normalize('NFC'),
    redirects: extractRedirectObservations(input.redirects),
    blockedRedirects: extractBlockedRedirectObservations(input.blockedRedirects),
    responses,
    assets: Object.freeze([]),
  })
}

function resolveBodyByteLength(hop: ExternalTransportHopSource): number {
  if (typeof hop.bodyByteLength === 'number' && Number.isFinite(hop.bodyByteLength)) {
    return Math.max(0, Math.trunc(hop.bodyByteLength))
  }
  if (hop.body !== undefined) {
    return hop.body.byteLength
  }
  return 0
}
