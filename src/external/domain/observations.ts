/**
 * DTO foundation for future External observation graphs.
 * No network I/O. Fields avoid raw secrets, bodies, and cookie values.
 */

export type ExternalHttpMethod = 'GET' | 'HEAD'

export type ExternalHeaderObservation = Readonly<{
  name: string
  /** Header value truncated/redacted by later slices; never Authorization. */
  value: string
}>

export type ExternalCookieSameSite = 'Strict' | 'Lax' | 'None' | 'unknown'

/**
 * Cookie attribute observation. Deliberately has no `value` field.
 */
export type ExternalCookieAttributeObservation = Readonly<{
  name: string
  secure: boolean
  httpOnly: boolean
  sameSite: ExternalCookieSameSite
  domain?: string
  path?: string
  maxAgeSeconds?: number
  expiresAtIso?: string
  hostPrefix: boolean
  securePrefix: boolean
}>

export type ExternalTlsObservation = Readonly<{
  protocol?: string
  authorized: boolean
  authorizationError?: string
  validFromIso?: string
  validToIso?: string
  subjectCn?: string
  issuerCn?: string
}>

export type ExternalRedirectObservation = Readonly<{
  /** Zero-based hop index; sequence order is meaningful — do not sort away. */
  index: number
  fromUrl: string
  toUrl: string
  statusCode: number
}>

export type ExternalHttpResponseObservation = Readonly<{
  url: string
  method: ExternalHttpMethod
  statusCode: number
  headers: readonly ExternalHeaderObservation[]
  /** Declared content-type token if present; no body bytes. */
  contentType?: string
  /** Observed content-encoding token if present. */
  contentEncoding?: string
  /** Byte length observed or capped; not the body itself. */
  bodyByteLength?: number
  cookies: readonly ExternalCookieAttributeObservation[]
  tls?: ExternalTlsObservation
}>

export type ExternalAssetObservation = Readonly<{
  sourceUrl: string
  requestUrl: string
  kind: 'script' | 'stylesheet'
  sameOrigin: boolean
}>

/**
 * Immutable capture of observations for one External scan.
 * Redirects remain in sequence order; other collections may be sorted later.
 */
export type ExternalObservationGraph = Readonly<{
  initialRequestUrl: string
  finalUrl?: string
  redirects: readonly ExternalRedirectObservation[]
  responses: readonly ExternalHttpResponseObservation[]
  assets: readonly ExternalAssetObservation[]
}>

export function createEmptyExternalObservationGraph(
  initialRequestUrl: string,
): ExternalObservationGraph {
  if (typeof initialRequestUrl !== 'string' || initialRequestUrl.length === 0) {
    throw new TypeError('initialRequestUrl must be a non-empty string.')
  }
  return Object.freeze({
    initialRequestUrl,
    redirects: Object.freeze([]),
    responses: Object.freeze([]),
    assets: Object.freeze([]),
  })
}
