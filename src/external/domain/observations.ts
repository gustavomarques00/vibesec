/**
 * DTO foundation for External observation graphs.
 * No network I/O. Fields avoid raw secrets, bodies, and cookie values.
 */

export type ExternalHttpMethod = 'GET' | 'HEAD'

/** Factual extraction state — not a security verdict. */
export type ExternalFactStatus = 'OBSERVED' | 'MISSING' | 'UNKNOWN' | 'NOT_APPLICABLE'

export type ExternalHeaderObservation = Readonly<{
  name: string
  /** Bounded allowlisted header value; never Authorization / cookie values. */
  value: string
}>

/**
 * Canonical security-relevant header identifiers (lowercase).
 * Presence/absence is factual; quality is E1.6.
 */
export type ExternalSecurityHeaderId =
  | 'strict-transport-security'
  | 'content-security-policy'
  | 'x-content-type-options'
  | 'referrer-policy'
  | 'permissions-policy'
  | 'cross-origin-opener-policy'
  | 'cross-origin-resource-policy'
  | 'cross-origin-embedder-policy'
  | 'content-type'
  | 'content-encoding'
  | 'location'
  | 'set-cookie'

export type ExternalSecurityHeaderObservation = Readonly<{
  name: ExternalSecurityHeaderId
  status: 'OBSERVED' | 'MISSING'
  /**
   * Encounter-order values when OBSERVED.
   * For set-cookie: always empty — attributes live in `cookies` only.
   */
  values: readonly string[]
}>

/**
 * Purely syntactic HSTS directives. Presence of directives is factual;
 * whether max-age is "enough" is E1.6.
 */
export type ExternalHstsObservation = Readonly<{
  status: 'OBSERVED' | 'MISSING' | 'NOT_APPLICABLE'
  rawValue?: string
  maxAgeSeconds?: number
  includeSubDomains?: boolean
  preload?: boolean
  malformed?: boolean
}>

/**
 * Cookie SameSite fact:
 * - Strict / Lax / None: recognized attribute value
 * - absent: Set-Cookie observed and SameSite attribute was not present
 * - unknown: SameSite attribute present but value was not recognized
 *
 * Rules must not treat `unknown` as "missing".
 */
export type ExternalCookieSameSite = 'Strict' | 'Lax' | 'None' | 'absent' | 'unknown'

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
  /** True when the Set-Cookie line could not be fully parsed. */
  malformed?: boolean
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

export type ExternalBlockedRedirectReason =
  | 'https-to-http'
  | 'blocked-destination'
  | 'unsupported-port'
  | 'unsupported-scheme'
  | 'credentials'
  | 'loop'
  | 'budget'
  | 'malformed-location'
  | 'other'

/**
 * Factual record of a redirect that was not followed.
 * Populated by callers when transport blocked a hop; not a finding.
 */
export type ExternalBlockedRedirectObservation = Readonly<{
  index: number
  fromUrl: string
  toUrl?: string
  statusCode?: number
  reason: ExternalBlockedRedirectReason
}>

export type ExternalHttpResponseObservation = Readonly<{
  url: string
  method: ExternalHttpMethod
  statusCode: number
  scheme: 'http' | 'https'
  /** Allowlisted header observations only (excludes Set-Cookie raw values). */
  headers: readonly ExternalHeaderObservation[]
  /** Presence catalog for security-relevant headers. */
  securityHeaders: readonly ExternalSecurityHeaderObservation[]
  hsts: ExternalHstsObservation
  /** Declared content-type token if present; no body bytes. */
  contentType?: string
  /** Observed content-encoding token if present. */
  contentEncoding?: string
  /** Byte length observed or capped; not the body itself. */
  bodyByteLength: number
  cookies: readonly ExternalCookieAttributeObservation[]
  tlsUsed: boolean
  tls?: ExternalTlsObservation
}>

export type ExternalAssetSkipReason =
  | 'off-origin'
  | 'unsupported-scheme'
  | 'credentials'
  | 'unsupported-port'
  | 'normalize-failed'
  | 'budget'
  | 'max-assets'
  | 'redirect-left-origin'
  | 'fetch-failed'
  | 'oversized-html'
  | 'not-html'
  | 'duplicate'

export type ExternalAssetObservation = Readonly<{
  sourceUrl: string
  requestUrl: string
  kind: 'script' | 'stylesheet'
  sameOrigin: boolean
  fetched: boolean
  statusCode?: number
  contentType?: string
  byteLength?: number
  redirected?: boolean
  skipReason?: ExternalAssetSkipReason
  sourceMapReferenced?: boolean
  /** Bounded external map URL reference; never inline data payload. */
  sourceMapReference?: string
  inlineSourceMap?: boolean
}>

/**
 * Immutable capture of observations for one External scan.
 * Redirects remain in sequence order; other collections may be sorted later.
 */
export type ExternalObservationGraph = Readonly<{
  initialRequestUrl: string
  finalUrl?: string
  redirects: readonly ExternalRedirectObservation[]
  blockedRedirects: readonly ExternalBlockedRedirectObservation[]
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
    blockedRedirects: Object.freeze([]),
    responses: Object.freeze([]),
    assets: Object.freeze([]),
  })
}
