import type { ExternalSecurityHeaderId } from '../domain/observations.js'

/**
 * Allowlisted response headers for External observation extraction.
 * Authorization / Proxy-Authorization / WWW-Authenticate are intentionally absent.
 */
export const SECURITY_HEADER_IDS = Object.freeze([
  'strict-transport-security',
  'content-security-policy',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'cross-origin-embedder-policy',
  'content-type',
  'content-encoding',
  'location',
  'set-cookie',
] as const satisfies readonly ExternalSecurityHeaderId[])

export const SECURITY_HEADER_ID_SET: ReadonlySet<string> = new Set(SECURITY_HEADER_IDS)

/** Headers whose raw values must never be retained (secret-bearing / cookies). */
export const FORBIDDEN_HEADER_NAMES: ReadonlySet<string> = new Set([
  'authorization',
  'proxy-authorization',
  'www-authenticate',
  'cookie',
])

export const MAX_HEADER_VALUE_CHARS = 8_192
export const MAX_COOKIE_NAME_CHARS = 256
