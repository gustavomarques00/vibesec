import {
  InvalidExternalTargetError,
  UnsupportedExternalPortError,
  UnsupportedExternalSchemeError,
} from './errors.js'

export type ExternalScheme = 'http' | 'https'

export type ExternalTargetInput = string

/**
 * Scheme + host + effective port for same-origin comparisons in later slices.
 * Default ports are recorded explicitly as 80/443.
 */
export type ExternalOrigin = Readonly<{
  scheme: ExternalScheme
  hostname: string
  port: 80 | 443
  /** WHATWG-style origin string without credentials (default ports omitted). */
  origin: string
}>

/**
 * Canonical initial External target after E1 policy normalization.
 * Contains no DNS/IP resolution results.
 */
export type NormalizedExternalTarget = Readonly<{
  scheme: ExternalScheme
  hostname: string
  port: 80 | 443
  origin: string
  pathname: string
  search: string
  /** Absolute URL used for the initial request identity (no credentials, no fragment). */
  requestUrl: string
  /** Stable human-facing target string (equals requestUrl). */
  displayTarget: string
}>

const CONTROL_OR_SPACE = /[\s\u007f\u0080-\u009f]/u
const HAS_SCHEME = /^[a-zA-Z][a-zA-Z0-9+.-]*:/u
const CIDR_OR_RANGE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\/\d{1,3}$/u

/**
 * Trailing-dot policy (E1): strip trailing dots from the hostname after URL
 * parsing so `example.com.` and `example.com` share one canonical identity.
 */
export function normalizeExternalTarget(
  input: ExternalTargetInput,
): NormalizedExternalTarget {
  if (typeof input !== 'string') throw new InvalidExternalTargetError()

  const trimmed = input.trim()
  if (trimmed.length === 0) throw new InvalidExternalTargetError()
  if (trimmed.includes('\0')) throw new InvalidExternalTargetError()
  for (const character of trimmed) {
    const code = character.codePointAt(0)
    if (code !== undefined && code < 0x20) throw new InvalidExternalTargetError()
  }
  if (CONTROL_OR_SPACE.test(trimmed)) throw new InvalidExternalTargetError()
  if (trimmed.includes('*')) throw new InvalidExternalTargetError()
  if (CIDR_OR_RANGE.test(trimmed)) throw new InvalidExternalTargetError()
  if (trimmed.includes(',') || trimmed.includes(';')) {
    throw new InvalidExternalTargetError()
  }

  const withScheme = ensureScheme(trimmed)
  let parsed: URL
  try {
    parsed = new URL(withScheme)
  } catch {
    throw new InvalidExternalTargetError()
  }

  const scheme = readScheme(parsed.protocol)

  if (parsed.username !== '' || parsed.password !== '') {
    throw new InvalidExternalTargetError()
  }

  const hostname = canonicalizeHostname(parsed.hostname)
  if (hostname.length === 0) throw new InvalidExternalTargetError()
  if (hostname.includes('*')) throw new InvalidExternalTargetError()

  const port = readAllowedPort(scheme, parsed.port)

  const pathname = parsed.pathname.length === 0 ? '/' : parsed.pathname.normalize('NFC')
  const search = parsed.search.normalize('NFC')

  const requestUrl = buildRequestUrl(scheme, hostname, port, pathname, search)
  const origin = buildOrigin(scheme, hostname, port)

  return Object.freeze({
    scheme,
    hostname,
    port,
    origin,
    pathname,
    search,
    requestUrl,
    displayTarget: requestUrl,
  })
}

export function toExternalOrigin(target: NormalizedExternalTarget): ExternalOrigin {
  return Object.freeze({
    scheme: target.scheme,
    hostname: target.hostname,
    port: target.port,
    origin: target.origin,
  })
}

function ensureScheme(trimmed: string): string {
  if (!HAS_SCHEME.test(trimmed)) {
    // Bare host / host+path without scheme → HTTPS only (never invent HTTP).
    return `https://${trimmed}`
  }
  return trimmed
}

function readScheme(protocol: string): ExternalScheme {
  if (protocol === 'https:') return 'https'
  if (protocol === 'http:') return 'http'
  throw new UnsupportedExternalSchemeError()
}

function canonicalizeHostname(hostname: string): string {
  // URL already lowercases ASCII hostnames and applies IDN→punycode.
  // Strip accidental brackets then trailing dots for a stable host identity.
  const withoutBrackets = hostname.replace(/^\[/u, '').replace(/\]$/u, '')
  return withoutBrackets.replace(/\.+$/u, '').normalize('NFC')
}

function readAllowedPort(scheme: ExternalScheme, portField: string): 80 | 443 {
  if (portField === '') {
    return scheme === 'https' ? 443 : 80
  }
  if (!/^\d+$/u.test(portField)) throw new UnsupportedExternalPortError()
  const port = Number(portField)
  if (port === 80 || port === 443) return port
  throw new UnsupportedExternalPortError()
}

function formatHostForUrl(hostname: string): string {
  return hostname.includes(':') ? `[${hostname}]` : hostname
}

function buildOrigin(scheme: ExternalScheme, hostname: string, port: 80 | 443): string {
  const hostForUrl = formatHostForUrl(hostname)
  const defaultPort = scheme === 'https' ? 443 : 80
  if (port === defaultPort) return `${scheme}://${hostForUrl}`
  return `${scheme}://${hostForUrl}:${String(port)}`
}

function buildRequestUrl(
  scheme: ExternalScheme,
  hostname: string,
  port: 80 | 443,
  pathname: string,
  search: string,
): string {
  // Fragment intentionally omitted — never part of request identity.
  return `${buildOrigin(scheme, hostname, port)}${pathname}${search}`
}
