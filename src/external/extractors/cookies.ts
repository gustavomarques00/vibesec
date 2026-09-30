import { compareExternalStrings } from '../domain/ordering.js'
import type {
  ExternalCookieAttributeObservation,
  ExternalCookieSameSite,
} from '../domain/observations.js'
import { MAX_COOKIE_NAME_CHARS } from './header-names.js'
import type { RawHeaderInput } from './headers.js'
import { canonicalizeHeaderName } from './headers.js'

/**
 * Parse Set-Cookie headers into attribute-only observations.
 * Cookie values are discarded at the parsing boundary and never retained.
 */
export function extractCookieAttributeObservations(
  headers: readonly RawHeaderInput[],
): readonly ExternalCookieAttributeObservation[] {
  const cookies: ExternalCookieAttributeObservation[] = []

  for (const header of headers) {
    if (canonicalizeHeaderName(header.name) !== 'set-cookie') continue
    const parsed = parseSetCookieLine(header.value)
    if (parsed !== undefined) cookies.push(parsed)
  }

  return Object.freeze(
    [...cookies].sort((left, right) => {
      const byName = compareExternalStrings(left.name, right.name)
      if (byName !== 0) return byName
      return compareExternalStrings(cookieSortKey(left), cookieSortKey(right))
    }),
  )
}

function parseSetCookieLine(
  rawLine: string,
): ExternalCookieAttributeObservation | undefined {
  // Work on a local copy; never return or store the raw line.
  const line = rawLine.normalize('NFC')
  if (line.trim().length === 0) return undefined

  const firstSemi = line.indexOf(';')
  const pair = firstSemi === -1 ? line : line.slice(0, firstSemi)
  const rest = firstSemi === -1 ? '' : line.slice(firstSemi + 1)

  const eq = pair.indexOf('=')
  const rawName = (eq === -1 ? pair : pair.slice(0, eq)).trim()
  // VALUE is intentionally discarded here and never assigned to any field.
  void (eq === -1 ? '' : pair.slice(eq + 1))

  const name = sanitizeCookieName(rawName)
  if (name === undefined) {
    return Object.freeze({
      name: 'malformed',
      secure: false,
      httpOnly: false,
      sameSite: 'unknown' as const,
      hostPrefix: false,
      securePrefix: false,
      malformed: true,
    })
  }

  let secure = false
  let httpOnly = false
  let sameSite: ExternalCookieSameSite = 'unknown'
  let domain: string | undefined
  let path: string | undefined
  let maxAgeSeconds: number | undefined
  let expiresAtIso: string | undefined
  let malformed = false

  for (const segment of rest.split(';')) {
    const trimmed = segment.trim()
    if (trimmed.length === 0) continue
    const attrEq = trimmed.indexOf('=')
    const attrName = (attrEq === -1 ? trimmed : trimmed.slice(0, attrEq))
      .trim()
      .toLowerCase()
    const attrValue = attrEq === -1 ? '' : trimmed.slice(attrEq + 1).trim()

    if (attrName === 'secure') {
      secure = true
      continue
    }
    if (attrName === 'httponly') {
      httpOnly = true
      continue
    }
    if (attrName === 'samesite') {
      sameSite = parseSameSite(attrValue)
      continue
    }
    if (attrName === 'domain') {
      domain = boundAttrToken(attrValue)
      continue
    }
    if (attrName === 'path') {
      path = boundAttrToken(attrValue)
      continue
    }
    if (attrName === 'max-age') {
      if (/^-?\d+$/u.test(attrValue)) {
        const parsed = Number(attrValue)
        if (Number.isSafeInteger(parsed)) maxAgeSeconds = parsed
        else malformed = true
      } else {
        malformed = true
      }
      continue
    }
    if (attrName === 'expires') {
      const iso = tryParseExpiresIso(attrValue)
      if (iso === undefined) malformed = true
      else expiresAtIso = iso
      continue
    }
    // Unknown attributes intentionally ignored (no raw retention).
  }

  const lowerName = name.toLowerCase()
  return Object.freeze({
    name,
    secure,
    httpOnly,
    sameSite,
    ...(domain !== undefined ? { domain } : {}),
    ...(path !== undefined ? { path } : {}),
    ...(maxAgeSeconds !== undefined ? { maxAgeSeconds } : {}),
    ...(expiresAtIso !== undefined ? { expiresAtIso } : {}),
    hostPrefix: lowerName.startsWith('__host-'),
    securePrefix: lowerName.startsWith('__secure-'),
    ...(malformed ? { malformed: true } : {}),
  })
}

function sanitizeCookieName(raw: string): string | undefined {
  const name = raw.normalize('NFC')
  if (name.length === 0 || name.length > MAX_COOKIE_NAME_CHARS) return undefined
  // RFC 6265 cookie-name token: exclude CTLs, separators; keep printable ASCII.
  if (!/^[\u0021-\u007e]+$/u.test(name)) return undefined
  if (/[()<>@,;:\\"/[\]?={}\s]/u.test(name)) return undefined
  return name
}

function parseSameSite(value: string): ExternalCookieSameSite {
  const normalized = value.toLowerCase()
  if (normalized === 'strict') return 'Strict'
  if (normalized === 'lax') return 'Lax'
  if (normalized === 'none') return 'None'
  return 'unknown'
}

function boundAttrToken(value: string): string {
  const normalized = value.normalize('NFC')
  if (normalized.length <= MAX_COOKIE_NAME_CHARS) return normalized
  return normalized.slice(0, MAX_COOKIE_NAME_CHARS)
}

function tryParseExpiresIso(value: string): string | undefined {
  const ms = Date.parse(value)
  if (!Number.isFinite(ms)) return undefined
  return new Date(ms).toISOString()
}

function cookieSortKey(cookie: ExternalCookieAttributeObservation): string {
  return [
    cookie.secure ? '1' : '0',
    cookie.httpOnly ? '1' : '0',
    cookie.sameSite,
    cookie.domain ?? '',
    cookie.path ?? '',
    cookie.maxAgeSeconds === undefined ? '' : String(cookie.maxAgeSeconds),
    cookie.expiresAtIso ?? '',
  ].join('\u0000')
}
