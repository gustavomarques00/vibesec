import { compareExternalStrings } from '../domain/ordering.js'
import type {
  ExternalHeaderObservation,
  ExternalHstsObservation,
  ExternalSecurityHeaderId,
  ExternalSecurityHeaderObservation,
} from '../domain/observations.js'
import {
  FORBIDDEN_HEADER_NAMES,
  MAX_HEADER_VALUE_CHARS,
  SECURITY_HEADER_IDS,
  SECURITY_HEADER_ID_SET,
} from './header-names.js'

export type RawHeaderInput = Readonly<{
  name: string
  value: string
}>

/**
 * Collect allowlisted header facts. Set-Cookie raw values are never retained.
 */
export function extractSecurityHeaderObservations(
  headers: readonly RawHeaderInput[],
): readonly ExternalSecurityHeaderObservation[] {
  const buckets = new Map<ExternalSecurityHeaderId, string[]>()

  for (const header of headers) {
    const canonical = canonicalizeHeaderName(header.name)
    if (!SECURITY_HEADER_ID_SET.has(canonical)) continue
    if (FORBIDDEN_HEADER_NAMES.has(canonical)) continue

    const id = canonical as ExternalSecurityHeaderId
    if (id === 'set-cookie') {
      // Presence only — cookie attributes are extracted separately.
      if (!buckets.has(id)) buckets.set(id, [])
      continue
    }

    const bounded = boundHeaderValue(header.value)
    const existing = buckets.get(id)
    if (existing === undefined) buckets.set(id, [bounded])
    else existing.push(bounded)
  }

  return Object.freeze(
    SECURITY_HEADER_IDS.map((name) => {
      const values = buckets.get(name)
      if (values === undefined) {
        return Object.freeze({
          name,
          status: 'MISSING' as const,
          values: Object.freeze([]),
        })
      }
      return Object.freeze({
        name,
        status: 'OBSERVED' as const,
        values: Object.freeze([...values]),
      })
    }),
  )
}

/**
 * Flatten allowlisted header name/value pairs for the response DTO.
 * Excludes set-cookie raw values. Sorted deterministically.
 */
export function extractAllowlistedHeaderPairs(
  headers: readonly RawHeaderInput[],
): readonly ExternalHeaderObservation[] {
  const pairs: ExternalHeaderObservation[] = []
  for (const header of headers) {
    const name = canonicalizeHeaderName(header.name)
    if (!SECURITY_HEADER_ID_SET.has(name)) continue
    if (name === 'set-cookie') continue
    if (FORBIDDEN_HEADER_NAMES.has(name)) continue
    pairs.push(
      Object.freeze({
        name,
        value: boundHeaderValue(header.value),
      }),
    )
  }
  return Object.freeze(
    [...pairs].sort((left, right) => {
      const byName = compareExternalStrings(left.name, right.name)
      if (byName !== 0) return byName
      return compareExternalStrings(left.value, right.value)
    }),
  )
}

export function extractHstsObservation(
  securityHeaders: readonly ExternalSecurityHeaderObservation[],
  scheme: 'http' | 'https',
): ExternalHstsObservation {
  if (scheme !== 'https') {
    return Object.freeze({ status: 'NOT_APPLICABLE' })
  }

  const hsts = securityHeaders.find(
    (entry) => entry.name === 'strict-transport-security',
  )
  if (hsts === undefined || hsts.status === 'MISSING') {
    return Object.freeze({ status: 'MISSING' })
  }

  const rawValue = hsts.values[0] ?? ''
  const parsed = parseHstsDirectives(rawValue)
  return Object.freeze({
    status: 'OBSERVED',
    rawValue,
    ...(parsed.maxAgeSeconds !== undefined
      ? { maxAgeSeconds: parsed.maxAgeSeconds }
      : {}),
    ...(parsed.includeSubDomains ? { includeSubDomains: true } : {}),
    ...(parsed.preload ? { preload: true } : {}),
    ...(parsed.malformed ? { malformed: true } : {}),
  })
}

export function canonicalizeHeaderName(name: string): string {
  return name.trim().toLowerCase().normalize('NFC')
}

export function boundHeaderValue(value: string): string {
  const normalized = value.normalize('NFC')
  if (normalized.length <= MAX_HEADER_VALUE_CHARS) return normalized
  return normalized.slice(0, MAX_HEADER_VALUE_CHARS)
}

function parseHstsDirectives(raw: string): {
  maxAgeSeconds?: number
  includeSubDomains: boolean
  preload: boolean
  malformed: boolean
} {
  let maxAgeSeconds: number | undefined
  let includeSubDomains = false
  let preload = false
  let malformed = false

  if (raw.trim().length === 0) {
    return { includeSubDomains: false, preload: false, malformed: true }
  }

  for (const part of raw.split(';')) {
    const trimmed = part.trim()
    if (trimmed.length === 0) continue
    const eq = trimmed.indexOf('=')
    const name = (eq === -1 ? trimmed : trimmed.slice(0, eq)).trim().toLowerCase()
    const value = eq === -1 ? '' : trimmed.slice(eq + 1).trim()

    if (name === 'max-age') {
      if (!/^\d+$/u.test(value)) {
        malformed = true
        continue
      }
      const parsed = Number(value)
      if (!Number.isSafeInteger(parsed)) {
        malformed = true
        continue
      }
      maxAgeSeconds = parsed
      continue
    }
    if (name === 'includesubdomains') {
      includeSubDomains = true
      continue
    }
    if (name === 'preload') {
      preload = true
      continue
    }
    // Unknown directives ignored structurally.
  }

  return {
    ...(maxAgeSeconds !== undefined ? { maxAgeSeconds } : {}),
    includeSubDomains,
    preload,
    malformed,
  }
}
