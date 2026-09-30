import type {
  ExternalBlockedRedirectObservation,
  ExternalRedirectObservation,
} from '../domain/observations.js'

/**
 * Preserve redirect sequence order exactly as provided by transport.
 * Does not sort. Does not invent security verdicts.
 */
export function extractRedirectObservations(
  redirects: readonly ExternalRedirectObservation[],
): readonly ExternalRedirectObservation[] {
  return Object.freeze(
    redirects.map((redirect, index) =>
      Object.freeze({
        index: redirect.index >= 0 ? redirect.index : index,
        fromUrl: redirect.fromUrl.normalize('NFC'),
        toUrl: redirect.toUrl.normalize('NFC'),
        statusCode: redirect.statusCode,
      }),
    ),
  )
}

export function extractBlockedRedirectObservations(
  blocked: readonly ExternalBlockedRedirectObservation[] | undefined,
): readonly ExternalBlockedRedirectObservation[] {
  if (blocked === undefined || blocked.length === 0) {
    return Object.freeze([])
  }
  return Object.freeze(
    blocked.map((entry, index) =>
      Object.freeze({
        index: entry.index >= 0 ? entry.index : index,
        fromUrl: entry.fromUrl.normalize('NFC'),
        ...(entry.toUrl !== undefined ? { toUrl: entry.toUrl.normalize('NFC') } : {}),
        ...(entry.statusCode !== undefined ? { statusCode: entry.statusCode } : {}),
        reason: entry.reason,
      }),
    ),
  )
}
