import type { ExternalTlsObservation } from '../domain/observations.js'

export type RawTlsInput = Readonly<{
  authorized: boolean
  protocol?: string
  authorizationError?: string
  validFromIso?: string
  validToIso?: string
  subjectCn?: string
  issuerCn?: string
}>

/**
 * Canonicalize TLS transport metadata into observation facts.
 * Does not decide trust outcomes for reporting; does not retain certificate bytes.
 */
export function extractTlsObservation(
  scheme: 'http' | 'https',
  tls: RawTlsInput | undefined,
): { tlsUsed: boolean; tls?: ExternalTlsObservation } {
  if (scheme !== 'https') {
    return Object.freeze({ tlsUsed: false })
  }

  if (tls === undefined) {
    return Object.freeze({
      tlsUsed: true,
      tls: Object.freeze({
        authorized: false,
        authorizationError: 'unknown',
      }),
    })
  }

  return Object.freeze({
    tlsUsed: true,
    tls: Object.freeze({
      authorized: tls.authorized,
      ...(tls.protocol !== undefined
        ? { protocol: tls.protocol.normalize('NFC') }
        : {}),
      ...(tls.authorizationError !== undefined
        ? { authorizationError: boundText(tls.authorizationError) }
        : {}),
      ...(tls.validFromIso !== undefined ? { validFromIso: tls.validFromIso } : {}),
      ...(tls.validToIso !== undefined ? { validToIso: tls.validToIso } : {}),
      ...(tls.subjectCn !== undefined ? { subjectCn: boundText(tls.subjectCn) } : {}),
      ...(tls.issuerCn !== undefined ? { issuerCn: boundText(tls.issuerCn) } : {}),
    }),
  })
}

function boundText(value: string): string {
  const normalized = value.normalize('NFC')
  return normalized.length <= 512 ? normalized : normalized.slice(0, 512)
}
