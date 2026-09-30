declare const sanitizedTextBrand: unique symbol
declare const fingerprintBrand: unique symbol
declare const safeOutputBrand: unique symbol

/**
 * Opaque scan-scoped tokens. Their payloads live exclusively in private WeakMaps
 * owned by the issuing redaction boundary.
 */
export type SanitizedText = Readonly<{ readonly [sanitizedTextBrand]: true }>

export type IssuedSecretFingerprint = Readonly<{
  readonly [fingerprintBrand]: true
}>

export type SafeOutput = Readonly<{ readonly [safeOutputBrand]: true }>

export type ProtectedSensitiveValue = Readonly<{
  redacted: SanitizedText
  fingerprint: IssuedSecretFingerprint
}>
