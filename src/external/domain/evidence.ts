/**
 * External evidence kinds for future VS-EXT findings.
 * Intentionally distinct from Code evidence kinds and file path locations.
 */
export const EXTERNAL_EVIDENCE_KINDS = Object.freeze([
  'http',
  'tls',
  'header',
  'cookie-attr',
  'redirect',
  'asset',
] as const)

export type ExternalEvidenceKind = (typeof EXTERNAL_EVIDENCE_KINDS)[number]

/**
 * URL-scoped evidence identity. Does not reuse Code file path locations.
 */
export type ExternalEvidenceLocation = Readonly<{
  kind: 'url'
  /** Absolute request/observation URL without credentials or fragment. */
  url: string
}>

export type ExternalEvidenceDraft = Readonly<{
  kind: ExternalEvidenceKind
  summary: string
  location?: ExternalEvidenceLocation
  /** Optional bounded redacted excerpt — never raw secrets/bodies by convention. */
  redactedSnippet?: string
}>
