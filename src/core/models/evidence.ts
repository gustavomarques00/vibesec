import type { IssuedSecretFingerprint, SanitizedText } from '../../security/tokens.js'
import type { SourceLocation } from './source-location.js'

export type EvidenceKind = 'code' | 'config' | 'migration' | 'correlation'

export type EvidenceDraft = Readonly<{
  kind: EvidenceKind
  summary: string
  redactedSnippet?: SanitizedText
  locations: readonly SourceLocation[]
  secretFingerprint?: IssuedSecretFingerprint
}>

export type Evidence = Readonly<{
  kind: EvidenceKind
  summary: string
  redactedSnippet?: string
  locations: readonly SourceLocation[]
  secretFingerprint?: string
}>
