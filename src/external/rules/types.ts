import type {
  FindingConfidence,
  FindingSeverity,
  FindingStatus,
} from '../../core/models/finding.js'
import type {
  ExternalEvidenceDraft,
  ExternalEvidenceKind,
  ExternalEvidenceLocation,
} from '../domain/evidence.js'
import type { ExternalObservationGraph } from '../domain/observations.js'

export type ExternalRuleId =
  | 'VS-EXT-001'
  | 'VS-EXT-002'
  | 'VS-EXT-003'
  | 'VS-EXT-004'
  | 'VS-EXT-005'
  | 'VS-EXT-006'
  | 'VS-EXT-007'
  | 'VS-EXT-008'
  | 'VS-EXT-009'
  | 'VS-EXT-010'
  | 'VS-EXT-011'

export type ExternalRuleMetadata = Readonly<{
  id: ExternalRuleId
  version: string
  title: string
  category: string
  defaultSeverity: FindingSeverity
  evidenceKind: ExternalEvidenceKind
  description: string
}>

/**
 * Injected evaluation context. Rules must not read the wall clock.
 */
export type ExternalRuleEvaluationContext = Readonly<{
  /** Unix epoch milliseconds used for time-dependent TLS checks. */
  evaluationTimeMs: number
}>

export type ExternalFindingEvidence = Readonly<{
  kind: ExternalEvidenceKind
  summary: string
  location: ExternalEvidenceLocation
  redactedSnippet?: string
}>

/**
 * External finding. URL-native identity — never Code file-path locations.
 */
export type ExternalFinding = Readonly<{
  schemaVersion: '1'
  id: string
  ruleId: ExternalRuleId
  ruleVersion: string
  title: string
  description: string
  category: string
  severity: FindingSeverity
  confidence: FindingConfidence
  status: FindingStatus
  primaryUrl: string
  evidence: readonly ExternalFindingEvidence[]
  impact: string
  remediation: string
  limitations: readonly string[]
  tags: readonly string[]
}>

export type ExternalFindingDraft = Readonly<{
  ruleId: ExternalRuleId
  primaryUrl: string
  /** Bounded non-secret discriminator (cookie name/path, asset URL, etc.). */
  discriminator?: string
  description: string
  severity?: FindingSeverity
  confidence: FindingConfidence
  status: FindingStatus
  evidence: readonly ExternalEvidenceDraft[]
  impact: string
  remediation: string
  limitations: readonly string[]
  tags: readonly string[]
}>

export type ExternalRule = Readonly<{
  metadata: ExternalRuleMetadata
  evaluate(
    graph: ExternalObservationGraph,
    context: ExternalRuleEvaluationContext,
  ): readonly ExternalFindingDraft[]
}>
