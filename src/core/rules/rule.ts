import type { EvidenceDraft } from '../models/evidence.js'
import type {
  FindingConfidence,
  FindingSeverity,
  FindingStatus,
} from '../models/finding.js'
import type { FactKind } from '../models/fact.js'
import type { SourceLocation } from '../models/source-location.js'
import type { RuleContext } from './rule-context.js'

export interface RuleMetadata {
  readonly id: string
  readonly version: string
  readonly title: string
  readonly category: string
  readonly defaultSeverity: FindingSeverity
  readonly supportedFacts: readonly FactKind[]
  readonly references: readonly string[]
}

/**
 * Export-safe rule result before deterministic ID assignment and normalization.
 * Rule-controlled metadata is intentionally absent and is supplied by the evaluator.
 */
export type FindingDraft = Readonly<{
  description: string
  severity?: FindingSeverity
  confidence: FindingConfidence
  status: FindingStatus
  primaryLocation?: SourceLocation
  relatedLocations: readonly SourceLocation[]
  evidence: readonly EvidenceDraft[]
  impact: string
  remediation: string
  limitations: readonly string[]
  tags: readonly string[]
}>

/**
 * Rules are pure deterministic functions over immutable, already-extracted facts.
 * This contract intentionally exposes no filesystem, network, subprocess, logger,
 * reporter, clock, random source, or raw sensitive value.
 */
export interface Rule {
  readonly metadata: RuleMetadata
  evaluate(context: RuleContext): readonly FindingDraft[]
}
