import type { Evidence } from './evidence.js'
import type { SourceLocation } from './source-location.js'

export const FINDING_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const

export type FindingSeverity = (typeof FINDING_SEVERITIES)[number]

export const FINDING_CONFIDENCES = ['high', 'medium', 'low'] as const

export type FindingConfidence = (typeof FINDING_CONFIDENCES)[number]

/**
 * Evidence status for the exact, narrowly worded claim in a finding.
 *
 * - confirmed: directly verifiable in the analyzed repository material.
 * - suspicious: potentially unsafe pattern with insufficient evidence.
 * - requires_authorization: confirmation requires validation in the owner's environment.
 *
 * "confirmed" does not mean a confirmed exploit, vulnerable production system,
 * valid credential, or accessible data.
 */
export const FINDING_STATUSES = [
  'confirmed',
  'suspicious',
  'requires_authorization',
] as const

export type FindingStatus = (typeof FINDING_STATUSES)[number]

export type Finding = Readonly<{
  schemaVersion: '1'
  id: string
  ruleId: string
  ruleVersion: string
  title: string
  description: string
  category: string
  severity: FindingSeverity
  confidence: FindingConfidence
  status: FindingStatus
  primaryLocation?: SourceLocation
  relatedLocations: readonly SourceLocation[]
  evidence: readonly Evidence[]
  impact: string
  remediation: string
  limitations: readonly string[]
  references: readonly string[]
  tags: readonly string[]
}>
