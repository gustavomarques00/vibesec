import type { ExternalFinding } from '../rules/types.js'
import type { ExternalObservationGraph } from '../domain/observations.js'
import type { FindingSeverity } from '../../core/models/finding.js'

export type { ExternalFinding }

export type ExternalReportFormat = 'terminal' | 'json' | 'markdown'

export type ExternalFindingSeveritySummary = Readonly<{
  total: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
}>

/**
 * Bounded External scan result for reporters.
 * schemaVersion ext-1 is distinct from Code JSON schema "1".
 */
export type ExternalScanResult = Readonly<{
  schemaVersion: 'ext-1'
  target: string
  effectiveUrl: string
  findings: readonly ExternalFinding[]
  summary: ExternalFindingSeveritySummary
  limitations: readonly string[]
  evaluationTimeMs: number
  requestsConsumed: number
}>

export type ExternalJsonReportDocument = Readonly<{
  schemaVersion: 'ext-1'
  target: string
  effectiveUrl: string
  summary: ExternalFindingSeveritySummary
  findings: readonly ExternalFinding[]
  limitations: readonly string[]
  evaluationTimeMs: number
  requestsConsumed: number
}>

/**
 * Pure deterministic severity summary from finalized findings.
 */
export function summarizeExternalFindings(
  findings: readonly ExternalFinding[],
): ExternalFindingSeveritySummary {
  const counts: Record<FindingSeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  }
  for (const finding of findings) {
    counts[finding.severity] += 1
  }
  return Object.freeze({
    total: findings.length,
    critical: counts.critical,
    high: counts.high,
    medium: counts.medium,
    low: counts.low,
    info: counts.info,
  })
}

/**
 * Derive factual scan limitations from the observation graph.
 * Does not invent coverage claims.
 */
export function deriveExternalLimitations(
  graph: ExternalObservationGraph,
): readonly string[] {
  const limitations: string[] = []
  const skipReasons = new Set(
    graph.assets
      .map((asset) => asset.skipReason)
      .filter((reason): reason is NonNullable<typeof reason> => reason !== undefined),
  )

  if (skipReasons.has('max-assets')) {
    limitations.push('Asset inventory stopped after reaching maxAssets.')
  }
  if (skipReasons.has('budget')) {
    limitations.push('One or more assets were skipped due to the request budget.')
  }
  if (skipReasons.has('oversized-html')) {
    limitations.push('HTML body exceeded maxHtmlBytes; asset extraction was skipped.')
  }
  if (skipReasons.has('not-html')) {
    limitations.push(
      'Document content-type was not treated as HTML for asset extraction.',
    )
  }

  const hasPublicMapReference = graph.assets.some(
    (asset) =>
      asset.fetched &&
      asset.sourceMapReferenced === true &&
      typeof asset.sourceMapReference === 'string',
  )
  if (hasPublicMapReference) {
    limitations.push(
      'Source map URLs may be publicly referenced; map files are not fetched by design.',
    )
  }

  return Object.freeze(limitations)
}

export function createExternalScanResult(args: {
  target: string
  effectiveUrl: string
  findings: readonly ExternalFinding[]
  limitations: readonly string[]
  evaluationTimeMs: number
  requestsConsumed: number
}): ExternalScanResult {
  return Object.freeze({
    schemaVersion: 'ext-1',
    target: args.target,
    effectiveUrl: args.effectiveUrl,
    findings: Object.freeze([...args.findings]),
    summary: summarizeExternalFindings(args.findings),
    limitations: Object.freeze([...args.limitations]),
    evaluationTimeMs: args.evaluationTimeMs,
    requestsConsumed: args.requestsConsumed,
  })
}
